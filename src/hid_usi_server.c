// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022, Intel Corporation
 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/resource.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <glib.h>
#include <gio/gio.h>

#include "bpf_util.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/hidraw.h>

#include "hid_usi.h"
#include "hid_parser.h"
#include "hid_usi_server_kern.h"

static char ver_buf[256];
static char *version = ver_buf;
static GMainLoop *mainloop;
static DBusConnection *dbus_conn;

static int hid_id;
static int sysfs_fd;
static int hidraw_fd;
static int cache;
static struct ring_buffer *event_rb;

static bool use_session_bus;
static bool in_range;

static const struct option long_options[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "session", no_argument, NULL, 'e' },
	{ "debug", no_argument, NULL, 'd' },
};

static struct hid_usi_server_kern *skel;

static struct hid_config_data inputs[USI_NUM_PARAMS];
static struct hid_config_data features[USI_NUM_PARAMS];

static bool debug;

static unsigned vendor;
static unsigned product;

static const char *server_introspection_xml =
	DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE
	"<node>\n"
	"  <interface name='org.freedesktop.DBus.Introspectable'>\n"
	"    <method name='Introspect'>\n"
	"      <arg name='data' type='s' direction='out' />\n"
	"    </method>\n"
	"  </interface>\n"

	"  <interface name='org.freedesktop.DBus.Properties'>\n"
	"    <method name='Get'>\n"
	"      <arg name='interface' type='s' direction='in' />\n"
	"      <arg name='property'  type='s' direction='in' />\n"
	"      <arg name='value'     type='v' direction='out' />\n"
	"    </method>\n"
	"    <method name='Set'>\n"
	"      <arg name='interface' type='s' direction='in' />\n"
	"      <arg name='property'  type='s' direction='in' />\n"
	"      <arg name='value'     type='v' direction='in' />\n"
	"    </method>\n"
	"    <method name='GetAll'>\n"
	"      <arg name='properties' type='a{sv}' direction='out'/>\n"
	"    </method>\n"
	"  </interface>\n"

	"  <interface name='org.universalstylus.PenInterface'>\n"
	"    <property name='Version' type='s' access='read' />\n"
	"    <property name='LineColor' type='u' access='readwrite' />\n"
	"    <property name='LineWidth' type='u' access='readwrite' />\n"
	"    <property name='LineStyle' type='u' access='readwrite' />\n"
	"  </interface>\n"
	"</node>\n";

static int usi_ioctl(int fd, char *buf, int reqtype)
{
	int ret;
	static GMutex ioctl_mutex;
	struct usi_args args = { 0 };
	LIBBPF_OPTS(bpf_test_run_opts, run_attrs,
			.ctx_in = &args,
			.ctx_size_in = sizeof(args),
	);

	memcpy(&args.data, buf, sizeof(args.data));
	args.request_type = reqtype;
	args.hid_id = hid_id;

	g_mutex_lock(&ioctl_mutex);

	ret = bpf_prog_test_run_opts(fd, &run_attrs);

	/* Sleep until op finished */
	usleep(40 * 1000);

	g_mutex_unlock(&ioctl_mutex);

	return ret;
}

static int usi_query_feature(int fea)
{
	char buf[4];

	buf[0] = features[fea].idx;
	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 0;

	return usi_ioctl(hidraw_fd, buf, HID_REQ_GET_REPORT);
}

static int usi_set_feature(int fea, int val)
{
	char buf[4];

	buf[0] = features[fea].idx;
	buf[1] = 1;
	buf[2] = val;
	buf[3] = 0;

	return usi_ioctl(hidraw_fd, buf, HID_REQ_SET_REPORT);
}

static void int_exit(int sig)
{
	hid_usi_server_kern__destroy(skel);
	close(sysfs_fd);
	exit(EXIT_SUCCESS);
}

static void usage(void)
{
	extern const char *__progname;

	fprintf(stderr,
		"usage: %s [--session] [--debug] <hidraw-id>\n\n",
		__progname);
}

static const char *idx_to_param(u32 idx)
{
	if (idx == USI_PEN_COLOR)
		return "LineColor";
	if (idx == USI_PEN_LINE_WIDTH)
		return "LineWidth";
	if (idx == USI_PEN_LINE_STYLE)
		return "LineStyle";

	return NULL;
}

static int param_to_idx(const char *param)
{
	if (!param)
		return -EINVAL;
	if (!strcmp(param, "LineColor"))
		return USI_PEN_COLOR;
	if (!strcmp(param, "LineWidth"))
		return USI_PEN_LINE_WIDTH;
	if (!strcmp(param, "LineStyle"))
		return USI_PEN_LINE_STYLE;

	return -EINVAL;
}

static int write_value(const char *param, int value)
{
	int err, max, idx = param_to_idx(param);

	if (idx < 0)
		return idx;

	max = (1 << features[idx].size) - 1;

	if (value < 0 || value > max)
		return -EINVAL;

	if (!in_range)
		return -ENODEV;

	err = bpf_map_update_elem(cache, &idx, &value, BPF_ANY);
	if (err) {
		fprintf(stderr, "Update failed for %d, err=%d\n", idx, err);
		return err;
	}

	usi_set_feature(idx, value);

	return 0;
}

static int read_value(const char *param)
{
	int value = -ENOENT;
	int idx = param_to_idx(param);

	bpf_map_lookup_elem(cache, &idx, &value);

	return value;
}

static DBusHandlerResult usi_set_prop(DBusConnection *conn, DBusError *err,
				      DBusMessage *msg, DBusMessage *reply)
{
	DBusMessageIter iter, variant;
	const char *interface, *property;
	unsigned int value;
	int ret;

	if (!dbus_message_iter_init(msg, &iter))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_iter_get_basic(&iter, &interface);

	if (!dbus_message_iter_next(&iter))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_iter_get_basic(&iter, &property);
	if (!dbus_message_iter_next(&iter))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_iter_recurse(&iter, &variant);
	if (dbus_message_iter_get_arg_type(&variant) != DBUS_TYPE_UINT32)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_iter_get_basic(&variant, &value);

	debug_printf("%s: i=%s, p=%s, v=%d\n", __func__, interface, property,
		     value);

	ret = write_value(property, value);
	if (ret < 0) {
		dbus_set_error(err, DBUS_ERROR_IO_ERROR,
			       "Setting property (%s) failed: %d",
			       property, ret);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult usi_get_prop(DBusConnection *conn, DBusError *err,
				      DBusMessage *msg, DBusMessage *reply)
{
	DBusMessageIter iter, variant;
	const char *interface, *property;
	int value;
	void *ptr;
	int itype;
	char *stype;

	if (!dbus_message_get_args(msg, err,
				   DBUS_TYPE_STRING, &interface,
				   DBUS_TYPE_STRING, &property,
				   DBUS_TYPE_INVALID))
		return -1;

	dbus_message_iter_init_append(reply, &iter);

	if (!strcmp(property, "Version")) {
		ptr = &version;
		stype = "s";
		itype = DBUS_TYPE_STRING;
	} else {
		value = read_value(property);
		debug_printf("%s: i=%s, p=%s, v=%d", __func__, interface,
			     property, value);

		if (value < 0)
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

		ptr = &value;
		stype = "u";
		itype = DBUS_TYPE_UINT32;
	}

	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT, stype,
					      &variant))
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (!dbus_message_iter_append_basic(&variant, itype, ptr))
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (!dbus_message_iter_close_container(&iter, &variant))
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult usi_get_all_props(DBusConnection *conn, DBusError *err,
					   DBusMessage *reply)
{
	DBusMessageIter array, dict, iter, variant;
	static const char *props[] = {
		"Version", "LineColor", "LineWidth", "LineStyle"
	};
	static const char *types[] = { "s", "u", "u", "u" };
	int i;
	unsigned int value;
	void *ptr;
	int itype;

	dbus_message_iter_init_append(reply, &iter);
	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}",
					      &array))
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	for (i = 0; i < ARRAY_SIZE(props); i++) {
		if (!dbus_message_iter_open_container(&array, DBUS_TYPE_DICT_ENTRY, NULL, &dict))
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		if (!dbus_message_iter_append_basic(&dict, DBUS_TYPE_STRING, &props[i]))
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		if (!dbus_message_iter_open_container(&dict, DBUS_TYPE_VARIANT, types[i], &variant))
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		if (i == 0) {
			ptr = &version;
			itype = DBUS_TYPE_STRING;
		} else {
			value = read_value(props[i]);
			ptr = &value;
			itype = DBUS_TYPE_UINT32;
		}
		if (!dbus_message_iter_append_basic(&variant, itype, ptr))
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		if (!dbus_message_iter_close_container(&dict, &variant))
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		if (!dbus_message_iter_close_container(&array, &dict))
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	if (!dbus_message_iter_close_container(&iter, &array))
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult usi_message_handler(DBusConnection *conn,
					     DBusMessage *message, void *data)
{
	DBusHandlerResult result = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	DBusMessage *reply;
	DBusError err;

	debug_printf("Got D-Bus request: %s.%s on %s\n",
		     dbus_message_get_interface(message),
		     dbus_message_get_member(message),
		     dbus_message_get_path(message));

	dbus_error_init(&err);

	reply = dbus_message_new_method_return(message);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (dbus_message_is_method_call(message, DBUS_INTERFACE_INTROSPECTABLE, "Introspect")) {
		dbus_message_append_args(reply,
					 DBUS_TYPE_STRING, &server_introspection_xml,
					 DBUS_TYPE_INVALID);

	} else if (dbus_message_is_method_call(message, DBUS_INTERFACE_PROPERTIES, "Get")) {
		result = usi_get_prop(conn, &err, message, reply);
	} else if (dbus_message_is_method_call(message, DBUS_INTERFACE_PROPERTIES, "GetAll")) {
		result = usi_get_all_props(conn, &err, reply);
	} else if (dbus_message_is_method_call(message, DBUS_INTERFACE_PROPERTIES, "Set")) {
		result = usi_set_prop(conn, &err, message, reply);
	} else {
		dbus_message_unref(reply);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (dbus_error_is_set(&err)) {
		dbus_message_unref(reply);

		reply = dbus_message_new_error(message, err.name, err.message);
		dbus_error_free(&err);

		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	if (!dbus_connection_send(conn, reply, NULL))
		result = DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_unref(reply);

	return result;
}

static int usi_property_changed(u32 idx)
{
	const char *prop_name = idx_to_param(idx);
	u32 val = read_value(prop_name);
	DBusMessage *signal;
	DBusMessageIter iter, array, dict, variant;
	const char *ifname = "org.universalstylus.PenInterface";
	int retval = 0;

	signal = dbus_message_new_signal("/org/universalstylus/Pen",
					 "org.freedesktop.DBus.Properties",
					 "PropertiesChanged");
	if (!signal)
		return -1;

	dbus_message_iter_init_append(signal, &iter);

	if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &ifname)) {
		retval = -1;
		goto exit;
	}

	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}",
					      &array)) {
		retval = -1;
		goto exit;
	}

	if (!dbus_message_iter_open_container(&array, DBUS_TYPE_DICT_ENTRY,
					      NULL, &dict)) {
		retval = -1;
		goto exit;
	}

	if (!dbus_message_iter_append_basic(&dict, DBUS_TYPE_STRING,
					    &prop_name)) {
		retval = -1;
		goto exit;
	}

	if (!dbus_message_iter_open_container(&dict, DBUS_TYPE_VARIANT,
					      DBUS_TYPE_UINT32_AS_STRING,
					      &variant)) {
		retval = -1;
		goto exit;
	}

	if (!dbus_message_iter_append_basic(&variant, DBUS_TYPE_UINT32, &val)) {
		retval = -1;
		goto exit;
	}

	if (!dbus_message_iter_close_container(&dict, &variant)) {
		retval = -1;
		goto exit;
	}

	if (!dbus_message_iter_close_container(&array, &dict)) {
		retval = -1;
		goto exit;
	}

	if (!dbus_message_iter_close_container(&iter, &array)) {
		retval = -1;
		goto exit;
	}

	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "s",
					      &array)) {
		retval = -1;
		goto exit;
	}

	if (!dbus_message_iter_close_container(&iter, &array)) {
		retval = -1;
		goto exit;
	}

	dbus_connection_send(dbus_conn, signal, NULL);

exit:
	dbus_message_unref(signal);

	return retval;
}

const DBusObjectPathVTable usi_vtable = {
	.message_function = usi_message_handler,
};

static int handle_rb_event(void *ctx, void *data, size_t sz)
{
	const struct usi_event *e = data;

	switch (e->event) {
	case USI_EVENT_RUN_QUERY:
		usi_query_feature(e->data);
		break;
	case USI_EVENT_IN_RANGE:
		in_range = e->data;
		break;
	case USI_EVENT_VAL_CHANGED:
		usi_property_changed(e->data);
		break;
	default:
		fprintf(stderr, "%s: bad event: %d\n", __func__, e->event);
	}
	return 0;
}

static void event_thread(GTask *task, gpointer obj, gpointer tdata,
			 GCancellable *cancellable)
{
	int err;

	while (1) {
		err = ring_buffer__poll(event_rb, -1);
		if (err < 0) {
			fprintf(stderr, "%s: error=%d\n", __func__, err);
			return;
		}
	}
}

static void event_thread_run(void)
{
	GTask *task;

	task = g_task_new(NULL, NULL, NULL, mainloop);
	g_task_run_in_thread(task, event_thread);

	g_object_unref(task);
}

static int server_run(void)
{
	DBusError err;
	int rv;
	int bus_type = DBUS_BUS_SYSTEM;

	sprintf(ver_buf, "v%d.%d (g%s)", VERSION_MAJOR, VERSION_MINOR,
		GIT_COMMIT);

	printf("Starting dbus USI server %s\n", ver_buf);

	if (use_session_bus)
		bus_type = DBUS_BUS_SESSION;

	dbus_error_init(&err);

	dbus_conn = dbus_bus_get(bus_type, &err);
	if (!dbus_conn) {
		fprintf(stderr, "Failed to get a %s DBus connection: %s\n",
			use_session_bus ? "session" : "system",
			err.message);
		goto fail;
	}

	rv = dbus_bus_request_name(dbus_conn, "org.universalstylus.PenServer",
				   DBUS_NAME_FLAG_REPLACE_EXISTING, &err);
	if (rv != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		fprintf(stderr, "Failed to request name on bus: %s\n", err.message);
		goto fail;
	}

	if (!dbus_connection_register_object_path(dbus_conn,
						  "/org/universalstylus/Pen",
						  &usi_vtable, NULL)) {
		fprintf(stderr, "Failed to register a object path for 'Pen'\n");
		goto fail;
	}

	mainloop = g_main_loop_new(NULL, false);
	dbus_connection_setup_with_g_main(dbus_conn, NULL);
	event_thread_run();
	g_main_loop_run(mainloop);

	return 0;
fail:
	dbus_error_free(&err);
	return -1;
}

static int attach_prog_to_hid(struct bpf_program *prog, int hid)
{
	int err;
	struct attach_prog_args args = { 0 };
	int attach_fd;
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, tattr,
			    .ctx_in = &args,
			    .ctx_size_in = sizeof(args),
	);

	args.hid = hid;

	attach_fd = bpf_program__fd(skel->progs.attach_prog);
	args.prog_fd = bpf_program__fd(prog);

	err = bpf_prog_test_run_opts(attach_fd, &tattr);
	if (err)
		fprintf(stderr, "Failed to attach prog to hid: %d\n", err);

	return err;
}

static int attach_progs(void)
{
	int err = 0;
	struct hid_config_data *cfg_bpf;
	int fd;
	u32 quirks;
	int i;

	skel = hid_usi_server_kern__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton.\n");
		return 1;
	}

	quirks = 0;

	/*
	 * Goodix USI controller (vendor = 27c6) does not properly
	 * update pen data, unless the corresponding report is
	 * read (GET_REPORT) from it. Add a quirk flag to do this.
	 */
	if (vendor == 0x27c6 && product == 0xe00)
		quirks |= BIT(USI_QUIRK_FORCE_QUERY);

	skel->rodata->quirks = quirks;

	debug_printf("Updated quirks to %x\n", quirks);

	cfg_bpf = skel->rodata->inputs;

	memcpy(cfg_bpf, inputs, sizeof(inputs));

	for (i = 0; i < USI_NUM_PARAMS; i++)
		debug_printf("Updated inputs%d: idx=%x, size=%d, offset=%d\n",
			     i, cfg_bpf[i].idx, cfg_bpf[i].size,
			     cfg_bpf[i].offset);

	err = hid_usi_server_kern__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton.\n");
		goto cleanup;
	}

	err = attach_prog_to_hid(skel->progs.usi_user_request, hid_id);
	if (err) {
		fprintf(stderr, "HID attach failed for usi_user_request: %d\n",
			err);
		goto cleanup;
	}

	hidraw_fd = bpf_program__fd(skel->progs.usi_user_request);

	err = attach_prog_to_hid(skel->progs.hid_raw_event, hid_id);
	if (err) {
		fprintf(stderr, "HID attach failed for hid_raw_event: %d\n",
			err);
		goto cleanup;
	}

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	err = cache = bpf_map__fd(skel->maps.cache);
	if (err < 0) {
		printf("can't get 'cache' shared mem from object - %m\n");
		goto cleanup;
	}

	/* Setup thread for polling the event ringbuf */
	fd = bpf_map__fd(skel->maps.events);
	if (fd < 0) {
		printf("can't get 'events' shared mem from object - %m\n");
		err = fd;
		goto cleanup;
	}
	event_rb = ring_buffer__new(fd, handle_rb_event, NULL, NULL);
	if (!event_rb) {
		printf("failed to create event ringbuf.\n");
		err = 1;
		goto cleanup;
	}

	server_run();

cleanup:
	hid_usi_server_kern__destroy(skel);
	return err;
}

static int process_rdesc_type(struct hid_parser *parser, int type,
			      struct hid_config_data *data)
{
	unsigned int id;
	struct hid_field *field;
	struct hid_report *report;
	unsigned int i, j;

	/* Lookup for pen input report */
	for (id = 0; id < HID_MAX_IDS; id++) {
		report = parser->device->report_enum[type].report_id_hash[id];
		if (!report)
			continue;

		debug_printf("%s: checking %s report %d\n", __func__,
			     type == HID_INPUT_REPORT ? "input" :
			     "feature", id);
		debug_printf("%s: app=%x, logical=%x\n", __func__,
			     report->field[0]->application,
			     report->field[0]->logical);

		if (report->field[0]->application != HID_DG_PEN)
			continue;

		for (i = 0; i < report->maxfield; i++) {
			struct hid_config_data *ptr = NULL;
			u32 hid_usage;

			field = report->field[i];

			for (j = 0; j < field->maxusage; j++) {
				hid_usage = field->usage[j].hid;

				if ((hid_usage & HID_USAGE_PAGE) ==
				    HID_UP_MSVENDOR) {
					hid_usage &= ~((u32)HID_USAGE_PAGE);
					hid_usage |= HID_UP_DIGITIZER;
				}

				debug_printf("%s: checking field[%d], usage[%d] = %x\n",
					     __func__, i, j, hid_usage);

				switch (hid_usage) {
				case HID_DG_PEN_COLOR:
					ptr = &data[USI_PEN_COLOR];
					break;
				case HID_DG_PEN_LINE_WIDTH:
					ptr = &data[USI_PEN_LINE_WIDTH];
					break;
				case HID_DG_PEN_LINE_STYLE_INK:
					ptr = &data[USI_PEN_LINE_STYLE];
					break;
				case HID_DG_INRANGE:
					ptr = &data[USI_PEN_IN_RANGE];
					break;
				case HID_DG_TIPSWITCH:
					ptr = &data[USI_PEN_TOUCHING];
					break;
				default:
					continue;
				}

				ptr->idx = id;
				ptr->offset = 8 + field->report_offset +
					field->report_size * j;
				ptr->size = field->report_size;

				debug_printf("%s: mapped id=%d, usage=%x, offset=%d, size=%d\n",
					     __func__, id, hid_usage,
					     ptr->offset, ptr->size);
			}
		}
	}

	return 0;
}

static int process_rdesc(struct hid_parser *parser)
{
	int ret;

	ret = process_rdesc_type(parser, HID_INPUT_REPORT, inputs);
	ret |= process_rdesc_type(parser, HID_FEATURE_REPORT, features);

	return ret;
}

int main(int argc, char **argv)
{
	int opt;
	struct stat statbuf;
	unsigned char rdesc_data[BUFSIZ];
	FILE *fin;
	int rdesc_size;
	struct hid_parser *parser;
	char buf[256];
	char *c;
	char uevent_fname[BUFSIZ];
	char rdesc_fname[BUFSIZ];
	int hidraw_id;

	while ((opt = getopt_long(argc, argv, "hed", long_options,
				  NULL)) != -1) {
		switch (opt) {
		case 'e':
			use_session_bus = true;
			break;
		case 'd':
			debug = true;
			break;
		default:
			usage();
			exit(EXIT_FAILURE);
		}
	}

	if (optind == argc) {
		usage();
		exit(EXIT_FAILURE);
	}

	errno = 0;
	hidraw_id = -1;

	hidraw_id = strtol(argv[optind], &c, 10);
	if (errno != 0 || argv[optind] == c) {
		fprintf(stderr, "Bad hidraw ID '%s', please provide an integer 0..\n", argv[optind]);
		exit(EXIT_FAILURE);
	}

	sprintf(uevent_fname, "/sys/class/hidraw/hidraw%d/device", hidraw_id);
	strcpy(rdesc_fname, uevent_fname);
	strcat(uevent_fname, "/uevent");
	if (stat(uevent_fname, &statbuf)) {
		fprintf(stderr, "hidraw%d not found\n", hidraw_id);
		exit(EXIT_FAILURE);
	}

	fin = fopen(uevent_fname, "r");
	if (!fin) {
		fprintf(stderr, "Unable to open %s for read.\n",
			uevent_fname);
		exit(EXIT_FAILURE);
	}

	if (!fread(buf, 1, 256, fin)) {
		fprintf(stderr, "Failed to read %s.\n", uevent_fname);
		fclose(fin);
		exit(EXIT_FAILURE);
	}

	fclose(fin);

	sysfs_fd = open(uevent_fname, O_RDONLY);
	if (sysfs_fd < 0) {
		fprintf(stderr, "Failed to open %s.\n", uevent_fname);
		exit(EXIT_FAILURE);
	}

	c = buf;

	while (*c) {
		switch (*c) {
		case 'v':
			vendor = strtol(c + 1, &c, 16);
			continue;
		case 'p':
			product = strtol(c + 1, &c, 16);
			continue;
		}

		c++;
	}

	hid_id = 1;

	printf("vendor: %x\n", vendor);
	printf("product: %x\n", product);
	printf("sysfs-path: %s\n", rdesc_fname);
	strcat(rdesc_fname, "/report_descriptor");

	fin = fopen(rdesc_fname, "rb");
	if (!fin) {
		fprintf(stderr, "Unable to open %s for read.\n", rdesc_fname);
		goto err;
	}

	rdesc_size = fread(rdesc_data, 1, BUFSIZ, fin);

	printf("rdesc-len=%d\n", rdesc_size);

	fclose(fin);

	parser = hid_parse(rdesc_data, rdesc_size, debug);
	if (!parser)
		goto err;

	process_rdesc(parser);

	hid_parser_free(parser);

	return attach_progs();

err:
	close(sysfs_fd);
	exit(EXIT_FAILURE);
}
