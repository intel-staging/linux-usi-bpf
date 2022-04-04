// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022, Intel Corporation
 */

#include <stdio.h>
#include <stdbool.h>
#include <gio/gio.h>
#include <getopt.h>
#include <stdint.h>
#include <errno.h>

#include "hid_usi.h"

static bool monitor_exit;

static void usi_var_get(GDBusProxy *proxy, const char *var)
{
	GVariant *result;
	unsigned int val;
	const GVariantType *type;
	char *str;

	result = g_dbus_proxy_get_cached_property(proxy, var);
	type = g_variant_get_type(result);
	if (g_variant_type_equal(type, G_VARIANT_TYPE_UINT32)) {
		g_variant_get(result, "u", &val);
		printf("Value for %s (u): %u\n", var, val);
	} else if (g_variant_type_equal(type, G_VARIANT_TYPE_STRING)) {
		g_variant_get(result, "&s", &str);
		printf("Value for %s (s): %s\n", var, str);
	} else {
		printf("Unsupported type %s for %s\n",
		       g_variant_get_type_string(result), var);
	}
	g_variant_unref(result);
}

static void usi_dump_vars(GDBusProxy *proxy)
{
	gchar **vars;
	int i;

	vars = g_dbus_proxy_get_cached_property_names(proxy);

	for (i = 0; vars && vars[i]; i++)
		usi_var_get(proxy, vars[i]);

	g_strfreev(vars);
}

static int usi_var_set(GDBusProxy *proxy, const char *var, unsigned int value)
{
	GError *error = NULL;

	g_dbus_proxy_call_sync(proxy,
			       "org.freedesktop.DBus.Properties.Set",
			       g_variant_new("(ssv)",
					     "org.universalstylus.PenInterface",
					     var,
					     g_variant_new("u", value)),
			       G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

	if (error) {
		fprintf(stderr, "Failed to set variable %s to %d, error=%d\n",
			var, value, error->code);
		return EXIT_FAILURE;
	}

	return 0;
}

static void usage(void)
{
	extern const char *__progname;

	printf("Usage: %s [--help] [--dump] [--monitor] [--wait] [--session] [--color] [--width] [--style] [value]\n",
	       __progname);

	printf("\nOptions:\n");
	printf("    --help, -h          this help text\n");
	printf("    --color [value]     gets/sets stylus color\n");
	printf("    --width [value]     gets/sets stylus line width\n");
	printf("    --style [value]     gets/sets stylus line style\n");
	printf("    --dump              dump all variables\n");
	printf("    --exit              exit monitor from first prop. change\n");
	printf("    --monitor           monitor variables until terminated\n");
	printf("    --session           use D-BUS session bus (default system)\n");
}

static void props_changed(GDBusProxy *proxy, GVariant *changed_props,
			  const gchar * const *inv_props, gpointer user_data)
{
	printf("Properties changed:\n");
	if (g_variant_n_children(changed_props) > 0) {
		GVariantIter *iter;
		const gchar *key;
		GVariant *val;

		g_variant_get(changed_props, "a{sv}", &iter);
		while (g_variant_iter_loop(iter, "{&sv}", &key, &val)) {
			gchar *val_str;

			val_str = g_variant_print(val, TRUE);
			printf("\t%s = %s\n", key, val_str);
			g_free(val_str);
		}
		g_variant_iter_free(iter);
	}

	if (monitor_exit)
		exit(0);
}

int main(int argc, char *argv[])
{
	GDBusProxy *proxy = NULL;
	GDBusConnection *conn = NULL;
	GError *error = NULL;
	const char *version;
	GVariant *variant;
	const char *var = NULL;
	static struct option options[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "color", no_argument, NULL, 'c' },
		{ "width", no_argument, NULL, 'w' },
		{ "style", no_argument, NULL, 's' },
		{ "dump", no_argument, NULL, 'd' },
		{ "session", no_argument, NULL, 'e' },
		{ "monitor", no_argument, NULL, 'm' },
		{ "exit", no_argument, NULL, 'x' },
	};
	int opt;
	int retval = 0;
	unsigned int value;
	bool dump = false;
	bool session = false;
	bool monitor = false;
	GMainLoop *loop = NULL;

	while ((opt = getopt_long(argc, argv, "hcwsdem", options, NULL)) != -1) {
		switch (opt) {
		case 'c':
			var = "LineColor";
			break;
		case 'w':
			var = "LineWidth";
			break;
		case 's':
			var = "LineStyle";
			break;
		case 'd':
			dump = true;
			break;
		case 'e':
			session = true;
			break;
		case 'm':
			monitor = true;
			break;
		case 'x':
			monitor = true;
			monitor_exit = true;
			break;
		default:
			usage();
			retval = EXIT_FAILURE;
			goto exit;
		}
	}

	printf("HID USI client v%d.%d (g%s)\n", VERSION_MAJOR, VERSION_MINOR,
	       GIT_COMMIT);

	printf("Using D-BUS %s bus to connect.\n",
	       session ? "session" : "system");

	conn = g_bus_get_sync(session ? G_BUS_TYPE_SESSION : G_BUS_TYPE_SYSTEM,
			      NULL, &error);
	if (error) {
		fprintf(stderr, "Failed to connect to DBUS.\n");
		goto exit;
	}

	if (monitor) {
		loop = g_main_loop_new(NULL, FALSE);
		if (!loop) {
			fprintf(stderr, "Failed to create main loop\n");
			goto exit;
		}
	}

	proxy = g_dbus_proxy_new_sync(conn,
				      G_DBUS_PROXY_FLAGS_NONE,
				      NULL,				/* GDBusInterfaceInfo */
				      "org.universalstylus.PenServer",		/* name */
				      "/org/universalstylus/Pen",	/* object path */
				      "org.universalstylus.PenInterface",	/* interface */
				      NULL,				/* GCancellable */
				      &error);
	if (error) {
		fprintf(stderr, "Failed to connect to USI pen server.\n");
		goto exit;
	}

	if (dump) {
		usi_dump_vars(proxy);
		if (!monitor)
			goto exit;
	}

	/* read the version property of the interface */
	variant = g_dbus_proxy_get_cached_property(proxy, "Version");
	if (!variant) {
		fprintf(stderr, "Failed to get server version over DBUS.\n");
		goto exit;
	}
	g_variant_get(variant, "s", &version);
	g_variant_unref(variant);
	printf("Server version %s\n", version);

	if (monitor) {
		g_signal_connect(proxy, "g-properties-changed",
				 G_CALLBACK(props_changed), NULL);
		printf("Monitoring signals.\n");
		g_main_loop_run(loop);
		goto exit;
	}

	if (!var) {
		usage();
		retval = EXIT_FAILURE;
		goto exit;
	}
	if (argc == optind) {
		usi_var_get(proxy, var);
	} else if (argc == optind + 1) {
		errno = 0;
		value = strtol(argv[argc - 1], NULL, 10);
		if (errno) {
			fprintf(stderr, "Bad value: %s\n", argv[argc - 1]);
			retval = EXIT_FAILURE;
			goto exit;
		}
		retval = usi_var_set(proxy, var, value);
	} else {
		usage();
		retval = EXIT_FAILURE;
	}

exit:
	if (loop)
		g_main_loop_unref(loop);

	if (proxy)
		g_object_unref(proxy);

	if (conn)
		g_object_unref(conn);

	return retval;
}
