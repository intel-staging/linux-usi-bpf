// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 Intel Corporation. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "hid_usi.h"

#define MS_TO_NS(t) ((t) * 1000000)
#define MS_TO_JIFFIES(t) ((t) * HZ / 1000)

static const char param_names[USI_NUM_PARAMS][6] = {
	"id",
	"range",
	"touch",
	"color",
	"width",
	"style",
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, USI_NUM_PARAMS);
} cache SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, USI_NUM_PARAMS);
} p_raw SEC(".maps");

/* HID-BPF kfunc API definitions */
extern u8 *hid_bpf_get_data(struct hid_bpf_ctx *ctx, unsigned int offset,
			    const size_t __sz) __ksym;
extern int hid_bpf_attach_prog(unsigned int hid_id, int prog_fd,
			       u32 flags) __ksym;
extern struct hid_bpf_ctx *hid_bpf_allocate_context(unsigned int hid_id) __ksym;
extern void hid_bpf_release_context(struct hid_bpf_ctx *ctx) __ksym;
extern int hid_bpf_hw_request(struct hid_bpf_ctx *ctx, __u8 *data,
			      size_t len, enum hid_report_type type,
			      enum hid_class_request reqtype) __ksym;

/*
 * These are used as configuration variables passed in by the server.
 * volatile modifier is needed, as otherwise the compiler assumes these
 * to be constants and does not recognize the changes done by the server;
 * effectively hardcoding the values as all zeroes in the compiled BPF
 * code.
 */
const volatile u32 quirks;
const volatile struct hid_config_data inputs[USI_NUM_PARAMS];

static u64 last_pen_event;
static int last_touching;

SEC("syscall")
int attach_prog(struct attach_prog_args *args)
{
	args->retval = hid_bpf_attach_prog(args->hid, args->prog_fd,
					   args->flags);
	return 0;
}

SEC("syscall")
int usi_user_request(struct usi_args *args)
{
	struct hid_bpf_ctx *ctx;
	int ret;

	ctx = hid_bpf_allocate_context(args->hid_id);
	if (!ctx)
		return 0;

	ret = hid_bpf_hw_request(ctx, args->data, 4, HID_FEATURE_REPORT,
				 args->request_type);
	args->retval = ret;

	hid_bpf_release_context(ctx);

	return 0;
}

static void usi_send_event(struct hid_bpf_ctx *ctx, int event, int data)
{
	struct usi_event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;

	e->event = event;
	e->data = data;

	bpf_ringbuf_submit(e, 0);
}

static u32 _get_bits(u8 *buf, unsigned int offset, int n)
{
	unsigned int idx = offset / 8;
	unsigned int bit_nr = 0;
	unsigned int bit_shift = offset & 0x7;
	int bits_to_copy = 8 - bit_shift;
	u32 value = 0;
	u32 mask = n < 32 ? (1U << n) - 1 : ~0U;

	while (n > 0) {
		value |= ((u32)buf[idx] >> bit_shift) << bit_nr;
		n -= bits_to_copy;
		bit_nr += bits_to_copy;
		bits_to_copy = 8;
		bit_shift = 0;
		idx++;
	}

	return value & mask;
}

static void _set_bits(u8 *buf, unsigned int offset, int n, u32 value)
{
	unsigned int idx = offset / 8;
	unsigned int bit_shift = offset & 0x7;
	int bits_to_set = 8 - bit_shift;

	while (n - bits_to_set >= 0) {
		buf[idx] &= ~(0xff << bit_shift);
		buf[idx] |= value << bit_shift;
		value >>= bits_to_set;
		n -= bits_to_set;
		bits_to_set = 8;
		bit_shift = 0;
		idx++;
	}
}

SEC("fmod_ret/hid_bpf_device_event")
int BPF_PROG(hid_raw_event, struct hid_bpf_ctx *hctx)
{
	u32 i;
	u32 tmp;
	u32 val, new_val;
	u32 *c, *p;
	u32 flags = 0;
	u32 offset;
	u32 size;
	u32 in_range = 0;
	u32 touching = 0;
	u64 time;
	u8 *buf;

	/*
	 * Size 128 is hardcoded here, should have enough space to
	 * contain any USI events
	 */
	buf = hid_bpf_get_data(hctx, 0, 128 /* hctx->allocated_size */);
	if (!buf || buf[0] != inputs[USI_PEN_IN_RANGE].idx)
		return 0;

	in_range = _get_bits(buf, inputs[USI_PEN_IN_RANGE].offset,
			     inputs[USI_PEN_IN_RANGE].size);
	touching = _get_bits(buf, inputs[USI_PEN_TOUCHING].offset,
			     inputs[USI_PEN_TOUCHING].size);

	if (quirks & BIT(USI_QUIRK_FORCE_QUERY))
		touching = in_range;

	if (touching != last_touching)
		usi_send_event(hctx, USI_EVENT_IN_RANGE, touching);

	last_touching = touching;

	if (!touching)
		last_pen_event = 0;

	if (!in_range)
		return 0;

	if (!touching)
		return 0;

	if (!in_range) {
		hctx->size = 0;
		return 0;
	}

	time = bpf_ktime_get_ns();

	if (!last_pen_event) {
		last_pen_event = time;
		if (quirks & BIT(USI_QUIRK_FORCE_QUERY)) {
			usi_send_event(hctx, USI_EVENT_RUN_QUERY, USI_PEN_COLOR);
			usi_send_event(hctx, USI_EVENT_RUN_QUERY,
				       USI_PEN_LINE_WIDTH);
			usi_send_event(hctx, USI_EVENT_RUN_QUERY,
				       USI_PEN_LINE_STYLE);
			/* Filter out initial bogus events */
			last_pen_event++;
		}
	}

	for (i = USI_PEN_COLOR; i < USI_NUM_PARAMS; i++) {
		offset = inputs[i].offset;
		size = inputs[i].size;
		bool changed = false;

		val = _get_bits(buf, offset, size);

		new_val = val;
		if (i == USI_PEN_LINE_STYLE && (new_val == 0x77 || new_val == 255))
			new_val = 6;

		/*
		 * Make a local copy of 'i' which we can refer via a
		 * pointer to satisfy BPF verifier.
		 */
		tmp = i;

		c = bpf_map_lookup_elem(&cache, &tmp);
		p = bpf_map_lookup_elem(&p_raw, &tmp);
		if (!c || !p)
			continue;

		if (*p != new_val) {
			changed = true;
			*p = new_val;
		}

		if (changed && time < last_pen_event + MS_TO_NS(250) &&
		    time >= last_pen_event) {
			if (*c != new_val)
				usi_send_event(hctx, USI_EVENT_VAL_CHANGED, i);
			*c = new_val;
		}

		if (new_val != *c)
			new_val = *c;

		if (new_val != val)
			_set_bits(buf, offset, size, new_val);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
