// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 Intel Corporation. */

#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/hid.h>
#include <uapi/linux/bpf_hid.h>
#include <bpf/bpf_helpers.h>

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

SEC("hid/user_event")
int usi_user_request(struct hid_bpf_ctx *ctx)
{
	int ret;
	u8 *buf;

	buf = bpf_hid_get_data(ctx, 0, 4);
	if (!buf)
		return 0;

	ret = bpf_hid_raw_request(ctx, &buf[1], 3, HID_FEATURE_REPORT,
				  buf[0]);
	ctx->retval = ret;
	ctx->size = 0;

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

SEC("hid/device_event")
int hid_raw_event(struct hid_bpf_ctx *ctx)
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

	buf = bpf_hid_get_data(ctx, 0, 1);
	if (!buf || buf[0] != inputs[USI_PEN_IN_RANGE].idx)
		return 0;

	if (bpf_hid_get_bits(ctx, inputs[USI_PEN_IN_RANGE].offset,
			     inputs[USI_PEN_IN_RANGE].size, &in_range) <= 0)
		return 0;

	if (bpf_hid_get_bits(ctx, inputs[USI_PEN_TOUCHING].offset,
			     inputs[USI_PEN_TOUCHING].size, &touching) <= 0)
		return 0;

	if (quirks & BIT(USI_QUIRK_FORCE_QUERY))
		touching = in_range;

	if (touching != last_touching)
		usi_send_event(ctx, USI_EVENT_IN_RANGE, touching);

	last_touching = touching;

	if (!touching)
		last_pen_event = 0;

	if (!in_range) {
		ctx->size = 0;
		return 0;
	}

	time = bpf_ktime_get_ns();

	if (!last_pen_event) {
		last_pen_event = time;
		if (quirks & BIT(USI_QUIRK_FORCE_QUERY)) {
			usi_send_event(ctx, USI_EVENT_RUN_QUERY, USI_PEN_COLOR);
			usi_send_event(ctx, USI_EVENT_RUN_QUERY,
				       USI_PEN_LINE_WIDTH);
			usi_send_event(ctx, USI_EVENT_RUN_QUERY,
				       USI_PEN_LINE_STYLE);
		}
	}

	for (i = USI_PEN_COLOR; i < USI_NUM_PARAMS; i++) {
		offset = inputs[i].offset;
		size = inputs[i].size;
		bool changed = false;

		val = 0;

		if (bpf_hid_get_bits(ctx, offset, size, &val) <= 0)
			continue;

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

		if (changed && time < last_pen_event + MS_TO_NS(200) &&
		    time > last_pen_event) {
			if (*c != new_val)
				usi_send_event(ctx, USI_EVENT_VAL_CHANGED, i);
			*c = new_val;
		}

		if (new_val != *c)
			new_val = *c;

		if (new_val != val)
			bpf_hid_set_bits(ctx, offset, size, new_val);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
