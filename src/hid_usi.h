/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2022 Intel Corporation.
 */

#ifndef HID_USI_H_
#define HID_USI_H_

#include <linux/bits.h>

#ifdef __clang__
typedef uint64_t u64;
typedef uint32_t u32;
#endif

#define VERSION_MAJOR	0
#define VERSION_MINOR	7

#define USI_ARGS_DATA_SZ	4

#define debug_printf(fmt, ...) \
	do { if (debug) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)

enum {
	USI_PEN_ID,
	USI_PEN_IN_RANGE,
	USI_PEN_TOUCHING,
	USI_PEN_COLOR,
	USI_PEN_LINE_WIDTH,
	USI_PEN_LINE_STYLE,
	USI_NUM_PARAMS
};

enum {
	USI_QUIRK_FORCE_QUERY,
};

/**
 * struct hid_config_data - configuration data passed from server to USI eBPF
 * @offset:	offset of the field, in bits, from start of HID report
 * @size:	size of the field, in bits
 * @idx:	unique ID of the HID report containing the field
 */
struct hid_config_data {
	int offset;
	int size;
	int idx;
};

/**
 * struct usi_event - USI event passed from USI eBPF to server
 * @event:	Event ID
 * @data:	Data associated with the event
 */
struct usi_event {
	int event;
	int data;
};

/**
 * struct usi_args - arguments passed from server to USI eBPF
 * @data:		data buffer
 * @hid_id:		HID driver ID, usually just 1
 * @request_type:	either HID_REQ_GET_REPORT or HID_REQ_SET_REPORT
 * @retval:		return value from eBPF to userspace
 */
struct usi_args {
	u8 data[USI_ARGS_DATA_SZ];
	int hid_id;
	int request_type;
	int retval;
};

enum {
	USI_EVENT_RUN_QUERY,
	USI_EVENT_IN_RANGE,
	USI_EVENT_VAL_CHANGED,
};

#endif /* HID_USI_H */
