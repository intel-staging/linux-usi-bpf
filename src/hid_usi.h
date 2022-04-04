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

struct hid_config_data {
	int offset;
	int size;
	int idx;
};

struct usi_event {
	int event;
	int data;
};

enum {
	USI_EVENT_RUN_QUERY,
	USI_EVENT_IN_RANGE,
	USI_EVENT_VAL_CHANGED,
};

#endif /* HID_USI_H */
