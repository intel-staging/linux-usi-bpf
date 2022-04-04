/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022, Intel Corporation
 * HID Parser tool. This is mostly copied from Linux Kernel HID subsystem:
 * include/linux/hid.h authored by:
 *   Jiri Kosina <jikos@kernel.org>
 *   Benjamin Tissoires <benjamin.tissoires@redhat.com>
 *   ... and others.
 */

#ifndef __HID_PARSER_H__
#define __HID_PARSER_H__

#include <linux/hid.h>

#define HID_MAX_USAGES			12288
#define HID_MAX_FIELDS			256
#define HID_GLOBAL_STACK_SIZE		4
#define HID_COLLECTION_STACK_SIZE	4
#define HID_MAX_BUFFER_SIZE		16384
#define HID_MAX_IDS			256
#define HID_DEFAULT_NUM_COLLECTIONS	16

typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint32_t u32;
typedef int32_t s32;

#define hid_warn(dev, fmt, ...) \
	do { if (debug) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)
#define hid_err(dev, fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define dbg_hid(fmt, ...) \
	do { if (debug) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)

struct hid_device;

/**
 * struct hid_collection - HID collection describing a usage
 * @parent_idx: device->collection
 * @type: type of collection
 * @usage: usage of collection
 * @level: offset in collection stack
 */
struct hid_collection {
	int parent_idx;
	unsigned type;
	unsigned usage;
	unsigned level;
};

/**
 * struct hid_local - HID Local parser current state
 * @usage: usage array
 * @usage_size: usage size array
 * @collection_index: collection index array
 * @usage_index: index of the current usage
 * @usage_minimum: minimum usage value
 * @delimiter_depth: depth of the delimiter set
 * @delimiter_branch: current delimiter branch number
 */
struct hid_local {
	unsigned usage[HID_MAX_USAGES]; /* usage array */
	u8 usage_size[HID_MAX_USAGES]; /* usage size array */
	unsigned collection_index[HID_MAX_USAGES]; /* collection index array */
	unsigned usage_index;
	unsigned usage_minimum;
	unsigned delimiter_depth;
	unsigned delimiter_branch;
};

/**
 * struct hid_global - HID global entries
 * @usage_page: Usage value
 * @logical_minimum: Logical minimum value for the entry
 * @logical_maximum: Logical maximum value for the entry
 * @physical_minimum: Physical minimum value for the entry
 * @physical_maximum: Physical maximum value for the entry
 * @unit_exponent: Unit exponent for the field
 * @unit: Unit for the field (degrees, cm etc.)
 * @report_id: Report identifier
 * @report_size: Report size (in bits)
 * @report_count: Number of entries for the report
 */
struct hid_global {
	unsigned	usage_page;
	s32		logical_minimum;
	s32		logical_maximum;
	s32		physical_minimum;
	s32		physical_maximum;
	s32		unit_exponent;
	unsigned	unit;
	unsigned	report_id;
	unsigned	report_size;
	unsigned	report_count;
};

/**
 * struct hid_usage - HID usage info for an item
 * @hid: hid usage code
 * @collection_index: index into collection array
 * @usage_index: index into usage array
 * @resolution_multiplier: effective resolution multiplier
 */
struct hid_usage {
	unsigned	hid;
	unsigned	collection_index;
	unsigned	usage_index;
	s8		resolution_multiplier;
};

/**
 * struct hid_field: Data for a single HID field
 * @physical: physical usage for this field
 * @logical: logical usage for this field
 * @application: application usage for this field
 * @usage: usage table for this function
 * @maxusage: maximum usage index
 * @flags: main-item flags (i.e. volatile,array,constant)
 * @report_offset: bit offset in the report
 * @report_size: size of this field in the report
 * @report_count: number of this field in the report
 * @report_type: (input,output,feature)
 * @value: last known value(s)
 * @new_value: newly read value(s)
 * @usages_priorities: priority of each usage when reading the report
 * @logical_minimum: logical minimum value
 * @logical_maximum: logical maximum value
 * @physical_minimum: physical minimum value
 * @physical_maximum: physical maximum value
 * @unit_exponent: unit exponent for the field
 * @unit: unit type for this field (degrees, cm etc.)
 * @report: associated report
 * @index: index into report->field[]
 */
struct hid_field {
	unsigned  physical;
	unsigned  logical;
	unsigned  application;
	struct hid_usage *usage;
	unsigned  maxusage;
	unsigned  flags;
	unsigned  report_offset;
	unsigned  report_size;
	unsigned  report_count;
	unsigned  report_type;
	s32	*value;
	s32	*new_value;
	s32	*usages_priorities;
	s32     logical_minimum;
	s32     logical_maximum;
	s32     physical_minimum;
	s32     physical_maximum;
	s32     unit_exponent;
	unsigned  unit;
	struct hid_report *report;
	unsigned index;
};

/**
 * struct hid_report - Contents of a single HID report
 * @id: id of this report
 * @type: report type
 * @application: application usage for this report
 * @field: fields of the report
 * @maxfield: maximum valid field index
 * @size: size of the report (bits)
 * @device: associated device
 */
struct hid_report {
	unsigned int id;
	unsigned int type;
	unsigned int application;
	struct hid_field *field[HID_MAX_FIELDS];
	unsigned maxfield;
	unsigned size;
	struct hid_device *device;
};

/**
 * struct hid_report_enum - HID report storage class
 * @numbered: report has a valid ID or not
 * @report_id_hash: pointer to the actual HID report
 */
struct hid_report_enum {
	unsigned numbered;
	struct hid_report *report_id_hash[HID_MAX_IDS];
};

/**
 * struct hid_device - HID device information
 * @collection: List of HID collections
 * @collection_size: Number of allocated hid_collections
 * @maxcollection: Number of parsed collections
 * @maxapplication: Number of applications
 * @report_enum: Report types hash
 */
struct hid_device {
	struct hid_collection *collection;
	unsigned collection_size;
	unsigned maxcollection;
	unsigned maxapplication;
	struct hid_report_enum  report_enum[HID_REPORT_TYPES];
};

/**
 * struct hid_parser - HID parser state information
 * @global: HID current global entry
 * @global_stack: HID global entries stack
 * @global_stack_ptr: HID global entries stack pointer
 * @local: HID current local entry data
 * @collection_stack: collection stack
 * @collection_stack_ptr: collection stack pointer
 * @collection_stack_size: size of collection stack
 * @device: HID device pointer
 * @scan_flags: HID parser scanner option flags
 */
struct hid_parser {
	struct hid_global	global;
	struct hid_global	global_stack[HID_GLOBAL_STACK_SIZE];
	unsigned int		global_stack_ptr;
	struct hid_local	local;
	unsigned int		*collection_stack;
	unsigned int		collection_stack_ptr;
	unsigned int		collection_stack_size;
	struct hid_device	*device;
	unsigned int		scan_flags;
};

struct hid_parser *hid_parse(u8 *rdesc, int size, bool debug);
void hid_parser_free(struct hid_parser *parser);

#endif
