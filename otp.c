// Copyright (c) 2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: (GPL-2.0)

#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#define BIT(nr) (((uint32_t)1) << (nr))
#define NEXT_ARG() do { argv++; if (--argc <= 0) incomplete_command(); } while(0)
#define NEXT_ARG_OPT() do { if (argc - 1 != 0) argv++; } while (0)
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define ETH_ALEN 6

#define OTP_TAG_OFFSET 4096
#define OTP_TAG_ENTRY_LENGTH 8
#define OTP_TAG_VAL_LENGTH 6

#define OTP_TAG_GET_SIZE(tag) ((0xff & (uint16_t)tag[7]) / 32)
#define OTP_TAG_GET_CONT(tag) (((0xff & (uint16_t)tag[7]) / 16) & 0x1)
#define OTP_TAG_GET_TAG(tag)  ((((uint16_t)tag[7]) & 0x4) | tag[6])

#define OTP_TAG_SET_SIZE(tag, size) (tag[7] |= ((size) << 5))
#define OTP_TAG_SET_CONT(tag, cont) (tag[7] |= ((cont) << 4))
#define OTP_TAG_SET_TAG(tag, t) \
	(tag[7] |= (uint16_t)t >> 8); \
	(tag[6] = (t & 0xff))
#define OTP_TAG_SET_VAL(tag, val, size) (memcpy(tag, val, size))

#define OTP_TBBR_TNVCT_LENGTH 32
#define OTP_TBBR_NTNVCT_OFFSET 0x200
#define OTP_TBBR_TNVCT_OFFSET 0x220

#define OTP_KEYS_LENGTH 256
#define OTP_KEYS_OFFSET 0x100
#define OTP_TBBR_KEYS_LENGTH 128
#define OTP_TBBR_HUK_OFFSET 0x20
#define OTP_TBBR_HUK_LENGTH 0x20

#define OTP_REGION_ADDR_OFFSET 0x44
#define OTP_REGION_WRITE_PROTECT_OFFSET 0x40
#define OTP_REGION_LENGTH 8

#define OTP_PARTID_LENGTH 2
#define OTP_PARTID_OFFSET 0x5

#define __otp_printf(otp, debug, format,...)	\
	if ((otp)->verbose || !debug)		\
		printf(format, ##__VA_ARGS__);

#define otp_debug(otp, format,...)		\
	__otp_printf(otp, true, format, ##__VA_ARGS__)

#define otp_error(otp, format,...)		\
	__otp_printf(otp, false, format, ##__VA_ARGS__)

#define otp_printf(otp, format,...)		\
	__otp_printf(otp, false, format, ##__VA_ARGS__)

static const struct otp_props {
	char *name;
	uint16_t chip_id_base;
	uint16_t chip_bitmask;
	size_t size;
	bool tz_aware;
} chips[] = {
	{ "LAN966X",
	  0x9660,
	  BIT(2) | BIT(8),
	  8 * 1024,
	  false
	},
	{ "LAN969X",
	  0x9690,
	  BIT(1) | BIT (2) | BIT(3) | BIT(4) | BIT(5) | BIT(6) | BIT(7) | BIT(8) | BIT(9) | BIT(10) | BIT(11) | BIT(12),
          16 * 1024,
	  true
	},
};

struct otp {
	bool verbose;
	char *device;
	uint32_t chip_id;
	size_t size;
	bool force_chip_id;
	bool no_confirm;
	bool merge;
	bool no_randomize;
	const struct otp_props *props;
};

struct otp_cmd {
	const char *name;
	int (*func) (struct otp *otp, int argc, char **argv);
};

struct otp_field {
	char *name;
	uint32_t offset;
	uint32_t length;
};

static struct otp_field otp_fields[] = {
	{ .name = "OTP_PRG",			.offset = 0x0,		.length = 4,	},
	{ .name = "FEAT_IDS",			.offset = 0x4,		.length = 1,	},
	{ .name = "PARTID",			.offset = 0x5,		.length = 2,	},
	{ .name = "TST_TRK",			.offset = 0x7,		.length = 1,	},
	{ .name = "SERIAL_NUMBER",		.offset = 0x8,		.length = 8,	},
	{ .name = "SECURE_JTAG",		.offset = 0x10,		.length = 4,	},
	{ .name = "WAFER_JTAG",			.offset = 0x14,		.length = 7,	},
	{ .name = "JTAG_UUID",			.offset = 0x20,		.length = 10,	},
	{ .name = "TRIM",			.offset = 0x30,		.length = 8,	},
	{ .name = "PROTECT_OTP_WRITE",		.offset = 0x40,		.length = 4,	},
	{ .name = "PROTECT_REGION_ADDR",	.offset = 0x44,		.length = 32,	},
	{ .name = "OTP_PCIE_FLAGS",		.offset = 0x64,		.length = 4,	},
	{ .name = "OTP_PCIE_DEV",		.offset = 0x68,		.length = 4,	},
	{ .name = "OTP_PCIE_ID",		.offset = 0x6c,		.length = 8,	},
	{ .name = "OTP_PCIE_BARS",		.offset = 0x74,		.length = 40,	},
	{ .name = "OTP_TBBR_ROTPK",		.offset = 0x100,	.length = 32,	},
	{ .name = "OTP_TBBR_HUK",		.offset = 0x120,	.length = 32,	},
	{ .name = "OTP_TBBR_EK",		.offset = 0x140,	.length = 32,	},
	{ .name = "OTP_TBBR_SSK",		.offset = 0x160,	.length = 32,	},
	{ .name = "OTP_SJTAG_SSK",		.offset = 0x180,	.length = 32,	},
	{ .name = "OTP_STRAP_DISABLE_MASK",	.offset = 0x1a4,	.length = 2,	},
};

struct otp_addr {
	uint32_t offset;
	uint32_t length;
};

enum otp_value_type {
	otp_value_type_unknown = 0,
	otp_value_type_ascii = 1,
	otp_value_type_hex = 2,
	otp_value_type_decimal = 3,
	otp_value_type_binary = 4,
	otp_value_type_3ascii_decimal = 5,
};

struct otp_value {
	char *val;
	enum otp_value_type type;
	char *raw;
	int raw_length;
};

enum otp_tag_type {
	otp_tag_type_invalid,
	otp_tag_type_password,
	otp_tag_type_pcb,
	otp_tag_type_revision,
	otp_tag_type_ethaddr,
	otp_tag_type_ethaddr_count,
	otp_tag_type_fit_config,
	otp_tag_type_pcb_2,
};

struct otp_tag {
	char *name;
	enum otp_tag_type tag;
};

static struct otp_tag otp_tags[] = {
	{ .name = "password",		.tag = otp_tag_type_password },
	{ .name = "pcb",		.tag = otp_tag_type_pcb },
	{ .name = "revision",		.tag = otp_tag_type_revision },
	{ .name = "ethaddr",		.tag = otp_tag_type_ethaddr },
	{ .name = "ethaddr_count",	.tag = otp_tag_type_ethaddr_count },
	{ .name = "fit_config",		.tag = otp_tag_type_fit_config },
	{ .name = "pcb_2",		.tag = otp_tag_type_pcb_2 },
};

struct otp_region {
	uint16_t start;
	uint16_t end;
	bool write_protect;
	bool non_secure;	/* lan969x */
};

static struct otp_region otp_regions[] = {
	{ .start = 0x0,		.end = 0x3f,	.non_secure = true, }, /* Manuf */
	{ .start = 0x40,	.end = 0x43,	.non_secure = true, }, /* OTP Write protect */
	{ .start = 0x44,	.end = 0x63,	.non_secure = true, }, /* OTP Region Definitions */
	{ .start = 0x64,	.end = 0xff,	.non_secure = true, }, /* Insecure configuration #1 */
	{ .start = 0x100,	.end = 0x1ff,	.non_secure = false, }, /* TBBR */
	{ .start = 0x200,	.end = 0x23f,	.non_secure = false, }, /* Non-volatile secure counters */
	{ .start = 0x240,	.end = 0x7ff,	.non_secure = true, }, /* Insecure configuration #2 */
	{ .start = 0x800,	.end = 0x2000,	.non_secure = true, }, /* User-space (tags) */
};

static bool otp_tag_valid(struct otp *otp, char *tag_raw)
{
	uint8_t size;

	size = OTP_TAG_GET_SIZE(tag_raw);
	if (size != 0 && size != 7)
		return true;

	return false;
}

static bool otp_tag_used(struct otp *otp, char *tag_raw)
{
	uint8_t size;

	size = OTP_TAG_GET_SIZE(tag_raw);
	if (size != 0)
		return true;

	return false;
}

static enum otp_tag_type otp_tag_type_from_str(char *val)
{
	int res = 0;
	char *end;
	int i;

	res = strtoul(val, &end, 0);

	/* In case it failed to parse the input as a digit */
	if (res == 0 && val == end) {
		for (i = 0; i < ARRAY_SIZE(otp_tags); ++i) {
			if (strcmp(otp_tags[i].name, val) == 0)
				return otp_tags[i].tag;
		}
	}
	if (res >= ARRAY_SIZE(otp_tags))
		return otp_tag_type_invalid;

	return res;
}

static enum otp_value_type otp_value_type_from_str(char *val) {
	if (!strcmp(val, "ascii"))
		return otp_value_type_ascii;
	if (!strcmp(val, "hex"))
		return otp_value_type_hex;
	if (!strcmp(val, "dec"))
		return otp_value_type_decimal;
	if (!strcmp(val, "binary"))
		return otp_value_type_binary;
	if (!strcmp(val, "3ascii-dec"))
		return otp_value_type_3ascii_decimal;

	return otp_value_type_unknown;
};

static void otp_value_free(struct otp_value *val)
{
	if (val && val->raw)
		free(val->raw);
}

static int otp_hex_to_bytearray(struct otp *otp, char *hex, char *raw, int length)
{
	int raw_length = 0;
	int i;

	if (length % 2 != 0) {
		otp_error(otp, "Invalid length of hex string, needs to be be "
			       "a multiple of 2\n");
		return -EINVAL;
	}

	if (hex[0] == '0' && hex[1] == 'x') {
		hex += 2;
		length -= 2;
	}

	for (i = 0; i < length; ++i) {
		if (!((hex[i] >= '0' && hex[i] <= '9') ||
		      (hex[i] >= 'A' && hex[i] <= 'F') ||
		      (hex[i] >= 'a' && hex[i] <= 'f'))) {
			otp_error(otp, "Invalid hex string\n");
			return -EINVAL;
		}
	}

	for (i = 0; i < length / 2; ++i) {
		sscanf(hex, "%2hhx", &raw[i]);
		hex += 2;
		raw_length++;
	}

	return raw_length;
}

static int otp_binary_to_bytearray(struct otp *otp, char *binary, char *raw, int length)
{
	int i;

	if (binary[0] == '0' && binary[1] == 'b') {
		binary += 2;
		length -= 2;
	}

	if (length % 8 != 0) {
		otp_error(otp, "Invalid length of binary string, needs to be "
			       "a multiple of 8\n");
		return -EINVAL;
	}

	for (i = 0; i < length; ++i) {
		if (binary[i] != '1' && binary[i] != '0') {
			otp_error(otp, "Invalid binary string\n");
			return -EINVAL;
		}
	}

	for (i = 0; i < length; ++i) {
		if (binary[i] == '1')
			raw[i / 8] |= BIT(i % 8);
	}

	return 0;
}

static int otp_decimal_to_bytearray(struct otp *otp, char *decimal, char *raw, int length)
{
	int64_t res;
	char *end;
	int i = 0;

	res = strtoul(decimal, &end, 0);
	/* In case it failed to parse the input as a digit */
	if (res == -1 || (res == 0 && decimal == end)) {
		otp_error(otp, "Failed to part %s as a decimal\n", decimal);
		return -EINVAL;
	}

	while (res > 0) {
		raw[i] = 0xff & res;
		i++;
		res >>= 8;
	}

	return i;
}

/* This is a special case because the input format is required to be
 * like this: MMMYYWWPPNNNN where:
 *  MMM - represents the manufacture
 *  YY - represents the year ex: 22, 23, 40
 *  WW - represents the week in each chip is created 1-52
 *  PP - represents the number times it produces the chip in that week
 *  NNNN - represents the serial number of the chip
 */
static int otp_3ascii_decimal_to_bytearray(struct otp *otp, char *value, char *raw, int length)
{
	long long int serial;
	uint8_t man[3];
	int ret = 0;
	char *tmp;

	/* When scanning the version number they will have actually a format of
	 * XX-XXXXX-XX/Serial-number. The first part until '/' needs to be
	 * ignored
	 */
	tmp = strchr(value, '/');
	if (tmp) {
		value = tmp + 1;
		length = strlen(value);
	}

	if (length != 13) {
		otp_error(otp, "Wrong format for serial number\n");
		return -EINVAL;
	}

	ret = sscanf(value, "%c%c%c%lld", &man[2], &man[1], &man[0], &serial);
	if (ret != 4) {
		otp_error(otp, "Wrong parsing of the serial number\n");
		return -EINVAL;
	}

	raw[7] = man[2];
	raw[6] = man[1];
	raw[5] = man[0];
	raw[4] = (serial >> 32) & 0xff;
	raw[3] = (serial >> 24) & 0xff;
	raw[2] = (serial >> 16) & 0xff;
	raw[1] = (serial >>  8) & 0xff;
	raw[0] = (serial >>  0) & 0xff;

	return 8;
}

static int otp_value_format(struct otp *otp, enum otp_value_type type,
			    char *value, int length, struct otp_value *val)
{
	int ret = 0;

	memset(val, 0x0, sizeof(*val));
	val->val = value;
	val->type = type;

	val->raw = malloc(length);
	if (!val->raw) {
		otp_error(otp, "No memory\n");
		return -ENOMEM;
	}
	memset(val->raw, 0x0, length);

	switch (val->type) {
	case otp_value_type_ascii:
		memcpy(val->raw, val->val, length);
		val->raw_length = length;
		return 0;
	case otp_value_type_hex:
		ret = otp_hex_to_bytearray(otp, val->val, val->raw, length);
		if (ret < 0)
			goto out;
		val->raw_length = ret;
		return 0;
	case otp_value_type_binary:
		ret = otp_binary_to_bytearray(otp, val->val, val->raw, length);
		if (ret < 0)
			goto out;

		val->raw_length = ret;
		return 0;
	case otp_value_type_decimal:
		ret = otp_decimal_to_bytearray(otp, val->val, val->raw, length);
		if (ret < 0)
			goto out;

		val->raw_length = ret;
		return 0;
	case otp_value_type_3ascii_decimal:
		ret = otp_3ascii_decimal_to_bytearray(otp, val->val, val->raw, length);
		if (ret < 0)
			goto out;

		val->raw_length = ret;
		return 0;
	default:
		otp_error(otp, "Invalid format type\n");
		return -EINVAL;
	}

out:
	free(val->raw);
	return ret;
}

static char otp_value_char_print(char c)
{
	if (isprint(c))
		return c;

	return '.';
}

static void otp_value_print(struct otp *otp, char *raw, int offset, int length)
{
	int i;

	otp_printf(otp, "%d ", length);
	for (i = 0; i < length; ++i)
		otp_printf(otp, "%02x", 0xff & raw[i]);

	otp_printf(otp, "|");
	for (i = 0; i < length; ++i)
		otp_printf(otp, "%c", otp_value_char_print(raw[i]));

	otp_printf(otp, "|\n");
}

static void incomplete_command(void)
{
	printf("Command line is not complete. Try option \"help\"\n");
	exit(-1);
}

static void otp_print_help(void)
{
	printf("This tool can be used to access and modify the OTP in the following SoCs:\n"
		" - LAN9662\n"
		" - LAN9668\n"
		" - LAN969X\n"
		"\n"
		"Usage:\n"
		" otp field list\n"
		" otp field get [<NAME>]\n"
		" otp field set [--merge] <NAME> (ascii|hex|dec|3ascii-dec) <VALUE>\n"
		" otp addr get <ADDRESS> <BYTE-LENGTH>\n"
		" otp addr set [--merge] <ADDRESS> <BYTE-LENGTH> (ascii|hex|dec) <VALUE>\n"
		" otp tag list-tag-names\n"
		" otp tag print\n"
		" otp tag info\n"
		" otp tag get (<tag-number>|<tag-name>)\n"
		" otp tag del (<tag-number>|<tag-name>)\n"
		" otp tag set (<tag-number>|<tag-name>) (ascii|hex|dec) <VALUE>\n"
		" otp nvcnt get (trusted|nontrusted)\n"
		" otp nvcnt set <VALUE> (trusted|nontrusted)\n"
		" otp import-keys [--no-randomize-huk] <FILE>\n"
		" otp region show\n"
		" otp region write-protect <REGION-NUMBER>\n"
		" otp region non-secure <REGION-NUMBER>\n"
		" otp init pcb <PCB> ethaddr (random-ethaddr|<ETHADDR-ADDRESS>) ethaddr_count <COUNT> \n"
		" otp init pcb_2 <PCB_NAME> ethaddr (random-ethaddr|<ETHADDR-ADDRESS>) ethaddr_count <COUNT> \n"
		"\n"
		"Options:\n"
		" -h --help             Show this screen.\n"
		" --version             Show version.\n"
		" --verbose             Enable verbose traces on console\n"
		" -d DEV --device DEV   NVRAM device\n"
		"                       This can also be a normal block device, or even a file.\n"
		" -i ID --chip-id ID    Specify OTP layout coresponding to the given chip ID.\n"
		"                       NOTE: This setting is only allowed on devices where the\n"
		"                       part-ID at byte address 0x5-0x6 is not programmed, or if\n"
		"                       the programmed part-ID matches the provided ID.\n"
		" --chip-id-force       Force usage of the ID given with --chip-id=ID, even\n"
		"                       though a different part ID is programmed in the OTP.\n"
		" --no-confirm          Do not require the user to confirm write operations.\n"
		"\n"
		"General:\n"
		"\n"
		" The OTP in these products are accessed by various elements including: discrete\n"
		" logic in the chip, TF-A bootrom (BL1), Secure Boot loader (BL2), EL3 Runtime\n"
		" software (BL31/BL32), UBoot, Linux kernel and this user-space application.\n"
		" The OTP has a concept of regions, which can be used to configure access\n"
		" control (read and write protection). The regions and write protect mask is in\n"
		" the OTP it self and need to be provisioned.\n"
		"\n"
		" This tool support 3 different kind of content:\n"
		"   Fields:                This is fixed-length data at fixed positions in the\n"
		"                          OTP. The tool has a build in template for each of the\n"
		"                          supported SoC with name, address, length and\n"
		"                          description.\n"
		"\n"
		"   Non volatile counters: This is counters which can only be incremented. This\n"
		"                          is used to do rollback protection. This is\n"
		"                          implemented as a bitfields, and the max value is\n"
		"                          therefore the number of allocated bits for a given\n"
		"                          counter.\n"
		"\n"
		"   Tagged data:           This is semi-one-time-programmable data. The purpose\n"
		"                          of this is to allow store various data such as:\n"
		"                          mac-addresses, board-ID, ECO level, uniq default\n"
		"                          password which may be printed on the device, etc.\n"
		"                          This is implemented as an array of 64-bits records\n"
		"                          with the following layout:\n"
		"\n"
		"                           +--------+--------+--------+----------+\n"
		"                           | size:3 | cont:1 | tag:12 | value:48 |\n"
		"                           +--------+--------+--------+----------+\n"
		"\n"
		"                          Where:\n"
		"                            size:   specify the number of valid bytes in value.\n"
		"                                    0 and 0b111 (7) are invalid. If a record\n"
		"                                    needs to be invalidated, then it is a\n"
		"                                    matter of writing 0b111 in this field.\n"
		"                            cont:   specify that the content continues in the\n"
		"                                    next valid record with the given tag value.\n"
		"                            tag:    This is a number from 0-2047 specifying the\n"
		"                                    type of data (the implementation has a list\n"
		"                                    of named tags which may be used).\n"
		"                            value:  Value associated to the tag.\n"
		"\n"
		"\n"
		"Note:\n"
		" All commands writing ('field set', 'addr set', 'tag del|set') to OTP shall do:\n"
		" - Read out existing content.\n"
		" - If '--merge' flag is not set, confirm that the specified value is possible\n"
		"   to set. Abort if not.\n"
		" - Print in hex what is about the be written where\n"
		" - Let use user confirm.\n"
		"\n"
		"Command details:\n"
		" otp help:\n"
		"   Print this message\n"
		"\n"
		" otp field list:\n"
		"   List all fields recognized by the implementation template.\n"
		"\n"
		" otp field get [<NAME>]\n"
		"   Get the content of a specific fields, or all fields if non is provided.\n"
		"   NOTE: This shall skip fields in areas being read-protected, but will happily\n"
		"   print secrets if not proper protected.\n"
		"\n"
		" otp field set [--merge] <NAME> (ascii|hex|dec) <VALUE>\n"
		"   Set the content of a given field.\n"
		"   - If the --merge option is provided, then the content is bit-wised OR with\n"
		"     what is in the OTP field already. If not, a check is performed to confirm\n"
		"     that the desired value can be written as-is.\n"
		"   - The value can either be provided in ascii format, or as a hex-string.\n"
		"     - A hex string must always provide an equal number of chars (no half\n"
		"       bytes).\n"
		"   - The length of the value must match what is find in the template.\n"
		"\n"
		" otp addr get <address> <BYTE-LENGTH>\n"
		"   Read the raw content in OTP. If the requested area is (partly)\n"
		"   read-protected, then return error.\n"
		"\n"
		" otp addr set [--merge] <address> <BYTE-LENGTH> (ascii|hex|dec) <VALUE>\n"
		"   Write raw content in the OTP. If the requested area is (partly)\n"
		"   write-protected, then return error before any content is written.\n"
		"\n"
		" otp nvcnt (trusted|nontrusted) get\n"
		" otp nvcnt (trusted|nontrusted) set <VALUE>\n"
		"   Get/set the value of either the trusted or nontrusted\n"
		"   non-volatile-ever-incrementing-counter.\n"
		"   This is implemented as a bit-field, and a given implementation will have\n"
		"   limited capacity.\n"
		"   NOTE: This is used by the secure boot-ROM to implement rollback protection.\n"
		"\n"
		" otp tag list-tag-names\n"
		"   List all the tag names and associated numbers know by the implementation.\n"
		"\n"
		" otp tag info\n"
		"   Print statistics on tag usages.\n"
		" otp tag print\n"
		"   Print all valid tags in the otp.\n"
		"\n"
		" otp tag get (bin|hex) [(<tag-number>|<tag-name>)]\n"
		"   Read out the value of a given tag (either by name or by number) or dump all\n"
		"   tags if no name/number is provided.\n"
		"   If no valid tag with matching name/number was found, then return an error.\n"
		"\n"
		" otp tag [--merge] set (<tag-number>|<tag-name>) (ascii|hex) <VALUE>\n"
		"   Set a tagged value. If the --merge flag was set, then the content provided\n"
		"   must be of exact same length as the length of existing content in the OTP.\n"
		"   If this tag already exists, then it shall be replaced (meaning invalidating\n"
		"   the existing tag).\n"
		"\n"
		" otp tag append (<tag-number>|<tag-name>)\n"
		"   Append more data to a tag. This will always create a new record and set the\n"
		"   'cont' flag in existing tags.\n"
		"\n"
		" otp tag del (<tag-number>|<tag-name>)\n"
		"   Invalidate an existing tag in the OTP.\n"
		"\n"
		" otp import-keys [--no-randomize-huk] <FILE>:\n"
		"   This shall read the content from a file (or stdin if '-' is provided as\n"
		"   file-name).\n"
		"   The content is binary and length must match the platform expected length.\n"
		"   It can only be used to program the region with TF-A keys (on LAN966x\n"
		"   this is region 4). The region will not be defined when the tool is called,\n"
		"   and a per platform hard-coded offset/size will be used.\n"
		"   Unless the --no-randomize-huk flag is set, then the OTP_TBBR_HUK field will\n"
		"   be set with randomized content using /dev/random.\n"
		"\n"
		"otp region show:\n"
		"  Show the start-address, end-address and write-protect bit of all regions.\n"
		"  Some regions may be displayed with start- and end-address equal to 0, which\n"
		"  means that this region is still not defiend. \n"
		"\n"
		"otp region write-protect <REGION-NUMBER>:\n"
		"  This shall check if the region <REGION-NUMBER> is defined (in\n"
		"  `PROTECT_REGION_ADDR`).  If not, the region shall be defined using the\n"
		"  per-chip-id defined template.  Once the region is defined it shall be marked\n"
		"  as write-protected in `PROTECT_OTP_WRITE`.\n"
		"\n"
		"otp init pcb <PCBNO> ethaddr (random-ethaddr|<ETHADDR-ADDRESS>) ethaddr_count <COUNT>\n"
		"  NOTE: This shall only be called during board manufacturing!\n"
		"        Do not call more than once.\n"
		"\n"
		"  This sub-command will do the following:\n"
		"  - Do the equivalent of: $ opt tag set pcb dec <PCBNO>\n"
		"  - Do the equivalent of: $ opt tag set ethaddr_count dec <COUNT>\n"
		"  - Do the equivalent of: $ opt tag set ethaddr ascii <ETHADDR-ADDRESS>\n"
		"    - If the ethaddr-address is `random-ethaddr`, then generate a random ETHADDR with the\n"
		"      following limitation:\n"
		"      - Broadcast bit is 0\n"
		"      - Local-administrated bit is 1\n"
		"      - It must not be all zero and not all ff.\n"
		"otp init pcb_2 <PCB_NAME> ethaddr (random-ethaddr|<ETHADDR-ADDRESS>) ethaddr_count <COUNT>\n"
		"  NOTE: This shall only be called during board manufacturing!\n"
		"        Do not call more than once.\n"
		"\n"
		"  This sub-command will do the following:\n"
		"  - Do the equivalent of: $ opt tag set pcb string <PCB_NAME>\n"
		"  - Do the equivalent of: $ opt tag set ethaddr_count dec <COUNT>\n"
		"  - Do the equivalent of: $ opt tag set ethaddr ascii <ETHADDR-ADDRESS>\n"
		"    - If the ethaddr-address is `random-ethaddr`, then generate a random ETHADDR with the\n"
		"      following limitation:\n"
		"      - Broadcast bit is 0\n"
		"      - Local-administrated bit is 1\n"
		"      - It must not be all zero and not all ff.\n"

		"\n");
}

static void otp_print_version(void)
{
	printf("Version: %s\n", VER);
}

static void otp_check_confirm(struct otp *otp)
{
	if (!otp->no_confirm) {
		otp_printf(otp, "Confirm that the write should happen by pressing Enter");
		getchar();
	}
}

static int otp_file_read(struct otp *otp, uint32_t offset, uint32_t length,
			 char *res)
{
	int err;
	int fd;

	otp_debug(otp, "Opening file: %s to read at offset %d(0x%x) for lenght: %d\n",
		  otp->device, offset, offset, length);

	fd = open(otp->device, O_RDONLY);
	if (fd == -1) {
		otp_error(otp, "Faild to open file: %s error: %s\n",
			  otp->device, strerror(errno));
		return -ENOENT;
	}

	err = lseek(fd, offset, SEEK_SET);
	if (err == -1) {
		otp_error(otp, "Failed to go to offset: %d(0x%x) error: %s\n",
			  offset, offset, strerror(errno));
		close(fd);
		return -EINVAL;
	}

	err = read(fd, res, length);
	if (err != length) {
		otp_error(otp, "Failed to read: %d bytes\n", length);
		close(fd);
		return -EINVAL;
	}

	otp_debug(otp, "Read sucessfully from file: %s at offset: %d(0x%x) for length: %d\n",
		  otp->device, offset, offset, length);

	close(fd);
	return 0;
}

static int otp_file_write(struct otp *otp, uint32_t offset, uint32_t length,
			  char *val)
{
	int err;
	int fd;

	otp_debug(otp, "Opening file: %s to write at offset %d(0x%x) for lenght: %d\n",
		  otp->device, offset, offset, length);

	fd = open(otp->device, O_WRONLY);
	if (!fd) {
		otp_error(otp, "Faild to open file: %s\n", otp->device);
		return -ENOENT;
	}

	err = lseek(fd, offset, SEEK_SET);
	if (err == -1) {
		otp_error(otp, "Failed to go to offset: %d(0x%x)\n", offset, offset);
		close(fd);
		return -EINVAL;
	}

	err = write(fd, val, length);
	if (err != length) {
		otp_error(otp, "Failed to write : %d bytes\n", length);
		close(fd);
		return -EINVAL;
	}

	otp_debug(otp, "Write sucessfully from file: %s at offset: %d(0x%x) for length: %d\n",
		  otp->device, offset, offset, length);

	close(fd);
	return 0;
}

static int otp_field_read(struct otp *otp, const struct otp_field *field, void *res)
{
	return otp_file_read(otp, field->offset, field->length, res);
}

static int otp_file_update(struct otp *otp, uint32_t offset, uint32_t length, void *val)
{
	uint8_t data[length];
	int err, i;

	/* Read data */
	err = otp_file_read(otp, offset, length, (char*) data);
	if (err)
		return err;

	/* Check we can do this update */
	for (i = 0; i < length; i++) {
		uint8_t new = ((uint8_t*)val)[i];
		if (~new & data[i]) {
			otp_error(otp, "Cannot clear bits at offset %04x: Have %02x, want to set %02x\n",
				  offset + i, data[i], new);
			return -EINVAL;
		}
	}

	if (memcmp(val, data, length) == 0) {
		otp_debug(otp, "Data length %d at offset %04x unchanged\n", length, offset);
		return 0;
	}

	return otp_file_write(otp, offset, length, val);
}

static int otp_field_write(struct otp *otp, struct otp_value *val,
			   struct otp_field *field)
{
	otp_check_confirm(otp);

	return otp_file_write(otp, field->offset, val->raw_length, val->raw);
}

static struct otp_field *otp_field_get(struct otp *otp, char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(otp_fields); ++i) {
		if (strcmp(otp_fields[i].name, name))
			continue;

		return &otp_fields[i];
	}

	return NULL;
}

static int otp_field_can_write(struct otp *otp, char *name, struct otp_value *val,
			       struct otp_field *field)
{
	struct otp_field *f;
	char *tmp;
	int err;
	int i;

	f = otp_field_get(otp, name);
	if (!f) {
		otp_error(otp, "Field: %s was not found\n", name);
		return -EINVAL;
	}

	*field = *f;

	if (val->raw_length > field->length) {
		otp_error(otp, "The value written(%d) is longer than field length(%d)\n",
			  val->raw_length, field->length);
		return -EINVAL;
	}

	tmp = malloc(field->length);
	if (!tmp) {
		otp_error(otp, "Failed to allocate memory\n");
		return -ENOMEM;
	}

	err = otp_field_read(otp, field, tmp);
	if (err) {
		otp_error(otp, "Failed to read nr bytes: %d at offset %d(0x%x)\n",
			  field->length, field->offset, field->offset);
		goto out;
	}

	if (otp->merge) {
		for (i = 0; i < field->length; ++i) {
			val->raw[i] |= tmp[i];
		}
	} else {
		for (i = 0; i < field->length; ++i) {
			if ((val->raw[i] | tmp[i]) != val->raw[i]) {
				otp_error(otp, "Failed to merge values 0x%02x and 0x%02x\n",
					  val->raw[i], 0xff & tmp[i]);
				err = -EINVAL;
				goto out;
			}
		}
	}

	return 0;
out:
	free(tmp);
	return err;
}

static int otp_cmd_field_list(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(otp_fields); ++i)
		printf("Field: %25s offset: 0x%04x length: %02d\n",
			otp_fields[i].name,
			otp_fields[i].offset,
			otp_fields[i].length);

	return 0;
}

static int otp_cmd_field_get(struct otp *otp, char *name)
{
	struct otp_field *field;
	char *res;
	int err;

	field = otp_field_get(otp, name);
	if (!field) {
		otp_error(otp, "Field: %s was not found\n", name);
		return -EINVAL;
	}

	res = malloc(field->length);
	if (!res) {
		otp_error(otp, "Failed to allocate memory\n");
		return -ENOMEM;
	}
	memset(res, 0, field->length);

	err = otp_field_read(otp, field, res);
	if (err) {
		otp_error(otp, "Failed to read at offset: %x\n", field->offset);
		free(res);
		return err;
	}

	otp_debug(otp, "Field: %s \n", name);
	otp_value_print(otp, res, field->offset, field->length);
	free(res);

	return 0;
}

static int otp_cmd_field_set(struct otp *otp, char *name, enum otp_value_type type,
			     char *value)
{
	struct otp_field field;
	struct otp_value val;
	int err;

	err = otp_value_format(otp, type, value, strlen(value), &val);
	if (err) {
		otp_error(otp, "Failed to convert user input\n");
		return err;
	}

	err = otp_field_can_write(otp, name, &val, &field);
	if (err) {
		otp_error(otp, "Failed check to set field: %s to %s\n",
			  name, value);
		goto out;
	}

	err = otp_field_write(otp, &val, &field);
	if (err) {
		otp_error(otp, "Failed write to set field: %s to %s\n",
			  name, value);
		goto out;
	}

	otp_debug(otp, "Field: %s was set: %s\n", name, value);

out:
	otp_value_free(&val);
	return err;

}

static int otp_cmd_field(struct otp *otp, int argc, char **argv)
{
	enum otp_value_type type;
	char *name;
	char *val;

	/* skip the command */
	argv++;
	argc -= 1;

next_arg:
	if (*argv == NULL) {
		otp_error(otp, "Invalid format\n");
		otp_print_help();
		return -EINVAL;
	}

	if (strcmp(*argv, "list") == 0) {
		return otp_cmd_field_list();
	} else if (strcmp(*argv, "get") == 0) {
		NEXT_ARG();
		name = *argv;
		return otp_cmd_field_get(otp, name);
	} else if (strcmp(*argv, "set") == 0) {
		NEXT_ARG();
		name = *argv;
		NEXT_ARG();
		type = otp_value_type_from_str(*argv);
		NEXT_ARG();
		val = strdup(*argv);
		return otp_cmd_field_set(otp, name, type, val);
	} else if (strcmp(*argv, "--merge") == 0) {
		NEXT_ARG();
		otp->merge = true;
		goto next_arg;
	} else {
		otp_error(otp, "Unknown field: %s\n", *argv);
		otp_print_help();
		return -EINVAL;
	}

	return 0;
}

static int otp_addr_read(struct otp *otp, struct otp_addr *addr, char *res)
{
	return otp_file_read(otp, addr->offset, addr->length, res);
}

static int otp_addr_write(struct otp *otp, struct otp_addr *addr,
			  struct otp_value *val)
{

	otp_check_confirm(otp);

	return otp_file_write(otp, addr->offset, val->raw_length, val->raw);
}

static int otp_addr_can_write(struct otp *otp, struct otp_addr *addr,
			  struct otp_value *val)
{
	int err = 0;
	char *tmp;
	int i;

	if (val->raw_length > addr->length) {
		otp_error(otp, "Written value bigger(%d) than the length(%d)\n",
			  val->raw_length, addr->length);
		return -EINVAL;
	}

	if (addr->offset + addr->length >= otp->size) {
		otp_error(otp, "Write outside of memory\n");
		return -EINVAL;
	}

	tmp = malloc(addr->length);
	if (!tmp) {
		otp_error(otp, "Failed to allocate memory\n");
		return -ENOMEM;
	}

	err = otp_file_read(otp, addr->offset, addr->length, tmp);
	if (err) {
		otp_error(otp, "Failed to read nr bytes: %d at offset: %d(0x%x)\n",
			  addr->length, addr->offset, addr->offset);
		goto out;
	}

	if (otp->merge) {
		for (i = 0; i < addr->length; ++i) {
			val->raw[i] |= tmp[i];
		}
	} else {
		for (i = 0; i < addr->length; ++i) {
			if ((val->raw[i] | tmp[i]) != val->raw[i]) {
				otp_error(otp, "Failed to merge values 0x%02x and 0x%02x\n",
					  val->raw[i], 0xff & tmp[i]);
				err = -EINVAL;
				goto out;
			}
		}
	}

out:
	free(tmp);
	return err;
}

static int otp_cmd_addr_get(struct otp *otp, uint32_t offset, uint32_t length)
{
	struct otp_addr addr;
	char *res;
	int err;

	res = malloc(length);
	if (!res) {
		otp_error(otp, "Failed to allocate memory\n");
		return 1;
	}
	memset(res, 0, length);

	addr.offset = offset;
	addr.length = length;

	err = otp_addr_read(otp, &addr, res);
	if (err)
		goto out;

	otp_debug(otp, "Address: %d(0x%x): was read:\n", offset, offset);
	otp_value_print(otp, res, offset, length);

out:
	free(res);
	return err;
}

static int otp_cmd_addr_set(struct otp *otp, uint32_t offset, uint32_t length,
			    enum otp_value_type type, char *value)
{
	struct otp_value val;
	struct otp_addr addr;
	int err;

	err = otp_value_format(otp, type, value, strlen(value), &val);
	if (err) {
		otp_error(otp, "Failed to convert user input\n");
		free(value);
		return err;
	}

	addr.offset = offset;
	addr.length = length;
	err = otp_addr_can_write(otp, &addr, &val);
	if (err) {
		otp_error(otp, "Failed check to set addr: 0x%x to %s\n",
			  offset, value);
		goto out;
	}

	err = otp_addr_write(otp, &addr, &val);
	if (err) {
		otp_error(otp, "Failed check to set addr: 0x%x to %s\n",
			  offset, value);
		goto out;
	}

	otp_debug(otp, "Address: 0x%x was set: %s\n", offset, value);

out:
	otp_value_free(&val);
	free(value);
	return err;
}

static int otp_cmd_addr(struct otp *otp, int argc, char **argv)
{
	enum otp_value_type type;
	uint32_t length;
	uint32_t offset;
	char *val;

	/* skip the command */
	argv++;
	argc -= 1;

next_arg:
	if (*argv == NULL) {
		otp_error(otp, "Invalid format\n");
		otp_print_help();
		return -EINVAL;
	}

	if (strcmp(*argv, "get") == 0) {
		NEXT_ARG();
		offset = strtoul(*argv, NULL, 0);
		NEXT_ARG();
		length = strtoul(*argv, NULL, 0);
		return otp_cmd_addr_get(otp, offset, length);
	} else if (strcmp(*argv, "set") == 0) {
		NEXT_ARG();
		offset = strtoul(*argv, NULL, 0);
		NEXT_ARG();
		length = strtoul(*argv, NULL, 0);
		NEXT_ARG();
		type = otp_value_type_from_str(*argv);
		NEXT_ARG();
		val = strdup(*argv);
		return otp_cmd_addr_set(otp, offset, length, type, val);
	} else if (strcmp(*argv, "--merge") == 0) {
		NEXT_ARG();
		otp->merge = true;
		goto next_arg;
	} else {
		otp_error(otp, "Unknown field: %s\n", *argv);
		otp_print_help();
		return -EINVAL;
	}
	return 0;
}

static char *otp_tag_type_to_str(enum otp_tag_type tag)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(otp_tags); ++i)
		if (otp_tags[i].tag == tag)
			return otp_tags[i].name;

	return NULL;
}

static int otp_tag_write(struct otp *otp, uint32_t offset,
			 struct otp_value *value, struct otp_tag *tag)
{
	char tag_raw[OTP_TAG_ENTRY_LENGTH];
	int remain_length;
	int write;
	bool cont;
	int err;
	int i;

	otp_check_confirm(otp);

	i = 0;
	remain_length = value->raw_length;

	while (true) {
		err = otp_file_read(otp, offset, OTP_TAG_ENTRY_LENGTH, tag_raw);
		if (err) {
			otp_error(otp, "Failed to read at offset 0x%x\n", offset)
			return err;
		}

		if (remain_length > OTP_TAG_VAL_LENGTH)
			cont = true;
		else
			cont = false;

		if (remain_length > OTP_TAG_VAL_LENGTH)
			write = OTP_TAG_VAL_LENGTH;
		else
			write = remain_length;

		OTP_TAG_SET_SIZE(tag_raw, write);
		OTP_TAG_SET_CONT(tag_raw, cont);
		OTP_TAG_SET_TAG(tag_raw, tag->tag);
		OTP_TAG_SET_VAL(tag_raw, &value->raw[i], write);

		err = otp_file_write(otp, offset, OTP_TAG_ENTRY_LENGTH, tag_raw);
		if (err) {
			otp_error(otp, "Failed to write at offset 0x%x\n", offset);
			return -EIO;
		}

		remain_length -= write;
		if (remain_length == 0)
			break;

		offset += OTP_TAG_ENTRY_LENGTH;
		i += OTP_TAG_VAL_LENGTH;
	}

	return 0;
}

static int otp_tag_can_write(struct otp *otp, enum otp_tag_type tag_type,
			     struct otp_value *val, struct otp_tag *tag,
			     uint32_t *offset, uint32_t starting_offset)
{
	char tag_raw[OTP_TAG_ENTRY_LENGTH];
	uint32_t space, left_space;
	int err;
	int i;

	if (tag_type == otp_tag_type_invalid) {
		otp_error(otp, "Invalid tag type\n");
		return -EINVAL;
	}

	if (starting_offset + 8 > otp->size) {
		otp_error(otp, "Starting offset can't be bigger then %zd\n",
			  otp->size);
		return -EINVAL;
	}

	if (starting_offset % 8 != 0) {
		otp_error(otp, "Needs to be module 8\n");
		return -EINVAL;
	}

	for (i = 0; i < ARRAY_SIZE(otp_tags); ++i) {
		if (otp_tags[i].tag == tag_type)
			memcpy(tag, &otp_tags[i], sizeof(*tag));
	}

	/* Detect if entry exists */
	for (i = starting_offset; i < otp->size; i += OTP_TAG_ENTRY_LENGTH) {
		err = otp_file_read(otp, i, OTP_TAG_ENTRY_LENGTH, tag_raw);
		if (err) {
			otp_error(otp, "Failed to read offset 0x%x\n", i);
			return err;
		}

		if (otp_tag_used(otp, tag_raw)) {
			if (otp_tag_valid(otp, tag_raw) &&
			    OTP_TAG_GET_TAG(tag_raw) == tag->tag) {
				otp_error(otp, "The tag %s already exists\n",
					  tag->name);
				return -EINVAL;
			}
		}
	}

	if (val->raw_length % OTP_TAG_VAL_LENGTH == 0)
		space = val->raw_length / OTP_TAG_VAL_LENGTH;
	else
		space = (val->raw_length / OTP_TAG_VAL_LENGTH) + 1;
	left_space = space;

	/* Detect if enough space exists and if it is retun the offset to the
	 * first entry
	 */
	for (i = starting_offset; i < otp->size; i += OTP_TAG_ENTRY_LENGTH) {
		err = otp_file_read(otp, i, OTP_TAG_ENTRY_LENGTH, tag_raw);
		if (err) {
			otp_error(otp, "Failed to read offset 0x%x\n", i);
			return err;
		}

		if (otp_tag_used(otp, tag_raw)) {
			left_space = space;
			continue;
		}

		--left_space;
		if (!left_space) {
			*offset = i - (OTP_TAG_ENTRY_LENGTH * (space - 1));
			return 0;
		}
	}

	return -ENOMEM;
}

static int otp_tag_del(struct otp *otp, uint32_t offset, enum otp_tag_type tag)
{
	char tag_raw[OTP_TAG_ENTRY_LENGTH];
	int err;

	while (true) {
		err = otp_file_read(otp, offset, OTP_TAG_ENTRY_LENGTH, tag_raw);
		if (err) {
			otp_error(otp, "Failed to read offset 0x%x\n", offset);
			return err;
		}

		if (!otp_tag_valid(otp, tag_raw))
			break;

		OTP_TAG_SET_SIZE(tag_raw, 0x7);

		err = otp_file_write(otp, offset, OTP_TAG_ENTRY_LENGTH, tag_raw);
		if (err) {
			otp_error(otp, "Failed to write at offset 0x%x\n", offset);
			return -EIO;
		}

		offset += OTP_TAG_ENTRY_LENGTH;

		if (OTP_TAG_GET_TAG(tag_raw) != tag ||
		    !OTP_TAG_GET_CONT(tag_raw))
			break;
	}

	return 0;
}

static int otp_tag_print(struct otp *otp, uint32_t offset, enum otp_tag_type tag)
{
	char tag_raw[OTP_TAG_ENTRY_LENGTH];
	uint8_t full_size = 0;
	uint32_t orig_offset;
	uint8_t tmp;
	bool cont;
	char *val;
	int err;

	orig_offset = offset;

	/* Calculate the entire size */
	while (true) {
		err = otp_file_read(otp, offset, OTP_TAG_ENTRY_LENGTH, tag_raw);
		if (err) {
			otp_error(otp, "Failed to read offset 0x%x\n", offset);
			return err;
		}

		tmp = OTP_TAG_GET_SIZE(tag_raw);
		cont = OTP_TAG_GET_CONT(tag_raw);

		full_size += tmp;

		if (!cont)
			break;

		offset += OTP_TAG_ENTRY_LENGTH;
	}

	if (full_size == 0) {
		otp_error(otp, "Something went wrong\n");
		return -EINVAL;
	}

	val = malloc(full_size);
	if (!val) {
		otp_error(otp, "No memory\n");
		return -ENOMEM;
	}

	memset(val, 0, full_size);
	tmp = 0;

	/* Now copy the data */
	offset = orig_offset;
	while (true) {
		err = otp_file_read(otp, offset, OTP_TAG_ENTRY_LENGTH, tag_raw);
		if (err) {
			otp_error(otp, "Failed to read offset 0x%x\n", offset);
			free(val);
			return err;
		}

		memcpy(&val[tmp], tag_raw, OTP_TAG_GET_SIZE(tag_raw));

		cont = OTP_TAG_GET_CONT(tag_raw);
		if (!cont)
			break;

		offset += OTP_TAG_ENTRY_LENGTH;
		tmp += OTP_TAG_GET_SIZE(tag_raw);
	}

	otp_value_print(otp, val, offset, full_size);
	free(val);

	return 0;
}

static int otp_cmd_tag_names(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(otp_tags); ++i)
		printf("Tag: %10s, id: %d\n",
		       otp_tags[i].name,
		       otp_tags[i].tag);

	return 0;
}

static int otp_cmd_tag_print(struct otp *otp)
{
	char tag_raw[OTP_TAG_ENTRY_LENGTH];
	int err;
	int i;

	for (i = OTP_TAG_OFFSET; i < otp->size; i += OTP_TAG_ENTRY_LENGTH) {
		err = otp_file_read(otp, i, OTP_TAG_ENTRY_LENGTH, tag_raw);
		if (err) {
			otp_error(otp, "Failed to read offset 0x%x\n", i);
			return err;
		}

		if (!otp_tag_valid(otp, tag_raw))
			continue;

		otp_printf(otp, "At offset: 0x%x tag: %s\n",
			   i, otp_tag_type_to_str(OTP_TAG_GET_TAG(tag_raw)));
	}

	return 0;
}

static int otp_cmd_tag_info(struct otp *otp)
{
	char tag_raw[OTP_TAG_ENTRY_LENGTH];
	int used_entries = 0;
	int entries = 0;
	int err;
	int i;

	for (i = OTP_TAG_OFFSET; i < otp->size; i += OTP_TAG_ENTRY_LENGTH) {
		entries++;

		err = otp_file_read(otp, i, OTP_TAG_ENTRY_LENGTH, tag_raw);
		if (err) {
			otp_error(otp, "Failed to read offset 0x%x\n", i);
			return err;
		}

		if (otp_tag_used(otp, tag_raw))
			used_entries++;
	}

	otp_printf(otp, "Total number: %d, used entries: %d\n",
		   entries, used_entries);

	return 0;
}

static int otp_cmd_tag_get(struct otp *otp, enum otp_tag_type tag)
{
	char tag_raw[OTP_TAG_ENTRY_LENGTH];
	int err;
	int i;

	if (tag == otp_tag_type_invalid)
		return -EINVAL;

	for (i = OTP_TAG_OFFSET; i < otp->size; i += OTP_TAG_ENTRY_LENGTH) {
		err = otp_file_read(otp, i, OTP_TAG_ENTRY_LENGTH, tag_raw);
		if (err) {
			otp_error(otp, "Failed to read offset 0x%x\n", i);
			return err;
		}

		if (!otp_tag_valid(otp, tag_raw))
			continue;

		if (OTP_TAG_GET_TAG(tag_raw) != tag)
			continue;

		otp_debug(otp, "At offset: 0x%x tag: %s\n",
			  i, otp_tag_type_to_str(tag));
		otp_tag_print(otp, i, tag);

		break;
	}

	return 0;
}

static int otp_cmd_tag_del(struct otp *otp, enum otp_tag_type tag)
{
	char tag_raw[OTP_TAG_ENTRY_LENGTH];
	int err;
	int i;

	if (tag == otp_tag_type_invalid)
		return -EINVAL;

	for (i = OTP_TAG_OFFSET; i < otp->size; i += OTP_TAG_ENTRY_LENGTH) {
		err = otp_file_read(otp, i, OTP_TAG_ENTRY_LENGTH, tag_raw);
		if (err) {
			otp_error(otp, "Failed to read offset 0x%x\n", i);
			return err;
		}

		if (!otp_tag_valid(otp, tag_raw))
			continue;

		if (OTP_TAG_GET_TAG(tag_raw) != tag)
			continue;

		otp_check_confirm(otp);

		return otp_tag_del(otp, i, tag);
	}

	return -EINVAL;
}

static int otp_cmd_tag_set(struct otp *otp, enum otp_tag_type tag_type,
			   enum otp_value_type val_type, char *value)
{
	struct otp_value val;
	struct otp_tag tag;
	uint32_t offset;
	int err;

	err = otp_value_format(otp, val_type, value, strlen(value), &val);
	if (err) {
		otp_error(otp, "Failed to convert user input\n");
		return err;
	}

	err = otp_tag_can_write(otp, tag_type, &val, &tag, &offset,
				OTP_TAG_OFFSET);
	if (err) {
		otp_error(otp, "Failed check to set tag: %s to %s\n",
			  tag.name, value);
		goto out;
	}

	err = otp_tag_write(otp, offset, &val, &tag);
	if (err) {
		otp_error(otp, "Failed to set tag: %s to %s\n",
			  tag.name, value);
		goto out;
	}

	otp_debug(otp, "Tag: %s was set: %s\n", tag.name, value);

out:
	otp_value_free(&val);
	return err;

}

static int otp_cmd_tag(struct otp *otp, int argc, char **argv)
{
	enum otp_value_type type;
	enum otp_tag_type tag;
	char *val;

	/* skip the command */
	argv++;
	argc -= 1;

	if (*argv == NULL) {
		otp_error(otp, "Invalid format\n");
		otp_print_help();
		return -EINVAL;
	}

	if (strcmp(*argv, "list-tag-names") == 0) {
		return otp_cmd_tag_names();
	} else if (strcmp(*argv, "print") == 0) {
		return otp_cmd_tag_print(otp);
	} else if (strcmp(*argv, "info") == 0) {
		return otp_cmd_tag_info(otp);
	} else if (strcmp(*argv, "get") == 0) {
		NEXT_ARG();
		tag = otp_tag_type_from_str(*argv);
		return otp_cmd_tag_get(otp, tag);
	} else if (strcmp(*argv, "del") == 0) {
		NEXT_ARG();
		tag = otp_tag_type_from_str(*argv);
		return otp_cmd_tag_del(otp, tag);
	} else if (strcmp(*argv, "set") == 0) {
		NEXT_ARG();
		tag = otp_tag_type_from_str(*argv);
		NEXT_ARG();
		type = otp_value_type_from_str(*argv);
		NEXT_ARG();
		val = *argv;
		return otp_cmd_tag_set(otp, tag, type, val);
	} else {
		otp_error(otp, "Unknown field: %s\n", *argv);
		otp_print_help();
		return -EINVAL;
	}

	return 0;
}

static int otp_cmd_nvcnt_get(struct otp *otp, bool trusted)
{
	uint32_t version = 0;
	uint32_t offset;
	char *res;
	int err;
	int i;

	res = malloc(OTP_TBBR_TNVCT_LENGTH);
	if (!res) {
		otp_error(otp, "Failed to allocate memory\n");
		return -EINVAL;
	}
	memset(res, 0, OTP_TBBR_TNVCT_LENGTH);

	if (trusted)
		offset = OTP_TBBR_TNVCT_OFFSET;
	else
		offset = OTP_TBBR_NTNVCT_OFFSET;

	err = otp_file_read(otp, offset, OTP_TBBR_TNVCT_LENGTH, res);
	if (err) {
		otp_error(otp, "Failed to read offset: 0x%x\n", offset);
		return err;
	}

	for (i = 0; i < OTP_TBBR_TNVCT_LENGTH * 8; ++i) {
		if (res[i / 8] & BIT(i % 8))
			version++;
	}

	otp_printf(otp, "Current version is %d\n", version);
	return 0;
}

static int otp_cmd_nvcnt_set(struct otp *otp, uint32_t nbits, bool trusted)
{
	uint32_t bits = 0;
	uint32_t offset;
	char *res;
	int err;
	int i;

	if (nbits > 32 * 8) {
		otp_error(otp, "Version can't be bigger than 256\n");
		return -EINVAL;
	}

	res = malloc(OTP_TBBR_TNVCT_LENGTH);
	if (!res) {
		otp_error(otp, "Failed to allocate memory\n");
		return -ENOMEM;
	}
	memset(res, 0, OTP_TBBR_TNVCT_LENGTH);

	if (trusted)
		offset = OTP_TBBR_TNVCT_OFFSET;
	else
		offset = OTP_TBBR_NTNVCT_OFFSET;

	err = otp_file_read(otp, offset, OTP_TBBR_TNVCT_LENGTH, res);
	if (err) {
		otp_error(otp, "Failed to read offset: 0x%x\n", offset);
		return err;
	}

	for (i = 0; i < OTP_TBBR_TNVCT_LENGTH * 8; ++i) {
		if (res[i / 8] & BIT(i % 8))
			bits++;
	}

	if (bits >= nbits) {
		otp_error(otp, "Version number(%d) can't be smaller than the current(%d)\n",
			  bits, nbits);
		return -EINVAL;
	}

	bits = nbits - bits;
	for (i = 0; i < OTP_TBBR_TNVCT_LENGTH * 8; ++i) {
		if (!(res[i / 8] & BIT(i % 8))) {
			res[i / 8] |= BIT(i % 8);
			bits--;
		}

		if (!bits)
			break;
	}

	otp_check_confirm(otp);

	return otp_file_write(otp, offset, OTP_TBBR_TNVCT_LENGTH, res);
}

static int otp_cmd_nvcnt(struct otp *otp, int argc, char **argv)
{
	bool trusted = false;
	uint32_t val;

	/* skip the command */
	argv++;
	argc -= 1;

	if (*argv == NULL) {
		otp_error(otp, "Invalid format\n");
		otp_print_help();
		return -EINVAL;
	}

	if (strcmp(*argv, "get") == 0) {
		NEXT_ARG();
		if (strcmp(*argv, "trusted") == 0) {
			trusted = true;
		} else if (strcmp(*argv, "nontrusted") == 0) {
			trusted = false;
		} else {
			otp_error(otp, "Unknown field: %s\n", *argv);
			otp_print_help();
			return -EINVAL;
		}
		return otp_cmd_nvcnt_get(otp, trusted);
	} else if (strcmp(*argv, "set") == 0) {
		NEXT_ARG();
		if (strcmp(*argv, "trusted") == 0) {
			trusted = true;
		} else if (strcmp(*argv, "nontrusted") == 0) {
			trusted = false;
		} else {
			otp_error(otp, "Unknown field: %s\n", *argv);
			otp_print_help();
			return -EINVAL;
		}
		NEXT_ARG();
		val = strtoul(*argv, NULL, 0);
		return otp_cmd_nvcnt_set(otp, val, trusted);
	} else {
		otp_error(otp, "Unknown field: %s\n", *argv);
		otp_print_help();
		return -EINVAL;
	}

	return 0;
}

static int otp_cmd_import_file(struct otp *otp, int fd, char *file,
			       struct otp_value *val)
{
	char *tmp;
	int err;

	tmp = malloc(OTP_KEYS_LENGTH);
	if (!tmp) {
		otp_error(otp, "Not enough memory\n");
		return -ENOMEM;
	}

	memset(tmp, 0, OTP_KEYS_LENGTH);

	/* Read exactly 128 bytes in total */
	err = read(fd, tmp, OTP_TBBR_KEYS_LENGTH);
	if (err != OTP_TBBR_KEYS_LENGTH) {
		otp_error(otp, "Failed to read: %d bytes from file %s\n",
			  OTP_TBBR_KEYS_LENGTH, file);
		close(fd);
		return -EINVAL;
	}

	val->raw = tmp;

	return 0;
}

static int otp_cmd_import_stdin(struct otp *otp, struct otp_value *val)
{
	char tmp[OTP_KEYS_LENGTH];
	int err;

	memset(tmp, 0, OTP_KEYS_LENGTH);

	/* As the input is in hex, need to read twice as more data to be able to
	 * convert the input to binary
	 */
	err = read(0, tmp, OTP_KEYS_LENGTH);
	if (err != OTP_KEYS_LENGTH) {
		otp_error(otp, "Failed to read: %d bytes from stdin\n",
			  OTP_KEYS_LENGTH);
		return -EINVAL;
	}

	err = otp_value_format(otp, otp_value_type_hex, tmp, OTP_KEYS_LENGTH, val);
	if (err) {
		otp_error(otp, "Failed to convert user input\n");
		return -EINVAL;
	}

	return 0;
}

/* This will set all OTP_TBBR_* keys */
static int otp_cmd_import_import(struct otp *otp, char *file)
{
	char existing[OTP_KEYS_LENGTH];
	struct otp_value val;
	int err;
	int fd;
	int i;

	memset(&val, 0x0, sizeof(val));

	if (strcmp(file, "-")) {
		fd = open(file, O_RDONLY);
		if (fd == -1) {
			otp_error(otp, "Faild to open file: %s error: %s\n",
				  file, strerror(errno));
			return -ENOENT;
		}
	} else {
		fd = 0;		/* Console input */
	}

	if (fd)
		err = otp_cmd_import_file(otp, fd, file, &val);
	else
		err = otp_cmd_import_stdin(otp, &val);

	if (fd != 0)
		close(fd);

	if (err) {
		otp_value_free(&val);
		return -EINVAL;
	}

	err = otp_file_read(otp, OTP_KEYS_OFFSET, OTP_KEYS_LENGTH, existing);
	if (err) {
		otp_error(otp, "Failed to read: %d bytes from file %s\n",
			  OTP_KEYS_LENGTH, otp->device);
		otp_value_free(&val);
		return err;
	}

	for (i = 0; i < OTP_TBBR_KEYS_LENGTH; ++i)
		val.raw[i] |= existing[i];

	if (!otp->no_randomize) {
		srand(time(NULL));
		for (i = 0; i < OTP_TBBR_HUK_LENGTH; ++i)
			val.raw[i + OTP_TBBR_HUK_OFFSET] = rand() % 255;
	}

	otp_check_confirm(otp);

	err = otp_file_write(otp, OTP_KEYS_OFFSET, OTP_TBBR_KEYS_LENGTH, val.raw);
	if (err) {
		otp_error(otp, "Failed to write: %d bytes in file: %s\n",
			  OTP_TBBR_KEYS_LENGTH, otp->device);
		otp_value_free(&val);
		return -EINVAL;
	}

	otp_value_free(&val);
	return 0;
}

static int otp_cmd_import(struct otp *otp, int argc, char **argv)
{
	char *file;

	/* skip the command */
	argv++;
	argc -= 1;

next_arg:
	if (*argv == NULL) {
		otp_error(otp, "Invalid format\n");
		otp_print_help();
		return -EINVAL;
	}

	if (strcmp(*argv, "--no-randomize-huk") == 0) {
		otp->no_randomize = true;
		NEXT_ARG();
		goto next_arg;
	} else {
		file = *argv;
		return otp_cmd_import_import(otp, file);
	}

	return 0;
}

static int otp_region_get(struct otp *otp, uint32_t index,
			  struct otp_region *region)
{
	uint8_t write_protect;
	uint32_t offset;
	int err;

	offset = OTP_REGION_ADDR_OFFSET + index * 4;
	err = otp_file_read(otp, offset, 2, (char *)&region->start);
	if (err) {
		otp_error(otp, "Failed to read addr: %d(0x%x)\n",
			  offset, offset);
		return err;
	}

	if (otp->props->tz_aware) {
		region->non_secure = !!(region->start & BIT(15));
		region->start &= ~BIT(15);
	}

	offset += 2;
	err = otp_file_read(otp, offset, 2, (char *)&region->end);
	if (err) {
		otp_error(otp, "Failed to read addr: %d(0x%x)\n",
			  offset, offset);
		return err;
	}

	err = otp_file_read(otp, OTP_REGION_WRITE_PROTECT_OFFSET, 1,
			    (char *)&write_protect);
	if (err) {
		otp_error(otp, "Failed to read addr: %d(0x%x)\n",
			  OTP_REGION_WRITE_PROTECT_OFFSET,
			  OTP_REGION_WRITE_PROTECT_OFFSET);
		return err;
	}
	region->write_protect = !!(BIT(index) & write_protect);

	return 0;
}

static int otp_region_get_check(struct otp *otp, uint32_t index, struct otp_region *region,
				bool require_blank)
{
	int err;

	if (index >= OTP_REGION_LENGTH) {
		otp_error(otp, "Region index can't be bigger than: %d\n",
			  OTP_REGION_LENGTH - 1);
		return -EINVAL;
	}

	err = otp_region_get(otp, index, region);
	if (err) {
		otp_error(otp, "Failed to read region: %d\n", index);
		return -EIO;
	}

	if (require_blank && region->start != 0 && region->end != 0) {
		otp_error(otp, "Region index %d is already set\n", index);
		return -EINVAL;
	}

	return 0;
}

static int otp_region_set(struct otp *otp, uint32_t index,
			  struct otp_region *region, bool wp)
{
	char write_protect;
	uint32_t offset;
	uint16_t start;
	int err;

	/* start, handle tz */
	start = region->start;

	if (otp->props->tz_aware) {
		if (region->non_secure)
			start |= BIT(15);
	} else {
		/* Mask size */
		start &= (otp->size - 1);
	}

	offset = OTP_REGION_ADDR_OFFSET + index * 4;
	err = otp_file_update(otp, offset, 2, &start);
	if (err) {
		otp_error(otp, "Failed to update addr: %d(0x%x)\n",
			  offset, offset);
		return err;
	}

	offset += 2;
	err = otp_file_update(otp, offset, 2, &region->end);
	if (err) {
		otp_error(otp, "Failed to update addr: %d(0x%x)\n",
			  offset, offset);
		return err;
	}

	if (wp) {
		err = otp_file_read(otp, OTP_REGION_WRITE_PROTECT_OFFSET, 1,
				    &write_protect);
		if (err) {
			otp_error(otp, "Failed to read addr: %d(0x%x)\n",
				  OTP_REGION_WRITE_PROTECT_OFFSET,
				  OTP_REGION_WRITE_PROTECT_OFFSET);
			return err;
		}

		write_protect |= BIT(index);
		err = otp_file_update(otp, OTP_REGION_WRITE_PROTECT_OFFSET, 1,
				      &write_protect);
		if (err) {
			otp_error(otp, "Failed to update addr: %d(0x%x)\n",
				  OTP_REGION_WRITE_PROTECT_OFFSET,
				  OTP_REGION_WRITE_PROTECT_OFFSET);
			return err;
		}

		otp_debug(otp, "Region %d was marked as write-protected\n", index);
	}

	return 0;
}

static int otp_region_default(struct otp *otp)
{
	struct otp_region region;
	int err;
	int i;

	for (i = 0; i < OTP_REGION_LENGTH; ++i) {
		err = otp_region_get_check(otp, i, &region, true);
		if (err)
			return err;

		err = otp_region_set(otp, i, &otp_regions[i], false);
		if (err) {
			otp_error(otp, "Failed to define region %d.\n", i);
			break;
		}
	}

	return err;
}

static int otp_cmd_region_show(struct otp *otp)
{
	struct otp_region region;
	int err;
	int i;

	for (i = 0; i < OTP_REGION_LENGTH; ++i) {
		err = otp_region_get(otp, i, &region);
		if (err) {
			otp_error(otp, "Failed to read region: %d\n", i);
			return -EIO;
		}

		if (!otp->props->tz_aware) {
			otp_printf(otp,
				   "Region: %d, start: 0x%04x, end: 0x%04x, write_protect: %d\n",
				   i, region.start, region.end, region.write_protect);
		} else {
			otp_printf(otp,
				   "Region: %d, start: 0x%04x, end: 0x%04x, write_protect: %d, non_secure: %d\n",
				   i, region.start, region.end, region.write_protect, region.non_secure);
		}
	}

	return 0;
}

static int otp_cmd_region_write_protect(struct otp *otp, uint32_t index)
{
	struct otp_region region;
	int err;

	err = otp_region_get_check(otp, index, &region, false);
	if (err)
		return err;

	return otp_region_set(otp, index, &otp_regions[index], true);
}

static int otp_cmd_region_non_secure(struct otp *otp, uint32_t index)
{
	struct otp_region region;
	int err;

	err = otp_region_get_check(otp, index, &region, false);
	if (err)
		return err;

	/* Flip NS */
	region.non_secure = true;

	return otp_region_set(otp, index, &region, false);
}

static int otp_cmd_region(struct otp *otp, int argc, char **argv)
{
	uint32_t region;

	/* skip the command */
	argv++;
	argc -= 1;
	if (*argv == NULL) {
		otp_error(otp, "Invalid format\n");
		otp_print_help();
		return -EINVAL;
	}

	if (strcmp(*argv, "show") == 0) {
		return otp_cmd_region_show(otp);
	} else if (strcmp(*argv, "write-protect") == 0) {
		NEXT_ARG();
		region = strtoul(*argv, NULL, 0);
		return otp_cmd_region_write_protect(otp, region);
	} else if (strcmp(*argv, "non-secure") == 0) {
		NEXT_ARG();
		region = strtoul(*argv, NULL, 0);
		return otp_cmd_region_non_secure(otp, region);
	} else {
		otp_error(otp, "Unknown field: %s\n", *argv);
		otp_print_help();
		return -EINVAL;
	}

	return 0;
}

static int otp_parse_ethaddr(struct otp *otp, char *input, char *ethaddr)
{
	int i;

	/* It needs have the following format:
	 * 01:02:03:04:05:06
	 */
	if (strlen(input) != 17)
		return -EINVAL;

	for (i = 0; i < ETH_ALEN; ++i) {
		sscanf(input, "%2hhx", &ethaddr[ETH_ALEN - i - 1]);
		input += 3;
	}

	return 0;
}

static int otp_init(struct otp *otp, char *pcb,
		    char *ethaddr, char *ethaddr_count,
		    bool pcb_v2)
{
	struct otp_value pcb_val, ethaddr_val, ethaddr_count_val;
	uint32_t pcb_offset, ethaddr_offset, ethaddr_count_offset;
	struct otp_tag pcb_tag, ethaddr_tag, ethaddr_count_tag;
	char new_ethaddr[ETH_ALEN];
	struct timespec ts;
	uint16_t partid;
	int err;
	int i;

	err = otp_file_read(otp, OTP_PARTID_OFFSET, 2, (char*) &partid);
	if (err) {
		otp_error(otp, "Failed to read offset 0x%0x\n",
			  OTP_PARTID_OFFSET);
		return err;
	}

	if (partid != 0 && otp->chip_id != partid && !otp->force_chip_id) {
		otp_error(otp, "Part id doesn't match (%04x != %04x)\n", partid, otp->chip_id);
		return -EINVAL;
	}

	if (strcmp(ethaddr, "random-ethaddr") == 0) {
		timespec_get(&ts, TIME_UTC);
		srand(ts.tv_nsec);
		for (i = 0; i < ETH_ALEN; ++i)
			new_ethaddr[i] = rand() % 255;
		new_ethaddr[5] |= 0x02;
		new_ethaddr[5] &= 0xfe;
		new_ethaddr[0] &= 0x00;
	} else {
		if (otp_parse_ethaddr(otp, ethaddr, new_ethaddr)) {
			otp_error(otp, "Failed to parse ethaddr\n");
			return -EINVAL;
		}
	}

	if (pcb_v2 == false) {
		if (otp_value_format(otp, otp_value_type_decimal, pcb, strlen(pcb),
				     &pcb_val)) {
			otp_error(otp, "Failed to format pcb\n");
			return -EINVAL;
		}
	} else {
		if (otp_value_format(otp, otp_value_type_ascii, pcb, strlen(pcb),
				     &pcb_val)) {
			otp_error(otp, "Failed to format pcb_v2\n");
			return -EINVAL;
		}
	}

	if (otp_value_format(otp, otp_value_type_ascii, new_ethaddr, ETH_ALEN,
			     &ethaddr_val)) {
		otp_error(otp, "Failed to format ethaddr\n");
		return -EINVAL;
	}

	if (otp_value_format(otp, otp_value_type_decimal, ethaddr_count, strlen(ethaddr_count),
			     &ethaddr_count_val)) {
		otp_error(otp, "Failed to format ethaddr_count\n");
		return -EINVAL;
	}

	if (pcb_v2 == false) {
		if (otp_tag_can_write(otp, otp_tag_type_pcb, &pcb_val, &pcb_tag, &pcb_offset,
				      OTP_TAG_OFFSET)) {
			otp_error(otp, "Failed check to set pcb\n");
			return -EINVAL;
		}
	} else {
		if (otp_tag_can_write(otp, otp_tag_type_pcb_2, &pcb_val, &pcb_tag, &pcb_offset,
				      OTP_TAG_OFFSET)) {
			otp_error(otp, "Failed check to set pcb_v2\n");
			return -EINVAL;
		}
	}

	if (otp_tag_can_write(otp, otp_tag_type_ethaddr, &ethaddr_val, &ethaddr_tag, &ethaddr_offset,
			      pcb_offset + OTP_TAG_ENTRY_LENGTH)) {
		otp_error(otp, "Failed check to set ethaddr\n");
		return -EINVAL;
	}

	if (otp_tag_can_write(otp, otp_tag_type_ethaddr_count, &ethaddr_count_val, &ethaddr_count_tag,
			      &ethaddr_count_offset, ethaddr_offset + OTP_TAG_ENTRY_LENGTH)) {
		otp_error(otp, "Failed check to set ethaddr_count\n");
		return -EINVAL;
	}

	/* Check only here, so the other checks can be skipped */
	otp_check_confirm(otp);
	otp->no_confirm = true;

	if (otp_tag_write(otp, pcb_offset, &pcb_val, &pcb_tag) ||
	    otp_tag_write(otp, ethaddr_offset, &ethaddr_val, &ethaddr_tag) ||
	    otp_tag_write(otp, ethaddr_count_offset, &ethaddr_count_val, &ethaddr_count_tag)) {
		otp_error(otp, "Failed to set tags\n");
		return -EINVAL;
	}

	otp_value_free(&pcb_val);
	otp_value_free(&ethaddr_val);
	otp_value_free(&ethaddr_count_val);

	return otp_region_default(otp);
}

static int otp_cmd_init(struct otp *otp, int argc, char **argv)
{
	char *ethaddr_count = NULL;
	char *ethaddr = NULL;
	char *pcb = NULL;
	bool pcb_v2 = false;

	/* skip the command */
	argv++;
	argc -= 1;

next_arg:
	if (*argv == NULL) {
		goto out;
	}

	if (strcmp(*argv, "pcb") == 0) {
		NEXT_ARG();
		pcb = *argv;
		NEXT_ARG_OPT();
		goto next_arg;
	} if (strcmp(*argv, "pcb_2") == 0) {
		NEXT_ARG();
		pcb = *argv;
		pcb_v2 = true;
		NEXT_ARG_OPT();
		goto next_arg;
	} if (strcmp(*argv, "ethaddr") == 0) {
		NEXT_ARG();
		ethaddr = *argv;
		NEXT_ARG_OPT();
		goto next_arg;
	} if (strcmp(*argv, "ethaddr_count") == 0) {
		NEXT_ARG();
		ethaddr_count = *argv;
		NEXT_ARG_OPT();
		goto next_arg;
	} else {
		otp_error(otp, "Unknown field: %s\n", *argv);
		otp_print_help();
		return -EINVAL;
	}

out:
	if (!pcb || !ethaddr || !ethaddr_count) {
		otp_error(otp, "Not all fields were set\n");
		return -EINVAL;
	}

	return otp_init(otp, pcb, ethaddr, ethaddr_count, pcb_v2);
}

static struct otp_cmd commands[] =
{
	{"field", otp_cmd_field},
	{"addr", otp_cmd_addr},
	{"tag", otp_cmd_tag},
	{"nvcnt", otp_cmd_nvcnt},
	{"import-keys", otp_cmd_import},
	{"region", otp_cmd_region},
	{"init", otp_cmd_init},
};

static struct otp_cmd *command_lookup(char *cmd)
{
	int i;

	for(i = 0; i < ARRAY_SIZE(commands); ++i) {
		if(!strcmp(cmd, commands[i].name))
			return &commands[i];
	}

	return NULL;
}

static struct otp_cmd *command_lookup_and_validate(int argc,
						   char **argv)
{
	return command_lookup(argv[0]);
}

static int otp_device_check(struct otp *otp)
{
	struct otp_field *f_chip_id;
	uint16_t chip_id;
	int i;

	f_chip_id = otp_field_get(otp, "PARTID");
	assert(f_chip_id);
	otp_field_read(otp, f_chip_id, (void*) &chip_id);
	if (otp->chip_id == 0) {
		if (chip_id == 0) {
			otp_error(otp, "Chip id not present in OTP - use --chip-id id\n");
			return -EINVAL;
		}
		/* Use chipid from OTP */
		otp->chip_id = chip_id;
	}
	if (chip_id && chip_id != otp->chip_id) {
		if (!otp->force_chip_id) {
			otp_error(otp, "OTP chip id %04x differs from --chip-id arg - "
				  "use --chip-id-force option\n", chip_id);
			return -EINVAL;
		}
	}

	for (i = 0; i < ARRAY_SIZE(chips); i++) {
		unsigned int chip_id_base, variant;

		/* get base and variant */
		chip_id_base = otp->chip_id & ~0xF;
		variant = otp->chip_id & 0xF;

		if (chips[i].chip_id_base == chip_id_base &&
		    chips[i].chip_bitmask & BIT(variant))
			break;
	}

	if (i < ARRAY_SIZE(chips)) {
		otp->props = &chips[i];
	} else {
		otp_error(otp, "Chip id %04x not known\n", otp->chip_id);
		return -ENOENT;
	}

	/* Sanity check size */
	if (otp->size != otp->props->size) {
		otp_error(otp, "OTP size mismatch - %s chip has %zd bytes, but we "
			  "have %zd\n", otp->props->name, otp->props->size, otp->size);
		return -EINVAL;
	}

	return 0;
}

static const struct option options[] =
{
	{.name = "help",		.has_arg = no_argument,		.val = 'h'},
	{.name = "version",		.has_arg = no_argument,		.val = 'v'},
	{.name = "verbose",		.has_arg = no_argument,		.val = 'e'},
	{.name = "device",		.has_arg = required_argument,	.val = 'd'},
	{.name = "chip-id",		.has_arg = required_argument,	.val = 'i'},
	{.name = "chip-id-force",	.has_arg = no_argument,		.val = 'f'},
	{.name = "no-confirm",		.has_arg = no_argument,		.val = 'n'},
	{.name = "no-randomize-huk",	.has_arg = no_argument,		.val = 'r'},
	{.name = "merge",		.has_arg = no_argument,		.val = 'm'},
	{0}
};

int main (int argc, char **argv)
{
	bool device_set = false;
	struct otp_cmd *cmd;
	struct stat statb;
	struct otp otp;
	int f, err;

	memset(&otp, 0, sizeof(otp));

	while (EOF != (f = getopt_long(argc, argv, "hved:i:fnrm", options, NULL))) {
		switch (f) {
		case 'h':
			otp_print_help();
			return 0;
		case 'v':
			otp_print_version();
			return 0;
		case 'e':
			otp.verbose = true;
			break;
		case 'd':
			otp.device = optarg;
			device_set = true;
			break;
		case 'i':
			otp.chip_id = strtol(optarg, NULL, 16);
			break;
		case 'f':
			otp.force_chip_id = true;
			break;
		case 'n':
			otp.no_confirm = true;
			break;
		case 'r':
			otp.no_randomize = true;
			break;
		case 'm':
			otp.merge = true;
			break;
		}
	}

	if (!device_set) {
		printf("It is required to pass -d option\n");
		return -EINVAL;
	}

	if (stat(otp.device, &statb) != 0) {
		printf("Unable to access %s: %s\n", otp.device, strerror(errno));
		return -EINVAL;
	}

	otp.size = statb.st_size;
	if (otp.size < OTP_TAG_OFFSET) {
		printf("OTP file too small, must be minimum %d bytes\n", OTP_TAG_OFFSET);
		return -EINVAL;
	}

	/* Check chipid */
	err = otp_device_check(&otp);
	if (err)
		return err;
	otp_debug(&otp, "Using %s OTP chip\n", otp.props->name);

	/* Update last region end */
	otp_regions[ARRAY_SIZE(otp_regions) - 1].end = otp.size;

	argc -= optind;
	argv += optind;

	if (argc == 0) {
		otp_print_help();
		return -EINVAL;
	}

	cmd = command_lookup_and_validate(argc, argv);
	if (!cmd)
		return -EINVAL;

	return cmd->func(&otp, argc, argv);
}
