/*
 * guid.c
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("guid");

void guid_create_random(struct guid *guid)
{
	random_getbytes((uint8_t *)guid, sizeof(struct guid));
}

void guid_create_ubicom(struct guid *guid, uint8_t mac_addr[6], uint8_t sequence)
{
	uint8_t buf[22];
	memset(buf, 0, 16);
	memcpy(buf + 16, mac_addr, 6);
	buf[9] = sequence;

	md5_digest_t md5;
	md5_compute_digest(&md5, buf, 22);
	memcpy(guid, md5.u8, 16);

	guid->time_low = byteswap_be_to_cpu_u32(guid->time_low);
	guid->time_mid = byteswap_be_to_cpu_u16(guid->time_mid);
	guid->time_hi_and_version = byteswap_be_to_cpu_u16(guid->time_hi_and_version);

	guid->time_hi_and_version &= 0x0FFF;
	guid->time_hi_and_version |= (3 << 12);

	guid->clock_seq_hi_and_reserved &= 0x3F;
	guid->clock_seq_hi_and_reserved |= 0x80;
}

static bool guide_read_string_internal(struct guid *guid, const char *str)
{
	bool success = true;
	const char *ptr = str;
	char *stop;

	guid->time_low = (uint32_t)strtoul(ptr, &stop, 16); ptr += 8;
	success &= (ptr == stop) && (*ptr == '-'); ptr++;

	guid->time_mid = (uint16_t)strtoul(ptr, &stop, 16); ptr += 4;
	success &= (ptr == stop) && (*ptr == '-'); ptr++;

	guid->time_hi_and_version = (uint16_t)strtoul(ptr, &stop, 16); ptr += 4;
	success &= (ptr == stop) && (*ptr == '-'); ptr++;

	uint16_t tmp = (uint16_t)strtoul(ptr, &stop, 16); ptr += 4;
	guid->clock_seq_hi_and_reserved = (uint8_t)(tmp >> 8);
	guid->clock_seq_low = (uint8_t)(tmp >> 0);
	success &= (ptr == stop) && (*ptr == '-'); ptr++;

	for (uint8_t i = 0; i < 6; i++) {
		char buffer[3];
		buffer[0] = *ptr++;
		buffer[1] = *ptr++;
		buffer[2] = 0;

		guid->node[i] = (uint8_t)strtoul(buffer, &stop, 16);
		success &= (buffer + 2 == stop);
	}

	return success;
}

bool guid_read_string(struct guid *guid, const char *str)
{
	if (strlen(str) != 36) {
		return false;
	}

	return guide_read_string_internal(guid, str);
}

bool guid_read_netbuf(struct guid *guid, struct netbuf *nb)
{
	if (!netbuf_fwd_check_space(nb, 36)) {
		return false;
	}

	char str[37];
	netbuf_fwd_read(nb, str, 36);
	netbuf_retreat_pos(nb, 36);
	str[36] = 0;

	return guide_read_string_internal(guid, str);
}

void guid_write_string(struct guid *guid, char *str)
{
	sprintf_custom(str, str + 37,
		"%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		guid->time_low, guid->time_mid, guid->time_hi_and_version,
		guid->clock_seq_hi_and_reserved, guid->clock_seq_low,
		guid->node[0], guid->node[1], guid->node[2],
		guid->node[3], guid->node[4], guid->node[5]
	);
}

bool guid_write_netbuf(struct guid *guid, struct netbuf *nb)
{
	return netbuf_sprintf(nb,
		"%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		guid->time_low, guid->time_mid, guid->time_hi_and_version,
		guid->clock_seq_hi_and_reserved, guid->clock_seq_low,
		guid->node[0], guid->node[1], guid->node[2],
		guid->node[3], guid->node[4], guid->node[5]
	);
}

bool guid_is_zero(struct guid *guid)
{
	uint32_t *data = (uint32_t *)guid;
	return (data[0] == 0) && (data[1] == 0) && (data[2] == 0) && (data[3] == 0);
}

bool guid_is_match(struct guid *guid_a, struct guid *guid_b)
{
	uint32_t *data_a = (uint32_t *)guid_a;
	uint32_t *data_b = (uint32_t *)guid_b;
	return (data_a[0] == data_b[0]) && (data_a[1] == data_b[1]) && (data_a[2] == data_b[2]) && (data_a[3] == data_b[3]);
}

int guid_compare(struct guid *guid_a, struct guid *guid_b)
{
	if (guid_a->time_low != guid_b->time_low) {
		return (guid_a->time_low > guid_b->time_low) ? 1 : -1;
	}
	if (guid_a->time_mid != guid_b->time_mid) {
		return (guid_a->time_mid > guid_b->time_mid) ? 1 : -1;
	}
	if (guid_a->time_hi_and_version != guid_b->time_hi_and_version) {
		return (guid_a->time_hi_and_version > guid_b->time_hi_and_version) ? 1 : -1;
	}
	return memcmp((uint8_t *)guid_a + 8, (uint8_t *)guid_b + 8, 8);
}
