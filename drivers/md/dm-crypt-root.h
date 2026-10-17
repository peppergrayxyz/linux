/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _DM_CRYPT_ROOT_H
#define _DM_CRYPT_ROOT_H

#include <linux/uuid.h>
#include <uapi/linux/dm-rootcrypt.h>

struct rootcrypt_record {
	const u8 *blob;
	const u8 *signature;
	size_t blob_size;
	size_t signed_size;
	size_t signature_size;
	u32 pcr_mask;
};

int rootcrypt_parse_record(const void *data, size_t size, const uuid_t *partuuid,
			   struct rootcrypt_record *record);

#endif /* _DM_CRYPT_ROOT_H */
