// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/unaligned.h>

#include "dm-crypt-root.h"

int rootcrypt_parse_record(const void *data, size_t size, const uuid_t *partuuid,
			   struct rootcrypt_record *record)
{
	const struct dm_rootcrypt_record *header = data;
	u32 blob_size, pcr_mask;
	size_t signed_size;

	if (size < sizeof(*header) || size > DM_ROOTCRYPT_MAX_RECORD_SIZE)
		return -EINVAL;
	if (memcmp(header->magic, DM_ROOTCRYPT_MAGIC, sizeof(header->magic)) ||
	    get_unaligned_le32(&header->version) != DM_ROOTCRYPT_VERSION ||
	    get_unaligned_le32(&header->reserved))
		return -EINVAL;
	if (memcmp(header->partuuid, partuuid->b, sizeof(header->partuuid)))
		return -EKEYREJECTED;

	pcr_mask = get_unaligned_le32(&header->pcr_mask);
	if (!pcr_mask || (pcr_mask & ~DM_ROOTCRYPT_PCR_MASK))
		return -EINVAL;
	blob_size = get_unaligned_le32(&header->blob_size);
	if (!blob_size || blob_size > DM_ROOTCRYPT_MAX_BLOB_SIZE)
		return -EINVAL;
	signed_size = sizeof(*header) + blob_size;
	if (signed_size >= size)
		return -EINVAL;

	*record = (struct rootcrypt_record) {
		.blob = (const u8 *)data + sizeof(*header),
		.blob_size = blob_size,
		.signature = (const u8 *)data + signed_size,
		.signature_size = size - signed_size,
		.signed_size = signed_size,
		.pcr_mask = pcr_mask,
	};
	return 0;
}
