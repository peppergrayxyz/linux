/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_DM_ROOTCRYPT_H
#define _UAPI_LINUX_DM_ROOTCRYPT_H

#include <linux/types.h>

#define DM_ROOTCRYPT_MAGIC		"DMROOTK"
#define DM_ROOTCRYPT_VERSION		1
#define DM_ROOTCRYPT_MAX_RECORD_SIZE	4096
#define DM_ROOTCRYPT_MAX_BLOB_SIZE	512
#define DM_ROOTCRYPT_PCR_MASK		0x00ffffffU
#define DM_ROOTCRYPT_EFI_GUID		"572e6a16-7a6b-4c2f-9e78-41a37c05290b"

/*
 * Followed by blob_size bytes of the native TPM2 trusted-key blob, then a
 * detached DER PKCS#7 signature over this header and the blob. UUID bytes
 * are in RFC 4122 order. Version 1 fixes AES-256-XTS, 512-byte sectors,
 * partition offset zero, and the SHA-256 PCR bank.
 */
struct dm_rootcrypt_record {
	__u8 magic[8];
	__le32 version;
	__le32 pcr_mask;
	__u8 partuuid[16];
	__le32 blob_size;
	__le32 reserved;
};

#endif /* _UAPI_LINUX_DM_ROOTCRYPT_H */
