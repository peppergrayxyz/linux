// SPDX-License-Identifier: GPL-2.0-only
/* Activate a TPM-protected, fixed-format root partition before userspace. */
#include <linux/blkdev.h>
#include <linux/cred.h>
#include <linux/delay.h>
#include <linux/device-mapper.h>
#include <linux/dm-rootcrypt.h>
#include <linux/efi.h>
#include <linux/file.h>
#include <linux/hex.h>
#include <linux/key.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/tpm.h>
#include <linux/verification.h>
#include <keys/trusted-type.h>

#include "dm-crypt-root.h"

/* trusted-type.h defines pr_fmt. */
#undef pr_fmt
#define pr_fmt(fmt) "rootcrypt: " fmt

#define ROOTCRYPT_WAIT_MS 30000
#define ROOTCRYPT_KEY_NAME "rootcrypt"

enum rootcrypt_option {
	ROOTCRYPT_DEVICE,
	ROOTCRYPT_KEY,
	ROOTCRYPT_TPM,
	ROOTCRYPT_TOKEN,
};

static unsigned long rootcrypt_options __initdata;
static int rootcrypt_parse_error __initdata;
static uuid_t rootcrypt_partuuid __initdata;

static bool __init rootcrypt_option(enum rootcrypt_option option)
{
	if (test_and_set_bit(option, &rootcrypt_options)) {
		rootcrypt_parse_error = -EINVAL;
		return false;
	}
	return true;
}

static int __init rootcrypt_device_setup(char *str)
{
	if (rootcrypt_option(ROOTCRYPT_DEVICE) &&
	    (strncmp(str, "PARTUUID=", 9) || strlen(str + 9) != UUID_STRING_LEN ||
	     uuid_parse(str + 9, &rootcrypt_partuuid)))
		rootcrypt_parse_error = -EINVAL;
	return 1;
}
__setup("rootcrypt=", rootcrypt_device_setup);

static int __init rootcrypt_key_setup(char *str)
{
	if (rootcrypt_option(ROOTCRYPT_KEY) && strcmp(str, "tpm2"))
		rootcrypt_parse_error = -EINVAL;
	return 1;
}
__setup("rootcrypt.key=", rootcrypt_key_setup);

static int __init rootcrypt_tpm_setup(char *str)
{
	if (rootcrypt_option(ROOTCRYPT_TPM) && strcmp(str, "0"))
		rootcrypt_parse_error = -EINVAL;
	return 1;
}
__setup("rootcrypt.tpm=", rootcrypt_tpm_setup);

static int __init rootcrypt_token_setup(char *str)
{
	if (rootcrypt_option(ROOTCRYPT_TOKEN) && strcmp(str, "0"))
		rootcrypt_parse_error = -EINVAL;
	return 1;
}
__setup("rootcrypt.token=", rootcrypt_token_setup);

static int __init rootcrypt_wait_for_devices(const char *name, dev_t *dev)
{
	unsigned long timeout = jiffies + msecs_to_jiffies(ROOTCRYPT_WAIT_MS);
	struct tpm_chip *chip;
	bool disk_ready, tpm_ready;

	do {
		disk_ready = !early_lookup_bdev(name, dev);
		tpm_ready = false;
		chip = tpm_default_chip();
		if (chip) {
			tpm_ready = chip->dev_num == 0 && tpm_is_tpm2(chip) > 0;
			put_device(&chip->dev);
			if (!tpm_ready)
				return -ENODEV;
		}
		if (disk_ready && tpm_ready)
			return 0;
		msleep(20);
	} while (time_before(jiffies, timeout));

	pr_err("timed out waiting for backing partition or TPM2 chip 0\n");
	return -ETIMEDOUT;
}

static int __init rootcrypt_read_record(void **data, size_t *len)
{
	efi_guid_t vendor = EFI_GUID(0x572e6a16, 0x7a6b, 0x4c2f,
				   0x9e, 0x78, 0x41, 0xa3, 0x7c, 0x05, 0x29, 0x0b);
	char name[64];
	efi_char16_t efi_name[64];
	unsigned long size = DM_ROOTCRYPT_MAX_RECORD_SIZE;
	efi_status_t status;
	void *buffer;
	u32 attributes;
	int i, ret;

	if (!efi_enabled(EFI_BOOT) || !efivar_is_available())
		return -ENODEV;
	snprintf(name, sizeof(name), "LinuxRootKey-%pUb-0", &rootcrypt_partuuid);
	for (i = 0; i <= strlen(name); i++)
		efi_name[i] = name[i];

	buffer = kmalloc(size, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;
	ret = efivar_lock();
	if (ret)
		goto free;
	status = efivar_get_variable(efi_name, &vendor, &attributes, &size, buffer);
	efivar_unlock();
	if (status != EFI_SUCCESS) {
		ret = efi_status_to_err(status);
		goto free;
	}
	if (!(attributes & EFI_VARIABLE_RUNTIME_ACCESS) ||
	    size > DM_ROOTCRYPT_MAX_RECORD_SIZE) {
		ret = -EINVAL;
		goto free;
	}

	*data = buffer;
	*len = size;
	return 0;
free:
	kfree(buffer);
	return ret;
}

static int __init rootcrypt_create_mapping(dev_t dev, sector_t sectors,
					  const struct rootcrypt_record *record)
{
	struct dm_target_spec spec = { .length = sectors };
	struct dm_target_spec *specs[] = { &spec };
	struct dm_ioctl dmi = {
		.target_count = 1,
		.flags = DM_PERSISTENT_DEV_FLAG,
		.dev = 0,
	};
	const struct cred *old;
	struct cred *cred;
	struct key *keyring;
	key_ref_t key;
	char params[128], *args[] = { params };
	char *payload, *end;
	int ret;

	/* Only the temporary mapping-creation credentials possess this keyring. */
	cred = prepare_kernel_cred(current);
	if (!cred)
		return -ENOMEM;
	keyring = keyring_alloc(".rootcrypt", GLOBAL_ROOT_UID, GLOBAL_ROOT_GID,
				cred, KEY_POS_ALL, KEY_ALLOC_NOT_IN_QUOTA, NULL, NULL);
	if (IS_ERR(keyring)) {
		ret = PTR_ERR(keyring);
		goto put_creds;
	}
	cred->session_keyring = keyring;

	payload = kmalloc(5 + record->blob_size * 2 + 32, GFP_KERNEL);
	if (!payload) {
		ret = -ENOMEM;
		goto put_creds;
	}
	memcpy(payload, "load ", 5);
	end = bin2hex(payload + 5, record->blob, record->blob_size);
	snprintf(end, 32, " pcrs=sha256:%06x", record->pcr_mask);

	old = override_creds(cred);
	key = key_create_or_update(make_key_ref(keyring, true), "trusted",
				   ROOTCRYPT_KEY_NAME, payload, strlen(payload),
				   KEY_POS_ALL, KEY_ALLOC_NOT_IN_QUOTA);
	kfree_sensitive(payload);
	if (IS_ERR(key)) {
		ret = PTR_ERR(key);
		goto revert;
	}

	strscpy(dmi.name, "rootcrypt");
	strscpy(spec.target_type, "crypt");
	snprintf(params, sizeof(params),
		 "aes-xts-plain64 :64:trusted:%s 0 %u:%u 0",
		 ROOTCRYPT_KEY_NAME, MAJOR(dev), MINOR(dev));
	ret = dm_early_create(&dmi, specs, args);
	key_revoke(key_ref_to_ptr(key));
	key_ref_put(key);
revert:
	revert_creds(old);
put_creds:
	put_cred(cred);
	return ret;
}

int __init dm_crypt_root_setup(const char *root)
{
	struct rootcrypt_record record;
	struct file *backing;
	char device[48];
	void *data = NULL;
	size_t size;
	sector_t sectors;
	dev_t dev;
	int ret;

	if (!rootcrypt_options)
		return 0;
	if (rootcrypt_parse_error ||
	    !test_bit(ROOTCRYPT_DEVICE, &rootcrypt_options) ||
	    !test_bit(ROOTCRYPT_KEY, &rootcrypt_options) ||
	    strcmp(root, "/dev/dm-0"))
		return -EINVAL;

	snprintf(device, sizeof(device), "PARTUUID=%pUb", &rootcrypt_partuuid);
	ret = rootcrypt_wait_for_devices(device, &dev);
	if (ret)
		return ret;
	ret = trusted_key_init_tpm();
	if (ret)
		return ret;
	ret = rootcrypt_read_record(&data, &size);
	if (ret)
		return ret;
	ret = rootcrypt_parse_record(data, size, &rootcrypt_partuuid, &record);
	if (ret)
		goto free;
	/* Only compiled-in certificates may authorize an enrollment. */
	ret = verify_pkcs7_signature(data, record.signed_size, record.signature,
				     record.signature_size, NULL,
				     VERIFYING_FIRMWARE_SIGNATURE, NULL, NULL);
	if (ret)
		goto free;

	backing = bdev_file_open_by_dev(dev, BLK_OPEN_READ, NULL, NULL);
	if (IS_ERR(backing)) {
		ret = PTR_ERR(backing);
		goto free;
	}
	sectors = bdev_nr_sectors(file_bdev(backing));
	if (!sectors)
		ret = -EINVAL;
	else
		ret = rootcrypt_create_mapping(dev, sectors, &record);
	fput(backing);
free:
	kfree(data);
	if (!ret)
		pr_info("TPM2 root mapping ready on /dev/dm-0\n");
	return ret;
}

MODULE_IMPORT_NS("EFIVAR");
