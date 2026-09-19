// SPDX-License-Identifier: GPL-2.0-only
#include <kunit/test.h>
#include <linux/unaligned.h>

#include "dm-crypt-root.h"

#define TEST_BLOB_SIZE 32
#define TEST_RECORD_SIZE (sizeof(struct dm_rootcrypt_record) + TEST_BLOB_SIZE + 1)

static const uuid_t test_uuid = UUID_INIT(0x12345678, 0x1234, 0x5678,
					0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78);

static void rootcrypt_test_record(u8 *buffer)
{
	struct dm_rootcrypt_record *header = (void *)buffer;

	memset(buffer, 0, TEST_RECORD_SIZE);
	memcpy(header->magic, DM_ROOTCRYPT_MAGIC, sizeof(header->magic));
	put_unaligned_le32(DM_ROOTCRYPT_VERSION, &header->version);
	put_unaligned_le32(BIT(7), &header->pcr_mask);
	memcpy(header->partuuid, test_uuid.b, sizeof(header->partuuid));
	put_unaligned_le32(TEST_BLOB_SIZE, &header->blob_size);
}

static void rootcrypt_valid_record(struct kunit *test)
{
	u8 buffer[TEST_RECORD_SIZE + 1];
	struct rootcrypt_record record;
	int ret;

	/* Firmware data need not have native integer alignment. */
	rootcrypt_test_record(buffer + 1);
	ret = rootcrypt_parse_record(buffer + 1, TEST_RECORD_SIZE, &test_uuid, &record);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, record.blob_size, (size_t)TEST_BLOB_SIZE);
	KUNIT_EXPECT_EQ(test, record.signature_size, (size_t)1);
	KUNIT_EXPECT_EQ(test, record.pcr_mask, (u32)BIT(7));
	KUNIT_EXPECT_PTR_EQ(test, record.blob,
			   buffer + 1 + sizeof(struct dm_rootcrypt_record));
	KUNIT_EXPECT_PTR_EQ(test, record.signature, buffer + TEST_RECORD_SIZE);
}

static void rootcrypt_record_bounds(struct kunit *test)
{
	u8 buffer[TEST_RECORD_SIZE];
	struct rootcrypt_record record;
	size_t size;

	rootcrypt_test_record(buffer);
	for (size = 0; size < TEST_RECORD_SIZE; size++)
		KUNIT_EXPECT_LT(test,
			rootcrypt_parse_record(buffer, size, &test_uuid, &record), 0);
	KUNIT_EXPECT_LT(test, rootcrypt_parse_record(buffer,
		DM_ROOTCRYPT_MAX_RECORD_SIZE + 1, &test_uuid, &record), 0);
}

static void rootcrypt_header_validation(struct kunit *test)
{
	u8 buffer[TEST_RECORD_SIZE];
	struct dm_rootcrypt_record *header = (void *)buffer;
	struct rootcrypt_record record;

	rootcrypt_test_record(buffer);
	header->magic[7] = 1;
	KUNIT_EXPECT_EQ(test, rootcrypt_parse_record(buffer, sizeof(buffer),
			&test_uuid, &record), -EINVAL);
	rootcrypt_test_record(buffer);
	put_unaligned_le32(2, &header->version);
	KUNIT_EXPECT_EQ(test, rootcrypt_parse_record(buffer, sizeof(buffer),
			&test_uuid, &record), -EINVAL);
	rootcrypt_test_record(buffer);
	put_unaligned_le32(1, &header->reserved);
	KUNIT_EXPECT_EQ(test, rootcrypt_parse_record(buffer, sizeof(buffer),
			&test_uuid, &record), -EINVAL);
	rootcrypt_test_record(buffer);
	header->partuuid[0] ^= 1;
	KUNIT_EXPECT_EQ(test, rootcrypt_parse_record(buffer, sizeof(buffer),
			&test_uuid, &record), -EKEYREJECTED);
}

static void rootcrypt_blob_bounds(struct kunit *test)
{
	static const u32 invalid[] = { 0, DM_ROOTCRYPT_MAX_BLOB_SIZE + 1, U32_MAX };
	u8 buffer[TEST_RECORD_SIZE];
	struct dm_rootcrypt_record *header = (void *)buffer;
	struct rootcrypt_record record;
	int i;

	for (i = 0; i < ARRAY_SIZE(invalid); i++) {
		rootcrypt_test_record(buffer);
		put_unaligned_le32(invalid[i], &header->blob_size);
		KUNIT_EXPECT_EQ(test, rootcrypt_parse_record(buffer, sizeof(buffer),
				&test_uuid, &record), -EINVAL);
	}
}

static void rootcrypt_pcr_selection(struct kunit *test)
{
	u8 buffer[TEST_RECORD_SIZE];
	struct dm_rootcrypt_record *header = (void *)buffer;
	struct rootcrypt_record record;

	rootcrypt_test_record(buffer);
	put_unaligned_le32(0, &header->pcr_mask);
	KUNIT_EXPECT_EQ(test, rootcrypt_parse_record(buffer, sizeof(buffer),
			&test_uuid, &record), -EINVAL);
	put_unaligned_le32(BIT(24), &header->pcr_mask);
	KUNIT_EXPECT_EQ(test, rootcrypt_parse_record(buffer, sizeof(buffer),
			&test_uuid, &record), -EINVAL);
	put_unaligned_le32(BIT(23), &header->pcr_mask);
	KUNIT_EXPECT_EQ(test, rootcrypt_parse_record(buffer, sizeof(buffer),
			&test_uuid, &record), 0);
}

static struct kunit_case rootcrypt_cases[] = {
	KUNIT_CASE(rootcrypt_valid_record),
	KUNIT_CASE(rootcrypt_record_bounds),
	KUNIT_CASE(rootcrypt_header_validation),
	KUNIT_CASE(rootcrypt_blob_bounds),
	KUNIT_CASE(rootcrypt_pcr_selection),
	{}
};

static struct kunit_suite rootcrypt_suite = {
	.name = "dm-rootcrypt-record",
	.test_cases = rootcrypt_cases,
};
kunit_test_suite(rootcrypt_suite);

MODULE_LICENSE("GPL");
