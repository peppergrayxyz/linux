// SPDX-License-Identifier: GPL-2.0-only
#include <kunit/test.h>
#include <linux/unaligned.h>

#include "../dm-crypt-root.h"

#define TEST_BLOB_SIZE 32
#define TEST_RECORD_SIZE (sizeof(struct dm_rootcrypt_record) + TEST_BLOB_SIZE + 1)

static const uuid_t test_uuid = UUID_INIT(0x12345678, 0x1234, 0x5678,
					  0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78);

static void rootcrypt_test_header(u8 *buffer, size_t size, u32 blob_size)
{
	struct dm_rootcrypt_record *header = (void *)buffer;

	memset(buffer, 0, size);
	memcpy(header->magic, DM_ROOTCRYPT_MAGIC, sizeof(header->magic));
	put_unaligned_le32(DM_ROOTCRYPT_VERSION, &header->version);
	put_unaligned_le32(BIT(7), &header->pcr_mask);
	memcpy(header->partuuid, test_uuid.b, sizeof(header->partuuid));
	put_unaligned_le32(blob_size, &header->blob_size);
}

static void rootcrypt_test_record(u8 *buffer)
{
	rootcrypt_test_header(buffer, TEST_RECORD_SIZE, TEST_BLOB_SIZE);
}

static int rootcrypt_test_parse(u8 *buffer, size_t size)
{
	struct rootcrypt_record record;

	return rootcrypt_parse_record(buffer, size, &test_uuid, &record);
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
			    (const u8 *)buffer + 1 + sizeof(struct dm_rootcrypt_record));
	KUNIT_EXPECT_PTR_EQ(test, record.signature, (const u8 *)buffer + TEST_RECORD_SIZE);
}

static void rootcrypt_record_bounds(struct kunit *test)
{
	u8 buffer[TEST_RECORD_SIZE];
	size_t size;

	/* Every truncation, including an empty signature, is rejected. */
	rootcrypt_test_record(buffer);
	for (size = 0; size < TEST_RECORD_SIZE; size++)
		KUNIT_EXPECT_LT(test, rootcrypt_test_parse(buffer, size), 0);
	KUNIT_EXPECT_LT(test, rootcrypt_test_parse(buffer, DM_ROOTCRYPT_MAX_RECORD_SIZE + 1), 0);
}

static void rootcrypt_maximum_sizes(struct kunit *test)
{
	u8 *buffer = kunit_kzalloc(test, DM_ROOTCRYPT_MAX_RECORD_SIZE + 1, GFP_KERNEL);
	struct rootcrypt_record record;

	KUNIT_ASSERT_NOT_NULL(test, buffer);
	rootcrypt_test_header(buffer, DM_ROOTCRYPT_MAX_RECORD_SIZE + 1,
			      DM_ROOTCRYPT_MAX_BLOB_SIZE);
	KUNIT_ASSERT_EQ(test, rootcrypt_parse_record(buffer, DM_ROOTCRYPT_MAX_RECORD_SIZE,
						     &test_uuid, &record), 0);
	KUNIT_EXPECT_EQ(test, record.blob_size, (size_t)DM_ROOTCRYPT_MAX_BLOB_SIZE);
	KUNIT_EXPECT_EQ(test, record.signed_size + record.signature_size,
			(size_t)DM_ROOTCRYPT_MAX_RECORD_SIZE);
	KUNIT_EXPECT_EQ(test, rootcrypt_test_parse(buffer, DM_ROOTCRYPT_MAX_RECORD_SIZE + 1),
			-EINVAL);
}

static void rootcrypt_header_validation(struct kunit *test)
{
	u8 buffer[TEST_RECORD_SIZE];
	struct dm_rootcrypt_record *header = (void *)buffer;

	rootcrypt_test_record(buffer);
	header->magic[7] = 1;
	KUNIT_EXPECT_EQ(test, rootcrypt_test_parse(buffer, sizeof(buffer)), -EINVAL);
	rootcrypt_test_record(buffer);
	put_unaligned_le32(2, &header->version);
	KUNIT_EXPECT_EQ(test, rootcrypt_test_parse(buffer, sizeof(buffer)), -EINVAL);
	rootcrypt_test_record(buffer);
	put_unaligned_le32(1, &header->reserved);
	KUNIT_EXPECT_EQ(test, rootcrypt_test_parse(buffer, sizeof(buffer)), -EINVAL);
	rootcrypt_test_record(buffer);
	header->partuuid[0] ^= 1;
	KUNIT_EXPECT_EQ(test, rootcrypt_test_parse(buffer, sizeof(buffer)), -EKEYREJECTED);
}

static void rootcrypt_blob_bounds(struct kunit *test)
{
	static const u32 invalid[] = { 0, DM_ROOTCRYPT_MAX_BLOB_SIZE + 1, U32_MAX };
	u8 buffer[TEST_RECORD_SIZE];
	struct dm_rootcrypt_record *header = (void *)buffer;
	int i;

	for (i = 0; i < ARRAY_SIZE(invalid); i++) {
		rootcrypt_test_record(buffer);
		put_unaligned_le32(invalid[i], &header->blob_size);
		KUNIT_EXPECT_EQ(test, rootcrypt_test_parse(buffer, sizeof(buffer)), -EINVAL);
	}
}

static void rootcrypt_pcr_selection(struct kunit *test)
{
	u8 buffer[TEST_RECORD_SIZE];
	struct dm_rootcrypt_record *header = (void *)buffer;

	rootcrypt_test_record(buffer);
	put_unaligned_le32(0, &header->pcr_mask);
	KUNIT_EXPECT_EQ(test, rootcrypt_test_parse(buffer, sizeof(buffer)), -EINVAL);
	put_unaligned_le32(BIT(24), &header->pcr_mask);
	KUNIT_EXPECT_EQ(test, rootcrypt_test_parse(buffer, sizeof(buffer)), -EINVAL);
	put_unaligned_le32(BIT(23), &header->pcr_mask);
	KUNIT_EXPECT_EQ(test, rootcrypt_test_parse(buffer, sizeof(buffer)), 0);
}

static struct kunit_case rootcrypt_cases[] = {
	KUNIT_CASE(rootcrypt_valid_record),
	KUNIT_CASE(rootcrypt_record_bounds),
	KUNIT_CASE(rootcrypt_maximum_sizes),
	KUNIT_CASE(rootcrypt_header_validation),
	KUNIT_CASE(rootcrypt_blob_bounds),
	KUNIT_CASE(rootcrypt_pcr_selection),
	{}
};

static struct kunit_suite rootcrypt_suite = {
	.name = "dm_crypt_root",
	.test_cases = rootcrypt_cases,
};

kunit_test_suite(rootcrypt_suite);

MODULE_DESCRIPTION("KUnit tests for TPM2 root enrollment parsing");
MODULE_LICENSE("GPL");
