// SPDX-License-Identifier: GPL-2.0-only
/*
 * Static PID 1 for the rootcrypt QEMU tests. No shell or initramfs is used.
 * It builds against tools/include/nolibc, so no ARM64 C library is needed.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static void finish(int failed)
{
	if (failed)
		printf("ROOTCRYPT_TEST_FAIL: %s\n", strerror(errno));
	/* Both roots are read-only and efivarfs writes are synchronous. */
	fflush(stdout);
	reboot(RB_POWER_OFF);
	for (;;)
		sleep(1);
}

static ssize_t read_file(const char *path, char *buffer, size_t capacity)
{
	ssize_t count, total = 0;
	char extra;
	int fd = open(path, O_RDONLY);

	if (fd < 0)
		return -1;
	while ((size_t)total < capacity - 1) {
		count = read(fd, buffer + total, capacity - 1 - total);
		if (count < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return -1;
		}
		if (!count)
			break;
		total += count;
	}
	/* Refuse truncated fixtures or command lines. */
	if ((size_t)total == capacity - 1 && read(fd, &extra, 1) != 0) {
		close(fd);
		errno = EFBIG;
		return -1;
	}
	close(fd);
	buffer[total] = '\0';
	return total;
}

static int valid_record_name(const char *name)
{
	for (; *name; name++)
		if (!((*name >= 'a' && *name <= 'z') ||
		      (*name >= '0' && *name <= '9') || *name == '-'))
			return 0;
	return 1;
}

static void provision(const char *name)
{
	char path[512], variable[256], record[8192], check[8192];
	ssize_t length, written;
	int fd;

	if (!valid_record_name(name)) {
		errno = EINVAL;
		finish(1);
	}
	/* An empty name only lets the firmware initialize its variable store. */
	if (!*name) {
		printf("ROOTCRYPT_PROVISIONED: none\n");
		return;
	}
	if (mount("efivarfs", "/sys/firmware/efi/efivars", "efivarfs", 0, NULL))
		finish(1);
	if (read_file("/variable-name", variable, sizeof(variable)) <= 0)
		finish(1);
	snprintf(path, sizeof(path), "/records/%s", name);
	length = read_file(path, record, sizeof(record));
	if (length <= 4) {
		errno = EINVAL;
		finish(1);
	}
	snprintf(path, sizeof(path), "/sys/firmware/efi/efivars/%s", variable);
	/* Every provisioning boot gets a fresh copy of the firmware template. */
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0)
		finish(1);
	written = write(fd, record, length);
	if (close(fd))
		finish(1);
	if (written != length) {
		errno = EIO;
		finish(1);
	}
	if (read_file(path, check, sizeof(check)) != length ||
	    memcmp(record, check, length)) {
		errno = EIO;
		finish(1);
	}
	printf("ROOTCRYPT_PROVISIONED: %s\n", name);
}

/* Return whether the "/" mount of device major:minor has filesystem @type. */
static int root_mount_is(unsigned int major, unsigned int minor, const char *type)
{
	char mounts[8192], device[64], *line, *end, *fields;
	size_t length = strlen(type);

	if (read_file("/proc/self/mountinfo", mounts, sizeof(mounts)) < 0)
		return 0;
	snprintf(device, sizeof(device), " %u:%u / / ", major, minor);
	for (line = mounts; *line; line = end + 1) {
		end = strchr(line, '\n');
		if (!end)
			return 0;
		*end = '\0';
		if (!strstr(line, device))
			continue;
		fields = strstr(line, " - ");
		return fields && !strncmp(fields + 3, type, length) &&
		       fields[3 + length] == ' ';
	}
	return 0;
}

static void check_root(void)
{
	char path[128], name[64], proof[128];
	struct stat root, mapper;

	if (stat("/", &root) || stat("/dev/dm-0", &mapper))
		finish(1);
	if (root.st_dev != mapper.st_rdev || !S_ISBLK(mapper.st_mode) ||
	    !root_mount_is(major(root.st_dev), minor(root.st_dev), "ext4")) {
		errno = ENODEV;
		finish(1);
	}
	snprintf(path, sizeof(path), "/sys/dev/block/%u:%u/dm/name",
		 major(root.st_dev), minor(root.st_dev));
	if (read_file(path, name, sizeof(name)) != 10 ||
	    strcmp(name, "rootcrypt\n")) {
		errno = ENODEV;
		finish(1);
	}
	if (read_file("/proof", proof, sizeof(proof)) != 64) {
		errno = EIO;
		finish(1);
	}
	printf("ROOTCRYPT_BOOT_OK: %s\n", proof);
}

int main(void)
{
	static const char option[] = "rootcrypt_test.record=";
	char command_line[4096], *word, *end;
	const char *record = NULL;

	if (mount("proc", "/proc", "proc", 0, NULL) ||
	    mount("sysfs", "/sys", "sysfs", 0, NULL))
		finish(1);
	if (read_file("/proc/cmdline", command_line, sizeof(command_line)) < 0)
		finish(1);
	for (word = command_line; *word; word = end) {
		while (*word == ' ' || *word == '\n')
			word++;
		for (end = word; *end && *end != ' ' && *end != '\n'; end++)
			;
		if (*end)
			*end++ = '\0';
		if (!strncmp(word, option, sizeof(option) - 1))
			record = word + sizeof(option) - 1;
	}
	if (record)
		provision(record);
	else
		check_root();
	finish(0);
	return 0;
}
