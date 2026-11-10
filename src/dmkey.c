/*
 * dmkey - minimal device-mapper table loader for Android recovery.
 *
 * dmctl in this recovery only understands "linear" and "zero".  We need
 * dm-default-key to reproduce the FBE view of /data, so talk to
 * /dev/device-mapper directly.
 *
 * usage:
 *   dmkey create <name> <ro|rw> <type> <start> <length> [params...]
 *   dmkey remove <name>
 *   dmkey status <name>
 *
 * On success `create` prints the device node path (e.g. /dev/block/dm-0).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <linux/dm-ioctl.h>

#ifndef DM_VERSION_MAJOR
#define DM_VERSION_MAJOR 4
#endif
#ifndef DM_VERSION_MINOR
#define DM_VERSION_MINOR 0
#endif
#ifndef DM_VERSION_PATCHLEVEL
#define DM_VERSION_PATCHLEVEL 0
#endif

static int dmfd = -1;
static unsigned char iobuf[16384] __attribute__((aligned(8)));

static struct dm_ioctl *mkio(size_t extra, const char *name)
{
	struct dm_ioctl *io;

	memset(iobuf, 0, sizeof(iobuf));
	io = (struct dm_ioctl *)iobuf;
	/*
	 * Send the oldest interface version.  The kernel rejects a userspace
	 * minor newer than its own (this phone runs 4.14), and everything we
	 * use here predates 4.0.
	 */
	io->version[0] = 4;
	io->version[1] = 0;
	io->version[2] = 0;
	io->data_size = sizeof(struct dm_ioctl) + extra;
	io->data_start = sizeof(struct dm_ioctl);
	if (name)
		snprintf(io->name, sizeof(io->name), "%s", name);
	return io;
}

static int dm_ioctl(unsigned long cmd, struct dm_ioctl *io)
{
	int r;

	do {
		r = ioctl(dmfd, cmd, io);
	} while (r < 0 && errno == EINTR);
	if (r < 0)
		return -errno;
	return 0;
}

static int make_node(const char *path, dev_t dev)
{
	if (mknod(path, S_IFBLK | 0600, dev) < 0 && errno != EEXIST)
		return -errno;
	return 0;
}

static int get_dev(const char *name, dev_t *out)
{
	struct dm_ioctl *io = mkio(0, name);
	int r = dm_ioctl(DM_DEV_STATUS, io);

	if (r < 0)
		return r;
	*out = (dev_t)io->dev;
	return 0;
}

static int do_create(int argc, char **argv)
{
	const char *name, *mode, *type;
	unsigned long long start, len;
	struct dm_ioctl *io;
	struct dm_target_spec *ts;
	char *params;
	size_t plen, extra;
	dev_t dev;
	int r, i;

	if (argc < 6) {
		fprintf(stderr, "create needs: name ro|rw type start length [params...]\n");
		return 2;
	}
	name = argv[0];
	mode = argv[1];
	type = argv[2];
	start = strtoull(argv[3], NULL, 0);
	len = strtoull(argv[4], NULL, 0);

	plen = 1;
	for (i = 5; i < argc; i++)
		plen += strlen(argv[i]) + 1;

	extra = sizeof(struct dm_target_spec) + plen;
	io = mkio(extra, name);
	if (!strcmp(mode, "ro"))
		io->flags |= DM_READONLY_FLAG;
	if ((r = dm_ioctl(DM_DEV_CREATE, io)) < 0) {
		fprintf(stderr, "DM_DEV_CREATE: %s\n", strerror(-r));
		return 1;
	}

	io = mkio(extra, name);
	if (!strcmp(mode, "ro"))
		io->flags |= DM_READONLY_FLAG;
	ts = (struct dm_target_spec *)(iobuf + sizeof(struct dm_ioctl));
	ts->sector_start = start;
	ts->length = len;
	snprintf(ts->target_type, sizeof(ts->target_type), "%s", type);
	ts->next = 0;
	params = (char *)(ts + 1);
	params[0] = '\0';
	for (i = 5; i < argc; i++) {
		if (i > 5)
			strcat(params, " ");
		strcat(params, argv[i]);
	}
	io->target_count = 1;
	if ((r = dm_ioctl(DM_TABLE_LOAD, io)) < 0) {
		fprintf(stderr, "DM_TABLE_LOAD: %s\n", strerror(-r));
		goto fail;
	}

	io = mkio(0, name);
	io->flags = 0; /* resume */
	if ((r = dm_ioctl(DM_DEV_SUSPEND, io)) < 0) {
		fprintf(stderr, "DM_DEV_SUSPEND(resume): %s\n", strerror(-r));
		goto fail;
	}

	if ((r = get_dev(name, &dev)) < 0) {
		fprintf(stderr, "DM_DEV_STATUS: %s\n", strerror(-r));
		goto fail;
	}

	{
		char path[128];
		snprintf(path, sizeof(path), "/dev/block/dm-%u", minor(dev));
		if (make_node(path, dev) == 0)
			printf("%s\n", path);
		else
			printf("/dev/block/dm-%u\n", minor(dev));
	}
	return 0;

fail:
	io = mkio(0, name);
	dm_ioctl(DM_DEV_REMOVE, io);
	return 1;
}

static int do_remove(const char *name)
{
	struct dm_ioctl *io = mkio(0, name);
	int r = dm_ioctl(DM_DEV_REMOVE, io);

	if (r < 0) {
		fprintf(stderr, "DM_DEV_REMOVE: %s\n", strerror(-r));
		return 1;
	}
	return 0;
}

static int do_status(const char *name)
{
	dev_t dev;
	int r;

	if ((r = get_dev(name, &dev)) < 0) {
		fprintf(stderr, "DM_DEV_STATUS: %s\n", strerror(-r));
		return 1;
	}
	printf("%s /dev/block/dm-%u %u:%u\n", name, minor(dev),
	       major(dev), minor(dev));
	return 0;
}

int main(int argc, char **argv)
{
	const char *cmd;

	if (argc < 2) {
		fprintf(stderr, "usage: %s create|remove|status ...\n", argv[0]);
		return 2;
	}
	cmd = argv[1];

	dmfd = open("/dev/device-mapper", O_RDWR | O_CLOEXEC);
	if (dmfd < 0) {
		perror("open /dev/device-mapper");
		return 1;
	}

	if (!strcmp(cmd, "create"))
		return do_create(argc - 2, argv + 2);
	if (!strcmp(cmd, "remove") && argc == 3)
		return do_remove(argv[2]);
	if (!strcmp(cmd, "status") && argc == 3)
		return do_status(argv[2]);

	fprintf(stderr, "usage: %s create <name> <ro|rw> <type> <start> <length> [params...]\n"
			"       %s remove <name>\n"
			"       %s status <name>\n", argv[0], argv[0], argv[0]);
	return 2;
}
