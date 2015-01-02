#define _GNU_SOURCE

#include <sys/stat.h>
#include <sys/types.h>
#include <getopt.h>
#include <ext2fs/ext2fs.h>

#include "linuxioctl.h"
#include "syslinux.h"
#include "syslxint.h"
#include "syslxopt.h"

/*
 * Get the size of a block device
 */
static uint64_t get_size(int dev_fd)
{
    uint64_t bytes;
    uint32_t sects;
    struct stat st;

#ifdef BLKGETSIZE64
    if (!ioctl(dev_fd, BLKGETSIZE64, &bytes))
	return bytes;
#endif
    if (!ioctl(dev_fd, BLKGETSIZE, &sects))
	return (uint64_t) sects << 9;
    else if (!fstat(dev_fd, &st) && st.st_size)
	return st.st_size;
    else
	return 0;
}

/*
 * Get device geometry and partition offset
 */
static struct geometry_table {
    uint64_t bytes;
    struct hd_geometry g;
};

static int sysfs_get_offset(int dev_fd, unsigned long *start)
{
    struct stat st;
    char sysfs_name[128];
    FILE *f;
    int rv;

    if (fstat(dev_fd, &st))
	return -1;

    if ((size_t)snprintf(sysfs_name, sizeof sysfs_name,
			 "/sys/dev/block/%u:%u/start",
			 major(st.st_rdev), minor(st.st_rdev))
	>= sizeof sysfs_name)
	return -1;

    f = fopen(sysfs_name, "r");
    if (!f)
	return -1;

    rv = fscanf(f, "%lu", start);
    fclose(f);

    return (rv == 1) ? 0 : -1;
}

/* Standard floppy disk geometries, plus LS-120.  Zipdisk geometry
   (x/64/32) is the final fallback.  I don't know what LS-240 has
   as its geometry, since I don't have one and don't know anyone that does,
   and Google wasn't helpful... */
static const struct geometry_table standard_geometries[] = {
    {360 * 1024, {2, 9, 40, 0}},
    {720 * 1024, {2, 9, 80, 0}},
    {1200 * 1024, {2, 15, 80, 0}},
    {1440 * 1024, {2, 18, 80, 0}},
    {1680 * 1024, {2, 21, 80, 0}},
    {1722 * 1024, {2, 21, 80, 0}},
    {2880 * 1024, {2, 36, 80, 0}},
    {3840 * 1024, {2, 48, 80, 0}},
    {123264 * 1024, {8, 32, 963, 0}},	/* LS120 */
    {0, {0, 0, 0, 0}}
};

static int get_geometry(int dev_fd, uint64_t totalbytes, struct hd_geometry *geo)
{
    struct floppy_struct fd_str;
    struct loop_info li;
    struct loop_info64 li64;
    const struct geometry_table *gp;
    int rv = 0;

    memset(geo, 0, sizeof *geo);

    if (!ioctl(dev_fd, HDIO_GETGEO, geo)) {
	goto ok;
    } else if (!ioctl(dev_fd, FDGETPRM, &fd_str)) {
	geo->heads = fd_str.head;
	geo->sectors = fd_str.sect;
	geo->cylinders = fd_str.track;
	geo->start = 0;
	goto ok;
    }

    /* Didn't work.  Let's see if this is one of the standard geometries */
    for (gp = standard_geometries; gp->bytes; gp++) {
	if (gp->bytes == totalbytes) {
	    memcpy(geo, &gp->g, sizeof *geo);
	    goto ok;
	}
    }

    /* Didn't work either... assign a geometry of 64 heads, 32 sectors; this is
       what zipdisks use, so this would help if someone has a USB key that
       they're booting in USB-ZIP mode. */

    geo->heads = opt.heads ? : 64;
    geo->sectors = opt.sectors ? : 32;
    geo->cylinders = totalbytes / (geo->heads * geo->sectors << SECTOR_SHIFT);
    geo->start = 0;

    if (!opt.sectors && !opt.heads) {
	fprintf(stderr,
		"Warning: unable to obtain device geometry (defaulting to %d heads, %d sectors)\n"
		"         (on hard disks, this is usually harmless.)\n",
		geo->heads, geo->sectors);
	rv = 1;			/* Suboptimal result */
    }

ok:
    /* If this is a loopback device, try to set the start */
    if (!ioctl(dev_fd, LOOP_GET_STATUS64, &li64))
	geo->start = li64.lo_offset >> SECTOR_SHIFT;
    else if (!ioctl(dev_fd, LOOP_GET_STATUS, &li))
	geo->start = (unsigned int)li.lo_offset >> SECTOR_SHIFT;
    else if (!sysfs_get_offset(dev_fd, &geo->start)) {
	/* OK */
    }

    return rv;
}


/* Patch syslinux_bootsect */
void syslinux_patch_bootsect(int dev_fd)
{
    uint64_t totalbytes, totalsectors;
    struct hd_geometry geo;
    struct fat_boot_sector *sbs;

    totalbytes = get_size(dev_fd);
    get_geometry(dev_fd, totalbytes, &geo);

    if (opt.heads)
	geo.heads = opt.heads;
    if (opt.sectors)
	geo.sectors = opt.sectors;

    /* Patch this into a fake FAT superblock.  This isn't because
       FAT is a good format in any way, it's because it lets the
       early bootstrap share code with the FAT version. */
    sbs = (struct fat_boot_sector *)syslinux_bootsect;

    totalsectors = totalbytes >> SECTOR_SHIFT;
    if (totalsectors >= 65536) {
	set_16(&sbs->bsSectors, 0);
    } else {
	set_16(&sbs->bsSectors, totalsectors);
    }
    set_32(&sbs->bsHugeSectors, totalsectors);

    set_16(&sbs->bsBytesPerSec, SECTOR_SIZE);
    set_16(&sbs->bsSecPerTrack, geo.sectors);
    set_16(&sbs->bsHeads, geo.heads);
    set_32(&sbs->bsHiddenSecs, geo.start);
}

