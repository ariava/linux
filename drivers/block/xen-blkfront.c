/*
 * blkfront.c
 *
 * XenLinux virtual block device driver.
 *
 * Copyright (c) 2003-2004, Keir Fraser & Steve Hand
 * Modifications by Mark A. Williamson are (c) Intel Research Cambridge
 * Copyright (c) 2004, Christian Limpach
 * Copyright (c) 2004, Andrew Warfield
 * Copyright (c) 2005, Christopher Clark
 * Copyright (c) 2005, XenSource Ltd
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <linux/interrupt.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>
#include <linux/cdrom.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/scatterlist.h>
#include <linux/bitmap.h>
#include <linux/list.h>
#include <linux/blk-mq.h>

#include <xen/xen.h>
#include <xen/xenbus.h>
#include <xen/grant_table.h>
#include <xen/events.h>
#include <xen/page.h>
#include <xen/platform_pci.h>

#include <xen/interface/grant_table.h>
#include <xen/interface/io/blkif.h>
#include <xen/interface/io/protocols.h>

#include <asm/xen/hypervisor.h>

#include "xen-blkback/common.h"	/* for struct blkif_x86_64_request */

enum blkif_state {
	BLKIF_STATE_DISCONNECTED,
	BLKIF_STATE_CONNECTED,
	BLKIF_STATE_SUSPENDED,
};

struct grant {
	grant_ref_t gref;
	unsigned long pfn;
	struct list_head node;
};

struct blk_shadow {
	struct blkif_request req;
	struct request *request;
	struct grant **grants_used;
	struct grant **indirect_grants;
	struct scatterlist *sg;
};

struct split_bio {
	struct bio *bio;
	atomic_t pending;
	int err;
};

static DEFINE_MUTEX(blkfront_mutex);
static const struct block_device_operations xlvbd_block_fops;

/*
 * Maximum number of segments in indirect requests, the actual value used by
 * the frontend driver is the minimum of this value and the value provided
 * by the backend driver.
 */

static unsigned int xen_blkif_max_segments = 32;
module_param_named(max, xen_blkif_max_segments, int, S_IRUGO);
MODULE_PARM_DESC(max, "Maximum amount of segments in indirect requests (default is 32)");

#define BLK_RING_SIZE __CONST_RING_SIZE(blkif, PAGE_SIZE)

struct blkfront_ring_info
{
	spinlock_t io_lock;
	int ring_ref;
	struct blkif_front_ring ring;
	unsigned int evtchn, irq;
	struct blk_shadow shadow[BLK_RING_SIZE];
	unsigned long shadow_free;

	struct work_struct work;
	struct gnttab_free_callback callback;
	struct list_head grants;
	struct list_head indirect_pages;
	unsigned int persistent_gnts_c;

	struct blkfront_info *info;
	unsigned int hctx_index;
};

/*
 * We have one of these per vbd, whether ide, scsi or 'other'.  They
 * hang in private_data off the gendisk structure. We may end up
 * putting all kinds of interesting stuff here :-)
 */
struct blkfront_info
{
	struct mutex mutex;
	struct xenbus_device *xbdev;
	struct gendisk *gd;
	int vdevice;
	blkif_vdev_t handle;
	enum blkif_state connected;
	unsigned int nr_rings;
	struct blkfront_ring_info *rinfo;
	struct request_queue *rq;
	unsigned int feature_flush;
	unsigned int flush_op;
	unsigned int feature_discard:1;
	unsigned int feature_secdiscard:1;
	unsigned int discard_granularity;
	unsigned int discard_alignment;
	unsigned int feature_persistent:1;
	unsigned int nr_hw_queues;
	unsigned int max_indirect_segments;
	int is_ready;
};

static unsigned int nr_minors;
static unsigned long *minors;
static DEFINE_SPINLOCK(minor_lock);

#define MAXIMUM_OUTSTANDING_BLOCK_REQS \
	(BLKIF_MAX_SEGMENTS_PER_REQUEST * BLK_RING_SIZE)
#define GRANT_INVALID_REF	0

#define PARTS_PER_DISK		16
#define PARTS_PER_EXT_DISK      256

#define BLKIF_MAJOR(dev) ((dev)>>8)
#define BLKIF_MINOR(dev) ((dev) & 0xff)

#define EXT_SHIFT 28
#define EXTENDED (1<<EXT_SHIFT)
#define VDEV_IS_EXTENDED(dev) ((dev)&(EXTENDED))
#define BLKIF_MINOR_EXT(dev) ((dev)&(~EXTENDED))
#define EMULATED_HD_DISK_MINOR_OFFSET (0)
#define EMULATED_HD_DISK_NAME_OFFSET (EMULATED_HD_DISK_MINOR_OFFSET / 256)
#define EMULATED_SD_DISK_MINOR_OFFSET (0)
#define EMULATED_SD_DISK_NAME_OFFSET (EMULATED_SD_DISK_MINOR_OFFSET / 256)

#define DEV_NAME	"xvd"	/* name in /dev */

#define SEGS_PER_INDIRECT_FRAME \
	(PAGE_SIZE/sizeof(struct blkif_request_segment))
#define INDIRECT_GREFS(_segs) \
	((_segs + SEGS_PER_INDIRECT_FRAME - 1)/SEGS_PER_INDIRECT_FRAME)

static int blkfront_gather_indirect(struct blkfront_info *info);
static int blkfront_setup_indirect(struct blkfront_ring_info *rinfo,
				   unsigned int segs);

static int get_id_from_freelist(struct blkfront_ring_info *rinfo)
{
	unsigned long free = rinfo->shadow_free;
	BUG_ON(free >= BLK_RING_SIZE);
	rinfo->shadow_free = rinfo->shadow[free].req.u.rw.id;
	rinfo->shadow[free].req.u.rw.id = 0x0fffffee; /* debug */
	return free;
}

static int add_id_to_freelist(struct blkfront_ring_info *rinfo,
			       unsigned long id)
{
	if (rinfo->shadow[id].req.u.rw.id != id)
		return -EINVAL;
	if (rinfo->shadow[id].request == NULL)
		return -EINVAL;
	rinfo->shadow[id].req.u.rw.id  = rinfo->shadow_free;
	rinfo->shadow[id].request = NULL;
	rinfo->shadow_free = id;
	return 0;
}

static int fill_grant_buffer(struct blkfront_ring_info *rinfo, int num)
{
	struct blkfront_info *info = rinfo->info;
	struct page *granted_page;
	struct grant *gnt_list_entry, *n;
	int i = 0;

	while(i < num) {
		gnt_list_entry = kzalloc(sizeof(struct grant), GFP_NOIO);
		if (!gnt_list_entry)
			goto out_of_memory;

		if (info->feature_persistent) {
			granted_page = alloc_page(GFP_NOIO);
			if (!granted_page) {
				kfree(gnt_list_entry);
				goto out_of_memory;
			}
			gnt_list_entry->pfn = page_to_pfn(granted_page);
		}

		gnt_list_entry->gref = GRANT_INVALID_REF;
		list_add(&gnt_list_entry->node, &rinfo->grants);
		i++;
	}

	return 0;

out_of_memory:
	list_for_each_entry_safe(gnt_list_entry, n,
	                         &rinfo->grants, node) {
		list_del(&gnt_list_entry->node);
		if (info->feature_persistent)
			__free_page(pfn_to_page(gnt_list_entry->pfn));
		kfree(gnt_list_entry);
		i--;
	}
	BUG_ON(i != 0);
	return -ENOMEM;
}

static struct grant *get_grant(grant_ref_t *gref_head,
                               unsigned long pfn,
                               struct blkfront_ring_info *rinfo)
{
	struct grant *gnt_list_entry;
	unsigned long buffer_mfn;

	BUG_ON(list_empty(&rinfo->grants));
	gnt_list_entry = list_first_entry(&rinfo->grants, struct grant,
	                                  node);
	list_del(&gnt_list_entry->node);

	if (gnt_list_entry->gref != GRANT_INVALID_REF) {
		rinfo->persistent_gnts_c--;
		return gnt_list_entry;
	}

	/* Assign a gref to this page */
	gnt_list_entry->gref = gnttab_claim_grant_reference(gref_head);
	BUG_ON(gnt_list_entry->gref == -ENOSPC);
	if (!rinfo->info->feature_persistent) {
		BUG_ON(!pfn);
		gnt_list_entry->pfn = pfn;
	}
	buffer_mfn = pfn_to_mfn(gnt_list_entry->pfn);
	gnttab_grant_foreign_access_ref(gnt_list_entry->gref,
	                                rinfo->info->xbdev->otherend_id,
	                                buffer_mfn, 0);
	return gnt_list_entry;
}

static const char *op_name(int op)
{
	static const char *const names[] = {
		[BLKIF_OP_READ] = "read",
		[BLKIF_OP_WRITE] = "write",
		[BLKIF_OP_WRITE_BARRIER] = "barrier",
		[BLKIF_OP_FLUSH_DISKCACHE] = "flush",
		[BLKIF_OP_DISCARD] = "discard" };

	if (op < 0 || op >= ARRAY_SIZE(names))
		return "unknown";

	if (!names[op])
		return "reserved";

	return names[op];
}
static int xlbd_reserve_minors(unsigned int minor, unsigned int nr)
{
	unsigned int end = minor + nr;
	int rc;

	if (end > nr_minors) {
		unsigned long *bitmap, *old;

		bitmap = kcalloc(BITS_TO_LONGS(end), sizeof(*bitmap),
				 GFP_KERNEL);
		if (bitmap == NULL)
			return -ENOMEM;

		spin_lock(&minor_lock);
		if (end > nr_minors) {
			old = minors;
			memcpy(bitmap, minors,
			       BITS_TO_LONGS(nr_minors) * sizeof(*bitmap));
			minors = bitmap;
			nr_minors = BITS_TO_LONGS(end) * BITS_PER_LONG;
		} else
			old = bitmap;
		spin_unlock(&minor_lock);
		kfree(old);
	}

	spin_lock(&minor_lock);
	if (find_next_bit(minors, end, minor) >= end) {
		bitmap_set(minors, minor, nr);
		rc = 0;
	} else
		rc = -EBUSY;
	spin_unlock(&minor_lock);

	return rc;
}

static void xlbd_release_minors(unsigned int minor, unsigned int nr)
{
	unsigned int end = minor + nr;

	BUG_ON(end > nr_minors);
	spin_lock(&minor_lock);
	bitmap_clear(minors,  minor, nr);
	spin_unlock(&minor_lock);
}

static void blkif_restart_queue_callback(void *arg)
{
	struct blkfront_ring_info *rinfo = (struct blkfront_ring_info *)arg;
	schedule_work(&rinfo->work);
}

static int blkif_getgeo(struct block_device *bd, struct hd_geometry *hg)
{
	/* We don't have real geometry info, but let's at least return
	   values consistent with the size of the device */
	sector_t nsect = get_capacity(bd->bd_disk);
	sector_t cylinders = nsect;

	hg->heads = 0xff;
	hg->sectors = 0x3f;
	sector_div(cylinders, hg->heads * hg->sectors);
	hg->cylinders = cylinders;
	if ((sector_t)(hg->cylinders + 1) * hg->heads * hg->sectors < nsect)
		hg->cylinders = 0xffff;
	return 0;
}

static int blkif_ioctl(struct block_device *bdev, fmode_t mode,
		       unsigned command, unsigned long argument)
{
	struct blkfront_info *info = bdev->bd_disk->private_data;
	int i;

	dev_dbg(&info->xbdev->dev, "command: 0x%x, argument: 0x%lx\n",
		command, (long)argument);

	switch (command) {
	case CDROMMULTISESSION:
		dev_dbg(&info->xbdev->dev, "FIXME: support multisession CDs later\n");
		for (i = 0; i < sizeof(struct cdrom_multisession); i++)
			if (put_user(0, (char __user *)(argument + i)))
				return -EFAULT;
		return 0;

	case CDROM_GET_CAPABILITY: {
		struct gendisk *gd = info->gd;
		if (gd->flags & GENHD_FL_CD)
			return 0;
		return -EINVAL;
	}

	default:
		/*printk(KERN_ALERT "ioctl %08x not supported by Xen blkdev\n",
		  command);*/
		return -EINVAL; /* same return as native Linux */
	}

	return 0;
}

/*
 * Generate a Xen blkfront IO request from a blk layer request.  Reads
 * and writes are handled as expected.
 *
 * @req: a request struct
 */
static int blkif_queue_request(struct request *req, unsigned int ring_idx)
{
	struct blkfront_info *info = req->rq_disk->private_data;
	struct blkfront_ring_info *rinfo = &info->rinfo[ring_idx];
	struct blkif_front_ring *ring = &info->rinfo[ring_idx].ring;
	struct blkif_request *ring_req;
	unsigned long id;
	unsigned int fsect, lsect;
	int i, ref, n;
	struct blkif_request_segment *segments = NULL;

	/*
	 * Used to store if we are able to queue the request by just using
	 * existing persistent grants, or if we have to get new grants,
	 * as there are not sufficiently many free.
	 */
	bool new_persistent_gnts;
	grant_ref_t gref_head;
	struct grant *gnt_list_entry = NULL;
	struct scatterlist *sg;
	int nseg, max_grefs;

	if (unlikely(info->connected != BLKIF_STATE_CONNECTED))
		return 1;

	max_grefs = req->nr_phys_segments;
	if (max_grefs > BLKIF_MAX_SEGMENTS_PER_REQUEST)
		/*
		 * If we are using indirect segments we need to account
		 * for the indirect grefs used in the request.
		 */
		max_grefs += INDIRECT_GREFS(req->nr_phys_segments);

	/* Check if we have enough grants to allocate a requests */
	if (rinfo->persistent_gnts_c < max_grefs) {
		new_persistent_gnts = 1;
		if (gnttab_alloc_grant_references(
		    max_grefs - rinfo->persistent_gnts_c,
		    &gref_head) < 0) {
			gnttab_request_free_callback(
				&rinfo->callback,
				blkif_restart_queue_callback,
				rinfo,
				max_grefs);
			return 1;
		}
	} else
		new_persistent_gnts = 0;

	/* Fill out a communications ring structure. */
	ring_req = RING_GET_REQUEST(ring, ring->req_prod_pvt);
	id = get_id_from_freelist(rinfo);
	rinfo->shadow[id].request = req;

	if (unlikely(req->cmd_flags & (REQ_DISCARD | REQ_SECURE))) {
		ring_req->operation = BLKIF_OP_DISCARD;
		ring_req->u.discard.nr_sectors = blk_rq_sectors(req);
		ring_req->u.discard.id = id;
		ring_req->u.discard.sector_number = (blkif_sector_t)blk_rq_pos(req);
		if ((req->cmd_flags & REQ_SECURE) && info->feature_secdiscard)
			ring_req->u.discard.flag = BLKIF_DISCARD_SECURE;
		else
			ring_req->u.discard.flag = 0;
	} else {
		BUG_ON(info->max_indirect_segments == 0 &&
		       req->nr_phys_segments > BLKIF_MAX_SEGMENTS_PER_REQUEST);
		BUG_ON(info->max_indirect_segments &&
		       req->nr_phys_segments > info->max_indirect_segments);
		nseg = blk_rq_map_sg(req->q, req, rinfo->shadow[id].sg);
		ring_req->u.rw.id = id;
		if (nseg > BLKIF_MAX_SEGMENTS_PER_REQUEST) {
			/*
			 * The indirect operation can only be a BLKIF_OP_READ or
			 * BLKIF_OP_WRITE
			 */
			BUG_ON(req->cmd_flags & (REQ_FLUSH | REQ_FUA));
			ring_req->operation = BLKIF_OP_INDIRECT;
			ring_req->u.indirect.indirect_op = rq_data_dir(req) ?
				BLKIF_OP_WRITE : BLKIF_OP_READ;
			ring_req->u.indirect.sector_number = (blkif_sector_t)blk_rq_pos(req);
			ring_req->u.indirect.handle = info->handle;
			ring_req->u.indirect.nr_segments = nseg;
		} else {
			ring_req->u.rw.sector_number = (blkif_sector_t)blk_rq_pos(req);
			ring_req->u.rw.handle = info->handle;
			ring_req->operation = rq_data_dir(req) ?
				BLKIF_OP_WRITE : BLKIF_OP_READ;
			if (req->cmd_flags & (REQ_FLUSH | REQ_FUA)) {
				/*
				 * Ideally we can do an unordered flush-to-disk. In case the
				 * backend onlysupports barriers, use that. A barrier request
				 * a superset of FUA, so we can implement it the same
				 * way.  (It's also a FLUSH+FUA, since it is
				 * guaranteed ordered WRT previous writes.)
				 */
				ring_req->operation = info->flush_op;
			}
			ring_req->u.rw.nr_segments = nseg;
		}
		for_each_sg(rinfo->shadow[id].sg, sg, nseg, i) {
			fsect = sg->offset >> 9;
			lsect = fsect + (sg->length >> 9) - 1;

			if ((ring_req->operation == BLKIF_OP_INDIRECT) &&
			    (i % SEGS_PER_INDIRECT_FRAME == 0)) {
				unsigned long uninitialized_var(pfn);

				if (segments)
					kunmap_atomic(segments);

				n = i / SEGS_PER_INDIRECT_FRAME;
				if (!info->feature_persistent) {
					struct page *indirect_page;

					/* Fetch a pre-allocated page to use for indirect grefs */
					BUG_ON(list_empty(&rinfo->indirect_pages));
					indirect_page = list_first_entry(&rinfo->indirect_pages,
					                                 struct page, lru);
					list_del(&indirect_page->lru);
					pfn = page_to_pfn(indirect_page);
				}
				gnt_list_entry = get_grant(&gref_head, pfn, rinfo);
				rinfo->shadow[id].indirect_grants[n] = gnt_list_entry;
				segments = kmap_atomic(pfn_to_page(gnt_list_entry->pfn));
				ring_req->u.indirect.indirect_grefs[n] = gnt_list_entry->gref;
			}

			gnt_list_entry = get_grant(&gref_head, page_to_pfn(sg_page(sg)), rinfo);
			ref = gnt_list_entry->gref;

			rinfo->shadow[id].grants_used[i] = gnt_list_entry;

			if (rq_data_dir(req) && info->feature_persistent) {
				char *bvec_data;
				void *shared_data;

				BUG_ON(sg->offset + sg->length > PAGE_SIZE);

				shared_data = kmap_atomic(pfn_to_page(gnt_list_entry->pfn));
				bvec_data = kmap_atomic(sg_page(sg));

				/*
				 * this does not wipe data stored outside the
				 * range sg->offset..sg->offset+sg->length.
				 * Therefore, blkback *could* see data from
				 * previous requests. This is OK as long as
				 * persistent grants are shared with just one
				 * domain. It may need refactoring if this
				 * changes
				 */
				memcpy(shared_data + sg->offset,
				       bvec_data   + sg->offset,
				       sg->length);

				kunmap_atomic(bvec_data);
				kunmap_atomic(shared_data);
			}
			if (ring_req->operation != BLKIF_OP_INDIRECT) {
				ring_req->u.rw.seg[i] =
						(struct blkif_request_segment) {
							.gref       = ref,
							.first_sect = fsect,
							.last_sect  = lsect };
			} else {
				n = i % SEGS_PER_INDIRECT_FRAME;
				segments[n] =
					(struct blkif_request_segment) {
							.gref       = ref,
							.first_sect = fsect,
							.last_sect  = lsect };
			}
		}
		if (segments)
			kunmap_atomic(segments);
	}

	ring->req_prod_pvt++;

	/* Keep a private copy so we can reissue requests when recovering. */
	rinfo->shadow[id].req = *ring_req;

	if (new_persistent_gnts)
		gnttab_free_grant_references(gref_head);

	return 0;
}


static inline void flush_requests(struct blkfront_info *info,
				  unsigned int ring_idx)
{
	struct blkfront_ring_info *rinfo = &info->rinfo[ring_idx];
	int notify;

	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&rinfo->ring, notify);

	if (notify)
		notify_remote_via_irq(rinfo->irq);
}

static inline bool blkif_request_flush_mismatch(struct request *req,
						struct blkfront_info *info)
{
	return ((req->cmd_type != REQ_TYPE_FS) ||
		((req->cmd_flags & (REQ_FLUSH | REQ_FUA)) &&
		!info->flush_op));
}

static int blkif_queue_rq(struct blk_mq_hw_ctx *hctx, struct request *req)
{
	struct blkfront_info *info = req->rq_disk->private_data;
	struct blkfront_ring_info *rinfo =
			(struct blkfront_ring_info *)hctx->driver_data;

	pr_debug("Entered blkif_queue_rq\n");

	if (RING_FULL(&rinfo->ring))
		goto wait;

	if (blkif_request_flush_mismatch(req, info)) {
		req->errors = -EIO;
		blk_mq_complete_request(req);
		return BLK_MQ_RQ_QUEUE_ERROR;
	}

	spin_lock_irq(&rinfo->io_lock);
	if (blkif_queue_request(req, rinfo->hctx_index)) {
wait:
		/*
		 * Only stop the hardware queue; the block layer
		 * will take care of requeueing the request when
		 * seeing the return value.
		 */
		blk_mq_stop_hw_queue(hctx);
		return BLK_MQ_RQ_QUEUE_BUSY;
	}

	flush_requests(info, rinfo->hctx_index);
	spin_unlock_irq(&rinfo->io_lock);
	return BLK_MQ_RQ_QUEUE_OK;
}

/*
 * do_blkif_request
 *  read a block; request is in a request queue
 */
static void do_blkif_request(struct request_queue *rq)
{
	struct blkfront_info *info = NULL;
	struct request *req;
	int queued;

	pr_debug("Entered do_blkif_request\n");

	queued = 0;

	while ((req = blk_peek_request(rq)) != NULL) {
		info = req->rq_disk->private_data;
		BUG_ON(info->nr_rings != 1);

		if (RING_FULL(&info->rinfo[0].ring))
			goto wait;

		blk_start_request(req);

		if (blkif_request_flush_mismatch(req, info)) {
			__blk_end_request_all(req, -EIO);
			continue;
		}

		pr_debug("do_blk_req %p: cmd %p, sec %lx, "
			 "(%u/%u) buffer:%p [%s]\n",
			 req, req->cmd, (unsigned long)blk_rq_pos(req),
			 blk_rq_cur_sectors(req), blk_rq_sectors(req),
			 req->buffer, rq_data_dir(req) ? "write" : "read");

		if (blkif_queue_request(req, 0)) {
			blk_requeue_request(rq, req);
wait:
			/* Avoid pointless unplugs. */
			blk_stop_queue(rq);
			break;
		}

		queued++;
	}

	if (queued != 0)
		flush_requests(info, 0);
}

static inline void blkif_complete(struct request *req)
{
	blk_mq_end_io(req, req->errors);
}

static int blkfront_init_hctx(struct blk_mq_hw_ctx *hctx, void *driver_data,
			      unsigned int hctx_index)
{
	struct blkfront_info *info = (struct blkfront_info *)driver_data;

	hctx->driver_data = &info->rinfo[hctx_index];
	info->rinfo[hctx_index].hctx_index = hctx_index;

	return 0;
}

static struct blk_mq_ops blkfront_mq_ops = {
	.queue_rq	= blkif_queue_rq,
	.map_queue	= blk_mq_map_queue,
	.alloc_hctx	= blk_mq_alloc_single_hw_queue,
	.free_hctx	= blk_mq_free_single_hw_queue,
	.init_hctx	= blkfront_init_hctx,
	.complete	= blkif_complete,
};

static struct blk_mq_reg blkfront_mq_reg = {
	.ops		= &blkfront_mq_ops,
	/*
	 * see blkfront_connect() for the initialization of
	 * the following three fields
	 */
	.nr_hw_queues	= 0,
	.queue_depth	= 0,
	.cmd_size	= 0,
	.numa_node	= NUMA_NO_NODE,
	.flags		= BLK_MQ_F_SHOULD_MERGE,
};

static int xlvbd_init_blk_queue(struct gendisk *gd, u16 sector_size,
				unsigned int physical_sector_size,
				unsigned int segments)
{
	struct request_queue *rq;
	struct blkfront_info *info = gd->private_data;

	if (info->nr_hw_queues == 0)
		rq = blk_init_queue(do_blkif_request, &info->rinfo[0].io_lock);
	else
		rq = blk_mq_init_queue(&blkfront_mq_reg, info);
	if (rq == NULL)
		return -1;

	queue_flag_set_unlocked(QUEUE_FLAG_VIRT, rq);

	if (info->feature_discard) {
		queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, rq);
		blk_queue_max_discard_sectors(rq, get_capacity(gd));
		rq->limits.discard_granularity = info->discard_granularity;
		rq->limits.discard_alignment = info->discard_alignment;
		if (info->feature_secdiscard)
			queue_flag_set_unlocked(QUEUE_FLAG_SECDISCARD, rq);
	}

	/* Hard sector size and max sectors impersonate the equiv. hardware. */
	blk_queue_logical_block_size(rq, sector_size);
	blk_queue_physical_block_size(rq, physical_sector_size);
	blk_queue_max_hw_sectors(rq, (segments * PAGE_SIZE) / 512);

	/* Each segment in a request is up to an aligned page in size. */
	blk_queue_segment_boundary(rq, PAGE_SIZE - 1);
	blk_queue_max_segment_size(rq, PAGE_SIZE);

	/* Ensure a merged request will fit in a single I/O ring slot. */
	blk_queue_max_segments(rq, segments);

	/* Make sure buffer addresses are sector-aligned. */
	blk_queue_dma_alignment(rq, 511);

	/* Make sure we don't use bounce buffers. */
	blk_queue_bounce_limit(rq, BLK_BOUNCE_ANY);

	gd->queue = rq;

	return 0;
}


static void xlvbd_flush(struct blkfront_info *info)
{
	blk_queue_flush(info->rq, info->feature_flush);
	printk(KERN_INFO "blkfront: %s: %s: %s %s %s %s %s\n",
	       info->gd->disk_name,
	       info->flush_op == BLKIF_OP_WRITE_BARRIER ?
		"barrier" : (info->flush_op == BLKIF_OP_FLUSH_DISKCACHE ?
		"flush diskcache" : "barrier or flush"),
	       info->feature_flush ? "enabled;" : "disabled;",
	       "persistent grants:",
	       info->feature_persistent ? "enabled;" : "disabled;",
	       "indirect descriptors:",
	       info->max_indirect_segments ? "enabled;" : "disabled;");
}

static int xen_translate_vdev(int vdevice, int *minor, unsigned int *offset)
{
	int major;
	major = BLKIF_MAJOR(vdevice);
	*minor = BLKIF_MINOR(vdevice);
	switch (major) {
		case XEN_IDE0_MAJOR:
			*offset = (*minor / 64) + EMULATED_HD_DISK_NAME_OFFSET;
			*minor = ((*minor / 64) * PARTS_PER_DISK) +
				EMULATED_HD_DISK_MINOR_OFFSET;
			break;
		case XEN_IDE1_MAJOR:
			*offset = (*minor / 64) + 2 + EMULATED_HD_DISK_NAME_OFFSET;
			*minor = (((*minor / 64) + 2) * PARTS_PER_DISK) +
				EMULATED_HD_DISK_MINOR_OFFSET;
			break;
		case XEN_SCSI_DISK0_MAJOR:
			*offset = (*minor / PARTS_PER_DISK) + EMULATED_SD_DISK_NAME_OFFSET;
			*minor = *minor + EMULATED_SD_DISK_MINOR_OFFSET;
			break;
		case XEN_SCSI_DISK1_MAJOR:
		case XEN_SCSI_DISK2_MAJOR:
		case XEN_SCSI_DISK3_MAJOR:
		case XEN_SCSI_DISK4_MAJOR:
		case XEN_SCSI_DISK5_MAJOR:
		case XEN_SCSI_DISK6_MAJOR:
		case XEN_SCSI_DISK7_MAJOR:
			*offset = (*minor / PARTS_PER_DISK) + 
				((major - XEN_SCSI_DISK1_MAJOR + 1) * 16) +
				EMULATED_SD_DISK_NAME_OFFSET;
			*minor = *minor +
				((major - XEN_SCSI_DISK1_MAJOR + 1) * 16 * PARTS_PER_DISK) +
				EMULATED_SD_DISK_MINOR_OFFSET;
			break;
		case XEN_SCSI_DISK8_MAJOR:
		case XEN_SCSI_DISK9_MAJOR:
		case XEN_SCSI_DISK10_MAJOR:
		case XEN_SCSI_DISK11_MAJOR:
		case XEN_SCSI_DISK12_MAJOR:
		case XEN_SCSI_DISK13_MAJOR:
		case XEN_SCSI_DISK14_MAJOR:
		case XEN_SCSI_DISK15_MAJOR:
			*offset = (*minor / PARTS_PER_DISK) + 
				((major - XEN_SCSI_DISK8_MAJOR + 8) * 16) +
				EMULATED_SD_DISK_NAME_OFFSET;
			*minor = *minor +
				((major - XEN_SCSI_DISK8_MAJOR + 8) * 16 * PARTS_PER_DISK) +
				EMULATED_SD_DISK_MINOR_OFFSET;
			break;
		case XENVBD_MAJOR:
			*offset = *minor / PARTS_PER_DISK;
			break;
		default:
			printk(KERN_WARNING "blkfront: your disk configuration is "
					"incorrect, please use an xvd device instead\n");
			return -ENODEV;
	}
	return 0;
}

static char *encode_disk_name(char *ptr, unsigned int n)
{
	if (n >= 26)
		ptr = encode_disk_name(ptr, n / 26 - 1);
	*ptr = 'a' + n % 26;
	return ptr + 1;
}

static int xlvbd_alloc_gendisk(blkif_sector_t capacity,
			       struct blkfront_info *info,
			       u16 vdisk_info, u16 sector_size,
			       unsigned int physical_sector_size)
{
	struct gendisk *gd;
	int nr_minors = 1;
	int err;
	unsigned int offset;
	int minor;
	int nr_parts;
	char *ptr;

	BUG_ON(info->gd != NULL);
	BUG_ON(info->rq != NULL);

	if ((info->vdevice>>EXT_SHIFT) > 1) {
		/* this is above the extended range; something is wrong */
		printk(KERN_WARNING "blkfront: vdevice 0x%x is above the extended range; ignoring\n", info->vdevice);
		return -ENODEV;
	}

	if (!VDEV_IS_EXTENDED(info->vdevice)) {
		err = xen_translate_vdev(info->vdevice, &minor, &offset);
		if (err)
			return err;		
 		nr_parts = PARTS_PER_DISK;
	} else {
		minor = BLKIF_MINOR_EXT(info->vdevice);
		nr_parts = PARTS_PER_EXT_DISK;
		offset = minor / nr_parts;
		if (xen_hvm_domain() && offset < EMULATED_HD_DISK_NAME_OFFSET + 4)
			printk(KERN_WARNING "blkfront: vdevice 0x%x might conflict with "
					"emulated IDE disks,\n\t choose an xvd device name"
					"from xvde on\n", info->vdevice);
	}
	if (minor >> MINORBITS) {
		pr_warn("blkfront: %#x's minor (%#x) out of range; ignoring\n",
			info->vdevice, minor);
		return -ENODEV;
	}

	if ((minor % nr_parts) == 0)
		nr_minors = nr_parts;

	err = xlbd_reserve_minors(minor, nr_minors);
	if (err)
		goto out;
	err = -ENODEV;

	gd = alloc_disk(nr_minors);
	if (gd == NULL)
		goto release;

	strcpy(gd->disk_name, DEV_NAME);
	ptr = encode_disk_name(gd->disk_name + sizeof(DEV_NAME) - 1, offset);
	BUG_ON(ptr >= gd->disk_name + DISK_NAME_LEN);
	if (nr_minors > 1)
		*ptr = 0;
	else
		snprintf(ptr, gd->disk_name + DISK_NAME_LEN - ptr,
			 "%d", minor & (nr_parts - 1));

	gd->major = XENVBD_MAJOR;
	gd->first_minor = minor;
	gd->fops = &xlvbd_block_fops;
	gd->private_data = info;
	gd->driverfs_dev = &(info->xbdev->dev);
	set_capacity(gd, capacity);

	if (xlvbd_init_blk_queue(gd, sector_size, physical_sector_size,
				 info->max_indirect_segments ? :
				 BLKIF_MAX_SEGMENTS_PER_REQUEST)) {
		del_gendisk(gd);
		goto release;
	}

	info->rq = gd->queue;
	info->gd = gd;

	xlvbd_flush(info);

	if (vdisk_info & VDISK_READONLY)
		set_disk_ro(gd, 1);

	if (vdisk_info & VDISK_REMOVABLE)
		gd->flags |= GENHD_FL_REMOVABLE;

	if (vdisk_info & VDISK_CDROM)
		gd->flags |= GENHD_FL_CD;

	return 0;

 release:
	xlbd_release_minors(minor, nr_minors);
 out:
	return err;
}

void blk_mq_free_queue(struct request_queue *q);

static void xlvbd_release_gendisk(struct blkfront_info *info)
{
	unsigned int minor, nr_minors;
	unsigned long *flags;
	int i;

	if (info->rq == NULL)
		return;

	flags = kzalloc(sizeof(unsigned long) * info->nr_rings,
			GFP_KERNEL);
	if (!flags)
		return;
	for (i = 0 ; i < info->nr_rings ; i++)
		spin_lock_irqsave(&info->rinfo[i].io_lock, flags[i]);

	/* No more blkif_request(). */
	if (info->nr_hw_queues == 0)
		blk_stop_queue(info->rq);
	else
		blk_mq_stop_hw_queues(info->rq);

	/* No more gnttab callback work. */
	for (i = 0 ; i < info->nr_rings ; i++) {
		gnttab_cancel_free_callback(&info->rinfo[i].callback);
		spin_unlock_irqrestore(&info->rinfo[i].io_lock, flags[i]);
	}

	/* Flush gnttab callback work. Must be done with no locks held. */
	for (i = 0 ; i < info->nr_rings ; i++)
		flush_work(&info->rinfo[i].work);

	del_gendisk(info->gd);

	minor = info->gd->first_minor;
	nr_minors = info->gd->minors;
	xlbd_release_minors(minor, nr_minors);

	if (info->nr_hw_queues == 0)
		blk_cleanup_queue(info->rq);
	else
		blk_mq_free_queue(info->rq);
	info->rq = NULL;

	put_disk(info->gd);
	info->gd = NULL;
}

static void kick_pending_request_queues(struct blkfront_ring_info *rinfo)
{
	if (!RING_FULL(&rinfo->ring)) {
		struct blkfront_info *info = rinfo->info;
		/*
		 * Re-enable calldowns and kick things off immediately.
		 */
		if (info->nr_hw_queues == 0) {
			blk_start_queue(info->rq);
			do_blkif_request(info->rq);
		} else
			blk_mq_start_stopped_hw_queues(info->rq);
	}
}

static void blkif_restart_queue(struct work_struct *work)
{
	struct blkfront_ring_info *rinfo = container_of(work,
				struct blkfront_ring_info, work);
	struct blkfront_info *info = rinfo->info;

	spin_lock_irq(&rinfo->io_lock);
	if (info->connected == BLKIF_STATE_CONNECTED)
		kick_pending_request_queues(rinfo);
	spin_unlock_irq(&rinfo->io_lock);
}

static void blkif_free_ring(struct blkfront_ring_info *rinfo,
			    int persistent)
{
	struct grant *persistent_gnt;
	int i, j, segs;

	for (i = 0; i < BLK_RING_SIZE; i++) {
		/*
		 * Clear persistent grants present in requests already
		 * on the shared ring
		 */
		if (!rinfo->shadow[i].request)
			goto free_shadow;

		segs = rinfo->shadow[i].req.operation == BLKIF_OP_INDIRECT ?
		       rinfo->shadow[i].req.u.indirect.nr_segments :
		       rinfo->shadow[i].req.u.rw.nr_segments;
		for (j = 0; j < segs; j++) {
			persistent_gnt = rinfo->shadow[i].grants_used[j];
			gnttab_end_foreign_access(persistent_gnt->gref, 0, 0UL);
			if (persistent)
				__free_page(pfn_to_page(persistent_gnt->pfn));
			kfree(persistent_gnt);
		}

		if (rinfo->shadow[i].req.operation != BLKIF_OP_INDIRECT)
			/*
			 * If this is not an indirect operation don't try to
			 * free indirect segments
			 */
			goto free_shadow;

		for (j = 0; j < INDIRECT_GREFS(segs); j++) {
			persistent_gnt = rinfo->shadow[i].indirect_grants[j];
			gnttab_end_foreign_access(persistent_gnt->gref, 0, 0UL);
			__free_page(pfn_to_page(persistent_gnt->pfn));
			kfree(persistent_gnt);
		}

free_shadow:
		kfree(rinfo->shadow[i].grants_used);
		rinfo->shadow[i].grants_used = NULL;
		kfree(rinfo->shadow[i].indirect_grants);
		rinfo->shadow[i].indirect_grants = NULL;
		kfree(rinfo->shadow[i].sg);
		rinfo->shadow[i].sg = NULL;
	}

	/* Free resources associated with old device channel. */
	if (rinfo->ring_ref != GRANT_INVALID_REF) {
		gnttab_end_foreign_access(rinfo->ring_ref, 0,
					  (unsigned long)rinfo->ring.sring);
		rinfo->ring_ref = GRANT_INVALID_REF;
		rinfo->ring.sring = NULL;
	}
	if (rinfo->irq)
		unbind_from_irqhandler(rinfo->irq, rinfo);
	rinfo->evtchn = rinfo->irq = 0;

}

static void blkif_free(struct blkfront_info *info, int suspend)
{
	struct grant *persistent_gnt;
	struct grant *n;
	int i;

	/* Prevent new requests being issued until we fix things up. */
	for (i = 0 ; i < info->nr_rings ; i++)
		spin_lock_irq(&info->rinfo[i].io_lock);
	info->connected = suspend ?
		BLKIF_STATE_SUSPENDED : BLKIF_STATE_DISCONNECTED;
	/* No more blkif_request(). */
	if (info->rq) {
		if (info->nr_hw_queues == 0)
			blk_stop_queue(info->rq);
		else
			blk_mq_stop_hw_queues(info->rq);
	}

	for (i = 0 ; i < info->nr_rings ; i++) {
		struct blkfront_ring_info *rinfo = &info->rinfo[i];
		/* Remove all persistent grants */
		if (!list_empty(&rinfo->grants)) {
			list_for_each_entry_safe(persistent_gnt, n,
			                         &rinfo->grants, node) {
				list_del(&persistent_gnt->node);
				if (persistent_gnt->gref != GRANT_INVALID_REF) {
					gnttab_end_foreign_access(persistent_gnt->gref,
					                          0, 0UL);
					rinfo->persistent_gnts_c--;
				}
				if (info->feature_persistent)
					__free_page(pfn_to_page(persistent_gnt->pfn));
				kfree(persistent_gnt);
			}
		}
		BUG_ON(rinfo->persistent_gnts_c != 0);

		/*
		 * Remove indirect pages, this only happens when using indirect
		 * descriptors but not persistent grants
		 */
		if (!list_empty(&rinfo->indirect_pages)) {
			struct page *indirect_page, *n;

			BUG_ON(info->feature_persistent);
			list_for_each_entry_safe(indirect_page, n, &rinfo->indirect_pages, lru) {
				list_del(&indirect_page->lru);
				__free_page(indirect_page);
			}
		}

		blkif_free_ring(&info->rinfo[i], info->feature_persistent);
	}

	/* No more gnttab callback work. */
	for (i = 0 ; i < info->nr_rings ; i++) {
		gnttab_cancel_free_callback(&info->rinfo[i].callback);
		spin_unlock_irq(&info->rinfo[i].io_lock);
	}

	/* Flush gnttab callback work. Must be done with no locks held. */
	for (i = 0 ; i < info->nr_rings ; i++)
		flush_work(&info->rinfo[i].work);
}

static void blkif_completion(struct blk_shadow *s,
			     struct blkfront_ring_info *rinfo,
			     struct blkif_response *bret)
{
	struct blkfront_info *info = rinfo->info;
	int i = 0;
	struct scatterlist *sg;
	char *bvec_data;
	void *shared_data;
	int nseg;

	nseg = s->req.operation == BLKIF_OP_INDIRECT ?
		s->req.u.indirect.nr_segments : s->req.u.rw.nr_segments;

	if (bret->operation == BLKIF_OP_READ && info->feature_persistent) {
		/*
		 * Copy the data received from the backend into the bvec.
		 * Since bv_offset can be different than 0, and bv_len different
		 * than PAGE_SIZE, we have to keep track of the current offset,
		 * to be sure we are copying the data from the right shared page.
		 */
		for_each_sg(s->sg, sg, nseg, i) {
			BUG_ON(sg->offset + sg->length > PAGE_SIZE);
			shared_data = kmap_atomic(
				pfn_to_page(s->grants_used[i]->pfn));
			bvec_data = kmap_atomic(sg_page(sg));
			memcpy(bvec_data   + sg->offset,
			       shared_data + sg->offset,
			       sg->length);
			kunmap_atomic(bvec_data);
			kunmap_atomic(shared_data);
		}
	}
	/* Add the persistent grant into the list of free grants */
	for (i = 0; i < nseg; i++) {
		if (gnttab_query_foreign_access(s->grants_used[i]->gref)) {
			/*
			 * If the grant is still mapped by the backend (the
			 * backend has chosen to make this grant persistent)
			 * we add it at the head of the list, so it will be
			 * reused first.
			 */
			if (!info->feature_persistent)
				pr_alert_ratelimited("backed has not unmapped grant: %u\n",
						     s->grants_used[i]->gref);
			list_add(&s->grants_used[i]->node, &rinfo->grants);
			rinfo->persistent_gnts_c++;
		} else {
			/*
			 * If the grant is not mapped by the backend we end the
			 * foreign access and add it to the tail of the list,
			 * so it will not be picked again unless we run out of
			 * persistent grants.
			 */
			gnttab_end_foreign_access(s->grants_used[i]->gref, 0, 0UL);
			s->grants_used[i]->gref = GRANT_INVALID_REF;
			list_add_tail(&s->grants_used[i]->node, &rinfo->grants);
		}
	}
	if (s->req.operation == BLKIF_OP_INDIRECT) {
		for (i = 0; i < INDIRECT_GREFS(nseg); i++) {
			if (gnttab_query_foreign_access(s->indirect_grants[i]->gref)) {
				if (!info->feature_persistent)
					pr_alert_ratelimited("backed has not unmapped grant: %u\n",
							     s->indirect_grants[i]->gref);
				list_add(&s->indirect_grants[i]->node, &rinfo->grants);
				rinfo->persistent_gnts_c++;
			} else {
				struct page *indirect_page;

				gnttab_end_foreign_access(s->indirect_grants[i]->gref, 0, 0UL);
				/*
				 * Add the used indirect page back to the list of
				 * available pages for indirect grefs.
				 */
				indirect_page = pfn_to_page(s->indirect_grants[i]->pfn);
				list_add(&indirect_page->lru, &rinfo->indirect_pages);
				s->indirect_grants[i]->gref = GRANT_INVALID_REF;
				list_add_tail(&s->indirect_grants[i]->node, &rinfo->grants);
			}
		}
	}
}

static irqreturn_t blkif_interrupt(int irq, void *dev_id)
{
	struct request *req;
	struct blkif_response *bret;
	RING_IDX i, rp;
	unsigned long flags;
	struct blkfront_ring_info *rinfo = (struct blkfront_ring_info *)dev_id;
	struct blkfront_info *info = rinfo->info;
	int error;

	spin_lock_irqsave(&rinfo->io_lock, flags);

	if (unlikely(info->connected != BLKIF_STATE_CONNECTED)) {
		spin_unlock_irqrestore(&rinfo->io_lock, flags);
		return IRQ_HANDLED;
	}

 again:
	rp = rinfo->ring.sring->rsp_prod;
	rmb(); /* Ensure we see queued responses up to 'rp'. */

	for (i = rinfo->ring.rsp_cons; i != rp; i++) {
		unsigned long id;

		bret = RING_GET_RESPONSE(&rinfo->ring, i);
		id   = bret->id;
		/*
		 * The backend has messed up and given us an id that we would
		 * never have given to it (we stamp it up to BLK_RING_SIZE -
		 * look in get_id_from_freelist.
		 */
		if (id >= BLK_RING_SIZE) {
			WARN(1, "%s: response to %s has incorrect id (%ld)\n",
			     info->gd->disk_name, op_name(bret->operation), id);
			/* We can't safely get the 'struct request' as
			 * the id is busted. */
			continue;
		}
		req  = rinfo->shadow[id].request;

		if (bret->operation != BLKIF_OP_DISCARD)
			blkif_completion(&rinfo->shadow[id], rinfo, bret);

		if (add_id_to_freelist(rinfo, id)) {
			WARN(1, "%s: response to %s (id %ld) couldn't be recycled!\n",
			     info->gd->disk_name, op_name(bret->operation), id);
			continue;
		}

		error = req->errors = (bret->status == BLKIF_RSP_OKAY) ? 0 : -EIO;
		switch (bret->operation) {
		case BLKIF_OP_DISCARD:
			if (unlikely(bret->status == BLKIF_RSP_EOPNOTSUPP)) {
				struct request_queue *rq = info->rq;
				printk(KERN_WARNING "blkfront: %s: %s op failed\n",
					   info->gd->disk_name, op_name(bret->operation));
				error = req->errors = -EOPNOTSUPP;
				info->feature_discard = 0;
				info->feature_secdiscard = 0;
				queue_flag_clear(QUEUE_FLAG_DISCARD, rq);
				queue_flag_clear(QUEUE_FLAG_SECDISCARD, rq);
			}
			if (info->nr_hw_queues == 0)
				__blk_end_request_all(req, error);
			else
				blk_mq_complete_request(req);
			break;
		case BLKIF_OP_FLUSH_DISKCACHE:
		case BLKIF_OP_WRITE_BARRIER:
			if (unlikely(bret->status == BLKIF_RSP_EOPNOTSUPP)) {
				printk(KERN_WARNING "blkfront: %s: %s op failed\n",
				       info->gd->disk_name, op_name(bret->operation));
				error = req->errors = -EOPNOTSUPP;
			}
			if (unlikely(bret->status == BLKIF_RSP_ERROR &&
				     rinfo->shadow[id].req.u.rw.nr_segments == 0)) {
				printk(KERN_WARNING "blkfront: %s: empty %s op failed\n",
				       info->gd->disk_name, op_name(bret->operation));
				error = req->errors = -EOPNOTSUPP;
			}
			if (unlikely(error)) {
				if (error == -EOPNOTSUPP)
					error = req->errors = 0;
				info->feature_flush = 0;
				info->flush_op = 0;
				xlvbd_flush(info);
			}
			/* fall through */
		case BLKIF_OP_READ:
		case BLKIF_OP_WRITE:
			if (unlikely(bret->status != BLKIF_RSP_OKAY))
				dev_dbg(&info->xbdev->dev, "Bad return from blkdev data "
					"request: %x\n", bret->status);

			if (info->nr_hw_queues == 0)
				__blk_end_request_all(req, error);
			else
				blk_mq_complete_request(req);
			break;
		default:
			BUG();
		}
	}

	rinfo->ring.rsp_cons = i;

	if (i != rinfo->ring.req_prod_pvt) {
		int more_to_do;
		RING_FINAL_CHECK_FOR_RESPONSES(&rinfo->ring, more_to_do);
		if (more_to_do)
			goto again;
	} else
		rinfo->ring.sring->rsp_event = i + 1;

	kick_pending_request_queues(rinfo);

	spin_unlock_irqrestore(&rinfo->io_lock, flags);

	return IRQ_HANDLED;
}


static int setup_blkring(struct xenbus_device *dev,
			 struct blkfront_ring_info *rinfo)
{
	struct blkif_sring *sring;
	int err;

	rinfo->ring_ref = GRANT_INVALID_REF;

	sring = (struct blkif_sring *)__get_free_page(GFP_NOIO | __GFP_HIGH);
	if (!sring) {
		xenbus_dev_fatal(dev, -ENOMEM, "allocating shared ring");
		return -ENOMEM;
	}
	SHARED_RING_INIT(sring);
	FRONT_RING_INIT(&rinfo->ring, sring, PAGE_SIZE);

	err = xenbus_grant_ring(dev, virt_to_mfn(rinfo->ring.sring));
	if (err < 0) {
		free_page((unsigned long)sring);
		rinfo->ring.sring = NULL;
		goto fail;
	}
	rinfo->ring_ref = err;

	err = xenbus_alloc_evtchn(dev, &rinfo->evtchn);
	if (err)
		goto fail;

	err = bind_evtchn_to_irqhandler(rinfo->evtchn, blkif_interrupt, 0,
					"blkif", rinfo);
	if (err <= 0) {
		xenbus_dev_fatal(dev, err,
				 "bind_evtchn_to_irqhandler failed");
		goto fail;
	}
	rinfo->irq = err;

	return 0;
fail:
	blkif_free(rinfo->info, 0);
	return err;
}


/* Common code used when first setting up, and when resuming. */
static int talk_to_blkback(struct xenbus_device *dev,
			   struct blkfront_info *info)
{
	const char *message = NULL;
	char ring_ref_s[64] = "", evtchn_s[64] = "";
	struct xenbus_transaction xbt;
	int i, err;

	for (i = 0 ; i < info->nr_rings ; i++) {
		/* Create shared ring, alloc event channel. */
		err = setup_blkring(dev, &info->rinfo[i]);
		if (err)
			goto out;
	}

again:
	err = xenbus_transaction_start(&xbt);
	if (err) {
		xenbus_dev_fatal(dev, err, "starting transaction");
		goto destroy_blkring;
	}

	for (i = 0 ; i < info->nr_rings ; i++) {
		if (info->nr_hw_queues == 0) {
			BUG_ON(i > 0);
			/* Support old XenStore keys */
			snprintf(ring_ref_s, 64, "ring-ref");
			snprintf(evtchn_s, 64, "event-channel");
		} else {
			snprintf(ring_ref_s, 64, "ring-ref-%d", i);
			snprintf(evtchn_s, 64, "event-channel-%d", i);
		}
		err = xenbus_printf(xbt, dev->nodename,
				    ring_ref_s, "%u", info->rinfo[i].ring_ref);
		if (err) {
			message = "writing ring-ref";
			goto abort_transaction;
		}
		err = xenbus_printf(xbt, dev->nodename,
				    evtchn_s, "%u", info->rinfo[i].evtchn);
		if (err) {
			message = "writing event-channel";
			goto abort_transaction;
		}
	}

	err = xenbus_printf(xbt, dev->nodename, "protocol", "%s",
			    XEN_IO_PROTO_ABI_NATIVE);
	if (err) {
		message = "writing protocol";
		goto abort_transaction;
	}
	err = xenbus_printf(xbt, dev->nodename,
			    "feature-persistent", "%u", 1);
	if (err)
		dev_warn(&dev->dev,
			 "writing persistent grants feature to xenbus");

	err = xenbus_transaction_end(xbt, 0);
	if (err) {
		if (err == -EAGAIN)
			goto again;
		xenbus_dev_fatal(dev, err, "completing transaction");
		goto destroy_blkring;
	}

	xenbus_switch_state(dev, XenbusStateInitialised);

	return 0;

 abort_transaction:
	xenbus_transaction_end(xbt, 1);
	if (message)
		xenbus_dev_fatal(dev, err, "%s", message);
 destroy_blkring:
	blkif_free(info, 0);
 out:
	return err;
}

/**
 * Entry point to this code when a new device is created.  Allocate the basic
 * structures and the ring buffer for communication with the backend, and
 * inform the backend of the appropriate details for those.  Switch to
 * Initialised state.
 */
static int blkfront_probe(struct xenbus_device *dev,
			  const struct xenbus_device_id *id)
{
	int err, vdevice, i, r;
	struct blkfront_info *info;
	unsigned int nr_queues;

	/* FIXME: Use dynamic device id if this is not set. */
	err = xenbus_scanf(XBT_NIL, dev->nodename,
			   "virtual-device", "%i", &vdevice);
	if (err != 1) {
		/* go looking in the extended area instead */
		err = xenbus_scanf(XBT_NIL, dev->nodename, "virtual-device-ext",
				   "%i", &vdevice);
		if (err != 1) {
			xenbus_dev_fatal(dev, err, "reading virtual-device");
			return err;
		}
	}

	if (xen_hvm_domain()) {
		char *type;
		int len;
		/* no unplug has been done: do not hook devices != xen vbds */
		if (xen_has_pv_and_legacy_disk_devices()) {
			int major;

			if (!VDEV_IS_EXTENDED(vdevice))
				major = BLKIF_MAJOR(vdevice);
			else
				major = XENVBD_MAJOR;

			if (major != XENVBD_MAJOR) {
				printk(KERN_INFO
						"%s: HVM does not support vbd %d as xen block device\n",
						__FUNCTION__, vdevice);
				return -ENODEV;
			}
		}
		/* do not create a PV cdrom device if we are an HVM guest */
		type = xenbus_read(XBT_NIL, dev->nodename, "device-type", &len);
		if (IS_ERR(type))
			return -ENODEV;
		if (strncmp(type, "cdrom", 5) == 0) {
			kfree(type);
			return -ENODEV;
		}
		kfree(type);
	}
	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		xenbus_dev_fatal(dev, -ENOMEM, "allocating info structure");
		return -ENOMEM;
	}

	mutex_init(&info->mutex);
	info->xbdev = dev;
	info->vdevice = vdevice;
	info->connected = BLKIF_STATE_DISCONNECTED;

	/* Front end dir is a number, which is used as the id. */
	info->handle = simple_strtoul(strrchr(dev->nodename, '/')+1, NULL, 0);
	dev_set_drvdata(&dev->dev, info);

	/* Gather the number of hardware queues as soon as possible */
	err = xenbus_gather(XBT_NIL, info->xbdev->otherend,
			    "nr_supported_hw_queues", "%u", &nr_queues,
			    NULL);
	if (err)
		info->nr_hw_queues = 0;
	else
		info->nr_hw_queues = nr_queues;
	printk(KERN_CRIT "XEN blkfront_probe nr_hw_queues %u\n", info->nr_hw_queues);
	if (info->nr_hw_queues > 0) { /* supports multiqueue */
		blkfront_mq_reg.nr_hw_queues = info->nr_hw_queues;
		blkfront_mq_reg.queue_depth = info->max_indirect_segments ?
					      MAXIMUM_OUTSTANDING_BLOCK_REQS :
					      BLK_RING_SIZE;
		blkfront_mq_reg.cmd_size = max(sizeof(struct blkif_request),
					sizeof(struct blkif_x86_64_request));
	}
	/*
	 * The backend has told us the number of hw queues he wants.
	 * Allocate the correct number of rings.
	 */
	info->nr_rings = info->nr_hw_queues ? : 1;
	printk(KERN_CRIT "XEN blkfront_probe %d\n", info->nr_rings);
	info->rinfo = kzalloc(info->nr_rings * sizeof(struct blkfront_ring_info),
			      GFP_KERNEL);
	for (r = 0 ; r < info->nr_rings ; r++) {
		struct blkfront_ring_info *rinfo = &info->rinfo[r];

		rinfo->info = info;
		rinfo->persistent_gnts_c = 0;
		INIT_LIST_HEAD(&rinfo->grants);
		INIT_LIST_HEAD(&rinfo->indirect_pages);
		INIT_WORK(&rinfo->work, blkif_restart_queue);
		spin_lock_init(&rinfo->io_lock);
		for (i = 0; i < BLK_RING_SIZE; i++)
			rinfo->shadow[i].req.u.rw.id = i+1;
		rinfo->shadow[BLK_RING_SIZE-1].req.u.rw.id = 0x0fffffff;
	}

	err = talk_to_blkback(dev, info);
	if (err) {
		kfree(info);
		dev_set_drvdata(&dev->dev, NULL);
		return err;
	}

	return 0;
}

static void split_bio_end(struct bio *bio, int error)
{
	struct split_bio *split_bio = bio->bi_private;

	if (error)
		split_bio->err = error;

	if (atomic_dec_and_test(&split_bio->pending)) {
		split_bio->bio->bi_phys_segments = 0;
		bio_endio(split_bio->bio, split_bio->err);
		kfree(split_bio);
	}
	bio_put(bio);
}

static int blkif_setup_shadow(struct blkfront_ring_info *rinfo,
			      struct blk_shadow **copy)
{
	int i;

	/* Stage 1: Make a safe copy of the shadow state. */
	*copy = kmemdup(rinfo->shadow, sizeof(rinfo->shadow),
		       GFP_NOIO | __GFP_REPEAT | __GFP_HIGH);
	if (!*copy)
		return -ENOMEM;

	/* Stage 2: Set up free list. */
	memset(&rinfo->shadow, 0, sizeof(rinfo->shadow));
	for (i = 0; i < BLK_RING_SIZE; i++)
		rinfo->shadow[i].req.u.rw.id = i+1;
	rinfo->shadow_free = rinfo->ring.req_prod_pvt;
	rinfo->shadow[BLK_RING_SIZE-1].req.u.rw.id = 0x0fffffff;

	return 0;
}

static int blkif_recover(struct blkfront_info *info)
{
	int i, r;
	struct request *req, *n;
	struct blk_shadow *copy;
	int rc = 0;
	struct bio *bio, *cloned_bio;
	struct bio_list bio_list, merge_bio;
	unsigned int segs, offset;
	int pending, size;
	struct split_bio *split_bio;
	struct list_head requests;

	segs = blkfront_gather_indirect(info);

	for (r = 0 ; r < info->nr_rings ; i++) {
		rc |= blkif_setup_shadow(&info->rinfo[i], &copy);

		rc |= blkfront_setup_indirect(&info->rinfo[i], segs);
		if (rc) {
			kfree(copy);
			return rc;
		}

		segs = info->max_indirect_segments ? : BLKIF_MAX_SEGMENTS_PER_REQUEST;
		blk_queue_max_segments(info->rq, segs);
		bio_list_init(&bio_list);
		INIT_LIST_HEAD(&requests);
		for (i = 0; i < BLK_RING_SIZE; i++) {
			/* Not in use? */
			if (!copy[i].request)
				continue;

			/*
			 * Get the bios in the request so we can re-queue them.
			 */
			if (copy[i].request->cmd_flags &
			    (REQ_FLUSH | REQ_FUA | REQ_DISCARD | REQ_SECURE)) {
				/*
				 * Flush operations don't contain bios, so
				 * we need to requeue the whole request
				 */
				list_add(&copy[i].request->queuelist, &requests);
				continue;
			}
			merge_bio.head = copy[i].request->bio;
			merge_bio.tail = copy[i].request->biotail;
			bio_list_merge(&bio_list, &merge_bio);
			copy[i].request->bio = NULL;
			blk_put_request(copy[i].request);
		}

		kfree(copy);
	}

	/*
	 * If we are using the request interface, empty the queue,
	 * this is important because we might have requests in the
	 * queue with more segments than what we can handle now.
	 */
	if (info->nr_hw_queues == 0) {
		spin_lock_irq(&info->rinfo[0].io_lock);
		while ((req = blk_fetch_request(info->rq)) != NULL) {
			if (req->cmd_flags &
			    (REQ_FLUSH | REQ_FUA | REQ_DISCARD | REQ_SECURE)) {
				list_add(&req->queuelist, &requests);
				continue;
			}
			merge_bio.head = req->bio;
			merge_bio.tail = req->biotail;
			bio_list_merge(&bio_list, &merge_bio);
			req->bio = NULL;
			if (req->cmd_flags & (REQ_FLUSH | REQ_FUA))
				pr_alert("diskcache flush request found!\n");
			__blk_put_request(info->rq, req);
		}
		spin_unlock_irq(&info->rinfo[0].io_lock);
	}

	xenbus_switch_state(info->xbdev, XenbusStateConnected);

	for (i = 0 ; i < info->nr_rings ; i++)
		spin_lock_irq(&info->rinfo[i].io_lock);

	/* Now safe for us to use the shared ring */
	info->connected = BLKIF_STATE_CONNECTED;

	/* Kick any other new requests queued since we resumed */
	for (i = 0 ; i < info->nr_rings ; i++)
		kick_pending_request_queues(&info->rinfo[i]);

	/*
	 * XXX this is most certainly buggy: we are in fact expected
	 *     to handle requests queued in hctxs; also note, in case
	 *     feature_multiqueue is enabled here requests is empty
	 */
	list_for_each_entry_safe(req, n, &requests, queuelist) {
		/* Requeue pending requests (flush or discard) */
		list_del_init(&req->queuelist);
		BUG_ON(req->nr_phys_segments > segs);
		blk_requeue_request(info->rq, req);
	}

	for (i = 0 ; i < info->nr_rings ; i++)
		spin_unlock_irq(&info->rinfo[i].io_lock);

	while ((bio = bio_list_pop(&bio_list)) != NULL) {
		/* Traverse the list of pending bios and re-queue them */
		if (bio_segments(bio) > segs) {
			/*
			 * This bio has more segments than what we can
			 * handle, we have to split it.
			 */
			pending = (bio_segments(bio) + segs - 1) / segs;
			split_bio = kzalloc(sizeof(*split_bio), GFP_NOIO);
			BUG_ON(split_bio == NULL);
			atomic_set(&split_bio->pending, pending);
			split_bio->bio = bio;
			for (i = 0; i < pending; i++) {
				offset = (i * segs * PAGE_SIZE) >> 9;
				size = min((unsigned int)(segs * PAGE_SIZE) >> 9,
					   (unsigned int)bio_sectors(bio) - offset);
				cloned_bio = bio_clone(bio, GFP_NOIO);
				BUG_ON(cloned_bio == NULL);
				bio_trim(cloned_bio, offset, size);
				cloned_bio->bi_private = split_bio;
				cloned_bio->bi_end_io = split_bio_end;
				submit_bio(cloned_bio->bi_rw, cloned_bio);
			}
			/*
			 * Now we have to wait for all those smaller bios to
			 * end, so we can also end the "parent" bio.
			 */
			continue;
		}
		/* We don't need to split this bio */
		submit_bio(bio->bi_rw, bio);
	}

	return 0;
}

/**
 * We are reconnecting to the backend, due to a suspend/resume, or a backend
 * driver restart.  We tear down our blkif structure and recreate it, but
 * leave the device-layer structures intact so that this is transparent to the
 * rest of the kernel.
 */
static int blkfront_resume(struct xenbus_device *dev)
{
	struct blkfront_info *info = dev_get_drvdata(&dev->dev);
	int err;

	dev_dbg(&dev->dev, "blkfront_resume: %s\n", dev->nodename);

	blkif_free(info, info->connected == BLKIF_STATE_CONNECTED);

	err = talk_to_blkback(dev, info);

	/*
	 * We have to wait for the backend to switch to
	 * connected state, since we want to read which
	 * features it supports.
	 */

	return err;
}

static void
blkfront_closing(struct blkfront_info *info)
{
	struct xenbus_device *xbdev = info->xbdev;
	struct block_device *bdev = NULL;

	mutex_lock(&info->mutex);

	if (xbdev->state == XenbusStateClosing) {
		mutex_unlock(&info->mutex);
		return;
	}

	if (info->gd)
		bdev = bdget_disk(info->gd, 0);

	mutex_unlock(&info->mutex);

	if (!bdev) {
		xenbus_frontend_closed(xbdev);
		return;
	}

	mutex_lock(&bdev->bd_mutex);

	if (bdev->bd_openers) {
		xenbus_dev_error(xbdev, -EBUSY,
				 "Device in use; refusing to close");
		xenbus_switch_state(xbdev, XenbusStateClosing);
	} else {
		xlvbd_release_gendisk(info);
		xenbus_frontend_closed(xbdev);
	}

	mutex_unlock(&bdev->bd_mutex);
	bdput(bdev);
}

static void blkfront_setup_discard(struct blkfront_info *info)
{
	int err;
	char *type;
	unsigned int discard_granularity;
	unsigned int discard_alignment;
	unsigned int discard_secure;

	type = xenbus_read(XBT_NIL, info->xbdev->otherend, "type", NULL);
	if (IS_ERR(type))
		return;

	info->feature_secdiscard = 0;
	if (strncmp(type, "phy", 3) == 0) {
		err = xenbus_gather(XBT_NIL, info->xbdev->otherend,
			"discard-granularity", "%u", &discard_granularity,
			"discard-alignment", "%u", &discard_alignment,
			NULL);
		if (!err) {
			info->feature_discard = 1;
			info->discard_granularity = discard_granularity;
			info->discard_alignment = discard_alignment;
		}
		err = xenbus_gather(XBT_NIL, info->xbdev->otherend,
			    "discard-secure", "%d", &discard_secure,
			    NULL);
		if (!err)
			info->feature_secdiscard = discard_secure;

	} else if (strncmp(type, "file", 4) == 0)
		info->feature_discard = 1;

	kfree(type);
}


static int blkfront_gather_indirect(struct blkfront_info *info)
{
	unsigned int indirect_segments, segs;
	int err = xenbus_gather(XBT_NIL, info->xbdev->otherend,
				"feature-max-indirect-segments", "%u",
				&indirect_segments,
				NULL);

	if (err) {
		info->max_indirect_segments = 0;
		segs = BLKIF_MAX_SEGMENTS_PER_REQUEST;
	} else {
		info->max_indirect_segments = min(indirect_segments,
						  xen_blkif_max_segments);
		segs = info->max_indirect_segments;
	}

	return segs;
}

static int blkfront_setup_indirect(struct blkfront_ring_info *rinfo,
				   unsigned int segs)
{
	struct blkfront_info *info = rinfo->info;
	int err, i;

	err = fill_grant_buffer(rinfo, (segs + INDIRECT_GREFS(segs)) * BLK_RING_SIZE);
	if (err)
		goto out_of_memory;

	if (!info->feature_persistent && info->max_indirect_segments) {
		/*
		 * We are using indirect descriptors but not persistent
		 * grants, we need to allocate a set of pages that can be
		 * used for mapping indirect grefs
		 */
		int num = INDIRECT_GREFS(segs) * BLK_RING_SIZE;

		BUG_ON(!list_empty(&rinfo->indirect_pages));
		for (i = 0; i < num; i++) {
			struct page *indirect_page = alloc_page(GFP_NOIO);
			if (!indirect_page)
				goto out_of_memory;
			list_add(&indirect_page->lru, &rinfo->indirect_pages);
		}
	}

	for (i = 0; i < BLK_RING_SIZE; i++) {
		rinfo->shadow[i].grants_used = kzalloc(
			sizeof(rinfo->shadow[i].grants_used[0]) * segs,
			GFP_NOIO);
		rinfo->shadow[i].sg = kzalloc(sizeof(rinfo->shadow[i].sg[0]) * segs, GFP_NOIO);
		if (info->max_indirect_segments)
			rinfo->shadow[i].indirect_grants = kzalloc(
				sizeof(rinfo->shadow[i].indirect_grants[0]) *
				INDIRECT_GREFS(segs),
				GFP_NOIO);
		if ((rinfo->shadow[i].grants_used == NULL) ||
			(rinfo->shadow[i].sg == NULL) ||
		     (info->max_indirect_segments &&
		     (rinfo->shadow[i].indirect_grants == NULL)))
			goto out_of_memory;
		sg_init_table(rinfo->shadow[i].sg, segs);
	}


	return 0;

out_of_memory:
	for (i = 0; i < BLK_RING_SIZE; i++) {
		kfree(rinfo->shadow[i].grants_used);
		rinfo->shadow[i].grants_used = NULL;
		kfree(rinfo->shadow[i].sg);
		rinfo->shadow[i].sg = NULL;
		kfree(rinfo->shadow[i].indirect_grants);
		rinfo->shadow[i].indirect_grants = NULL;
	}
	if (!list_empty(&rinfo->indirect_pages)) {
		struct page *indirect_page, *n;
		list_for_each_entry_safe(indirect_page, n, &rinfo->indirect_pages, lru) {
			list_del(&indirect_page->lru);
			__free_page(indirect_page);
		}
	}
	return -ENOMEM;
}

/*
 * Invoked when the backend is finally 'ready' (and has told produced
 * the details about the physical device - #sectors, size, etc).
 */
static void blkfront_connect(struct blkfront_info *info)
{
	unsigned long long sectors;
	unsigned long sector_size;
	unsigned int physical_sector_size;
	unsigned int binfo;
	unsigned int segs;
	int i, err;
	int barrier, flush, discard, persistent;

	switch (info->connected) {
	case BLKIF_STATE_CONNECTED:
		/*
		 * Potentially, the back-end may be signalling
		 * a capacity change; update the capacity.
		 */
		err = xenbus_scanf(XBT_NIL, info->xbdev->otherend,
				   "sectors", "%Lu", &sectors);
		if (XENBUS_EXIST_ERR(err))
			return;
		printk(KERN_INFO "Setting capacity to %Lu\n",
		       sectors);
		set_capacity(info->gd, sectors);
		revalidate_disk(info->gd);

		return;
	case BLKIF_STATE_SUSPENDED:
		/*
		 * If we are recovering from suspension, we need to wait
		 * for the backend to announce it's features before
		 * reconnecting, at least we need to know if the backend
		 * supports indirect descriptors, and how many.
		 */
		blkif_recover(info);
		return;

	default:
		break;
	}

	dev_dbg(&info->xbdev->dev, "%s:%s.\n",
		__func__, info->xbdev->otherend);

	err = xenbus_gather(XBT_NIL, info->xbdev->otherend,
			    "sectors", "%llu", &sectors,
			    "info", "%u", &binfo,
			    "sector-size", "%lu", &sector_size,
			    NULL);
	if (err) {
		xenbus_dev_fatal(info->xbdev, err,
				 "reading backend fields at %s",
				 info->xbdev->otherend);
		return;
	}

	/*
	 * physcial-sector-size is a newer field, so old backends may not
	 * provide this. Assume physical sector size to be the same as
	 * sector_size in that case.
	 */
	err = xenbus_scanf(XBT_NIL, info->xbdev->otherend,
			   "physical-sector-size", "%u", &physical_sector_size);
	if (err != 1)
		physical_sector_size = sector_size;

	info->feature_flush = 0;
	info->flush_op = 0;

	err = xenbus_gather(XBT_NIL, info->xbdev->otherend,
			    "feature-barrier", "%d", &barrier,
			    NULL);

	/*
	 * If there's no "feature-barrier" defined, then it means
	 * we're dealing with a very old backend which writes
	 * synchronously; nothing to do.
	 *
	 * If there are barriers, then we use flush.
	 */
	if (!err && barrier) {
		info->feature_flush = REQ_FLUSH | REQ_FUA;
		info->flush_op = BLKIF_OP_WRITE_BARRIER;
	}
	/*
	 * And if there is "feature-flush-cache" use that above
	 * barriers.
	 */
	err = xenbus_gather(XBT_NIL, info->xbdev->otherend,
			    "feature-flush-cache", "%d", &flush,
			    NULL);

	if (!err && flush) {
		info->feature_flush = REQ_FLUSH;
		info->flush_op = BLKIF_OP_FLUSH_DISKCACHE;
	}

	err = xenbus_gather(XBT_NIL, info->xbdev->otherend,
			    "feature-discard", "%d", &discard,
			    NULL);

	if (!err && discard)
		blkfront_setup_discard(info);

	err = xenbus_gather(XBT_NIL, info->xbdev->otherend,
			    "feature-persistent", "%u", &persistent,
			    NULL);
	if (err)
		info->feature_persistent = 0;
	else
		info->feature_persistent = persistent;

	segs = blkfront_gather_indirect(info);
	for (i = 0 ; i < info->nr_rings ; i++) {
		err = blkfront_setup_indirect(&info->rinfo[i], segs);
		if (err) {
			xenbus_dev_fatal(info->xbdev, err, "setup_indirect at %s",
					 info->xbdev->otherend);
			return;
		}
	}

	err = xlvbd_alloc_gendisk(sectors, info, binfo, sector_size,
				  physical_sector_size);
	if (err) {
		xenbus_dev_fatal(info->xbdev, err, "xlvbd_add at %s",
				 info->xbdev->otherend);
		return;
	}

	xenbus_switch_state(info->xbdev, XenbusStateConnected);

	/* Kick pending requests. */
	for (i = 0 ; i < info->nr_rings ; i++)
		spin_lock_irq(&info->rinfo[i].io_lock);
	info->connected = BLKIF_STATE_CONNECTED;
	for (i = 0 ; i < info->nr_rings ; i++) {
		kick_pending_request_queues(&info->rinfo[i]);
		spin_unlock_irq(&info->rinfo[i].io_lock);
	}

	add_disk(info->gd);

	info->is_ready = 1;
}

/**
 * Callback received when the backend's state changes.
 */
static void blkback_changed(struct xenbus_device *dev,
			    enum xenbus_state backend_state)
{
	struct blkfront_info *info = dev_get_drvdata(&dev->dev);

	dev_dbg(&dev->dev, "blkfront:blkback_changed to state %d.\n", backend_state);

	switch (backend_state) {
	case XenbusStateInitialising:
	case XenbusStateInitWait:
	case XenbusStateInitialised:
	case XenbusStateReconfiguring:
	case XenbusStateReconfigured:
	case XenbusStateUnknown:
		break;

	case XenbusStateConnected:
		blkfront_connect(info);
		break;

	case XenbusStateClosed:
		if (dev->state == XenbusStateClosed)
			break;
		/* Missed the backend's Closing state -- fallthrough */
	case XenbusStateClosing:
		blkfront_closing(info);
		break;
	}
}

static int blkfront_remove(struct xenbus_device *xbdev)
{
	struct blkfront_info *info = dev_get_drvdata(&xbdev->dev);
	struct block_device *bdev = NULL;
	struct gendisk *disk;

	dev_dbg(&xbdev->dev, "%s removed", xbdev->nodename);

	blkif_free(info, 0);

	mutex_lock(&info->mutex);

	disk = info->gd;
	if (disk)
		bdev = bdget_disk(disk, 0);

	info->xbdev = NULL;
	mutex_unlock(&info->mutex);

	if (!bdev) {
		kfree(info);
		return 0;
	}

	/*
	 * The xbdev was removed before we reached the Closed
	 * state. See if it's safe to remove the disk. If the bdev
	 * isn't closed yet, we let release take care of it.
	 */

	mutex_lock(&bdev->bd_mutex);
	info = disk->private_data;

	dev_warn(disk_to_dev(disk),
		 "%s was hot-unplugged, %d stale handles\n",
		 xbdev->nodename, bdev->bd_openers);

	if (info && !bdev->bd_openers) {
		xlvbd_release_gendisk(info);
		disk->private_data = NULL;
		kfree(info);
	}

	mutex_unlock(&bdev->bd_mutex);
	bdput(bdev);

	return 0;
}

static int blkfront_is_ready(struct xenbus_device *dev)
{
	struct blkfront_info *info = dev_get_drvdata(&dev->dev);

	return info->is_ready && info->xbdev;
}

static int blkif_open(struct block_device *bdev, fmode_t mode)
{
	struct gendisk *disk = bdev->bd_disk;
	struct blkfront_info *info;
	int err = 0;

	mutex_lock(&blkfront_mutex);

	info = disk->private_data;
	if (!info) {
		/* xbdev gone */
		err = -ERESTARTSYS;
		goto out;
	}

	mutex_lock(&info->mutex);

	if (!info->gd)
		/* xbdev is closed */
		err = -ERESTARTSYS;

	mutex_unlock(&info->mutex);

out:
	mutex_unlock(&blkfront_mutex);
	return err;
}

static void blkif_release(struct gendisk *disk, fmode_t mode)
{
	struct blkfront_info *info = disk->private_data;
	struct block_device *bdev;
	struct xenbus_device *xbdev;

	mutex_lock(&blkfront_mutex);

	bdev = bdget_disk(disk, 0);

	if (!bdev) {
		WARN(1, "Block device %s yanked out from us!\n", disk->disk_name);
		goto out_mutex;
	}
	if (bdev->bd_openers)
		goto out;

	/*
	 * Check if we have been instructed to close. We will have
	 * deferred this request, because the bdev was still open.
	 */

	mutex_lock(&info->mutex);
	xbdev = info->xbdev;

	if (xbdev && xbdev->state == XenbusStateClosing) {
		/* pending switch to state closed */
		dev_info(disk_to_dev(bdev->bd_disk), "releasing disk\n");
		xlvbd_release_gendisk(info);
		xenbus_frontend_closed(info->xbdev);
 	}

	mutex_unlock(&info->mutex);

	if (!xbdev) {
		/* sudden device removal */
		dev_info(disk_to_dev(bdev->bd_disk), "releasing disk\n");
		xlvbd_release_gendisk(info);
		disk->private_data = NULL;
		kfree(info);
	}

out:
	bdput(bdev);
out_mutex:
	mutex_unlock(&blkfront_mutex);
}

static const struct block_device_operations xlvbd_block_fops =
{
	.owner = THIS_MODULE,
	.open = blkif_open,
	.release = blkif_release,
	.getgeo = blkif_getgeo,
	.ioctl = blkif_ioctl,
};


static const struct xenbus_device_id blkfront_ids[] = {
	{ "vbd" },
	{ "" }
};

static DEFINE_XENBUS_DRIVER(blkfront, ,
	.probe = blkfront_probe,
	.remove = blkfront_remove,
	.resume = blkfront_resume,
	.otherend_changed = blkback_changed,
	.is_ready = blkfront_is_ready,
);

static int __init xlblk_init(void)
{
	int ret;

	if (!xen_domain())
		return -ENODEV;

	if (!xen_has_pv_disk_devices())
		return -ENODEV;

	if (register_blkdev(XENVBD_MAJOR, DEV_NAME)) {
		printk(KERN_WARNING "xen_blk: can't get major %d with name %s\n",
		       XENVBD_MAJOR, DEV_NAME);
		return -ENODEV;
	}

	ret = xenbus_register_frontend(&blkfront_driver);
	if (ret) {
		unregister_blkdev(XENVBD_MAJOR, DEV_NAME);
		return ret;
	}

	return 0;
}
module_init(xlblk_init);


static void __exit xlblk_exit(void)
{
	xenbus_unregister_driver(&blkfront_driver);
	unregister_blkdev(XENVBD_MAJOR, DEV_NAME);
	kfree(minors);
}
module_exit(xlblk_exit);

MODULE_DESCRIPTION("Xen virtual block device frontend");
MODULE_LICENSE("GPL");
MODULE_ALIAS_BLOCKDEV_MAJOR(XENVBD_MAJOR);
MODULE_ALIAS("xen:vbd");
MODULE_ALIAS("xenblk");
