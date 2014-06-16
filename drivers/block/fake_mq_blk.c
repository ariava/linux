#include <linux/module.h>

#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/blk-mq.h>
#include <linux/hrtimer.h>

static int fake_mq_major;
static int submit_queues;

static int gb = 250;
module_param(gb, int, S_IRUGO);
MODULE_PARM_DESC(gb, "Size in GB");

static int bs = 512;
module_param(bs, int, S_IRUGO);
MODULE_PARM_DESC(bs, "Block size (in bytes)");

static int hw_queue_depth = 64;
module_param(hw_queue_depth, int, S_IRUGO);
MODULE_PARM_DESC(hw_queue_depth, "Queue depth for each hardware queue. Default: 64");

struct fake_mq_cmd {
        struct request *rq;
        char *backend;
};

struct fake_mq {
	struct request_queue *q;
	struct gendisk *disk;
	unsigned int queue_depth;

	unsigned int nr_queues;

	char *hctx_data;
};

/* XXX turn this to a list */
struct fake_mq *fake_mq_dev;

/* No lock because each hctx accesses to separate data */
static void fake_mq_transfer(char *buffer, int write,
			     unsigned long nbytes,
			     struct blk_mq_hw_ctx *hctx)
{
	if (!write)
		memset(buffer, *(char *)hctx->driver_data, nbytes);
}

static int fake_mq_queue_rq(struct blk_mq_hw_ctx *hctx, struct request *rq)
{
	struct fake_mq_cmd *cmd = rq->special;

	cmd->rq = rq;
	cmd->backend = hctx->driver_data;

	fake_mq_transfer(rq->buffer, rq_data_dir(rq), blk_rq_bytes(rq),
			 hctx);
	blk_mq_complete_request(rq);

	return BLK_MQ_RQ_QUEUE_OK;
}

static int fake_mq_init_hctx(struct blk_mq_hw_ctx *hctx, void *driver_data,
			     unsigned int hctx_index)
{
	struct fake_mq *fake_mq = (struct fake_mq *)driver_data;

	hctx->driver_data = &fake_mq->hctx_data[hctx_index];

	return 0;
}

static void fake_mq_softirq_done(struct request *rq)
{
	blk_mq_end_io(rq, 0);
}

static struct blk_mq_ops fake_mq_ops = {
	.queue_rq       = fake_mq_queue_rq,
	.map_queue      = blk_mq_map_queue,
	.init_hctx	= fake_mq_init_hctx,
	.complete	= fake_mq_softirq_done,
};

static struct blk_mq_reg fake_mq_reg = {
	.ops		= &fake_mq_ops,
	.queue_depth	= 64,
	.cmd_size	= sizeof(struct fake_mq_cmd),
	.flags		= BLK_MQ_F_SHOULD_MERGE,
};

static int fake_mq_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void fake_mq_release(struct gendisk *disk, fmode_t mode)
{
}

static const struct block_device_operations fake_mq_fops = {
	.owner =	THIS_MODULE,
	.open =		fake_mq_open,
	.release =	fake_mq_release,
};

static int fake_mq_add_dev(void)
{
	struct gendisk *disk;
	struct fake_mq *fake_mq;
	sector_t size;
	int i;

	fake_mq = kzalloc_node(sizeof(*fake_mq), GFP_KERNEL, NUMA_NO_NODE);
	if (!fake_mq)
		return -ENOMEM;

	fake_mq->hctx_data = kzalloc_node(1 * submit_queues,
					  GFP_KERNEL, NUMA_NO_NODE);
	if (!fake_mq->hctx_data) {
		kfree(fake_mq);
		return -ENOMEM;
	}
	for (i = 0 ; i < submit_queues ; i++)
		fake_mq->hctx_data[i] = i;

	fake_mq_dev = fake_mq;

	fake_mq_reg.numa_node = NUMA_NO_NODE;
	fake_mq_reg.queue_depth = hw_queue_depth;
	fake_mq_reg.nr_hw_queues = submit_queues;
	fake_mq_reg.ops->alloc_hctx = blk_mq_alloc_single_hw_queue;
	fake_mq_reg.ops->free_hctx = blk_mq_free_single_hw_queue;

	fake_mq->q = blk_mq_init_queue(&fake_mq_reg, fake_mq);

	if (!fake_mq->q)
		goto queue_fail;

	fake_mq->q->queuedata = fake_mq;
	//queue_flag_set_unlocked(QUEUE_FLAG_NONROT, nullb->q);

	disk = fake_mq->disk = alloc_disk_node(1, NUMA_NO_NODE);
	if (!disk) {
queue_fail:
		blk_cleanup_queue(fake_mq->q);
		kfree(fake_mq);
		return -ENOMEM;
	}

	/* XXX when/if porting to multiple devices, init an index here */

	blk_queue_logical_block_size(fake_mq->q, bs);
	blk_queue_physical_block_size(fake_mq->q, bs);

	size = gb * 1024 * 1024 * 1024ULL;
	sector_div(size, bs);
	set_capacity(disk, size);

	disk->flags |= GENHD_FL_EXT_DEVT;
	disk->major		= fake_mq_major;
	disk->first_minor	= 0;
	disk->fops		= &fake_mq_fops;
	disk->private_data	= fake_mq;
	disk->queue		= fake_mq->q;
	sprintf(disk->disk_name, "fake_mq");
	add_disk(disk);
	return 0;
}

static void fake_mq_del_dev(struct fake_mq *fake_mq)
{
	del_gendisk(fake_mq->disk);
	blk_cleanup_queue(fake_mq->q);
	put_disk(fake_mq->disk);
	kfree(fake_mq);
}

static int __init fake_mq_init(void)
{
	submit_queues = nr_cpu_ids;

	fake_mq_major = register_blkdev(0, "fake_mq");
	if (fake_mq_major < 0)
		return fake_mq_major;

	if (fake_mq_add_dev()) {
		unregister_blkdev(fake_mq_major, "fake_mq");
		return -EINVAL;
	}

	pr_info("fake_mq: module loaded\n");
	return 0;
}

static void __exit fake_mq_exit(void)
{
	unregister_blkdev(fake_mq_major, "fake_mq");

	fake_mq_del_dev(fake_mq_dev);
}

module_init(fake_mq_init);
module_exit(fake_mq_exit);

MODULE_LICENSE("GPL");
