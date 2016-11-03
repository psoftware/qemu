#include <linux/compat.h>
#include <linux/eventfd.h>
#include <linux/vhost.h>
#include <linux/virtio_net.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "vhost.h"

enum {
	VHOST_PC_FEATURES = VHOST_FEATURES
};

struct vhost_pc {
	struct vhost_dev dev;
	struct vhost_virtqueue vq;
	struct vhost_poll poll; /* it should be useless */
};

/* Expects to be always run from workqueue - which acts as
 * read-size critical section for our kind of RCU. */
static void handle_tx(struct vhost_pc *pc)
{
	struct vhost_virtqueue *vq = &pc->vq;
	unsigned out, in;
	int head;
	size_t len, total_len = 0;

	mutex_lock(&vq->mutex);

	vhost_disable_notify(&pc->dev, vq);

	for (;;) {
                head = vhost_get_vq_desc(vq, vq->iov, ARRAY_SIZE(vq->iov),
                                         &out, &in, NULL, NULL);
		/* On error, stop handling until the next kick. */
		if (unlikely(head < 0))
			break;
		/* Nothing new?  Wait for eventfd to tell us they refilled. */
		if (head == vq->num) {
			if (unlikely(vhost_enable_notify(&pc->dev, vq))) {
				vhost_disable_notify(&pc->dev, vq);
				continue;
			}
			break;
		}
		if (in) {
			vq_err(vq, "Unexpected descriptor format for TX: "
			       "out %d, int %d\n", out, in);
			break;
		}
		len = iov_length(vq->iov, out);
                printk("msglen %d\n", (int)len);

		vhost_add_used_and_signal(&pc->dev, vq, head, 0);
		total_len += len;
	}
	mutex_unlock(&vq->mutex);
}

static void handle_tx_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue,
						  poll.work);
	struct vhost_pc *pc = container_of(vq->dev, struct vhost_pc, dev);

	handle_tx(pc);
}

static void handle_tx_poll(struct vhost_work *work)
{
	struct vhost_pc *pc = container_of(work, struct vhost_pc,
					    poll.work);
	handle_tx(pc);
}

static int vhost_pc_open(struct inode *inode, struct file *f)
{
	struct vhost_pc *pc;
	struct vhost_dev *dev;
	struct vhost_virtqueue **vqs;

	pc= kmalloc(sizeof *pc, GFP_KERNEL | __GFP_NOWARN | __GFP_REPEAT);
	if (!pc) {
		pc = vmalloc(sizeof *pc);
		if (!pc)
			return -ENOMEM;
	}
	vqs = kmalloc(1 * sizeof(*vqs), GFP_KERNEL);
	if (!vqs) {
		kvfree(pc);
		return -ENOMEM;
	}

	dev = &pc->dev;
	vqs[0] = &pc->vq;
	pc->vq.handle_kick = handle_tx_kick;
	vhost_dev_init(dev, vqs, 1);

	vhost_poll_init(&pc->poll, handle_tx_poll, POLLOUT, dev);

	f->private_data = pc;

	return 0;
}

static void vhost_pc_flush(struct vhost_pc *pc)
{
	vhost_poll_flush(&pc->poll);
	vhost_poll_flush(&pc->vq.poll);
}

static int vhost_pc_release(struct inode *inode, struct file *f)
{
	struct vhost_pc *pc = f->private_data;

	vhost_pc_flush(pc);
	vhost_dev_stop(&pc->dev);
	vhost_dev_cleanup(&pc->dev, false);
	/* Make sure no callbacks are outstanding */
	synchronize_rcu_bh();
	/* We do an extra flush before freeing memory,
	 * since jobs can re-queue themselves. */
	vhost_pc_flush(pc);
	kfree(pc->dev.vqs);
	kvfree(pc);
	return 0;
}

static long vhost_pc_reset_owner(struct vhost_pc *pc)
{
	struct vhost_memory *memory;
	long err;

	mutex_lock(&pc->dev.mutex);
	err = vhost_dev_check_owner(&pc->dev);
	if (err)
		goto done;
	memory = vhost_dev_reset_owner_prepare();
	if (!memory) {
		err = -ENOMEM;
		goto done;
	}
	vhost_pc_flush(pc);
	vhost_dev_reset_owner(&pc->dev, memory);
done:
	mutex_unlock(&pc->dev.mutex);
	return err;
}

static int vhost_pc_set_features(struct vhost_pc *pc, u64 features)
{
	mutex_lock(&pc->dev.mutex);
	if ((features & (1 << VHOST_F_LOG_ALL)) &&
	    !vhost_log_access_ok(&pc->dev)) {
		mutex_unlock(&pc->dev.mutex);
		return -EFAULT;
	}
        mutex_lock(&pc->vq.mutex);
        pc->vq.acked_features = features;
        mutex_unlock(&pc->vq.mutex);
	mutex_unlock(&pc->dev.mutex);
	return 0;
}

static long vhost_pc_set_owner(struct vhost_pc *pc)
{
	int r;

	mutex_lock(&pc->dev.mutex);
	if (vhost_dev_has_owner(&pc->dev)) {
		r = -EBUSY;
		goto out;
	}
	r = vhost_dev_set_owner(&pc->dev);
	if (r)
                goto out;
	vhost_pc_flush(pc);
out:
	mutex_unlock(&pc->dev.mutex);
	return r;
}

static long vhost_pc_ioctl(struct file *f, unsigned int ioctl,
			    unsigned long arg)
{
	struct vhost_pc *pc = f->private_data;
	void __user *argp = (void __user *)arg;
	u64 __user *featurep = argp;
	u64 features;
	int r;

	switch (ioctl) {
	case VHOST_GET_FEATURES:
		features = VHOST_PC_FEATURES;
		if (copy_to_user(featurep, &features, sizeof features))
			return -EFAULT;
		return 0;
	case VHOST_SET_FEATURES:
		if (copy_from_user(&features, featurep, sizeof features))
			return -EFAULT;
		if (features & ~VHOST_PC_FEATURES)
			return -EOPNOTSUPP;
		return vhost_pc_set_features(pc, features);
	case VHOST_RESET_OWNER:
		return vhost_pc_reset_owner(pc);
	case VHOST_SET_OWNER:
		return vhost_pc_set_owner(pc);
	default:
		mutex_lock(&pc->dev.mutex);
		r = vhost_dev_ioctl(&pc->dev, ioctl, argp);
		if (r == -ENOIOCTLCMD)
			r = vhost_vring_ioctl(&pc->dev, ioctl, argp);
		else
			vhost_pc_flush(pc);
		mutex_unlock(&pc->dev.mutex);
		return r;
	}
}

#ifdef CONFIG_COMPAT
static long vhost_pc_compat_ioctl(struct file *f, unsigned int ioctl,
				   unsigned long arg)
{
	return vhost_pc_ioctl(f, ioctl, (unsigned long)compat_ptr(arg));
}
#endif

static const struct file_operations vhost_pc_fops = {
	.owner          = THIS_MODULE,
	.release        = vhost_pc_release,
	.unlocked_ioctl = vhost_pc_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = vhost_pc_compat_ioctl,
#endif
	.open           = vhost_pc_open,
	.llseek		= noop_llseek,
};

static struct miscdevice vhost_pc_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "vhost-pc",
	.fops = &vhost_pc_fops,
};

static int vhost_pc_init(void)
{
	return misc_register(&vhost_pc_misc);
}
module_init(vhost_pc_init);

static void vhost_pc_exit(void)
{
	misc_deregister(&vhost_pc_misc);
}
module_exit(vhost_pc_exit);

MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Vincenzo Maffione");
MODULE_DESCRIPTION("Host kernel accelerator for virtio pc");
