#include <linux/compat.h>
#include <linux/eventfd.h>
#include <linux/vhost.h>
#include <linux/virtio_net.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/hrtimer.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/delay.h>

#include "vhost.h"
#include "producer.h"


static long tscofs = 0;
module_param(tscofs, long, 0644);

#define VHOST_PC_FEATURES   VHOST_FEATURES

struct vhost_pc {
    struct vhost_dev        hdev;
    struct vhost_virtqueue  vq;
    unsigned int            wc; /* in nanoseconds */
    unsigned int            yc; /* in nanoseconds */
    unsigned int            csleep; /* boolean */
    unsigned int            incsc; /* in nanoseconds */
    u64                     items;
    u64                     kicks;
    u64                     latency;
    u64                     last_dump;
    u64                     next_dump;
};

/******************************* TSC support ***************************/

/* initialize to avoid a division by 0 */
static uint64_t ticks_per_second = 1000000000; /* set by calibrate_tsc */

#define NS2TSC(x) ((x)*ticks_per_second/1000000000UL)
#define TSC2NS(x) ((x)*1000000000UL/ticks_per_second)

/*
 * do an idle loop to compute the clock speed. We expect
 * a constant TSC rate and locked on all CPUs.
 * Returns ticks per second
 */
static uint64_t
calibrate_tsc(void)
{
    uint64_t a, b;
    uint64_t ta_0, ta_1, tb_0, tb_1, dmax = ~0;
    uint64_t da, db, cy = 0;
    int i;
    for (i=0; i < 3; i++) {
	ta_0 = rdtsc();
        a = ktime_get_ns();
	ta_1 = rdtsc();
	usleep_range(20000, 20000);
	tb_0 = rdtsc();
        b = ktime_get_ns();
	tb_1 = rdtsc();
	da = ta_1 - ta_0;
	db = tb_1 - tb_0;
	if (da + db < dmax) {
            cy = b - a;
	    cy = ((tb_0 - ta_1)*1000000000)/cy;
	    dmax = da + db;
	}
    }
    ticks_per_second = cy;
    return cy;
}

/***********************************************************************/

static void consume(struct vhost_work *work)
{
    struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue,
                                              poll.work);
    struct vhost_pc *pc = container_of(vq->dev, struct vhost_pc, hdev);
    unsigned out, in;
    bool intr;
    int head;
    u64 next;
    u64 ts;

    mutex_lock(&vq->mutex);

    pc->kicks++;

    vhost_disable_notify(&pc->hdev, vq);

    if (pc->incsc) {
        next = ktime_get_ns() + pc->incsc;
        while (ktime_get_ns() < next) ;
    }

    next = ktime_get_ns() + pc->wc;

    for (;;) {
retry:
        head = vhost_get_vq_desc(vq, vq->iov, ARRAY_SIZE(vq->iov),
                &out, &in, NULL, NULL);
        /* On error, stop handling until the next kick. */
        if (unlikely(head < 0))
            break;

        /* Nothing new?  Wait for eventfd to tell us they refilled, or
         * sleep for a short while. */
        if (head == vq->num) {
            if (pc->csleep) {
                /* Taken from usleep_range */
                ktime_t to = ktime_set(0, pc->yc);
                __set_current_state(TASK_UNINTERRUPTIBLE);
                schedule_hrtimeout_range(&to, 0, HRTIMER_MODE_REL);
                goto retry;
            } else {
                if (unlikely(vhost_enable_notify(&pc->hdev, vq))) {
                    vhost_disable_notify(&pc->hdev, vq);
                    continue;
                }
                break;
            }
        }
        if (in) {
            vq_err(vq, "Unexpected descriptor format for TX: "
                    "out %d, int %d\n", out, in);
            break;
        }

        ts = *((u64*)(vq->iov->iov_base));
#if 0
        printk("msglen %d\n", (int)iov_length(vq->iov, out));
#endif

        while (ktime_get_ns() < next) ;
        next += pc->wc;

        vhost_add_used(vq, head, 0);
        intr = vhost_notify(&pc->hdev, vq);
        pc->items ++;
        ts = rdtsc() - (ts - tscofs);
        if (ts > pc->latency) {
            pc->latency = ts;
        } else {
            pc->latency = ((pc->latency * 120) >> 7) + (ts >> 4);
        }
        if (intr) {
            vhost_do_signal(vq);
            /* When the costly notification routine returns, we need to
             * reset next to correctly emulate the consumption of the
             * next item. */
            next = ktime_get_ns() + pc->wc;
        }

        if (unlikely(next > pc->next_dump)) {
            u64 ndiff = ktime_get_ns() - pc->last_dump;

            printk("PC: %llu items/s %llu kicks/s %llu avg_batch %llu latency\n",
                    (pc->items * 1000000000)/ndiff,
                    (pc->kicks * 1000000000)/ndiff,
                    pc->kicks ? (pc->items/pc->kicks) : 0,
                    TSC2NS(pc->latency));

            pc->items = pc->kicks = pc->latency = 0;

            pc->last_dump = ktime_get_ns();
            pc->next_dump = pc->last_dump + 1000000000;
        }
    }
    mutex_unlock(&vq->mutex);
}

static int vhost_pc_open(struct inode *inode, struct file *f)
{
    struct vhost_pc *pc;
    struct vhost_dev *hdev;
    struct vhost_virtqueue **vqs;

    pc = kmalloc(sizeof *pc, GFP_KERNEL | __GFP_NOWARN | __GFP_REPEAT);
    if (!pc) {
        return -ENOMEM;
    }
    memset(pc, 0, sizeof(*pc));
    vqs = kmalloc(1 * sizeof(*vqs), GFP_KERNEL);
    if (!vqs) {
        kvfree(pc);
        return -ENOMEM;
    }

    pc->wc = 2000; /* default to 2 microseconds */
    pc->yc = 3000; /* default to 3 microseconds */
    pc->last_dump = pc->next_dump = ktime_get_ns();
    hdev = &pc->hdev;
    vqs[0] = &pc->vq;
    pc->vq.handle_kick = consume;
    vhost_dev_init(hdev, vqs, 1);

    f->private_data = pc;

    calibrate_tsc();

    return 0;
}

static void vhost_pc_flush(struct vhost_pc *pc)
{
    pc->csleep = 0;
    vhost_poll_flush(&pc->vq.poll);
}

static int vhost_pc_release(struct inode *inode, struct file *f)
{
    struct vhost_pc *pc = f->private_data;

    vhost_pc_flush(pc);
    vhost_dev_stop(&pc->hdev);
    vhost_dev_cleanup(&pc->hdev, false);
    /* Make sure no callbacks are outstanding */
    synchronize_rcu_bh();
    /* We do an extra flush before freeing memory,
     * since jobs can re-queue themselves. */
    vhost_pc_flush(pc);
    kfree(pc->hdev.vqs);
    kvfree(pc);
    return 0;
}

static long vhost_pc_reset_owner(struct vhost_pc *pc)
{
    struct vhost_memory *memory;
    long err;

    mutex_lock(&pc->hdev.mutex);
    err = vhost_dev_check_owner(&pc->hdev);
    if (err)
        goto done;
    memory = vhost_dev_reset_owner_prepare();
    if (!memory) {
        err = -ENOMEM;
        goto done;
    }
    vhost_pc_flush(pc);
    vhost_dev_reset_owner(&pc->hdev, memory);
done:
    mutex_unlock(&pc->hdev.mutex);
    return err;
}

static int vhost_pc_set_features(struct vhost_pc *pc, u64 features)
{
    mutex_lock(&pc->hdev.mutex);
    if ((features & (1 << VHOST_F_LOG_ALL)) &&
            !vhost_log_access_ok(&pc->hdev)) {
        mutex_unlock(&pc->hdev.mutex);
        return -EFAULT;
    }
    mutex_lock(&pc->vq.mutex);
    pc->vq.acked_features = features;
    mutex_unlock(&pc->vq.mutex);
    mutex_unlock(&pc->hdev.mutex);
    return 0;
}

static long vhost_pc_set_owner(struct vhost_pc *pc)
{
    int r;

    mutex_lock(&pc->hdev.mutex);
    if (vhost_dev_has_owner(&pc->hdev)) {
        r = -EBUSY;
        goto out;
    }
    r = vhost_dev_set_owner(&pc->hdev);
    if (r)
        goto out;
    vhost_pc_flush(pc);
out:
    mutex_unlock(&pc->hdev.mutex);
    return r;
}

static long vhost_pc_ioctl(struct file *f, unsigned int ioctl,
        unsigned long arg)
{
    struct vhost_pc *pc = f->private_data;
    void __user *argp = (void __user *)arg;
    u64 __user *featurep = argp;
    struct vhost_vring_file file;
    u64 features;
    int r;

    switch (ioctl) {
        case VHOST_NET_SET_BACKEND:
            if (copy_from_user(&file, argp, sizeof(file))) {
                return -EFAULT;
            }
            switch (file.index) {
                case VPC_WC:
                    pc->wc = (unsigned int)file.fd;
                    printk("virtpc: set Wc=%uns\n", pc->wc);
                    break;

                case VPC_YC:
                    pc->yc = (unsigned int)file.fd;
                    printk("virtpc: set Yc=%uns\n", pc->yc);
                    break;

                case VPC_CSLEEP:
                    pc->csleep = (unsigned int)file.fd;
                    printk("virtpc: set csleep=%u\n", pc->csleep);
                    break;

                case VPC_INCSC:
                    pc->incsc = (unsigned int)file.fd;
                    printk("virtpc: set incSc=%u\n", pc->incsc);
                    break;

                default:
                    printk("virtpc: unknown param %u\n", file.index);
                    return -EINVAL;
            }
            return 0;
        case VHOST_GET_FEATURES:
            features = VHOST_PC_FEATURES;
            if (copy_to_user(featurep, &features, sizeof features))
                return -EFAULT;
            printk("virtpc: GET_FEATURES %lx\n", (long unsigned)features);
            return 0;
        case VHOST_SET_FEATURES:
            if (copy_from_user(&features, featurep, sizeof features))
                return -EFAULT;
            printk("virtpc: SET_FEATURES %lx\n", (long unsigned)features);
            if (features & ~VHOST_PC_FEATURES)
                return -EOPNOTSUPP;
            return vhost_pc_set_features(pc, features);
        case VHOST_RESET_OWNER:
            printk("virtpc: RESET OWNER\n");
            return vhost_pc_reset_owner(pc);
        case VHOST_SET_OWNER:
            printk("virtpc: SET OWNER\n");
            return vhost_pc_set_owner(pc);
        default:
            mutex_lock(&pc->hdev.mutex);
            r = vhost_dev_ioctl(&pc->hdev, ioctl, argp);
            if (r == -ENOIOCTLCMD)
                r = vhost_vring_ioctl(&pc->hdev, ioctl, argp);
            else
                vhost_pc_flush(pc);
            mutex_unlock(&pc->hdev.mutex);
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
