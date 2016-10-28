/* Virtio prodcons driver.
 *
 * Copyright 2016 Vincenzo Maffione
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <asm/uaccess.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/wait.h>

#include "virtio-prodcons.h"

#define DBG
//#undef DBG

/* Protected by a global lock. */
static int virtpc_devcnt = 0;
static LIST_HEAD(virtpc_devs);
DEFINE_MUTEX(lock);

struct virtpc_info {
	struct virtio_device	*vdev;
	struct list_head	node;
	unsigned int		devid;
	bool busy;

	wait_queue_head_t	wqh;
	struct virtqueue	*vq;
	struct scatterlist	sg[10];
	char			name[40];
	char			*buf[2048];
};

struct virtpc_priv {
};

static void
item_produced(struct virtqueue *vq)
{
	struct virtpc_info *vi = vq->vdev->priv;

	/* Suppress further interrupts and wake up the producer. */
	virtqueue_disable_cb(vq);
	wake_up_interruptible(&vi->wqh);
}

static void
cleanup_items(struct virtpc_info *vi)
{
	void *cookie;
	unsigned int len;

	while ((cookie = virtqueue_get_buf(vi->vq, &len)) != NULL) {
#ifdef DBG
		printk("virtpc: virtqueue_get_buf --> %p\n", cookie);
#endif
	}
}

static int
produce(struct virtpc_info *vi)
{
	struct virtqueue *vq = vi->vq;
	int err;

	/* The same buffer is reused. */
	sg_init_table(vi->sg, 1);
	sg_set_buf(vi->sg, vi->buf, 16);

	for (;;) {
		if (signal_pending(current)) {
			printk("signal received, returning\n");
			return -EAGAIN;
		}

		if (vq->num_free < 2) {
			cleanup_items(vi);
		}

		if (vq->num_free < 2) {
			set_current_state(TASK_INTERRUPTIBLE);
			if (!virtqueue_enable_cb_delayed(vq)) {
				/* More just got used, free them then recheck. */
				cleanup_items(vi);
			}
			if (vq->num_free >= 2) {
				virtqueue_disable_cb(vq);
				set_current_state(TASK_RUNNING);
			} else {
				schedule();
			}
		}

		err = virtqueue_add_outbuf(vq, vi->sg, 1, vi->buf, GFP_ATOMIC);
		if (unlikely(err)) {
			printk("virtpc: add_outbuf() failed %d\n", err);
#ifdef DBG
		} else {
			printk("virtpc: virtqueue_add_outbuf --> %p\n", vi->buf);
#endif
		}

		virtqueue_kick(vq);
		msleep_interruptible(1000);
	}

	return 0;
}

static int
virtpc_open(struct inode *inode, struct file *f)
{
	struct virtpc_priv *pc = kmalloc(sizeof(*pc), GFP_KERNEL);
	if (!pc) {
		return -ENOMEM;
	}
	f->private_data = pc;
	return 0;
}

static int
virtpc_release(struct inode *inode, struct file *f)
{
	struct virtpc_priv *pc = f->private_data;
	if (pc) {
		kfree(pc);
	}
	return 0;
}

static long
virtpc_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct virtpc_priv *pc = f->private_data;
	void __user *argp = (void __user *)arg;
	struct virtpc_info *vi = NULL, *tmp;
	DECLARE_WAITQUEUE(wait, current);
	struct virtpc_ioctl pcio;
	int ret = 0;

	(void)cmd;
	(void)pc;

	if (copy_from_user(&pcio, argp, sizeof(pcio))) {
		return -EFAULT;
	}

	mutex_lock(&lock);
	list_for_each_entry(tmp, &virtpc_devs, node) {
		if (tmp->devid == pcio.devid) {
			vi = tmp;
			break;
		}
	}

	if (vi == NULL || vi->busy) {
		mutex_unlock(&lock);
		return vi ? -EBUSY : -ENXIO;
	}

	vi->busy = true;
	mutex_unlock(&lock);

	add_wait_queue(&vi->wqh, &wait);
	ret = produce(vi);
	remove_wait_queue(&vi->wqh, &wait);

	mutex_lock(&lock);
	vi->busy = false;
	mutex_unlock(&lock);

	return ret;
}

static void
virtpc_config_changed(struct virtio_device *vdev)
{
	struct virtpc_info *vi = vdev->priv;
	(void)vi;
}

static void
detach_unused_bufs(struct virtpc_info *vi)
{
	void *cookie;

	while ((cookie = virtqueue_detach_unused_buf(vi->vq)) != NULL) {
	}
}

static void
virtpc_del_vqs(struct virtpc_info *vi)
{
	struct virtio_device *vdev = vi->vdev;

	vdev->config->del_vqs(vdev);
}

static int
virtpc_find_vqs(struct virtpc_info *vi)
{
	vq_callback_t **callbacks;
	struct virtqueue **vqs;
	const char **names;
	int ret = -ENOMEM;
	int num_vqs;

	num_vqs = 1;

	/* Allocate space for find_vqs parameters. */
	vqs = kzalloc(num_vqs * sizeof(*vqs), GFP_KERNEL);
	if (!vqs)
		goto err_vq;
	callbacks = kmalloc(num_vqs * sizeof(*callbacks), GFP_KERNEL);
	if (!callbacks)
		goto err_callback;
	names = kmalloc(num_vqs * sizeof(*names), GFP_KERNEL);
	if (!names)
		goto err_names;

	/* Allocate/initialize parameters for virtqueues. */
	callbacks[0] = item_produced;
	names[0] = vi->name;

	ret = vi->vdev->config->find_vqs(vi->vdev, num_vqs, vqs, callbacks,
					 names);
	if (ret)
		goto err_find;

	vi->vq = vqs[0];

	kfree(names);
	kfree(callbacks);
	kfree(vqs);

	return 0;

err_find:
	kfree(names);
err_names:
	kfree(callbacks);
err_callback:
	kfree(vqs);
err_vq:
	return ret;
}

static void
remove_vq_common(struct virtpc_info *vi)
{
	vi->vdev->config->reset(vi->vdev);
	detach_unused_bufs(vi);
	virtpc_del_vqs(vi);
}

static const struct file_operations virtpc_fops = {
	.owner		= THIS_MODULE,
	.release	= virtpc_release,
	.open		= virtpc_open,
	.unlocked_ioctl	= virtpc_ioctl,
	.llseek		= noop_llseek,
};

static struct miscdevice virtpc_misc = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "virtio-pc",
	.fops		= &virtpc_fops,
};

static int
virtpc_probe(struct virtio_device *vdev)
{
	struct virtpc_info *vi;
	unsigned int devcnt;
	int err;

	if (!vdev->config->get) {
		dev_err(&vdev->dev, "%s failure: config access disabled\n",
			__func__);
		return -EINVAL;
	}

	mutex_lock(&lock);
	devcnt = virtpc_devcnt ++;
	mutex_unlock(&lock);

	if (devcnt == 0) {
		err = misc_register(&virtpc_misc);
		if (err) {
			printk("Failed to register miscdevice\n");
			return err;
		}
		printk("virtio-prodcons miscdevice registered\n");
	}

	vi = kzalloc(sizeof(*vi), GFP_KERNEL);
	if (!vi) {
		err = -ENOMEM;
		goto free_misc;
	}

	vi->vdev = vdev;
	vdev->priv = vi;
	vi->devid = devcnt;
	init_waitqueue_head(&vi->wqh);
	sprintf(vi->name, "virtio-pc-%d", vi->devid);

	err = virtpc_find_vqs(vi);
	if (err)
		goto free;

	virtio_device_ready(vdev);

	mutex_lock(&lock);
	list_add_tail(&vi->node, &virtpc_devs);
	mutex_unlock(&lock);

	printk("virtpc: added device %s\n", vi->name);

	return 0;
free:
	kfree(vi);
free_misc:
	mutex_lock(&lock);
	-- virtpc_devcnt;
	mutex_unlock(&lock);
	if (--devcnt == 0) {
		misc_deregister(&virtpc_misc);
	}
	return err;
}

static void
virtpc_remove(struct virtio_device *vdev)
{
	struct virtpc_info *vi = vdev->priv;
	unsigned int devcnt;

	mutex_lock(&lock);
	printk("virtpc: removed device %s\n", vi->name);
	list_del(&vi->node);
	mutex_unlock(&lock);
	remove_vq_common(vi);
	kfree(vi);

	mutex_lock(&lock);
	devcnt = -- virtpc_devcnt;
	mutex_unlock(&lock);
	if (devcnt <= 0) {
		misc_deregister(&virtpc_misc);
		printk("virtio-prodcons miscdevice deregistered\n");
	}
}

#ifdef CONFIG_PM_SLEEP
static int
virtpc_freeze(struct virtio_device *vdev)
{
	struct virtpc_info *vi = vdev->priv;

	remove_vq_common(vi);

	return 0;
}

static int
virtpc_restore(struct virtio_device *vdev)
{
	struct virtpc_info *vi = vdev->priv;
	int err;

	err = virtpc_find_vqs(vi);
	if (err)
		return err;

	virtio_device_ready(vdev);

	return 0;
}
#endif

/* ID must be consistent with include/standard-headers/linux/virtio_ids.h */
#define VIRTIO_ID_PRODCONS	20

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_PRODCONS, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
	VIRTIO_F_ANY_LAYOUT,
};

static struct virtio_driver virtio_pc_driver = {
	.feature_table		= features,
	.feature_table_size	= ARRAY_SIZE(features),
	.driver.name		= KBUILD_MODNAME,
	.driver.owner		= THIS_MODULE,
	.id_table		= id_table,
	.probe			= virtpc_probe,
	.remove			= virtpc_remove,
	.config_changed		= virtpc_config_changed,
#ifdef CONFIG_PM_SLEEP
	.freeze			= virtpc_freeze,
	.restore		= virtpc_restore,
#endif
};

module_virtio_driver(virtio_pc_driver);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio prodcons driver");
MODULE_LICENSE("GPL");
