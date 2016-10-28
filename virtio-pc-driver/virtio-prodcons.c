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

/* to be protected by a lock */
static int virtpc_devcnt = 0;
static LIST_HEAD(virtpc_devs);

struct virtpc_info {
	struct virtio_device	*vdev;
	struct list_head	node;
	unsigned int		devid;
	bool busy;

	struct virtqueue	*vq;
	struct scatterlist	sg[10];
	char			name[40];
	char			*buf[2048];
};

struct virtpc_ioctl {
	unsigned int devid;
	unsigned int wp;
};

struct virtpc_priv {
};

static void skb_xmit_done(struct virtqueue *vq)
{
	//struct virtpc_info *vi = vq->vdev->priv;

	/* Suppress further interrupts. */
	virtqueue_disable_cb(vq);

	/* We were probably waiting for more output buffers. */
	// TODO wake up something
}

#if 0
static void free_old_xmit_skbs(struct virtpc_info *vi)
{
	struct void *cookie;
	unsigned int len;

	while ((cookie = virtqueue_get_buf(vi->vq, &len)) != NULL) {
	}
}

static int xmit_skb(struct send_queue *sq, struct sk_buff *skb)
{
	sg_init_table(vi->sg, 1);
	sg_set_buf(vi->sg, vi->buf, 16);
	return virtqueue_add_outbuf(vi->vq, vi->sg, 1, vi->buf, GFP_ATOMIC);
}

static int produce(void)
{
	struct virtpc_info *vi = NULL;

	/* Free up any pending old buffers before queueing new ones. */
	free_old_xmit_skbs(vi);

	/* Try to transmit */
	xmit_skb(sq, skb);

	if (sq->vq->num_free < 2+1) {
		// TODO stop caller
		if (unlikely(!virtqueue_enable_cb_delayed(vi->vq))) {
			/* More just got used, free them then recheck. */
			free_old_xmit_skbs(sq);
			if (vi->vq->num_free >= 2+1) {
				// TODO restart caller
				virtqueue_disable_cb(vi->vq);
			}
		}
	}

	virtqueue_kick(vi->vq);

	return 0;
}
#endif

static int
virtpc_open(struct inode *inode, struct file *f)
{
	struct virtpc_priv *pc;

	pc = kmalloc(sizeof(*pc), GFP_KERNEL);
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
	struct virtpc_ioctl pcio;
	struct virtpc_info *vi = NULL, *tmp;

	(void)cmd;
	(void)pc;

	if (copy_from_user(&pcio, argp, sizeof(pcio))) {
		return -EFAULT;
	}

	list_for_each_entry(tmp, &virtpc_devs, node) {
		if (tmp->devid == pcio.devid) {
			vi = tmp;
			break;
		}
	}

	if (vi == NULL) {
		return -ENXIO;
	}

	vi->busy = true;

	for (;;) {
		msleep_interruptible(50);
		if (signal_pending(current)) {
			printk("signal received, returning\n");
			break;
		}
	}

	vi->busy = false;

	return 0;
}

static void
virtpc_config_changed(struct virtio_device *vdev)
{
	struct virtpc_info *vi = vdev->priv;

	(void)vi;
}

static void
free_unused_bufs(struct virtpc_info *vi)
{
	void *cookie;

	while ((cookie = virtqueue_detach_unused_buf(vi->vq)) != NULL) {
	}
}

static void virtpc_del_vqs(struct virtpc_info *vi)
{
	struct virtio_device *vdev = vi->vdev;

	vdev->config->del_vqs(vdev);
}

static int virtpc_find_vqs(struct virtpc_info *vi)
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
	callbacks[0] = skb_xmit_done;
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

static void remove_vq_common(struct virtpc_info *vi)
{
	vi->vdev->config->reset(vi->vdev);

	/* Free unused buffers, if any. */
	free_unused_bufs(vi);

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
	int err;

	if (!vdev->config->get) {
		dev_err(&vdev->dev, "%s failure: config access disabled\n",
			__func__);
		return -EINVAL;
	}

	if (virtpc_devcnt == 0) {
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
	vi->devid = virtpc_devcnt ++;
	sprintf(vi->name, "virtio-pc-%d", vi->devid);

	err = virtpc_find_vqs(vi);
	if (err)
		goto free;

	virtio_device_ready(vdev);

	list_add_tail(&vi->node, &virtpc_devs);

	pr_debug("virtpc: registered device %s\n", vi->name);

	return 0;
free:
	kfree(vi);
free_misc:
	if (--virtpc_devcnt <= 0) {
		misc_deregister(&virtpc_misc);
	}
	return err;
}

static void
virtpc_remove(struct virtio_device *vdev)
{
	struct virtpc_info *vi = vdev->priv;

	list_del(&vi->node);
	remove_vq_common(vi);
	kfree(vi);
	if (--virtpc_devcnt <= 0) {
		misc_deregister(&virtpc_misc);
		printk("virtio-prodcons miscdevice deregistered\n");
	}
}

#ifdef CONFIG_PM_SLEEP
static int virtpc_freeze(struct virtio_device *vdev)
{
	struct virtpc_info *vi = vdev->priv;

	remove_vq_common(vi);

	return 0;
}

static int virtpc_restore(struct virtio_device *vdev)
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
