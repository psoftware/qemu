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

struct virtpc_info {
	struct virtio_device *vdev;

	struct virtqueue *vq;
	struct scatterlist sg[10];
	char name[40];
	char *buf[2048];
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

static void virtpc_config_changed(struct virtio_device *vdev)
{
	struct virtpc_info *vi = vdev->priv;

	(void)vi;
}

static void free_unused_bufs(struct virtpc_info *vi)
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
	sprintf(vi->name, "sharedq");
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

static int init_vqs(struct virtpc_info *vi)
{
	return virtpc_find_vqs(vi);
}

static int virtpc_probe(struct virtio_device *vdev)
{
	struct virtpc_info *vi;
	int err;

	if (!vdev->config->get) {
		dev_err(&vdev->dev, "%s failure: config access disabled\n",
			__func__);
		return -EINVAL;
	}

	vi = kmalloc(sizeof(*vi), GFP_KERNEL);
	if (!vi) {
		return -ENOMEM;
	}

	vi->vdev = vdev;
	vdev->priv = vi;

	err = init_vqs(vi);
	if (err)
		goto free;

	virtio_device_ready(vdev);

	pr_debug("virtpc: registered device %p\n", vi);

	return 0;

free:
	kfree(vi);
	return err;
}

static void remove_vq_common(struct virtpc_info *vi)
{
	vi->vdev->config->reset(vi->vdev);

	/* Free unused buffers, if any. */
	free_unused_bufs(vi);

	virtpc_del_vqs(vi);
}

static void virtpc_remove(struct virtio_device *vdev)
{
	struct virtpc_info *vi = vdev->priv;

	remove_vq_common(vi);
	kfree(vi);
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

	err = init_vqs(vi);
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
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name =	KBUILD_MODNAME,
	.driver.owner =	THIS_MODULE,
	.id_table =	id_table,
	.probe =	virtpc_probe,
	.remove =	virtpc_remove,
	.config_changed = virtpc_config_changed,
#ifdef CONFIG_PM_SLEEP
	.freeze =	virtpc_freeze,
	.restore =	virtpc_restore,
#endif
};

module_virtio_driver(virtio_pc_driver);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio prodcons driver");
MODULE_LICENSE("GPL");
