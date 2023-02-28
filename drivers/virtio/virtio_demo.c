/*
 * Virtio demo implementation
 */

#include <linux/virtio.h>
#include <linux/virtio_demo.h>
#include <linux/swap.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/oom.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/magic.h>




struct virtio_demo {
	struct virtio_device *vdev;
	struct virtqueue *vq;
	uint32_t opt;
	uint32_t buff;	
};

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_DEMO, VIRTIO_DEV_ANY_ID },
	{ 0 },
};


static void virtdemo_changed(struct virtio_device *vdev)
{

}



static void demo_handle_request(struct virtqueue *vq)
{
	struct virtio_demo *vb = vq->vdev->priv;
	struct scatterlist sg;
	unsigned int len;
	uint64_t *data;

	data = virtqueue_get_buf(vq, &len);
	if (!data)
		return;
	switch (*(uint32_t*)data)
	{
		case 0:
			printk("old buff: %u\n", *(uint32_t*)((void*)data+4));
			vb->opt = 1;
			vb->buff = 0x2333;
			sg_init_one(&sg, vb->opt, 8);
			virtqueue_add_outbuf(vq, &sg, 1, vb, GFP_KERNEL);
			virtqueue_kick(vq);
			break;
		case 1:
			printk("new buff: %u\n", *(uint32_t*)((void*)data+4));
			break;
		default:

	}
}

static int init_vqs(struct virtio_demo *vb)
{
	struct scatterlist sg;

	vb->vq = virtio_find_single_vq(vb->vdev, demo_handle_request, "demo-vq");
	if (!vb->vq)
		return ~0;
	
	vb->opt = 0;
	vb->buff = 0;
	sg_init_one(&sg, vb->opt, 8);
	virtqueue_add_outbuf(vb->vq, &sg, 1, vb, GFP_KERNEL);
	virtqueue_kick(vb->vq);

	return 0;
}

static int virtdemo_probe(struct virtio_device *vdev)
{
	struct virtio_demo *vb;
	int err;

	// if (!vdev->config->get) {
	// 	dev_err(&vdev->dev, "%s failure: config access disabled\n",
	// 		__func__);
	// 	return -EINVAL;
	// }

	vdev->priv = vb = kmalloc(sizeof(*vb), GFP_KERNEL);
	if (!vb) {
		err = -ENOMEM;
		goto out;
	}

	vb->vdev = vdev;

	demo_devinfo_init(&vb->vb_dev_info);

	err = init_vqs(vb);
	if (err)
		goto out_free_vb;

	virtio_device_ready(vdev);

	if (towards_target(vb))
		virtdemo_changed(vdev);
	return 0;

out_del_vqs:
	vdev->config->del_vqs(vdev);
out_free_vb:
	kfree(vb);
out:
	return err;
}

static void virtdemo_remove(struct virtio_device *vdev)
{
	struct virtio_demo *vb = vdev->priv;

	vb->vdev->config->reset(vb->vdev);
	vb->vdev->config->del_vqs(vb->vdev);
	kfree(vb);
}

static int virtdemo_validate(struct virtio_device *vdev)
{
	__virtio_clear_bit(vdev, VIRTIO_F_IOMMU_PLATFORM);
	return 0;
}

// static unsigned int features[] = {
// 
// };

static struct virtio_driver virtio_demo_driver = {
	// .feature_table = features,
	// .feature_table_size = ARRAY_SIZE(features),
	.driver.name =	KBUILD_MODNAME,
	.driver.owner =	THIS_MODULE,
	.id_table =	id_table,
	.validate =	virtdemo_validate,
	.probe =	virtdemo_probe,
	.remove =	virtdemo_remove,
	.config_changed = virtdemo_changed,
#ifdef CONFIG_PM_SLEEP
	.freeze	=	virtdemo_freeze,
	.restore =	virtdemo_restore,
#endif
};

module_virtio_driver(virtio_demo_driver);
MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio demo driver");
MODULE_LICENSE("GPL");
