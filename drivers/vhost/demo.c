// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2009 Red Hat, Inc.
 * Author: Michael S. Tsirkin <mst@redhat.com>
 *
 * virtio-net server in host kernel.
 */

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
#include <linux/sched/clock.h>
#include <linux/sched/signal.h>
#include <linux/vmalloc.h>

#include "vhost.h"

/* Max number of bytes transferred before requeueing the job.
 * Using this limit prevents one virtqueue from starving others. */
#define VHOST_DEMO_WEIGHT 0x80000

/* Max number of packets transferred before requeueing the job.
 * Using this limit prevents one virtqueue from starving others with small
 * pkts.
 */
#define VHOST_DEMO_PKT_WEIGHT 256

struct vhost_demo {
	struct vhost_dev dev;
	struct vhost_virtqueue vq;
	struct vhost_virtqueue *vqs[1];
	uint32_t v1;
	uint32_t v2;
	uint32_t v3;
	uint32_t v4;
};


static void handle_demo_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue,
						  poll.work);
	struct vhost_demo *demo = container_of(vq->dev, struct vhost_demo, dev);
	int head;
	unsigned in, out;
	size_t out_len, in_len, total_len = 0;
	struct iov_iter iov_iter;

	printk("vhost_demo: handle_demo_kick() begin\n");
	mutex_lock(&vq->mutex);
	vhost_disable_notify(&demo->dev, vq);
	printk("vhost_demo: handle_demo_kick() mutex_lock and vhost_disable_notify\n");

	for (;;) {

		head = vhost_get_vq_desc(vq, vq->iov,
				      ARRAY_SIZE(vq->iov), 
					  &out, &in, 
					  NULL, NULL);
		if (unlikely(head < 0)) {
			printk("vhost_demo: handle_demo_kick() for(;;) break1\n");
			break;
		}
		/* Nothing new?  Wait for eventfd to tell us they refilled. */
		if (head == vq->num) {
			if (unlikely(vhost_enable_notify(&demo->dev, vq))) {
				vhost_disable_notify(&demo->dev, vq);
				continue;
			}
			printk("vhost_demo: handle_demo_kick() for(;;) break2\n");
			break;
		}
		printk("vhost_demo: handle_demo_kick(), out=%u in=%u\n", out, in);

		out_len = iov_length(vq->iov, out);
		in_len = iov_length(&vq->iov[out], in);
		printk("vhost_demo: handle_demo_kick(), out_len=%lu in_len=%lu\n", 
			out_len, in_len);

		iov_iter_init(&iov_iter, WRITE, vq->iov, out, out_len);
		copy_from_iter(&demo->v1, 8, &iov_iter);

		demo->v3 = demo->v1;
		if (1 == demo->v1) {
			demo->v4 = demo->v2;
		}

		iov_iter_init(&iov_iter, READ, &vq->iov[out], in, in_len);
		copy_to_iter(&demo->v3, 8, &iov_iter);

		printk("vhost_demo: handle_demo_kick(), handle finish, v1-v4 = %u %u %u %u\n", 
			demo->v1, demo->v2, demo->v3, demo->v4);

		vhost_add_used_and_signal(&demo->dev, vq, head, 0);
		total_len += (out_len + in_len);
		if (unlikely(vhost_exceeds_weight(vq, 0, total_len))) {
			break;
		}
	}
	mutex_unlock(&vq->mutex);
	vhost_poll_queue(&vq->poll);
	printk("vhost_demo: handle_demo_kick() end\n");
	
}

static int vhost_demo_open(struct inode *inode, struct file *f)
{
	struct vhost_demo *d;

	printk("vhost_demo: vhost_demo_open() begin\n");
	d = kvmalloc(sizeof *d, GFP_KERNEL | __GFP_RETRY_MAYFAIL);
	if (!d)
		return -ENOMEM;
	
	printk("vhost_demo: vhost_demo_open() kvmalloc finish\n");
	
	d->vqs[0] = &d->vq;
	d->vq.handle_kick = handle_demo_kick;

	vhost_dev_init(&d->dev, d->vqs, 1,
		       UIO_MAXIOV,
		       VHOST_DEMO_PKT_WEIGHT, VHOST_DEMO_WEIGHT, true,
		       NULL);

	printk("vhost_demo: vhost_demo_open() vhost_dev_init finish\n");

	f->private_data = d;
	// n->page_frag.page = NULL;
	// n->refcnt_bias = 0;

	printk("vhost_demo: vhost_demo_open() end\n");
	return 0;
}

static void *vhost_demo_stop_vq(struct vhost_demo *d,
					struct vhost_virtqueue *vq)
{
	void *private;

	mutex_lock(&vq->mutex);
	private = vhost_vq_get_backend(vq);
	vhost_vq_set_backend(vq, NULL);
	mutex_unlock(&vq->mutex);
	return private;
}

static void vhost_demo_stop(struct vhost_demo *d, void **privatep)
{
	printk("vhost_demo_stop() begin\n");
	*privatep = vhost_demo_stop_vq(d, &d->vq);
}

static void vhost_demo_flush_vq(struct vhost_demo *d, int index)
{
	vhost_poll_flush(&d->vq.poll);
}

static void vhost_demo_flush(struct vhost_demo *d)
{
	printk("vhost_demo_flush() begin\n");
	vhost_demo_flush_vq(d, 0);
}

static int vhost_demo_release(struct inode *inode, struct file *f)
{
	struct vhost_demo *d = f->private_data;
	void  *private;

	printk("vhost_demo_release() begin\n");

	vhost_demo_stop(d, &private);
	vhost_demo_flush(d);
	vhost_dev_stop(&d->dev);
	vhost_dev_cleanup(&d->dev);
	/* Make sure no callbacks are outstanding */
	synchronize_rcu();
	
	kvfree(d);
	return 0;
}

// static struct socket *get_raw_socket(int fd)
// {
// 	int r;
// 	struct socket *sock = sockfd_lookup(fd, &r);

// 	if (!sock)
// 		return ERR_PTR(-ENOTSOCK);

// 	/* Parameter checking */
// 	if (sock->sk->sk_type != SOCK_RAW) {
// 		r = -ESOCKTNOSUPPORT;
// 		goto err;
// 	}

// 	if (sock->sk->sk_family != AF_PACKET) {
// 		r = -EPFNOSUPPORT;
// 		goto err;
// 	}
// 	return sock;
// err:
// 	sockfd_put(sock);
// 	return ERR_PTR(r);
// }

// static struct ptr_ring *get_tap_ptr_ring(int fd)
// {
// 	struct ptr_ring *ring;
// 	struct file *file = fget(fd);

// 	if (!file)
// 		return NULL;
// 	ring = tun_get_tx_ring(file);
// 	if (!IS_ERR(ring))
// 		goto out;
// 	ring = tap_get_ptr_ring(file);
// 	if (!IS_ERR(ring))
// 		goto out;
// 	ring = NULL;
// out:
// 	fput(file);
// 	return ring;
// }

// static struct socket *get_tap_socket(int fd)
// {
// 	struct file *file = fget(fd);
// 	struct socket *sock;

// 	if (!file)
// 		return ERR_PTR(-EBADF);
// 	sock = tun_get_socket(file);
// 	if (!IS_ERR(sock))
// 		return sock;
// 	sock = tap_get_socket(file);
// 	if (IS_ERR(sock))
// 		fput(file);
// 	return sock;
// }

// static struct socket *get_socket(int fd)
// {
// 	struct socket *sock;

// 	/* special case to disable backend */
// 	if (fd == -1)
// 		return NULL;
// 	sock = get_raw_socket(fd);
// 	if (!IS_ERR(sock))
// 		return sock;
// 	sock = get_tap_socket(fd);
// 	if (!IS_ERR(sock))
// 		return sock;
// 	return ERR_PTR(-ENOTSOCK);
// }

// static long vhost_net_set_backend(struct vhost_net *n, unsigned index, int fd)
// {
// 	struct socket *sock, *oldsock;
// 	struct vhost_virtqueue *vq;
// 	struct vhost_net_virtqueue *nvq;
// 	struct vhost_net_ubuf_ref *ubufs, *oldubufs = NULL;
// 	int r;

// 	mutex_lock(&n->dev.mutex);
// 	r = vhost_dev_check_owner(&n->dev);
// 	if (r)
// 		goto err;

// 	if (index >= VHOST_NET_VQ_MAX) {
// 		r = -ENOBUFS;
// 		goto err;
// 	}
// 	vq = &n->vqs[index].vq;
// 	nvq = &n->vqs[index];
// 	mutex_lock(&vq->mutex);

// 	/* Verify that ring has been setup correctly. */
// 	if (!vhost_vq_access_ok(vq)) {
// 		r = -EFAULT;
// 		goto err_vq;
// 	}
// 	sock = get_socket(fd);
// 	if (IS_ERR(sock)) {
// 		r = PTR_ERR(sock);
// 		goto err_vq;
// 	}

// 	/* start polling new socket */
// 	oldsock = vhost_vq_get_backend(vq);
// 	if (sock != oldsock) {
// 		ubufs = vhost_net_ubuf_alloc(vq,
// 					     sock && vhost_sock_zcopy(sock));
// 		if (IS_ERR(ubufs)) {
// 			r = PTR_ERR(ubufs);
// 			goto err_ubufs;
// 		}

// 		vhost_net_disable_vq(n, vq);
// 		vhost_vq_set_backend(vq, sock);
// 		vhost_net_buf_unproduce(nvq);
// 		r = vhost_vq_init_access(vq);
// 		if (r)
// 			goto err_used;
// 		r = vhost_net_enable_vq(n, vq);
// 		if (r)
// 			goto err_used;
// 		if (index == VHOST_NET_VQ_RX)
// 			nvq->rx_ring = get_tap_ptr_ring(fd);

// 		oldubufs = nvq->ubufs;
// 		nvq->ubufs = ubufs;

// 		n->tx_packets = 0;
// 		n->tx_zcopy_err = 0;
// 		n->tx_flush = false;
// 	}

// 	mutex_unlock(&vq->mutex);

// 	if (oldubufs) {
// 		vhost_net_ubuf_put_wait_and_free(oldubufs);
// 		mutex_lock(&vq->mutex);
// 		vhost_zerocopy_signal_used(n, vq);
// 		mutex_unlock(&vq->mutex);
// 	}

// 	if (oldsock) {
// 		vhost_net_flush_vq(n, index);
// 		sockfd_put(oldsock);
// 	}

// 	mutex_unlock(&n->dev.mutex);
// 	return 0;

// err_used:
// 	vhost_vq_set_backend(vq, oldsock);
// 	vhost_net_enable_vq(n, vq);
// 	if (ubufs)
// 		vhost_net_ubuf_put_wait_and_free(ubufs);
// err_ubufs:
// 	if (sock)
// 		sockfd_put(sock);
// err_vq:
// 	mutex_unlock(&vq->mutex);
// err:
// 	mutex_unlock(&n->dev.mutex);
// 	return r;
// }

static long vhost_demo_reset_owner(struct vhost_demo *d)
{
	void *privatep = NULL;
	long err;
	struct vhost_iotlb *umem;

	printk("vhost_demo_reset_owner() begin\n");

	mutex_lock(&d->dev.mutex);
	err = vhost_dev_check_owner(&d->dev);
	if (err)
		goto done;
	umem = vhost_dev_reset_owner_prepare();
	if (!umem) {
		err = -ENOMEM;
		goto done;
	}
	vhost_demo_stop(d, &privatep);
	vhost_demo_flush(d);
	vhost_dev_stop(&d->dev);
	vhost_dev_reset_owner(&d->dev, umem);
	// vhost_net_vq_reset(n);
done:
	mutex_unlock(&d->dev.mutex);
	if (privatep)
		fput((struct file *)privatep);
	return err;
}

static int vhost_demo_set_features(struct vhost_demo *d, u64 features)
{
	mutex_lock(&d->dev.mutex);
	if ((features & (1 << VHOST_F_LOG_ALL)) &&
	    !vhost_log_access_ok(&d->dev))
		goto out_unlock;

	if ((features & (1ULL << VIRTIO_F_ACCESS_PLATFORM))) {
		if (vhost_init_device_iotlb(&d->dev, true))
			goto out_unlock;
	}
	mutex_lock(&d->vq.mutex);
	d->vq.acked_features = features;
	mutex_unlock(&d->vq.mutex);
	mutex_unlock(&d->dev.mutex);
	return 0;

out_unlock:
	mutex_unlock(&d->dev.mutex);
	return -EFAULT;
}

static long vhost_demo_set_owner(struct vhost_demo *d)
{
	int r;

	printk("vhost_demo_set_owner() begin\n");

	mutex_lock(&d->dev.mutex);
	if (vhost_dev_has_owner(&d->dev)) {
		r = -EBUSY;
		goto out;
	}
	// r = vhost_net_set_ubuf_info(n);
	// if (r)
	// 	goto out;
	r = vhost_dev_set_owner(&d->dev);
	// if (r)
	// 	vhost_net_clear_ubuf_info(n);
	vhost_demo_flush(d);
out:
	mutex_unlock(&d->dev.mutex);
	return r;
}

static long vhost_demo_ioctl(struct file *f, unsigned int ioctl,
			    unsigned long arg)
{
	struct vhost_demo *d = f->private_data;
	void __user *argp = (void __user *)arg;
	u64 __user *featurep = argp;
	// struct vhost_vring_file backend;
	u64 features;
	int r;

	printk("vhost_demo_ioctl() begin\n");

	switch (ioctl) {
	// case VHOST_NET_SET_BACKEND:
	// 	if (copy_from_user(&backend, argp, sizeof backend))
	// 		return -EFAULT;
	// 	return vhost_net_set_backend(n, backend.index, backend.fd);
	case VHOST_GET_FEATURES:
		features = VHOST_FEATURES |
				(1ULL << VIRTIO_F_ACCESS_PLATFORM);
		if (copy_to_user(featurep, &features, sizeof features))
			return -EFAULT;
		return 0;
	case VHOST_SET_FEATURES:
		if (copy_from_user(&features, featurep, sizeof features))
			return -EFAULT;
		return vhost_demo_set_features(d, features);
	case VHOST_GET_BACKEND_FEATURES:
		features = (1ULL << VHOST_BACKEND_F_IOTLB_MSG_V2);
		if (copy_to_user(featurep, &features, sizeof(features)))
			return -EFAULT;
		return 0;
	case VHOST_SET_BACKEND_FEATURES:
		if (copy_from_user(&features, featurep, sizeof(features)))
			return -EFAULT;
		if (features & ~(1ULL << VHOST_BACKEND_F_IOTLB_MSG_V2))
			return -EOPNOTSUPP;
		vhost_set_backend_features(&d->dev, features);
		return 0;
	case VHOST_RESET_OWNER:
		return vhost_demo_reset_owner(d);
	case VHOST_SET_OWNER:
		return vhost_demo_set_owner(d);
	default:
		mutex_lock(&d->dev.mutex);
		r = vhost_dev_ioctl(&d->dev, ioctl, argp);
		if (r == -ENOIOCTLCMD)
			r = vhost_vring_ioctl(&d->dev, ioctl, argp);
		else
			vhost_demo_flush(d);
		mutex_unlock(&d->dev.mutex);
		return r;
	}
}

// static ssize_t vhost_demo_chr_read_iter(struct kiocb *iocb, struct iov_iter *to)
// {
// 	struct file *file = iocb->ki_filp;
// 	struct vhost_demo *d = file->private_data;
// 	struct vhost_dev *dev = &d->dev;
// 	int noblock = file->f_flags & O_NONBLOCK;

// 	return vhost_chr_read_iter(dev, to, noblock);
// }

// static ssize_t vhost_demo_chr_write_iter(struct kiocb *iocb,
// 					struct iov_iter *from)
// {
// 	struct file *file = iocb->ki_filp;
// 	struct vhost_demo *d = file->private_data;
// 	struct vhost_dev *dev = &d->dev;

// 	return vhost_chr_write_iter(dev, from);
// }

// static __poll_t vhost_demo_chr_poll(struct file *file, poll_table *wait)
// {
// 	struct vhost_demo *d = file->private_data;
// 	struct vhost_dev *dev = &d->dev;

// 	return vhost_chr_poll(file, dev, wait);
// }

static const struct file_operations vhost_demo_fops = {
	.owner          = THIS_MODULE,
	.release        = vhost_demo_release,
	// .read_iter      = vhost_demo_chr_read_iter,
	// .write_iter     = vhost_demo_chr_write_iter,
	// .poll           = vhost_demo_chr_poll,
	.unlocked_ioctl = vhost_demo_ioctl,
	.compat_ioctl   = compat_ptr_ioctl,
	.open           = vhost_demo_open,
	.llseek		= noop_llseek,
};

static struct miscdevice vhost_demo_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "vhost-demo",
	.fops = &vhost_demo_fops,
};
module_misc_device(vhost_demo_misc);


MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Haloo");
MODULE_DESCRIPTION("vhost demo");
//MODULE_ALIAS("devname:vhost-demo");
