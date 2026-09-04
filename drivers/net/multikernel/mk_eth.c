// SPDX-License-Identifier: GPL-2.0
/*
 * mk_eth - virtual Ethernet device over multikernel IPI messaging
 *
 * Presents a normal struct net_device ("mk0") in every kernel instance, so
 * unmodified AF_INET applications can talk between kernels. Frames are
 * carried as multikernel messages through the shared-memory IPI ring; the
 * link is point-to-point between this kernel and one peer instance.
 *
 * Addressing is left to userspace: bring mk0 up and assign addresses with
 * ip(8) exactly as for any other interface.
 *
 * The vsock transport already owns MK_MSG_NETWORK and the message registry
 * permits one handler per type, so this driver uses MK_MSG_USER. An in-tree
 * version should instead share MK_MSG_NETWORK and demultiplex on subtype.
 */

#include <linux/etherdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/multikernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>

#define MK_ETH_FRAME	(MK_MSG_USER + 1)	/* subtype: one Ethernet frame */

/* Largest payload that fits one IPI slot, less the message header. */
#define MK_ETH_MAX_PAYLOAD	(MK_MAX_DATA_SIZE - sizeof(struct mk_message))
#define MK_ETH_MAX_MTU		(MK_ETH_MAX_PAYLOAD - ETH_HLEN)

static int peer = -1;
module_param(peer, int, 0444);
MODULE_PARM_DESC(peer, "Peer multikernel instance id (default: 0 on a spawn, 1 on the host)");

static struct net_device *mk_eth_dev;

struct mk_eth_priv {
	int peer_id;
};

/*
 * Transmit: hand the frame to the peer kernel as a single message.
 *
 * Called with BHs disabled from the networking core; mk_send_message()
 * allocates GFP_ATOMIC and copies the payload into the peer's ring, so it
 * is safe here and the skb can be freed immediately on return.
 */
static netdev_tx_t mk_eth_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct mk_eth_priv *priv = netdev_priv(dev);
	int ret;

	if (skb->len > MK_ETH_MAX_PAYLOAD) {
		dev->stats.tx_dropped++;
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	ret = mk_send_message(priv->peer_id, MK_MSG_USER, MK_ETH_FRAME,
			      skb->data, skb->len);
	if (ret) {
		/*
		 * A full ring or an absent peer is a lost frame, not a stalled
		 * queue: the ring has no completion signal to wake us again,
		 * so returning NETDEV_TX_BUSY here would wedge the qdisc.
		 */
		dev->stats.tx_errors++;
		dev->stats.tx_dropped++;
	} else {
		dev->stats.tx_packets++;
		dev->stats.tx_bytes += skb->len;
	}

	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

/*
 * Receive: called from the multikernel IPI handler, i.e. hard interrupt
 * context. netif_rx() is safe there and defers to the backlog NAPI.
 */
static void mk_eth_recv(u32 msg_type, u32 subtype, void *payload,
			u32 payload_len, void *ctx)
{
	struct net_device *dev = ctx;
	struct sk_buff *skb;

	if (subtype != MK_ETH_FRAME || !dev)
		return;

	if (!payload || payload_len < ETH_HLEN ||
	    payload_len > MK_ETH_MAX_PAYLOAD) {
		dev->stats.rx_length_errors++;
		return;
	}

	/* NET_IP_ALIGN keeps the IP header 4-byte aligned after eth_type_trans. */
	skb = netdev_alloc_skb(dev, payload_len + NET_IP_ALIGN);
	if (!skb) {
		dev->stats.rx_dropped++;
		return;
	}

	skb_reserve(skb, NET_IP_ALIGN);
	skb_put_data(skb, payload, payload_len);

	skb->protocol = eth_type_trans(skb, dev);
	skb->ip_summed = CHECKSUM_UNNECESSARY;	/* shared memory, no wire */

	dev->stats.rx_packets++;
	dev->stats.rx_bytes += payload_len;

	netif_rx(skb);
}

static int mk_eth_open(struct net_device *dev)
{
	netif_carrier_on(dev);
	netif_start_queue(dev);
	return 0;
}

static int mk_eth_stop(struct net_device *dev)
{
	netif_stop_queue(dev);
	netif_carrier_off(dev);
	return 0;
}

static const struct net_device_ops mk_eth_netdev_ops = {
	.ndo_open		= mk_eth_open,
	.ndo_stop		= mk_eth_stop,
	.ndo_start_xmit		= mk_eth_xmit,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
};

static void mk_eth_setup(struct net_device *dev)
{
	ether_setup(dev);
	dev->netdev_ops = &mk_eth_netdev_ops;
	dev->flags &= ~IFF_MULTICAST;
	dev->min_mtu = ETH_MIN_MTU;
	dev->max_mtu = MK_ETH_MAX_MTU;
	dev->mtu = ETH_DATA_LEN;		/* 1500: interoperates with everything */
}

static int __init mk_eth_init(void)
{
	struct mk_eth_priv *priv;
	u8 addr[ETH_ALEN];
	int self_id, ret;

	if (!mk_self) {
		pr_err("mk_eth: no multikernel instance for this kernel\n");
		return -ENODEV;
	}
	self_id = mk_self->id;

	/*
	 * Default topology is a star around the host: a spawn talks to
	 * instance 0, and the host talks to the instance named by the
	 * module parameter.
	 */
	if (peer < 0)
		peer = self_id ? 0 : 1;

	if (peer == self_id) {
		pr_err("mk_eth: peer %d is this instance\n", peer);
		return -EINVAL;
	}

	mk_eth_dev = alloc_netdev(sizeof(*priv), "mk%d", NET_NAME_ENUM,
				  mk_eth_setup);
	if (!mk_eth_dev)
		return -ENOMEM;

	priv = netdev_priv(mk_eth_dev);
	priv->peer_id = peer;

	/* Locally administered unicast, keyed by instance id: 02:4d:4b ("MK"). */
	addr[0] = 0x02;
	addr[1] = 0x4d;
	addr[2] = 0x4b;
	addr[3] = 0x00;
	addr[4] = 0x00;
	addr[5] = (u8)self_id;
	eth_hw_addr_set(mk_eth_dev, addr);

	ret = mk_register_msg_handler(MK_MSG_USER, mk_eth_recv, mk_eth_dev);
	if (ret) {
		pr_err("mk_eth: cannot claim message type 0x%x: %d\n",
		       MK_MSG_USER, ret);
		goto err_free;
	}

	ret = register_netdev(mk_eth_dev);
	if (ret) {
		pr_err("mk_eth: register_netdev failed: %d\n", ret);
		goto err_unreg_handler;
	}

	netif_carrier_off(mk_eth_dev);

	pr_info("mk_eth: %s up as instance %d -> peer %d, mtu %u (max %lu)\n",
		mk_eth_dev->name, self_id, peer, mk_eth_dev->mtu,
		(unsigned long)MK_ETH_MAX_MTU);
	return 0;

err_unreg_handler:
	mk_unregister_msg_handler(MK_MSG_USER, mk_eth_recv);
err_free:
	free_netdev(mk_eth_dev);
	mk_eth_dev = NULL;
	return ret;
}

static void __exit mk_eth_exit(void)
{
	if (!mk_eth_dev)
		return;

	/* Stop inbound frames before the device they reference goes away. */
	mk_unregister_msg_handler(MK_MSG_USER, mk_eth_recv);
	unregister_netdev(mk_eth_dev);
	free_netdev(mk_eth_dev);
	mk_eth_dev = NULL;
}

module_init(mk_eth_init);
module_exit(mk_eth_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Virtual Ethernet over multikernel IPI messaging");
