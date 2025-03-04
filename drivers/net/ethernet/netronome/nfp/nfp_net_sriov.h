/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (C) 2017-2019 Netronome Systems, Inc. */

#ifndef _NFP_NET_SRIOV_H_
#define _NFP_NET_SRIOV_H_

/* SRIOV VF configuration.
 * The configuration memory begins with a mailbox region for communication with
 * the firmware followed by individual VF entries.
 */
#define NFP_NET_VF_CFG_SZ		16
#define NFP_NET_VF_CFG_MB_SZ		16

/* VF config mailbox */
#define NFP_NET_VF_CFG_MB				0x0
#define NFP_NET_VF_CFG_MB_CAP				0x0
#define   NFP_NET_VF_CFG_MB_CAP_MAC			  (0x1 << 0)
#define   NFP_NET_VF_CFG_MB_CAP_VLAN			  (0x1 << 1)
#define   NFP_NET_VF_CFG_MB_CAP_SPOOF			  (0x1 << 2)
#define   NFP_NET_VF_CFG_MB_CAP_LINK_STATE		  (0x1 << 3)
#define   NFP_NET_VF_CFG_MB_CAP_TRUST			  (0x1 << 4)
#define   NFP_NET_VF_CFG_MB_CAP_VLAN_PROTO		  (0x1 << 5)
#define   NFP_NET_VF_CFG_MB_CAP_RATE			  (0x1 << 6)
#define   NFP_NET_VF_CFG_MB_CAP_SPLIT			  (0x1 << 8)
#define NFP_NET_VF_CFG_MB_RET				0x2
#define NFP_NET_VF_CFG_MB_UPD				0x4
#define   NFP_NET_VF_CFG_MB_UPD_MAC			  (0x1 << 0)
#define   NFP_NET_VF_CFG_MB_UPD_VLAN			  (0x1 << 1)
#define   NFP_NET_VF_CFG_MB_UPD_SPOOF			  (0x1 << 2)
#define   NFP_NET_VF_CFG_MB_UPD_LINK_STATE		  (0x1 << 3)
#define   NFP_NET_VF_CFG_MB_UPD_TRUST			  (0x1 << 4)
#define   NFP_NET_VF_CFG_MB_UPD_VLAN_PROTO		  (0x1 << 5)
#define   NFP_NET_VF_CFG_MB_UPD_RATE			  (0x1 << 6)
#define   NFP_NET_VF_CFG_MB_UPD_SPLIT			  (0x1 << 8)
#define NFP_NET_VF_CFG_MB_VF_CNT			0x6
#define NFP_NET_VF_CFG_MB_VF_NUM			0x7

/* VF config entry
 * MAC_LO is set that the MAC address can be read in a single 6 byte read
 * by the NFP
 */
#define NFP_NET_VF_CFG_MAC				0x0
#define   NFP_NET_VF_CFG_MAC_HI				  0x0
#define   NFP_NET_VF_CFG_MAC_LO				  0x6
#define NFP_NET_VF_CFG_CTRL				0x4
#define   NFP_NET_VF_CFG_CTRL_TRUST			  0x8
#define   NFP_NET_VF_CFG_CTRL_SPOOF			  0x4
#define   NFP_NET_VF_CFG_CTRL_LINK_STATE		  0x3
#define     NFP_NET_VF_CFG_LS_MODE_AUTO			    0
#define     NFP_NET_VF_CFG_LS_MODE_ENABLE		    1
#define     NFP_NET_VF_CFG_LS_MODE_DISABLE		    2
#define NFP_NET_VF_CFG_VLAN				0x8
#define   NFP_NET_VF_CFG_VLAN_PROT			  0xffff0000
#define   NFP_NET_VF_CFG_VLAN_QOS			  0xe000
#define   NFP_NET_VF_CFG_VLAN_VID			  0x0fff
#define NFP_NET_VF_CFG_RATE				0xc
#define   NFP_NET_VF_CFG_MIN_RATE			0x0000ffff
#define   NFP_NET_VF_CFG_MAX_RATE			0xffff0000

#define NFP_NET_VF_RATE_MAX			0xffff

int nfp_app_set_vf_mac(struct net_device *netdev, int vf, u8 *mac);
int nfp_app_set_vf_vlan(struct net_device *netdev, int vf, u16 vlan, u8 qos,
			__be16 vlan_proto);
int nfp_app_set_vf_rate(struct net_device *netdev, int vf, int min_tx_rate,
			int max_tx_rate);
int nfp_app_set_vf_spoofchk(struct net_device *netdev, int vf, bool setting);
int nfp_app_set_vf_trust(struct net_device *netdev, int vf, bool setting);
int nfp_app_set_vf_link_state(struct net_device *netdev, int vf,
			      int link_state);
int nfp_app_get_vf_config(struct net_device *netdev, int vf,
			  struct ifla_vf_info *ivi);

int nfp_net_pf_init_sriov(struct nfp_pf *pf);

#endif /* _NFP_NET_SRIOV_H_ */
