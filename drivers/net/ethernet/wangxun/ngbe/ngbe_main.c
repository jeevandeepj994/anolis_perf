// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 - 2022 Beijing WangXun Technology Co., Ltd. */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/string.h>
#include <linux/aer.h>
#include <linux/etherdevice.h>
#include <linux/sctp.h>
#include <linux/mdio.h>

#include <net/ip6_checksum.h>

#include "ngbe.h"
#include "ngbe_phy.h"
#include "ngbe_hw.h"

char ngbe_driver_name[] = "ngbe";
static const char ngbe_driver_string[] =
			"WangXun Gigabit PCI Express Network Driver";
static const char ngbe_copyright[] =
		"Copyright (c) 2018 -2022 Beijing WangXun Technology Co., Ltd";

#define DRV_VERSION     __stringify(1.2.3anolis)
const char ngbe_driver_version[32] = DRV_VERSION;

static struct workqueue_struct *ngbe_wq;

static const char ngbe_underheat_msg[] =
	"Network adapter has been restarted since the temperature has been back to normal state";

static const char ngbe_overheat_msg[] =
	"Network adapter has been stopped because it has over heated.";

/* ngbe_pci_tbl - PCI Device ID Table
 *
 * { Vendor ID, Device ID, SubVendor ID, SubDevice ID,
 *   Class, Class Mask, private data (not used) }
 */
static const struct pci_device_id ngbe_pci_tbl[] = {
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860AL_W), 0},
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860A2), 0},
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860A2S), 0},
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860A4), 0},
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860A4S), 0},
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860AL2), 0},
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860AL2S), 0},
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860AL4), 0},
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860AL4S), 0},
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860LC), 0},
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860A1), 0},
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860A1L), 0},
	/* required last entry */
	{ .device = 0 }
};

union network_header {
	struct iphdr *ipv4;
	struct ipv6hdr *ipv6;
	void *raw;
};

/* Lookup table mapping the HW PTYPE to the bit field for decoding */
struct ngbe_dec_ptype ngbe_ptype_lookup[256] = {
	NGBE_UKN(0x00),
	NGBE_UKN(0x01),
	NGBE_UKN(0x02),
	NGBE_UKN(0x03),
	NGBE_UKN(0x04),
	NGBE_UKN(0x05),
	NGBE_UKN(0x06),
	NGBE_UKN(0x07),
	NGBE_UKN(0x08),
	NGBE_UKN(0x09),
	NGBE_UKN(0x0A),
	NGBE_UKN(0x0B),
	NGBE_UKN(0x0C),
	NGBE_UKN(0x0D),
	NGBE_UKN(0x0E),
	NGBE_UKN(0x0F),

	/* L2: mac */
	NGBE_UKN(0x10),
	NGBE_PTT(0x11, L2, NONE, NONE, NONE, NONE, PAY2),
	NGBE_PTT(0x12, L2, NONE, NONE, NONE, TS,   PAY2),
	NGBE_PTT(0x13, L2, NONE, NONE, NONE, NONE, PAY2),
	NGBE_PTT(0x14, L2, NONE, NONE, NONE, NONE, PAY2),
	NGBE_PTT(0x15, L2, NONE, NONE, NONE, NONE, NONE),
	NGBE_PTT(0x16, L2, NONE, NONE, NONE, NONE, PAY2),
	NGBE_PTT(0x17, L2, NONE, NONE, NONE, NONE, NONE),

	/* L2: ethertype filter */
	NGBE_PTT(0x18, L2, NONE, NONE, NONE, NONE, NONE),
	NGBE_PTT(0x19, L2, NONE, NONE, NONE, NONE, NONE),
	NGBE_PTT(0x1A, L2, NONE, NONE, NONE, NONE, NONE),
	NGBE_PTT(0x1B, L2, NONE, NONE, NONE, NONE, NONE),
	NGBE_PTT(0x1C, L2, NONE, NONE, NONE, NONE, NONE),
	NGBE_PTT(0x1D, L2, NONE, NONE, NONE, NONE, NONE),
	NGBE_PTT(0x1E, L2, NONE, NONE, NONE, NONE, NONE),
	NGBE_PTT(0x1F, L2, NONE, NONE, NONE, NONE, NONE),

	/* L3: ip non-tunnel */
	NGBE_UKN(0x20),
	NGBE_PTT(0x21, IP, FGV4, NONE, NONE, NONE, PAY3),
	NGBE_PTT(0x22, IP, IPV4, NONE, NONE, NONE, PAY3),
	NGBE_PTT(0x23, IP, IPV4, NONE, NONE, UDP,  PAY4),
	NGBE_PTT(0x24, IP, IPV4, NONE, NONE, TCP,  PAY4),
	NGBE_PTT(0x25, IP, IPV4, NONE, NONE, SCTP, PAY4),
	NGBE_UKN(0x26),
	NGBE_UKN(0x27),
	NGBE_UKN(0x28),
	NGBE_PTT(0x29, IP, FGV6, NONE, NONE, NONE, PAY3),
	NGBE_PTT(0x2A, IP, IPV6, NONE, NONE, NONE, PAY3),
	NGBE_PTT(0x2B, IP, IPV6, NONE, NONE, UDP,  PAY3),
	NGBE_PTT(0x2C, IP, IPV6, NONE, NONE, TCP,  PAY4),
	NGBE_PTT(0x2D, IP, IPV6, NONE, NONE, SCTP, PAY4),
	NGBE_UKN(0x2E),
	NGBE_UKN(0x2F),

	/* L2: fcoe */
	NGBE_PTT(0x30, FCOE, NONE, NONE, NONE, NONE, PAY3),
	NGBE_PTT(0x31, FCOE, NONE, NONE, NONE, NONE, PAY3),
	NGBE_PTT(0x32, FCOE, NONE, NONE, NONE, NONE, PAY3),
	NGBE_PTT(0x33, FCOE, NONE, NONE, NONE, NONE, PAY3),
	NGBE_PTT(0x34, FCOE, NONE, NONE, NONE, NONE, PAY3),
	NGBE_UKN(0x35),
	NGBE_UKN(0x36),
	NGBE_UKN(0x37),
	NGBE_PTT(0x38, FCOE, NONE, NONE, NONE, NONE, PAY3),
	NGBE_PTT(0x39, FCOE, NONE, NONE, NONE, NONE, PAY3),
	NGBE_PTT(0x3A, FCOE, NONE, NONE, NONE, NONE, PAY3),
	NGBE_PTT(0x3B, FCOE, NONE, NONE, NONE, NONE, PAY3),
	NGBE_PTT(0x3C, FCOE, NONE, NONE, NONE, NONE, PAY3),
	NGBE_UKN(0x3D),
	NGBE_UKN(0x3E),
	NGBE_UKN(0x3F),

	NGBE_UKN(0x40),
	NGBE_UKN(0x41),
	NGBE_UKN(0x42),
	NGBE_UKN(0x43),
	NGBE_UKN(0x44),
	NGBE_UKN(0x45),
	NGBE_UKN(0x46),
	NGBE_UKN(0x47),
	NGBE_UKN(0x48),
	NGBE_UKN(0x49),
	NGBE_UKN(0x4A),
	NGBE_UKN(0x4B),
	NGBE_UKN(0x4C),
	NGBE_UKN(0x4D),
	NGBE_UKN(0x4E),
	NGBE_UKN(0x4F),
	NGBE_UKN(0x50),
	NGBE_UKN(0x51),
	NGBE_UKN(0x52),
	NGBE_UKN(0x53),
	NGBE_UKN(0x54),
	NGBE_UKN(0x55),
	NGBE_UKN(0x56),
	NGBE_UKN(0x57),
	NGBE_UKN(0x58),
	NGBE_UKN(0x59),
	NGBE_UKN(0x5A),
	NGBE_UKN(0x5B),
	NGBE_UKN(0x5C),
	NGBE_UKN(0x5D),
	NGBE_UKN(0x5E),
	NGBE_UKN(0x5F),
	NGBE_UKN(0x60),
	NGBE_UKN(0x61),
	NGBE_UKN(0x62),
	NGBE_UKN(0x63),
	NGBE_UKN(0x64),
	NGBE_UKN(0x65),
	NGBE_UKN(0x66),
	NGBE_UKN(0x67),
	NGBE_UKN(0x68),
	NGBE_UKN(0x69),
	NGBE_UKN(0x6A),
	NGBE_UKN(0x6B),
	NGBE_UKN(0x6C),
	NGBE_UKN(0x6D),
	NGBE_UKN(0x6E),
	NGBE_UKN(0x6F),
	NGBE_UKN(0x70),
	NGBE_UKN(0x71),
	NGBE_UKN(0x72),
	NGBE_UKN(0x73),
	NGBE_UKN(0x74),
	NGBE_UKN(0x75),
	NGBE_UKN(0x76),
	NGBE_UKN(0x77),
	NGBE_UKN(0x78),
	NGBE_UKN(0x79),
	NGBE_UKN(0x7A),
	NGBE_UKN(0x7B),
	NGBE_UKN(0x7C),
	NGBE_UKN(0x7D),
	NGBE_UKN(0x7E),
	NGBE_UKN(0x7F),

	/* IPv4 --> IPv4/IPv6 */
	NGBE_UKN(0x80),
	NGBE_PTT(0x81, IP, IPV4, IPIP, FGV4, NONE, PAY3),
	NGBE_PTT(0x82, IP, IPV4, IPIP, IPV4, NONE, PAY3),
	NGBE_PTT(0x83, IP, IPV4, IPIP, IPV4, UDP,  PAY4),
	NGBE_PTT(0x84, IP, IPV4, IPIP, IPV4, TCP,  PAY4),
	NGBE_PTT(0x85, IP, IPV4, IPIP, IPV4, SCTP, PAY4),
	NGBE_UKN(0x86),
	NGBE_UKN(0x87),
	NGBE_UKN(0x88),
	NGBE_PTT(0x89, IP, IPV4, IPIP, FGV6, NONE, PAY3),
	NGBE_PTT(0x8A, IP, IPV4, IPIP, IPV6, NONE, PAY3),
	NGBE_PTT(0x8B, IP, IPV4, IPIP, IPV6, UDP,  PAY4),
	NGBE_PTT(0x8C, IP, IPV4, IPIP, IPV6, TCP,  PAY4),
	NGBE_PTT(0x8D, IP, IPV4, IPIP, IPV6, SCTP, PAY4),
	NGBE_UKN(0x8E),
	NGBE_UKN(0x8F),

	/* IPv4 --> GRE/NAT --> NONE/IPv4/IPv6 */
	NGBE_PTT(0x90, IP, IPV4, IG, NONE, NONE, PAY3),
	NGBE_PTT(0x91, IP, IPV4, IG, FGV4, NONE, PAY3),
	NGBE_PTT(0x92, IP, IPV4, IG, IPV4, NONE, PAY3),
	NGBE_PTT(0x93, IP, IPV4, IG, IPV4, UDP,  PAY4),
	NGBE_PTT(0x94, IP, IPV4, IG, IPV4, TCP,  PAY4),
	NGBE_PTT(0x95, IP, IPV4, IG, IPV4, SCTP, PAY4),
	NGBE_UKN(0x96),
	NGBE_UKN(0x97),
	NGBE_UKN(0x98),
	NGBE_PTT(0x99, IP, IPV4, IG, FGV6, NONE, PAY3),
	NGBE_PTT(0x9A, IP, IPV4, IG, IPV6, NONE, PAY3),
	NGBE_PTT(0x9B, IP, IPV4, IG, IPV6, UDP,  PAY4),
	NGBE_PTT(0x9C, IP, IPV4, IG, IPV6, TCP,  PAY4),
	NGBE_PTT(0x9D, IP, IPV4, IG, IPV6, SCTP, PAY4),
	NGBE_UKN(0x9E),
	NGBE_UKN(0x9F),

	/* IPv4 --> GRE/NAT --> MAC --> NONE/IPv4/IPv6 */
	NGBE_PTT(0xA0, IP, IPV4, IGM, NONE, NONE, PAY3),
	NGBE_PTT(0xA1, IP, IPV4, IGM, FGV4, NONE, PAY3),
	NGBE_PTT(0xA2, IP, IPV4, IGM, IPV4, NONE, PAY3),
	NGBE_PTT(0xA3, IP, IPV4, IGM, IPV4, UDP,  PAY4),
	NGBE_PTT(0xA4, IP, IPV4, IGM, IPV4, TCP,  PAY4),
	NGBE_PTT(0xA5, IP, IPV4, IGM, IPV4, SCTP, PAY4),
	NGBE_UKN(0xA6),
	NGBE_UKN(0xA7),
	NGBE_UKN(0xA8),
	NGBE_PTT(0xA9, IP, IPV4, IGM, FGV6, NONE, PAY3),
	NGBE_PTT(0xAA, IP, IPV4, IGM, IPV6, NONE, PAY3),
	NGBE_PTT(0xAB, IP, IPV4, IGM, IPV6, UDP,  PAY4),
	NGBE_PTT(0xAC, IP, IPV4, IGM, IPV6, TCP,  PAY4),
	NGBE_PTT(0xAD, IP, IPV4, IGM, IPV6, SCTP, PAY4),
	NGBE_UKN(0xAE),
	NGBE_UKN(0xAF),

	/* IPv4 --> GRE/NAT --> MAC+VLAN --> NONE/IPv4/IPv6 */
	NGBE_PTT(0xB0, IP, IPV4, IGMV, NONE, NONE, PAY3),
	NGBE_PTT(0xB1, IP, IPV4, IGMV, FGV4, NONE, PAY3),
	NGBE_PTT(0xB2, IP, IPV4, IGMV, IPV4, NONE, PAY3),
	NGBE_PTT(0xB3, IP, IPV4, IGMV, IPV4, UDP,  PAY4),
	NGBE_PTT(0xB4, IP, IPV4, IGMV, IPV4, TCP,  PAY4),
	NGBE_PTT(0xB5, IP, IPV4, IGMV, IPV4, SCTP, PAY4),
	NGBE_UKN(0xB6),
	NGBE_UKN(0xB7),
	NGBE_UKN(0xB8),
	NGBE_PTT(0xB9, IP, IPV4, IGMV, FGV6, NONE, PAY3),
	NGBE_PTT(0xBA, IP, IPV4, IGMV, IPV6, NONE, PAY3),
	NGBE_PTT(0xBB, IP, IPV4, IGMV, IPV6, UDP,  PAY4),
	NGBE_PTT(0xBC, IP, IPV4, IGMV, IPV6, TCP,  PAY4),
	NGBE_PTT(0xBD, IP, IPV4, IGMV, IPV6, SCTP, PAY4),
	NGBE_UKN(0xBE),
	NGBE_UKN(0xBF),

	/* IPv6 --> IPv4/IPv6 */
	NGBE_UKN(0xC0),
	NGBE_PTT(0xC1, IP, IPV6, IPIP, FGV4, NONE, PAY3),
	NGBE_PTT(0xC2, IP, IPV6, IPIP, IPV4, NONE, PAY3),
	NGBE_PTT(0xC3, IP, IPV6, IPIP, IPV4, UDP,  PAY4),
	NGBE_PTT(0xC4, IP, IPV6, IPIP, IPV4, TCP,  PAY4),
	NGBE_PTT(0xC5, IP, IPV6, IPIP, IPV4, SCTP, PAY4),
	NGBE_UKN(0xC6),
	NGBE_UKN(0xC7),
	NGBE_UKN(0xC8),
	NGBE_PTT(0xC9, IP, IPV6, IPIP, FGV6, NONE, PAY3),
	NGBE_PTT(0xCA, IP, IPV6, IPIP, IPV6, NONE, PAY3),
	NGBE_PTT(0xCB, IP, IPV6, IPIP, IPV6, UDP,  PAY4),
	NGBE_PTT(0xCC, IP, IPV6, IPIP, IPV6, TCP,  PAY4),
	NGBE_PTT(0xCD, IP, IPV6, IPIP, IPV6, SCTP, PAY4),
	NGBE_UKN(0xCE),
	NGBE_UKN(0xCF),

	/* IPv6 --> GRE/NAT -> NONE/IPv4/IPv6 */
	NGBE_PTT(0xD0, IP, IPV6, IG,   NONE, NONE, PAY3),
	NGBE_PTT(0xD1, IP, IPV6, IG,   FGV4, NONE, PAY3),
	NGBE_PTT(0xD2, IP, IPV6, IG,   IPV4, NONE, PAY3),
	NGBE_PTT(0xD3, IP, IPV6, IG,   IPV4, UDP,  PAY4),
	NGBE_PTT(0xD4, IP, IPV6, IG,   IPV4, TCP,  PAY4),
	NGBE_PTT(0xD5, IP, IPV6, IG,   IPV4, SCTP, PAY4),
	NGBE_UKN(0xD6),
	NGBE_UKN(0xD7),
	NGBE_UKN(0xD8),
	NGBE_PTT(0xD9, IP, IPV6, IG,   FGV6, NONE, PAY3),
	NGBE_PTT(0xDA, IP, IPV6, IG,   IPV6, NONE, PAY3),
	NGBE_PTT(0xDB, IP, IPV6, IG,   IPV6, UDP,  PAY4),
	NGBE_PTT(0xDC, IP, IPV6, IG,   IPV6, TCP,  PAY4),
	NGBE_PTT(0xDD, IP, IPV6, IG,   IPV6, SCTP, PAY4),
	NGBE_UKN(0xDE),
	NGBE_UKN(0xDF),

	/* IPv6 --> GRE/NAT -> MAC -> NONE/IPv4/IPv6 */
	NGBE_PTT(0xE0, IP, IPV6, IGM,  NONE, NONE, PAY3),
	NGBE_PTT(0xE1, IP, IPV6, IGM,  FGV4, NONE, PAY3),
	NGBE_PTT(0xE2, IP, IPV6, IGM,  IPV4, NONE, PAY3),
	NGBE_PTT(0xE3, IP, IPV6, IGM,  IPV4, UDP,  PAY4),
	NGBE_PTT(0xE4, IP, IPV6, IGM,  IPV4, TCP,  PAY4),
	NGBE_PTT(0xE5, IP, IPV6, IGM,  IPV4, SCTP, PAY4),
	NGBE_UKN(0xE6),
	NGBE_UKN(0xE7),
	NGBE_UKN(0xE8),
	NGBE_PTT(0xE9, IP, IPV6, IGM,  FGV6, NONE, PAY3),
	NGBE_PTT(0xEA, IP, IPV6, IGM,  IPV6, NONE, PAY3),
	NGBE_PTT(0xEB, IP, IPV6, IGM,  IPV6, UDP,  PAY4),
	NGBE_PTT(0xEC, IP, IPV6, IGM,  IPV6, TCP,  PAY4),
	NGBE_PTT(0xED, IP, IPV6, IGM,  IPV6, SCTP, PAY4),
	NGBE_UKN(0xEE),
	NGBE_UKN(0xEF),

	/* IPv6 --> GRE/NAT -> MAC--> NONE/IPv */
	NGBE_PTT(0xF0, IP, IPV6, IGMV, NONE, NONE, PAY3),
	NGBE_PTT(0xF1, IP, IPV6, IGMV, FGV4, NONE, PAY3),
	NGBE_PTT(0xF2, IP, IPV6, IGMV, IPV4, NONE, PAY3),
	NGBE_PTT(0xF3, IP, IPV6, IGMV, IPV4, UDP,  PAY4),
	NGBE_PTT(0xF4, IP, IPV6, IGMV, IPV4, TCP,  PAY4),
	NGBE_PTT(0xF5, IP, IPV6, IGMV, IPV4, SCTP, PAY4),
	NGBE_UKN(0xF6),
	NGBE_UKN(0xF7),
	NGBE_UKN(0xF8),
	NGBE_PTT(0xF9, IP, IPV6, IGMV, FGV6, NONE, PAY3),
	NGBE_PTT(0xFA, IP, IPV6, IGMV, IPV6, NONE, PAY3),
	NGBE_PTT(0xFB, IP, IPV6, IGMV, IPV6, UDP,  PAY4),
	NGBE_PTT(0xFC, IP, IPV6, IGMV, IPV6, TCP,  PAY4),
	NGBE_PTT(0xFD, IP, IPV6, IGMV, IPV6, SCTP, PAY4),
	NGBE_UKN(0xFE),
	NGBE_UKN(0xFF),
};

#define DEFAULT_DEBUG_LEVEL_SHIFT 3
#define INFO_STRING_LEN           255

static void ngbe_clean_rx_ring(struct ngbe_ring *rx_ring);
static void ngbe_sync_mac_table(struct ngbe_adapter *adapter);
static void ngbe_configure_pb(struct ngbe_adapter *adapter);
static void ngbe_configure(struct ngbe_adapter *adapter);
static int ngbe_vlan_rx_add_vid(struct net_device *netdev,
				__always_unused __be16 proto, u16 vid);

static inline struct ngbe_dec_ptype ngbe_decode_ptype(const u8 ptype)
{
	return ngbe_ptype_lookup[ptype];
}

static inline struct ngbe_dec_ptype
decode_rx_desc_ptype(const union ngbe_rx_desc *rx_desc)
{
	return ngbe_decode_ptype(NGBE_RXD_PKTTYPE(rx_desc));
}

/**
 *  ngbe_init_ops - Inits func ptrs and MAC type
 *  @hw: pointer to hardware structure
 **/
s32 ngbe_init_ops(struct ngbe_hw *hw)
{
	ngbe_init_phy_ops_common(hw);
	ngbe_init_ops_common(hw);
	ngbe_init_external_phy_ops_common(hw);

	return NGBE_OK;
}

/**
 *  ngbe_init_shared_code - Initialize the shared code
 *  @hw: pointer to hardware structure
 **/
s32 ngbe_init_shared_code(struct ngbe_hw *hw)
{
	if ((hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_M88E1512_SFP ||
	    (hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_LY_M88E1512_SFP)
		hw->phy.type = ngbe_phy_m88e1512_sfi;
	else if ((hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_M88E1512_RJ45 ||
		 (hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_M88E1512_RJ45)
		hw->phy.type = ngbe_phy_m88e1512;
	else if ((hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_M88E1512_MIX)
		hw->phy.type = ngbe_phy_m88e1512_unknown;
	else if ((hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_YT8521S_SFP ||
		 (hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_YT8521S_SFP_GPIO ||
		(hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_LY_YT8521S_SFP)
		hw->phy.type = ngbe_phy_yt8521s_sfi;
	else if ((hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_INTERNAL_YT8521S_SFP ||
		 (hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_INTERNAL_YT8521S_SFP_GPIO)
		hw->phy.type = ngbe_phy_internal_yt8521s_sfi;
	else
		hw->phy.type = ngbe_phy_internal;

	if ((hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_LY_M88E1512_SFP ||
	    (hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_LY_YT8521S_SFP ||
		(hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_YT8521S_SFP_GPIO ||
		(hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_INTERNAL_YT8521S_SFP_GPIO)
		hw->gpio_ctl = 1;

	/* select claus22 */
	wr32(hw, NGBE_MDIO_CLAUSE_SELECT, 0xF);

	return ngbe_init_ops(hw);
}

/**
 * ngbe_sw_init - Initialize general software structures (struct ngbe_adapter)
 * @adapter: board private structure to initialize
 **/
static const u32 def_rss_key[10] = {
	0xE291D73D, 0x1805EC6C, 0x2A94B30D,
	0xA54F2BEC, 0xEA49AF7C, 0xE214AD3D, 0xB855AABE,
	0x6A3E67EA, 0x14364D17, 0x3BED200D
};

static int ngbe_sw_init(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;
	struct pci_dev *pdev = adapter->pdev;
	int err;
	u32 ssid = 0;

	/* PCI config space info */
	hw->vendor_id = pdev->vendor;
	hw->device_id = pdev->device;
	hw->revision_id = pdev->revision;
	hw->oem_svid = pdev->subsystem_vendor;
	hw->oem_ssid = pdev->subsystem_device;

	if (pdev->subsystem_vendor == PCI_VENDOR_ID_WANGXUN) {
		hw->subsystem_vendor_id = pdev->subsystem_vendor;
		hw->subsystem_device_id = pdev->subsystem_device;
	} else {
		err = ngbe_flash_read_dword(hw, 0xfffdc, &ssid);
		if (err) {
			e_err(probe, "read of internal subsystem device id failed\n");
			err = -ENODEV;
			goto out;
		}
		hw->subsystem_device_id = ssid >> 8 | ssid << 8;
	}

	/* phy type, phy ops, mac ops */
	err = ngbe_init_shared_code(hw);
	if (err) {
		e_err(probe, "init_shared_code failed: %d\n", err);
		goto out;
	}

	adapter->mac_table = kzalloc(sizeof(*adapter->mac_table) *
						 hw->mac.num_rar_entries,
						 GFP_ATOMIC);
	if (!adapter->mac_table) {
		err = NGBE_ERR_OUT_OF_MEM;
		e_err(probe, "mac_table allocation failed: %d\n", err);
		goto out;
	}

	memcpy(adapter->rss_key, def_rss_key, sizeof(def_rss_key));

	/* Set common capability flags and settings */
	adapter->max_q_vectors = NGBE_MAX_MSIX_Q_VECTORS_EMERALD;

	/* Set MAC specific capability flags and exceptions */
	adapter->flags |= NGBE_FLAGS_SP_INIT;
	adapter->flags2 |= NGBE_FLAG2_TEMP_SENSOR_CAPABLE;
	adapter->flags2 |= NGBE_FLAG2_EEE_CAPABLE;

	/* default flow control settings */
	hw->fc.requested_mode = ngbe_fc_full;
	hw->fc.current_mode = ngbe_fc_full; /* init for ethtool output */

	adapter->last_lfc_mode = hw->fc.current_mode;
	hw->fc.pause_time = NGBE_DEFAULT_FCPAUSE;
	hw->fc.send_xon = true;
	hw->fc.disable_fc_autoneg = false;

	/* set default ring sizes */
	adapter->tx_ring_count = NGBE_DEFAULT_TXD;
	adapter->rx_ring_count = NGBE_DEFAULT_RXD;

	/* set default work limits */
	adapter->tx_work_limit = NGBE_DEFAULT_TX_WORK;
	adapter->rx_work_limit = NGBE_DEFAULT_RX_WORK;

	adapter->tx_timeout_recovery_level = 0;

	set_bit(__NGBE_DOWN, &adapter->state);
out:
	return err;
}

/**
 * ngbe_setup_tx_resources - allocate Tx resources (Descriptors)
 * @tx_ring:    tx descriptor ring (for a specific queue) to setup
 *
 * Return 0 on success, negative on failure
 **/
int ngbe_setup_tx_resources(struct ngbe_ring *tx_ring)
{
	struct device *dev = tx_ring->dev;
	int orig_node = dev_to_node(dev);
	int numa_node = -1;
	int size;

	size = sizeof(struct ngbe_tx_buffer) * tx_ring->count;

	if (tx_ring->q_vector)
		numa_node = tx_ring->q_vector->numa_node;

	tx_ring->tx_buffer_info = vzalloc_node(size, numa_node);
	if (!tx_ring->tx_buffer_info)
		tx_ring->tx_buffer_info = vzalloc(size);
	if (!tx_ring->tx_buffer_info)
		goto err;

	/* round up to nearest 4K */
	tx_ring->size = tx_ring->count * sizeof(union ngbe_tx_desc);
	tx_ring->size = ALIGN(tx_ring->size, 4096);

	set_dev_node(dev, numa_node);
	tx_ring->desc = dma_alloc_coherent(dev,
					   tx_ring->size,
					   &tx_ring->dma,
					   GFP_KERNEL);
	set_dev_node(dev, orig_node);
	if (!tx_ring->desc)
		tx_ring->desc = dma_alloc_coherent(dev, tx_ring->size,
						   &tx_ring->dma, GFP_KERNEL);
	if (!tx_ring->desc)
		goto err;

	return 0;

err:
	vfree(tx_ring->tx_buffer_info);
	tx_ring->tx_buffer_info = NULL;
	dev_err(dev, "Unable to allocate memory for the Tx descriptor ring\n");

	return -ENOMEM;
}

static inline struct netdev_queue *txring_txq(const struct ngbe_ring *ring)
{
	return netdev_get_tx_queue(ring->netdev, ring->queue_index);
}

/**
 * ngbe_clean_tx_ring - Free Tx Buffers
 * @tx_ring: ring to be cleaned
 **/
static void ngbe_clean_tx_ring(struct ngbe_ring *tx_ring)
{
	struct ngbe_tx_buffer *tx_buffer_info;
	unsigned long size;
	u16 i;

	/* ring already cleared, nothing to do */
	if (!tx_ring->tx_buffer_info)
		return;

	/* Free all the Tx ring sk_buffs */
	for (i = 0; i < tx_ring->count; i++) {
		tx_buffer_info = &tx_ring->tx_buffer_info[i];
		ngbe_unmap_and_free_tx_res(tx_ring, tx_buffer_info);
	}

	netdev_tx_reset_queue(txring_txq(tx_ring));

	size = sizeof(struct ngbe_tx_buffer) * tx_ring->count;
	memset(tx_ring->tx_buffer_info, 0, size);

	/* Zero out the descriptor ring */
	memset(tx_ring->desc, 0, tx_ring->size);
}

/**
 * ngbe_free_tx_resources - Free Tx Resources per Queue
 * @tx_ring: Tx descriptor ring for a specific queue
 *
 * Free all transmit software resources
 **/
void ngbe_free_tx_resources(struct ngbe_ring *tx_ring)
{
	ngbe_clean_tx_ring(tx_ring);

	vfree(tx_ring->tx_buffer_info);
	tx_ring->tx_buffer_info = NULL;

	/* if not set, then don't free */
	if (!tx_ring->desc)
		return;

	dma_free_coherent(tx_ring->dev, tx_ring->size,
			  tx_ring->desc, tx_ring->dma);
	tx_ring->desc = NULL;
}

/**
 * ngbe_setup_all_tx_resources - allocate all queues Tx resources
 * @adapter: board private structure
 *
 * Return 0 on success, negative on failure
 **/
static int ngbe_setup_all_tx_resources(struct ngbe_adapter *adapter)
{
	int i, err = 0;

	for (i = 0; i < adapter->num_tx_queues; i++) {
		err = ngbe_setup_tx_resources(adapter->tx_ring[i]);
		if (!err)
			continue;

		e_err(probe, "Allocation for Tx Queue %u failed\n", i);
		goto err_setup_tx;
	}

	return 0;
err_setup_tx:
	/* rewind the index freeing the rings as we go */
	while (i--)
		ngbe_free_tx_resources(adapter->tx_ring[i]);
	return err;
}

/**
 * ngbe_free_all_tx_resources - Free Tx Resources for All Queues
 * @adapter: board private structure
 *
 * Free all transmit software resources
 **/
static void ngbe_free_all_tx_resources(struct ngbe_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_tx_queues; i++)
		ngbe_free_tx_resources(adapter->tx_ring[i]);
}

/**
 * ngbe_setup_rx_resources - allocate Rx resources (Descriptors)
 * @rx_ring:    rx descriptor ring (for a specific queue) to setup
 *
 * Returns 0 on success, negative on failure
 **/
int ngbe_setup_rx_resources(struct ngbe_ring *rx_ring)
{
	struct device *dev = rx_ring->dev;
	int orig_node = dev_to_node(dev);
	int numa_node = -1;
	int size;

	size = sizeof(struct ngbe_rx_buffer) * rx_ring->count;

	if (rx_ring->q_vector)
		numa_node = rx_ring->q_vector->numa_node;

	rx_ring->rx_buffer_info = vzalloc_node(size, numa_node);
	if (!rx_ring->rx_buffer_info)
		rx_ring->rx_buffer_info = vzalloc(size);
	if (!rx_ring->rx_buffer_info)
		goto err;

	/* Round up to nearest 4K */
	rx_ring->size = rx_ring->count * sizeof(union ngbe_rx_desc);
	rx_ring->size = ALIGN(rx_ring->size, 4096);

	set_dev_node(dev, numa_node);
	rx_ring->desc = dma_alloc_coherent(dev,
					   rx_ring->size,
					   &rx_ring->dma,
					   GFP_KERNEL);
	set_dev_node(dev, orig_node);
	if (!rx_ring->desc)
		rx_ring->desc = dma_alloc_coherent(dev, rx_ring->size,
						   &rx_ring->dma, GFP_KERNEL);
	if (!rx_ring->desc)
		goto err;

	return 0;
err:
	vfree(rx_ring->rx_buffer_info);
	rx_ring->rx_buffer_info = NULL;
	dev_err(dev, "Unable to allocate memory for the Rx descriptor ring\n");
	return -ENOMEM;
}

/**
 * ngbe_free_rx_resources - Free Rx Resources
 * @rx_ring: ring to clean the resources from
 *
 * Free all receive software resources
 **/
void ngbe_free_rx_resources(struct ngbe_ring *rx_ring)
{
	ngbe_clean_rx_ring(rx_ring);

	vfree(rx_ring->rx_buffer_info);
	rx_ring->rx_buffer_info = NULL;

	/* if not set, then don't free */
	if (!rx_ring->desc)
		return;

	dma_free_coherent(rx_ring->dev, rx_ring->size,
			  rx_ring->desc, rx_ring->dma);

	rx_ring->desc = NULL;
}

/**
 * ngbe_setup_all_rx_resources - allocate all queues Rx resources
 * @adapter: board private structure
 *
 * Return 0 on success, negative on failure
 **/
static int ngbe_setup_all_rx_resources(struct ngbe_adapter *adapter)
{
	int i, err = 0;

	for (i = 0; i < adapter->num_rx_queues; i++) {
		err = ngbe_setup_rx_resources(adapter->rx_ring[i]);
		if (!err)
			continue;

		e_err(probe, "Allocation for Rx Queue %u failed\n", i);
		goto err_setup_rx;
	}

		return 0;
err_setup_rx:
	/* rewind the index freeing the rings as we go */
	while (i--)
		ngbe_free_rx_resources(adapter->rx_ring[i]);

	return err;
}

/**
 * ngbe_free_all_rx_resources - Free Rx Resources for All Queues
 * @adapter: board private structure
 *
 * Free all receive software resources
 **/
static void ngbe_free_all_rx_resources(struct ngbe_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_rx_queues; i++)
		ngbe_free_rx_resources(adapter->rx_ring[i]);
}

/**
 * ngbe_setup_isb_resources - allocate interrupt status resources
 * @adapter: board private structure
 *
 * Return 0 on success, negative on failure
 **/
static int ngbe_setup_isb_resources(struct ngbe_adapter *adapter)
{
	struct device *dev = pci_dev_to_dev(adapter->pdev);

	adapter->isb_mem = dma_alloc_coherent(dev,
					      sizeof(u32) * NGBE_ISB_MAX,
					   &adapter->isb_dma,
					   GFP_KERNEL);
	if (!adapter->isb_mem) {
		e_err(probe, "%s: alloc isb_mem failed\n", __func__);
		return -ENOMEM;
	}
	memset(adapter->isb_mem, 0, sizeof(u32) * NGBE_ISB_MAX);
	return 0;
}

void ngbe_service_event_schedule(struct ngbe_adapter *adapter)
{
	if (!test_bit(__NGBE_DOWN, &adapter->state) &&
	    !test_bit(__NGBE_REMOVING, &adapter->state) &&
		!test_and_set_bit(__NGBE_SERVICE_SCHED, &adapter->state))
		queue_work(ngbe_wq, &adapter->service_task);
}

static void ngbe_handle_phy_event(struct ngbe_hw *hw)
{
	struct ngbe_adapter *adapter = hw->back;
	u32 reg;

	reg = rd32(hw, NGBE_GPIO_INTSTATUS);
	wr32(hw, NGBE_GPIO_EOI, reg);

	if (!((hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_RGMII_FPGA))
		TCALL(hw, phy.ops.check_event);

	adapter->lsc_int++;
	adapter->link_check_timeout = jiffies;
	if (!test_bit(__NGBE_DOWN, &adapter->state))
		ngbe_service_event_schedule(adapter);
}

static void ngbe_check_overtemp_event(struct ngbe_adapter *adapter, u32 eicr)
{
	if (!(adapter->flags2 & NGBE_FLAG2_TEMP_SENSOR_CAPABLE))
		return;

	if (!(eicr & NGBE_PX_MISC_IC_OVER_HEAT))
		return;
	if (!test_bit(__NGBE_DOWN, &adapter->state)) {
		adapter->interrupt_event = eicr;
		adapter->flags2 |= NGBE_FLAG2_TEMP_SENSOR_EVENT;
		ngbe_service_event_schedule(adapter);
	}
}

/**
 * ngbe_irq_enable - Enable default interrupt generation settings
 * @adapter: board private structure
 **/
void ngbe_irq_enable(struct ngbe_adapter *adapter, bool queues, bool flush)
{
	u32 mask = 0;
	struct ngbe_hw *hw = &adapter->hw;

	/* enable misc interrupt */
	mask = NGBE_PX_MISC_IEN_MASK;

	if (adapter->flags2 & NGBE_FLAG2_TEMP_SENSOR_CAPABLE)
		mask |= NGBE_PX_MISC_IEN_OVER_HEAT;

	mask |= NGBE_PX_MISC_IEN_TIMESYNC;

	wr32(&adapter->hw, NGBE_GPIO_DDR, 0x1);
	wr32(&adapter->hw, NGBE_GPIO_INTEN, 0x3);
	wr32(&adapter->hw, NGBE_GPIO_INTTYPE_LEVEL, 0x0);
	if (adapter->hw.phy.type == ngbe_phy_yt8521s_sfi ||
	    adapter->hw.phy.type == ngbe_phy_internal_yt8521s_sfi)
		wr32(&adapter->hw, NGBE_GPIO_POLARITY, 0x0);
	else
		wr32(&adapter->hw, NGBE_GPIO_POLARITY, 0x3);

	if (adapter->hw.phy.type == ngbe_phy_yt8521s_sfi ||
	    adapter->hw.phy.type == ngbe_phy_internal_yt8521s_sfi)
		mask |= NGBE_PX_MISC_IEN_GPIO;

	wr32(hw, NGBE_PX_MISC_IEN, mask);

	/* unmask interrupt */
	if (queues)
		ngbe_intr_enable(&adapter->hw, NGBE_INTR_ALL);
	else
		ngbe_intr_enable(&adapter->hw, NGBE_INTR_MISC(adapter));

	/* flush configuration */
	if (flush)
		NGBE_WRITE_FLUSH(&adapter->hw);
}

static irqreturn_t ngbe_msix_other(int __always_unused irq, void *data)
{
	struct ngbe_adapter *adapter = data;
	struct ngbe_hw *hw = &adapter->hw;
	u32 eicr;
	u32 ecc;

	eicr = ngbe_misc_isb(adapter, NGBE_ISB_MISC);
	if (eicr & (NGBE_PX_MISC_IC_PHY | NGBE_PX_MISC_IC_GPIO))
		ngbe_handle_phy_event(hw);

	if (eicr & NGBE_PX_MISC_IC_INT_ERR) {
		e_info(link, "Received unrecoverable ECC Err, initiating reset.\n");
		ecc = rd32(hw, NGBE_MIS_ST);
		e_info(link, "ecc error status is 0x%08x\n", ecc);
		if (((ecc & NGBE_MIS_ST_LAN0_ECC) && hw->bus.lan_id == 0) ||
		    ((ecc & NGBE_MIS_ST_LAN1_ECC) && hw->bus.lan_id == 1))
			adapter->flags2 |= NGBE_FLAG2_DEV_RESET_REQUESTED;

		ngbe_service_event_schedule(adapter);
	}
	if (eicr & NGBE_PX_MISC_IC_DEV_RST) {
		adapter->flags2 |= NGBE_FLAG2_RESET_INTR_RECEIVED;
		ngbe_service_event_schedule(adapter);
	}
	if ((eicr & NGBE_PX_MISC_IC_STALL) ||
	    (eicr & NGBE_PX_MISC_IC_ETH_EVENT)) {
		adapter->flags2 |= NGBE_FLAG2_PF_RESET_REQUESTED;
		ngbe_service_event_schedule(adapter);
	}

	ngbe_check_overtemp_event(adapter, eicr);

	if (unlikely(eicr & NGBE_PX_MISC_IC_TIMESYNC))
		ngbe_ptp_check_pps_event(adapter);

	/* re-enable the original interrupt state, no lsc, no queues */
	if (!test_bit(__NGBE_DOWN, &adapter->state))
		ngbe_irq_enable(adapter, false, false);

	return IRQ_HANDLED;
}

static irqreturn_t ngbe_msix_clean_rings(int __always_unused irq, void *data)
{
	struct ngbe_q_vector *q_vector = data;

	/* EIAM disabled interrupts (on this vector) for us */

	if (q_vector->rx.ring || q_vector->tx.ring)
		napi_schedule_irqoff(&q_vector->napi);

	return IRQ_HANDLED;
}

/**
 * ngbe_clean_rx_ring - Free Rx Buffers per Queue
 * @rx_ring: ring to free buffers from
 **/
static void ngbe_clean_rx_ring(struct ngbe_ring *rx_ring)
{
	struct device *dev = rx_ring->dev;
	unsigned long size;
	u16 i;

	/* ring already cleared, nothing to do */
	if (!rx_ring->rx_buffer_info)
		return;

	/* Free all the Rx ring sk_buffs */
	for (i = 0; i < rx_ring->count; i++) {
		struct ngbe_rx_buffer *rx_buffer = &rx_ring->rx_buffer_info[i];

		if (rx_buffer->dma) {
			dma_unmap_single(dev,
					 rx_buffer->dma,
					 rx_ring->rx_buf_len,
					 DMA_FROM_DEVICE);
			rx_buffer->dma = 0;
		}

		if (rx_buffer->skb) {
			struct sk_buff *skb = rx_buffer->skb;

			if (NGBE_CB(skb)->dma_released) {
				dma_unmap_single(dev,
						 NGBE_CB(skb)->dma,
						rx_ring->rx_buf_len,
						DMA_FROM_DEVICE);
				NGBE_CB(skb)->dma = 0;
				NGBE_CB(skb)->dma_released = false;
			}

			if (NGBE_CB(skb)->page_released)
				dma_unmap_page(dev,
					       NGBE_CB(skb)->dma,
						ngbe_rx_bufsz(rx_ring),
						DMA_FROM_DEVICE);

			dev_kfree_skb(skb);
			rx_buffer->skb = NULL;
		}

		if (!rx_buffer->page)
			continue;

		dma_unmap_page(dev, rx_buffer->page_dma,
			       ngbe_rx_pg_size(rx_ring),
					DMA_FROM_DEVICE);

		__free_pages(rx_buffer->page,
			     ngbe_rx_pg_order(rx_ring));
		rx_buffer->page = NULL;
	}

	size = sizeof(struct ngbe_rx_buffer) * rx_ring->count;
	memset(rx_ring->rx_buffer_info, 0, size);

	/* Zero out the descriptor ring */
	memset(rx_ring->desc, 0, rx_ring->size);

	rx_ring->next_to_alloc = 0;
	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;
}

/**
 * ngbe_request_msix_irqs - Initialize MSI-X interrupts
 * @adapter: board private structure
 *
 * ngbe_request_msix_irqs allocates MSI-X vectors and requests
 * interrupts from the kernel.
 **/
static int ngbe_request_msix_irqs(struct ngbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	int vector, err;
	int ri = 0, ti = 0;

	for (vector = 0; vector < adapter->num_q_vectors; vector++) {
		struct ngbe_q_vector *q_vector = adapter->q_vector[vector];
		struct msix_entry *entry = &adapter->msix_entries[vector];

		if (q_vector->tx.ring && q_vector->rx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-TxRx-%d", netdev->name, ri++);
			ti++;
		} else if (q_vector->rx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-rx-%d", netdev->name, ri++);
		} else if (q_vector->tx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-tx-%d", netdev->name, ti++);
		} else {
			/* skip this unused q_vector */
			continue;
		}
		err = request_irq(entry->vector, &ngbe_msix_clean_rings, 0,
				  q_vector->name, q_vector);
		if (err) {
			e_err(probe, "request_irq failed for MSIX '%s' Error: %d\n",
			      q_vector->name, err);
			goto free_queue_irqs;
		}
	}

	err = request_irq(adapter->msix_entries[vector].vector,
			  ngbe_msix_other, 0, netdev->name, adapter);

	if (err) {
		e_err(probe, "request_irq for msix_other failed: %d\n", err);
		goto free_queue_irqs;
	}

	return 0;

free_queue_irqs:
	while (vector) {
		vector--;

		irq_set_affinity_hint(adapter->msix_entries[vector].vector, NULL);

		free_irq(adapter->msix_entries[vector].vector,
			 adapter->q_vector[vector]);
	}
	adapter->flags &= ~NGBE_FLAG_MSIX_ENABLED;
	pci_disable_msix(adapter->pdev);
	kfree(adapter->msix_entries);
	adapter->msix_entries = NULL;
	return err;
}

/**
 * ngbe_intr - legacy mode Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a network interface device structure
 **/
static irqreturn_t ngbe_intr(int __always_unused irq, void *data)
{
	struct ngbe_adapter *adapter = data;
	struct ngbe_hw *hw = &adapter->hw;
	struct ngbe_q_vector *q_vector = adapter->q_vector[0];
	u32 eicr;
	u32 eicr_misc;
	u32 ecc = 0;
	return IRQ_HANDLED;
	eicr = ngbe_misc_isb(adapter, NGBE_ISB_VEC0);
	if (!eicr) {
		/* shared interrupt alert!
		 * the interrupt that we masked before the EICR read.
		 */
		if (!test_bit(__NGBE_DOWN, &adapter->state))
			ngbe_irq_enable(adapter, true, true);
		return IRQ_NONE;        /* Not our interrupt */
	}
	adapter->isb_mem[NGBE_ISB_VEC0] = 0;
	if (!(adapter->flags & NGBE_FLAG_MSI_ENABLED))
		wr32(&adapter->hw, NGBE_PX_INTA, 1);

	eicr_misc = ngbe_misc_isb(adapter, NGBE_ISB_MISC);
	if (eicr_misc & (NGBE_PX_MISC_IC_PHY | NGBE_PX_MISC_IC_GPIO))
		ngbe_handle_phy_event(hw);

	if (eicr_misc & NGBE_PX_MISC_IC_INT_ERR) {
		e_info(link, "Received unrecoverable ECC Err, initiating reset.\n");
		ecc = rd32(hw, NGBE_MIS_ST);
		e_info(link, "ecc error status is 0x%08x\n", ecc);
		adapter->flags2 |= NGBE_FLAG2_DEV_RESET_REQUESTED;
		ngbe_service_event_schedule(adapter);
	}

	if (eicr_misc & NGBE_PX_MISC_IC_DEV_RST) {
		adapter->flags2 |= NGBE_FLAG2_RESET_INTR_RECEIVED;
		ngbe_service_event_schedule(adapter);
	}
	ngbe_check_overtemp_event(adapter, eicr_misc);

	if (unlikely(eicr_misc & NGBE_PX_MISC_IC_TIMESYNC))
		ngbe_ptp_check_pps_event(adapter);

	adapter->isb_mem[NGBE_ISB_MISC] = 0;

	/* would disable interrupts here but it is auto disabled */
	napi_schedule_irqoff(&q_vector->napi);

	/* re-enable link(maybe) and non-queue interrupts, no flush.
	 * ngbe_poll will re-enable the queue interrupts
	 */
	if (!test_bit(__NGBE_DOWN, &adapter->state))
		ngbe_irq_enable(adapter, false, false);

	return IRQ_HANDLED;
}

/**
 * ngbe_request_irq - initialize interrupts
 * @adapter: board private structure
 **/
static int ngbe_request_irq(struct ngbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	int err;

	if (adapter->flags & NGBE_FLAG_MSIX_ENABLED)
		err = ngbe_request_msix_irqs(adapter);
	else if (adapter->flags & NGBE_FLAG_MSI_ENABLED)
		err = request_irq(adapter->pdev->irq, &ngbe_intr, 0,
				  netdev->name, adapter);
	else
		err = request_irq(adapter->pdev->irq, &ngbe_intr, IRQF_SHARED,
				  netdev->name, adapter);

	if (err)
		e_err(probe, "request_irq failed, Error %d\n", err);

	return err;
}

static void ngbe_get_hw_control(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;

	/* Let firmware know the driver has taken over */
	wr32m(&adapter->hw, NGBE_CFG_PORT_CTL,
	      NGBE_CFG_PORT_CTL_DRV_LOAD, NGBE_CFG_PORT_CTL_DRV_LOAD);

	if (hw->phy.type == ngbe_phy_yt8521s_sfi)
		wr32(&adapter->hw, NGBE_CFG_LED_CTL, BIT(18));
}

static void ngbe_setup_gpie(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;
	u32 gpie = 0;

	if (adapter->flags & NGBE_FLAG_MSIX_ENABLED)
		gpie = NGBE_PX_GPIE_MODEL;

	wr32(hw, NGBE_PX_GPIE, gpie);
}

/**
 * ngbe_set_ivar - set the IVAR registers, mapping interrupt causes to vectors
 * @adapter: pointer to adapter struct
 * @direction: 0 for Rx, 1 for Tx, -1 for other causes
 * @queue: queue to map the corresponding interrupt to
 * @msix_vector: the vector to map to the corresponding queue
 **/
static void ngbe_set_ivar(struct ngbe_adapter *adapter, s8 direction,
			  u16 queue, u16 msix_vector)
{
	u32 ivar, index;
	struct ngbe_hw *hw = &adapter->hw;

	if (direction == -1) {
		/* other causes */
		msix_vector |= NGBE_PX_IVAR_ALLOC_VAL;
		index = 0;
		ivar = rd32(&adapter->hw, NGBE_PX_MISC_IVAR);
		ivar &= ~(0xFF << index);
		ivar |= (msix_vector << index);
		/* if assigned VFs >= 7, the pf misc irq shall be remapped to 0x88. */
		if (adapter->flags2 & NGBE_FLAG2_SRIOV_MISC_IRQ_REMAP)
			ivar = msix_vector;
		wr32(&adapter->hw, NGBE_PX_MISC_IVAR, ivar);
	} else {
		/* tx or rx causes */
		msix_vector |= NGBE_PX_IVAR_ALLOC_VAL;
		index = ((16 * (queue & 1)) + (8 * direction));
		ivar = rd32(hw, NGBE_PX_IVAR(queue >> 1));
		ivar &= ~(0xFF << index);
		ivar |= (msix_vector << index);
		wr32(hw, NGBE_PX_IVAR(queue >> 1), ivar);
	}
}

/**
 * ngbe_write_eitr - write EITR register in hardware specific way
 * @q_vector: structure containing interrupt and ring information
 */
void ngbe_write_eitr(struct ngbe_q_vector *q_vector)
{
	struct ngbe_adapter *adapter = q_vector->adapter;
	struct ngbe_hw *hw = &adapter->hw;
	int v_idx = q_vector->v_idx;
	u32 itr_reg = q_vector->itr & NGBE_MAX_EITR;

	itr_reg |= NGBE_PX_ITR_CNT_WDIS;

	wr32(hw, NGBE_PX_ITR(v_idx), itr_reg);
}

/**
 * ngbe_configure_msix - Configure MSI-X hardware
 * @adapter: board private structure
 *
 * ngbe_configure_msix sets up the hardware to properly generate MSI-X
 * interrupts.
 **/
static void ngbe_configure_msix(struct ngbe_adapter *adapter)
{
	u16 v_idx;
	u32 i;
	u32 eitrsel = 0;

	/* Populate MSIX to EITR Select */
	if (!(adapter->flags & NGBE_FLAG_VMDQ_ENABLED)) {
		wr32(&adapter->hw, NGBE_PX_ITRSEL, eitrsel);
	} else {
		for (i = 0; i < adapter->num_vfs; i++)
			eitrsel |= 1 << i;

		wr32(&adapter->hw, NGBE_PX_ITRSEL, eitrsel);
	}

	/* Populate the IVAR table and set the ITR values to the
	 * corresponding register.
	 */
	for (v_idx = 0; v_idx < adapter->num_q_vectors; v_idx++) {
		struct ngbe_q_vector *q_vector = adapter->q_vector[v_idx];
		struct ngbe_ring *ring;

		ngbe_for_each_ring(ring, q_vector->rx)
			ngbe_set_ivar(adapter, 0, ring->reg_idx, v_idx);

		ngbe_for_each_ring(ring, q_vector->tx)
			ngbe_set_ivar(adapter, 1, ring->reg_idx, v_idx);

		ngbe_write_eitr(q_vector);
	}

	ngbe_set_ivar(adapter, -1, 0, v_idx);
	wr32(&adapter->hw, NGBE_PX_ITR(v_idx), 1950);
}

/**
 * ngbe_configure_msi_and_legacy - Initialize PIN (INTA...) and MSI interrupts
 **/
static void ngbe_configure_msi_and_legacy(struct ngbe_adapter *adapter)
{
	struct ngbe_q_vector *q_vector = adapter->q_vector[0];
	struct ngbe_ring *ring;

	ngbe_write_eitr(q_vector);

	ngbe_for_each_ring(ring, q_vector->rx)
		ngbe_set_ivar(adapter, 0, ring->reg_idx, 0);

	ngbe_for_each_ring(ring, q_vector->tx)
		ngbe_set_ivar(adapter, 1, ring->reg_idx, 0);

	ngbe_set_ivar(adapter, -1, 0, 1);

	e_info(hw, "Legacy interrupt IVAR setup done\n");
}

/**
 * ngbe_non_sfp_link_config - set up non-SFP+ link
 * @hw: pointer to private hardware struct
 *
 * Returns 0 on success, negative on failure
 **/
static int ngbe_non_sfp_link_config(struct ngbe_hw *hw)
{
	u32 speed;
	u32 ret = NGBE_ERR_LINK_SETUP;

	if (hw->mac.autoneg)
		speed = hw->phy.autoneg_advertised;
	else
		speed = hw->phy.force_speed;

	if ((hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_OCP_CARD ||
	    (hw->subsystem_device_id & NGBE_NCSI_MASK) == NGBE_NCSI_SUP ||
		(hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_RGMII_FPGA)
		return 0;

		if (hw->phy.type == ngbe_phy_internal ||
			hw->phy.type == ngbe_phy_internal_yt8521s_sfi) {
			mdelay(50);
			if (hw->phy.type == ngbe_phy_internal ||
			    hw->phy.type == ngbe_phy_internal_yt8521s_sfi)
				TCALL(hw, phy.ops.setup_once);
		}

	ret = TCALL(hw, mac.ops.setup_link, speed, false);

	return ret;
}

static void ngbe_napi_enable_all(struct ngbe_adapter *adapter)
{
	struct ngbe_q_vector *q_vector;
	int q_idx;

	for (q_idx = 0; q_idx < adapter->num_q_vectors; q_idx++) {
		q_vector = adapter->q_vector[q_idx];

		napi_enable(&q_vector->napi);
	}
}

static void ngbe_up_complete(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;
	int err;

	ngbe_get_hw_control(adapter);
	ngbe_setup_gpie(adapter);

	if (adapter->flags & NGBE_FLAG_MSIX_ENABLED)
		ngbe_configure_msix(adapter);
	else
		ngbe_configure_msi_and_legacy(adapter);

	/* flush memory to make sure state is correct */
	smp_mb__before_atomic();
	clear_bit(__NGBE_DOWN, &adapter->state);
	ngbe_napi_enable_all(adapter);

	err = ngbe_non_sfp_link_config(hw);
	if (err)
		e_err(probe, "link_config FAILED %d\n", err);

	/* sellect GMII */
	wr32(hw, NGBE_MAC_TX_CFG,
	     (rd32(hw, NGBE_MAC_TX_CFG) & ~NGBE_MAC_TX_CFG_SPEED_MASK) |
		NGBE_MAC_TX_CFG_SPEED_1G);

	/* clear any pending interrupts, may auto mask */
	rd32(hw, NGBE_PX_IC);
	rd32(hw, NGBE_PX_MISC_IC);
	ngbe_irq_enable(adapter, true, true);

	if (hw->gpio_ctl == 1)
		/* gpio0 is used to power on/off control*/
		wr32(hw, NGBE_GPIO_DR, 0);

	/* enable transmits */
	netif_tx_start_all_queues(adapter->netdev);

	/* bring the link up in the watchdog, this could race with our first
	 * link up interrupt but shouldn't be a problem
	 */
	adapter->flags |= NGBE_FLAG_NEED_LINK_UPDATE;
	adapter->link_check_timeout = jiffies;

	mod_timer(&adapter->service_timer, jiffies);

	/* Set PF Reset Done bit so PF/VF Mail Ops can work */
	wr32m(hw, NGBE_CFG_PORT_CTL,
	      NGBE_CFG_PORT_CTL_PFRSTD, NGBE_CFG_PORT_CTL_PFRSTD);
}

static void ngbe_free_irq(struct ngbe_adapter *adapter)
{
	int vector;

	if (!(adapter->flags & NGBE_FLAG_MSIX_ENABLED)) {
		free_irq(adapter->pdev->irq, adapter);
		return;
	}

	for (vector = 0; vector < adapter->num_q_vectors; vector++) {
		struct ngbe_q_vector *q_vector = adapter->q_vector[vector];
		struct msix_entry *entry = &adapter->msix_entries[vector];

		/* free only the irqs that were actually requested */
		if (!q_vector->rx.ring && !q_vector->tx.ring)
			continue;

		/* clear the affinity_mask in the IRQ descriptor */
		irq_set_affinity_hint(entry->vector, NULL);

		free_irq(entry->vector, q_vector);
	}

	free_irq(adapter->msix_entries[vector++].vector, adapter);
}

/**
 * ngbe_free_isb_resources - allocate all queues Rx resources
 * @adapter: board private structure
 *
 * Return 0 on success, negative on failure
 **/
static void ngbe_free_isb_resources(struct ngbe_adapter *adapter)
{
	struct device *dev = pci_dev_to_dev(adapter->pdev);

	dma_free_coherent(dev, sizeof(u32) * NGBE_ISB_MAX,
			  adapter->isb_mem, adapter->isb_dma);
	adapter->isb_mem = NULL;
}

static void ngbe_flush_sw_mac_table(struct ngbe_adapter *adapter)
{
	u32 i;
	struct ngbe_hw *hw = &adapter->hw;

	for (i = 0; i < hw->mac.num_rar_entries; i++) {
		adapter->mac_table[i].state |= NGBE_MAC_STATE_MODIFIED;
		adapter->mac_table[i].state &= ~NGBE_MAC_STATE_IN_USE;
		memset(adapter->mac_table[i].addr, 0, ETH_ALEN);
		adapter->mac_table[i].pools = 0;
	}
	ngbe_sync_mac_table(adapter);
}

/* this function destroys the first RAR entry */
static void ngbe_mac_set_default_filter(struct ngbe_adapter *adapter,
					u8 *addr)
{
	struct ngbe_hw *hw = &adapter->hw;

	memcpy(&adapter->mac_table[0].addr, addr, ETH_ALEN);
	adapter->mac_table[0].pools = 1ULL << 0;
	adapter->mac_table[0].state = (NGBE_MAC_STATE_DEFAULT |
				       NGBE_MAC_STATE_IN_USE);
	TCALL(hw, mac.ops.set_rar, 0, adapter->mac_table[0].addr,
	      adapter->mac_table[0].pools,
			    NGBE_PSR_MAC_SWC_AD_H_AV);
}

void ngbe_reset(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	int err;
	u8 old_addr[ETH_ALEN];

	if (NGBE_REMOVED(hw->hw_addr))
		return;

	err = TCALL(hw, mac.ops.init_hw);
	switch (err) {
	case 0:
		break;
	case NGBE_ERR_MASTER_REQUESTS_PENDING:
		e_dev_err("master disable timed out\n");
		break;
	case NGBE_ERR_EEPROM_VERSION:
		/* We are running on a pre-production device, log a warning */
		e_dev_warn("eeprom version error.\n");
		break;
	default:
		e_dev_err("Hardware Error: %d\n", err);
	}

	/* do not flush user set addresses */
	memcpy(old_addr, &adapter->mac_table[0].addr, netdev->addr_len);
	ngbe_flush_sw_mac_table(adapter);
	ngbe_mac_set_default_filter(adapter, old_addr);

	/* Clear saved DMA coalescing values except for watchdog_timer */
	hw->mac.dmac_config.fcoe_en = false;
	hw->mac.dmac_config.link_speed = 0;
	hw->mac.dmac_config.fcoe_tc = 0;
	hw->mac.dmac_config.num_tcs = 0;

	if (test_bit(__NGBE_PTP_RUNNING, &adapter->state))
		ngbe_ptp_reset(adapter);
}

/**
 * ngbe_clean_all_tx_rings - Free Tx Buffers for all queues
 * @adapter: board private structure
 **/
static void ngbe_clean_all_tx_rings(struct ngbe_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_tx_queues; i++)
		ngbe_clean_tx_ring(adapter->tx_ring[i]);
}

/**
 * ngbe_clean_all_rx_rings - Free Rx Buffers for all queues
 * @adapter: board private structure
 **/
static void ngbe_clean_all_rx_rings(struct ngbe_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_rx_queues; i++)
		ngbe_clean_rx_ring(adapter->rx_ring[i]);
}

void ngbe_down(struct ngbe_adapter *adapter)
{
	ngbe_disable_device(adapter);

	if (!pci_channel_offline(adapter->pdev))
		ngbe_reset(adapter);

	ngbe_clean_all_tx_rings(adapter);
	ngbe_clean_all_rx_rings(adapter);
}

static void ngbe_release_hw_control(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;

	/* Let firmware take over control of h/w */
	wr32m(&adapter->hw, NGBE_CFG_PORT_CTL,
	      NGBE_CFG_PORT_CTL_DRV_LOAD, 0);

	if (hw->phy.type == ngbe_phy_yt8521s_sfi)
		wr32(&adapter->hw, NGBE_CFG_LED_CTL, 0x0);
}

/**
 * ngbe_open - Called when a network interface is made active
 * @netdev: network interface device structure
 *
 * Returns 0 on success, negative value on failure
 **/
int ngbe_open(struct net_device *netdev)
{
	struct ngbe_adapter *adapter = netdev_priv(netdev);
	int err;

	/* disallow open during test */
	if (test_bit(__NGBE_TESTING, &adapter->state))
		return -EBUSY;

	netif_carrier_off(netdev);

	/* allocate transmit descriptors */
	err = ngbe_setup_all_tx_resources(adapter);
	if (err)
		goto err_setup_tx;

	/* allocate receive descriptors */
	err = ngbe_setup_all_rx_resources(adapter);
	if (err)
		goto err_setup_rx;

	err = ngbe_setup_isb_resources(adapter);
	if (err)
		goto err_req_isb;

	ngbe_configure(adapter);

	err = ngbe_request_irq(adapter);
	if (err)
		goto err_req_irq;

	if (adapter->num_tx_queues) {
		/* Notify the stack of the actual queue counts. */
		err = netif_set_real_num_tx_queues(netdev, adapter->num_tx_queues);
		if (err)
			goto err_set_queues;
	}

	if (adapter->num_rx_queues) {
		err = netif_set_real_num_rx_queues(netdev, adapter->num_rx_queues);
		if (err)
			goto err_set_queues;
	}

	ngbe_ptp_init(adapter);

	ngbe_up_complete(adapter);

	return 0;

err_set_queues:
	ngbe_free_irq(adapter);
err_req_irq:
	ngbe_free_isb_resources(adapter);
err_req_isb:
	ngbe_free_all_rx_resources(adapter);

err_setup_rx:
	ngbe_free_all_tx_resources(adapter);
err_setup_tx:
	ngbe_reset(adapter);
	return err;
}

/**
 * ngbe_close - Disables a network interface
 * @netdev: network interface device structure
 *
 * Returns 0, this is not allowed to fail
 **/
int ngbe_close(struct net_device *netdev)
{
	struct ngbe_adapter *adapter = netdev_priv(netdev);

	ngbe_ptp_stop(adapter);

	ngbe_down(adapter);
	ngbe_free_irq(adapter);

	ngbe_free_isb_resources(adapter);
	ngbe_free_all_rx_resources(adapter);
	ngbe_free_all_tx_resources(adapter);

	ngbe_release_hw_control(adapter);

	return 0;
}

static u64 ngbe_get_tx_completed(struct ngbe_ring *ring)
{
	return ring->stats.packets;
}

static u64 ngbe_get_tx_pending(struct ngbe_ring *ring)
{
	struct ngbe_adapter *adapter;
	struct ngbe_hw *hw;
	u32 head, tail;

	if (ring->accel)
		adapter = ring->accel->adapter;
	else
		adapter = ring->q_vector->adapter;

	hw = &adapter->hw;
	head = rd32(hw, NGBE_PX_TR_RP(ring->reg_idx));
	tail = rd32(hw, NGBE_PX_TR_WP(ring->reg_idx));

	return ((head <= tail) ? tail : tail + ring->count) - head;
}

static inline bool ngbe_check_tx_hang(struct ngbe_ring *tx_ring)
{
	u64 tx_done = ngbe_get_tx_completed(tx_ring);
	u64 tx_done_old = tx_ring->tx_stats.tx_done_old;
	u64 tx_pending = ngbe_get_tx_pending(tx_ring);

	clear_check_for_tx_hang(tx_ring);

	/* Check for a hung queue, but be thorough. This verifies
	 * that a transmit has been completed since the previous
	 * check AND there is at least one packet pending. The
	 * ARMED bit is set to indicate a potential hang. The
	 * bit is cleared if a pause frame is received to remove
	 * false hang detection due to PFC or 802.3x frames. By
	 * requiring this to fail twice we avoid races with
	 * pfc clearing the ARMED bit and conditions where we
	 * run the check_tx_hang logic with a transmit completion
	 * pending but without time to complete it yet.
	 */
	if (tx_done_old == tx_done && tx_pending) {
		/* make sure it is true for two checks in a row */
		return test_and_set_bit(__NGBE_HANG_CHECK_ARMED,
					&tx_ring->state);
	}

	/* update completed stats and continue */
	tx_ring->tx_stats.tx_done_old = tx_done;
	/* reset the countdown */
	clear_bit(__NGBE_HANG_CHECK_ARMED, &tx_ring->state);

	return false;
}

/**
 * ngbe_clean_tx_irq - Reclaim resources after transmit completes
 * @q_vector: structure containing interrupt and ring information
 * @tx_ring: tx ring to clean
 **/
static bool ngbe_clean_tx_irq(struct ngbe_q_vector *q_vector,
			      struct ngbe_ring *tx_ring)
{
	struct ngbe_adapter *adapter = q_vector->adapter;
	struct ngbe_tx_buffer *tx_buffer;
	union ngbe_tx_desc *tx_desc;
	unsigned int total_bytes = 0, total_packets = 0;
	unsigned int budget = q_vector->tx.work_limit;
	unsigned int i = tx_ring->next_to_clean;
	struct ngbe_hw *hw = &adapter->hw;
	u16 vid = 0;

	if (test_bit(__NGBE_DOWN, &adapter->state))
		return true;

	tx_buffer = &tx_ring->tx_buffer_info[i];
	tx_desc = NGBE_TX_DESC(tx_ring, i);
	i -= tx_ring->count;

	do {
		union ngbe_tx_desc *eop_desc = tx_buffer->next_to_watch;

		/* if next_to_watch is not set then there is no work pending */
		if (!eop_desc)
			break;

		/* prevent any other reads prior to eop_desc */
		smp_rmb();

		/* if DD is not set pending work has not been completed */
		if (!(eop_desc->wb.status & cpu_to_le32(NGBE_TXD_STAT_DD)))
			break;

		/* clear next_to_watch to prevent false hangs */
		tx_buffer->next_to_watch = NULL;

		/* update the statistics for this packet */
		total_bytes += tx_buffer->bytecount;
		total_packets += tx_buffer->gso_segs;

		/* free the skb */
		dev_consume_skb_any(tx_buffer->skb);

		/* unmap skb header data */
		dma_unmap_single(tx_ring->dev,
				 dma_unmap_addr(tx_buffer, dma),
						dma_unmap_len(tx_buffer, len),
						DMA_TO_DEVICE);

		/* clear tx_buffer data */
		tx_buffer->skb = NULL;
		dma_unmap_len_set(tx_buffer, len, 0);

		/* unmap remaining buffers */
		while (tx_desc != eop_desc) {
			tx_buffer++;
			tx_desc++;
			i++;
			if (unlikely(!i)) {
				i -= tx_ring->count;
				tx_buffer = tx_ring->tx_buffer_info;
				tx_desc = NGBE_TX_DESC(tx_ring, 0);
			}

			/* unmap any remaining paged data */
			if (dma_unmap_len(tx_buffer, len)) {
				dma_unmap_page(tx_ring->dev,
					       dma_unmap_addr(tx_buffer, dma),
							dma_unmap_len(tx_buffer, len),
							DMA_TO_DEVICE);
				dma_unmap_len_set(tx_buffer, len, 0);
			}
		}

		/* move us one more past the eop_desc for start of next pkt */
		tx_buffer++;
		tx_desc++;
		i++;
		if (unlikely(!i)) {
			i -= tx_ring->count;
			tx_buffer = tx_ring->tx_buffer_info;
			tx_desc = NGBE_TX_DESC(tx_ring, 0);
		}

		/* issue prefetch for next Tx descriptor */
		prefetch(tx_desc);

		/* update budget accounting */
		budget--;
	} while (likely(budget));

	i += tx_ring->count;
	tx_ring->next_to_clean = i;
	u64_stats_update_begin(&tx_ring->syncp);
	tx_ring->stats.bytes += total_bytes;
	tx_ring->stats.packets += total_packets;
	u64_stats_update_end(&tx_ring->syncp);
	q_vector->tx.total_bytes += total_bytes;
	q_vector->tx.total_packets += total_packets;

	if (check_for_tx_hang(tx_ring)) {
		if (!ngbe_check_tx_hang(tx_ring))
			adapter->hang_cnt = 0;
		else
			adapter->hang_cnt++;

		if (adapter->hang_cnt >= 5) {
			/* schedule immediate reset if we believe we hung */

			e_err(drv, "Detected Tx Unit Hang\n"
				"  Tx Queue             <%d>\n"
				"  TDH, TDT             <%x>, <%x>\n"
				"  next_to_use          <%x>\n"
				"  next_to_clean        <%x>\n"
				"tx_buffer_info[next_to_clean]\n"
				"  time_stamp           <%lx>\n"
				"  jiffies              <%lx>\n",
				tx_ring->queue_index,
				rd32(hw, NGBE_PX_TR_RP(tx_ring->reg_idx)),
				rd32(hw, NGBE_PX_TR_WP(tx_ring->reg_idx)),
				tx_ring->next_to_use, i,
				tx_ring->tx_buffer_info[i].time_stamp, jiffies);

			pci_read_config_word(adapter->pdev, PCI_VENDOR_ID, &vid);
			if (vid == NGBE_FAILED_READ_CFG_WORD)
				e_info(hw, "pcie link has been lost.\n");

			netif_stop_subqueue(tx_ring->netdev, tx_ring->queue_index);

			e_info(probe,
			       "tx hang %d detected on queue %d, resetting adapter\n",
				adapter->tx_timeout_count + 1, tx_ring->queue_index);

			/* the adapter is about to reset, no point in enabling stuff */
			return true;
		}
	}

	netdev_tx_completed_queue(txring_txq(tx_ring),
				  total_packets, total_bytes);

#define TX_WAKE_THRESHOLD (DESC_NEEDED * 2)
	if (unlikely(total_packets && netif_carrier_ok(tx_ring->netdev) &&
		     (ngbe_desc_unused(tx_ring) >= TX_WAKE_THRESHOLD))) {
		/* Make sure that anybody stopping the queue after this
		 * sees the new next_to_clean.
		 */
		smp_mb();

		if (__netif_subqueue_stopped(tx_ring->netdev,
					     tx_ring->queue_index) &&
			!test_bit(__NGBE_DOWN, &adapter->state)) {
			netif_wake_subqueue(tx_ring->netdev,
					    tx_ring->queue_index);
			++tx_ring->tx_stats.restart_queue;
		}
	}

	return !!budget;
}

/**
 * ngbe_is_non_eop - process handling of non-EOP buffers
 * @rx_ring: Rx ring being processed
 * @rx_desc: Rx descriptor for current buffer
 * @skb: Current socket buffer containing buffer in progress
 *
 * This function updates next to clean.  If the buffer is an EOP buffer
 * this function exits returning false, otherwise it will place the
 * sk_buff in the next buffer to be chained and return true indicating
 * that this is in fact a non-EOP buffer.
 **/
static bool ngbe_is_non_eop(struct ngbe_ring *rx_ring,
			    union ngbe_rx_desc *rx_desc,
				 struct sk_buff *skb)
{
	struct ngbe_rx_buffer *rx_buffer =
			&rx_ring->rx_buffer_info[rx_ring->next_to_clean];
	u32 ntc = rx_ring->next_to_clean + 1;

	/* fetch, update, and store next to clean */
	ntc = (ntc < rx_ring->count) ? ntc : 0;
	rx_ring->next_to_clean = ntc;

	prefetch(NGBE_RX_DESC(rx_ring, ntc));

	/* if we are the last buffer then there is nothing else to do */
	if (likely(ngbe_test_staterr(rx_desc, NGBE_RXD_STAT_EOP)))
		return false;

	/* place skb in next buffer to be received */
	if (ring_is_hs_enabled(rx_ring)) {
		rx_buffer->skb = rx_ring->rx_buffer_info[ntc].skb;
		rx_buffer->dma = rx_ring->rx_buffer_info[ntc].dma;
		rx_ring->rx_buffer_info[ntc].dma = 0;
	}
	rx_ring->rx_buffer_info[ntc].skb = skb;
	rx_ring->rx_stats.non_eop_descs++;

	return true;
}

static inline void ngbe_rx_hash(struct ngbe_ring *ring,
				union ngbe_rx_desc *rx_desc,
			  struct sk_buff *skb)
{
	u16 rss_type;

	if (!(ring->netdev->features & NETIF_F_RXHASH))
		return;

	rss_type = le16_to_cpu(rx_desc->wb.lower.lo_dword.hs_rss.pkt_info) &
		NGBE_RXD_RSSTYPE_MASK;

	if (!rss_type)
		return;

	skb_set_hash(skb, le32_to_cpu(rx_desc->wb.lower.hi_dword.rss),
		     (NGBE_RSS_L4_TYPES_MASK & (1ul << rss_type)) ?
		  PKT_HASH_TYPE_L4 : PKT_HASH_TYPE_L3);
}

/**
 * ngbe_rx_checksum - indicate in skb if hw indicated a good cksum
 * @ring: structure containing ring specific data
 * @rx_desc: current Rx descriptor being processed
 * @skb: skb currently being received and modified
 **/
static inline void ngbe_rx_checksum(struct ngbe_ring *ring,
				    union ngbe_rx_desc *rx_desc,
				   struct sk_buff *skb)
{
	struct ngbe_dec_ptype dptype = decode_rx_desc_ptype(rx_desc);

	skb->ip_summed = CHECKSUM_NONE;
	skb_checksum_none_assert(skb);

	/* Rx csum disabled */
	if (!(ring->netdev->features & NETIF_F_RXCSUM))
		return;

	/* if IPv4 header checksum error */
	if ((ngbe_test_staterr(rx_desc, NGBE_RXD_STAT_IPCS) &&
	     ngbe_test_staterr(rx_desc, NGBE_RXD_ERR_IPE)) ||
		(ngbe_test_staterr(rx_desc, NGBE_RXD_STAT_OUTERIPCS) &&
		ngbe_test_staterr(rx_desc, NGBE_RXD_ERR_OUTERIPER))) {
		ring->rx_stats.csum_err++;
		return;
	}

	/* L4 checksum offload flag must set for the below code to work */
	if (!ngbe_test_staterr(rx_desc, NGBE_RXD_STAT_L4CS))
		return;

	/*likely incorrect csum if IPv6 Dest Header found */
	if (dptype.prot != NGBE_DEC_PTYPE_PROT_SCTP && NGBE_RXD_IPV6EX(rx_desc))
		return;

	/* if L4 checksum error */
	if (ngbe_test_staterr(rx_desc, NGBE_RXD_ERR_TCPE)) {
		ring->rx_stats.csum_err++;
		return;
	}
	/* If there is an outer header present that might contain a checksum
	 * we need to bump the checksum level by 1 to reflect the fact that
	 * we are indicating we validated the inner checksum.
	 */
	if (dptype.etype >= NGBE_DEC_PTYPE_ETYPE_IG)
		skb->csum_level = 1;

	/* It must be a TCP or UDP or SCTP packet with a valid checksum */
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	ring->rx_stats.csum_good_cnt++;
}

static void ngbe_rx_vlan(struct ngbe_ring *ring,
			 union ngbe_rx_desc *rx_desc,
			 struct sk_buff *skb)
{
	u8 idx = 0;
	u16 ethertype;

	if ((ring->netdev->features & NETIF_F_HW_VLAN_CTAG_RX) &&
	    ngbe_test_staterr(rx_desc, NGBE_RXD_STAT_VP)) {
		idx = (le16_to_cpu(rx_desc->wb.lower.lo_dword.hs_rss.pkt_info) &
			NGBE_RXD_TPID_MASK) >> NGBE_RXD_TPID_SHIFT;
		ethertype = ring->q_vector->adapter->hw.tpid[idx];
		__vlan_hwaccel_put_tag(skb,
				       htons(ethertype),
						   le16_to_cpu(rx_desc->wb.upper.vlan));
	}
}

/**
 * ngbe_process_skb_fields - Populate skb header fields from Rx descriptor
 * @rx_ring: rx descriptor ring packet is being transacted on
 * @rx_desc: pointer to the EOP Rx descriptor
 * @skb: pointer to current skb being populated
 *
 * This function checks the ring, descriptor, and packet information in
 * order to populate the hash, checksum, VLAN, timestamp, protocol, and
 * other fields within the skb.
 **/
static void ngbe_process_skb_fields(struct ngbe_ring *rx_ring,
				    union ngbe_rx_desc *rx_desc,
				  struct sk_buff *skb)
{
	u32 flags = rx_ring->q_vector->adapter->flags;

	ngbe_rx_hash(rx_ring, rx_desc, skb);
	ngbe_rx_checksum(rx_ring, rx_desc, skb);

	if (unlikely(flags & NGBE_FLAG_RX_HWTSTAMP_ENABLED) &&
	    unlikely(ngbe_test_staterr(rx_desc, NGBE_RXD_STAT_TS))) {
		ngbe_ptp_rx_hwtstamp(rx_ring->q_vector->adapter, skb);
		rx_ring->last_rx_timestamp = jiffies;
	}

	ngbe_rx_vlan(rx_ring, rx_desc, skb);
	skb_record_rx_queue(skb, rx_ring->queue_index);
	skb->protocol = eth_type_trans(skb, rx_ring->netdev);
}

/**
 * ngbe_pull_tail - ngbe specific version of skb_pull_tail
 * @skb: pointer to current skb being adjusted
 *
 * This function is an ngbe specific version of __pskb_pull_tail.  The
 * main difference between this version and the original function is that
 * this function can make several assumptions about the state of things
 * that allow for significant optimizations versus the standard function.
 * As a result we can do things like drop a frag and maintain an accurate
 * truesize for the skb.
 */
static void ngbe_pull_tail(struct sk_buff *skb)
{
	skb_frag_t *frag = &skb_shinfo(skb)->frags[0];
	unsigned char *va;
	unsigned int pull_len;

	/* it is valid to use page_address instead of kmap since we are
	 * working with pages allocated out of the lomem pool per
	 * alloc_page(GFP_ATOMIC)
	 */
	va = skb_frag_address(frag);

	/* we need the header to contain the greater of either ETH_HLEN or
	 * 60 bytes if the skb->len is less than 60 for skb_pad.
	 */
	pull_len = eth_get_headlen(skb->dev, va, NGBE_RX_HDR_SIZE);

	/* align pull length to size of long to optimize memcpy performance */
	skb_copy_to_linear_data(skb, va, ALIGN(pull_len, sizeof(long)));

	/* update all of the pointers */
	skb_frag_size_sub(frag, pull_len);
	skb_frag_off_add(frag, pull_len);
	skb->data_len -= pull_len;
	skb->tail += pull_len;
}

/**
 * ngbe_dma_sync_frag - perform DMA sync for first frag of SKB
 * @rx_ring: rx descriptor ring packet is being transacted on
 * @skb: pointer to current skb being updated
 *
 * This function provides a basic DMA sync up for the first fragment of an
 * skb.  The reason for doing this is that the first fragment cannot be
 * unmapped until we have reached the end of packet descriptor for a buffer
 * chain.
 */
static void ngbe_dma_sync_frag(struct ngbe_ring *rx_ring,
			       struct sk_buff *skb)
{
	/* if the page was released unmap it, else just sync our portion */
	if (unlikely(NGBE_CB(skb)->page_released)) {
		dma_unmap_page_attrs(rx_ring->dev, NGBE_CB(skb)->dma,
				     ngbe_rx_pg_size(rx_ring),
					 DMA_FROM_DEVICE,
					 NGBE_RX_DMA_ATTR);
	} else if (ring_uses_build_skb(rx_ring)) {
		unsigned long offset = (unsigned long)(skb->data) & ~PAGE_MASK;

		dma_sync_single_range_for_cpu(rx_ring->dev,
					      NGBE_CB(skb)->dma,
						  offset,
						  skb_headlen(skb),
						  DMA_FROM_DEVICE);
	} else {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[0];

		dma_sync_single_range_for_cpu(rx_ring->dev,
					      NGBE_CB(skb)->dma,
						  skb_frag_off(frag),
						  skb_frag_size(frag),
						  DMA_FROM_DEVICE);
	}
}

/**
 * ngbe_cleanup_headers - Correct corrupted or empty headers
 * @rx_ring: rx descriptor ring packet is being transacted on
 * @rx_desc: pointer to the EOP Rx descriptor
 * @skb: pointer to current skb being fixed
 *
 * Check for corrupted packet headers caused by senders on the local L2
 * embedded NIC switch not setting up their Tx Descriptors right.  These
 * should be very rare.
 *
 * Also address the case where we are pulling data in on pages only
 * and as such no data is present in the skb header.
 *
 * In addition if skb is not at least 60 bytes we need to pad it so that
 * it is large enough to qualify as a valid Ethernet frame.
 *
 * Returns true if an error was encountered and skb was freed.
 **/
static bool ngbe_cleanup_headers(struct ngbe_ring *rx_ring,
				 union ngbe_rx_desc *rx_desc,
				  struct sk_buff *skb)
{
	struct net_device *netdev = rx_ring->netdev;

	/* verify that the packet does not have any known errors */
	if (unlikely(ngbe_test_staterr(rx_desc,
				       NGBE_RXD_ERR_FRAME_ERR_MASK) &&
		!(netdev->features & NETIF_F_RXALL))) {
		dev_kfree_skb_any(skb);
		return true;
	}

	/* place header in linear portion of buffer */
	if (skb_is_nonlinear(skb)  && !skb_headlen(skb))
		ngbe_pull_tail(skb);

	/* if eth_skb_pad returns an error the skb was freed */
	if (eth_skb_pad(skb))
		return true;

	return false;
}

/**
 * ngbe_reuse_rx_page - page flip buffer and store it back on the ring
 * @rx_ring: rx descriptor ring to store buffers on
 * @old_buff: donor buffer to have page reused
 *
 * Synchronizes page for reuse by the adapter
 **/
static void ngbe_reuse_rx_page(struct ngbe_ring *rx_ring,
			       struct ngbe_rx_buffer *old_buff)
{
	struct ngbe_rx_buffer *new_buff;
	u16 nta = rx_ring->next_to_alloc;

	new_buff = &rx_ring->rx_buffer_info[nta];

	/* update, and store next to alloc */
	nta++;
	rx_ring->next_to_alloc = (nta < rx_ring->count) ? nta : 0;

	/* transfer page from old buffer to new buffer */
	new_buff->page_dma = old_buff->page_dma;
	new_buff->page = old_buff->page;
	new_buff->page_offset = old_buff->page_offset;

	/* sync the buffer for use by the device */
	dma_sync_single_range_for_device(rx_ring->dev, new_buff->page_dma,
					 new_buff->page_offset,
					 ngbe_rx_bufsz(rx_ring),
					 DMA_FROM_DEVICE);
}

static inline bool ngbe_page_is_reserved(struct page *page)
{
	return (page_to_nid(page) != numa_mem_id()) || page_is_pfmemalloc(page);
}

/**
 * ngbe_add_rx_frag - Add contents of Rx buffer to sk_buff
 * @rx_ring: rx descriptor ring to transact packets on
 * @rx_buffer: buffer containing page to add
 * @rx_desc: descriptor containing length of buffer written by hardware
 * @skb: sk_buff to place the data into
 *
 * This function will add the data contained in rx_buffer->page to the skb.
 * This is done either through a direct copy if the data in the buffer is
 * less than the skb header size, otherwise it will just attach the page as
 * a frag to the skb.
 *
 * The function will then update the page offset if necessary and return
 * true if the buffer can be reused by the adapter.
 **/
static bool ngbe_add_rx_frag(struct ngbe_ring *rx_ring,
			     struct ngbe_rx_buffer *rx_buffer,
				  union ngbe_rx_desc *rx_desc,
				  struct sk_buff *skb)
{
	struct page *page = rx_buffer->page;
	unsigned int size = le16_to_cpu(rx_desc->wb.upper.length);
	unsigned int truesize = ngbe_rx_bufsz(rx_ring);

	if (size <= NGBE_RX_HDR_SIZE && !skb_is_nonlinear(skb) &&
	    !ring_is_hs_enabled(rx_ring)) {
		unsigned char *va = page_address(page) + rx_buffer->page_offset;

		memcpy(__skb_put(skb, size), va, ALIGN(size, sizeof(long)));

		/* page is not reserved, we can reuse buffer as-is */
		if (likely(!ngbe_page_is_reserved(page)))
			return true;

		/* this page cannot be reused so discard it */
		__free_pages(page, ngbe_rx_pg_order(rx_ring));
		return false;
	}

	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, page,
			rx_buffer->page_offset, size, truesize);

	/* avoid re-using remote pages */
	if (unlikely(ngbe_page_is_reserved(page)))
		return false;

	/* if we are only owner of page we can reuse it */
	if (unlikely(page_count(page) != 1))
		return false;

	/* flip page offset to other buffer */
	rx_buffer->page_offset ^= truesize;

	/* Even if we own the page, we are not allowed to use atomic_set()
	 * This would break get_page_unless_zero() users.
	 */
	page_ref_inc(page);

	return true;
}

static struct sk_buff *ngbe_fetch_rx_buffer(struct ngbe_ring *rx_ring,
					    union ngbe_rx_desc *rx_desc)
{
	struct ngbe_rx_buffer *rx_buffer;
	struct sk_buff *skb;
	struct page *page;

	rx_buffer = &rx_ring->rx_buffer_info[rx_ring->next_to_clean];
	page = rx_buffer->page;
	prefetchw(page);

	skb = rx_buffer->skb;

	if (likely(!skb)) {
		void *page_addr = page_address(page) +
				  rx_buffer->page_offset;

		/* prefetch first cache line of first page */
		prefetch(page_addr);
#if L1_CACHE_BYTES < 128
		prefetch(page_addr + L1_CACHE_BYTES);
#endif

		/* allocate a skb to store the frags */
		skb = netdev_alloc_skb_ip_align(rx_ring->netdev,
						NGBE_RX_HDR_SIZE);
		if (unlikely(!skb)) {
			rx_ring->rx_stats.alloc_rx_buff_failed++;
			return NULL;
		}

		/* we will be copying header into skb->data in
		 * pskb_may_pull so it is in our interest to prefetch
		 * it now to avoid a possible cache miss
		 */
		prefetchw(skb->data);

		/* Delay unmapping of the first packet. It carries the
		 * header information, HW may still access the header
		 * after the writeback.  Only unmap it when EOP is
		 * reached
		 */
		if (likely(ngbe_test_staterr(rx_desc, NGBE_RXD_STAT_EOP)))
			goto dma_sync;

		NGBE_CB(skb)->dma = rx_buffer->page_dma;
	} else {
		if (ngbe_test_staterr(rx_desc, NGBE_RXD_STAT_EOP))
			ngbe_dma_sync_frag(rx_ring, skb);

dma_sync:
		/* we are reusing so sync this buffer for CPU use */
		dma_sync_single_range_for_cpu(rx_ring->dev,
					      rx_buffer->page_dma,
						  rx_buffer->page_offset,
						  ngbe_rx_bufsz(rx_ring),
						  DMA_FROM_DEVICE);

		rx_buffer->skb = NULL;
	}

	/* pull page into skb */
	if (ngbe_add_rx_frag(rx_ring, rx_buffer, rx_desc, skb)) {
		/* hand second half of page back to the ring */
		ngbe_reuse_rx_page(rx_ring, rx_buffer);
	} else if (NGBE_CB(skb)->dma == rx_buffer->page_dma) {
		/* the page has been released from the ring */
		NGBE_CB(skb)->page_released = true;
	} else {
		/* we are not reusing the buffer so unmap it */
		dma_unmap_page(rx_ring->dev, rx_buffer->page_dma,
			       ngbe_rx_pg_size(rx_ring),
				   DMA_FROM_DEVICE);
	}

	/* clear contents of buffer_info */
	rx_buffer->page = NULL;

	return skb;
}

static inline u16 ngbe_get_hlen(struct ngbe_ring __maybe_unused *rx_ring,
				union ngbe_rx_desc *rx_desc)
{
	__le16 hdr_info = rx_desc->wb.lower.lo_dword.hs_rss.hdr_info;
	u16 hlen = le16_to_cpu(hdr_info) & NGBE_RXD_HDRBUFLEN_MASK;

	if (hlen > (NGBE_RX_HDR_SIZE << NGBE_RXD_HDRBUFLEN_SHIFT))
		hlen = 0;
	else
		hlen >>= NGBE_RXD_HDRBUFLEN_SHIFT;

	return hlen;
}

static struct sk_buff *ngbe_fetch_rx_buffer_hs(struct ngbe_ring *rx_ring,
					       union ngbe_rx_desc *rx_desc)
{
	struct ngbe_rx_buffer *rx_buffer;
	struct sk_buff *skb;
	struct page *page;
	int hdr_len = 0;

	rx_buffer = &rx_ring->rx_buffer_info[rx_ring->next_to_clean];
	page = rx_buffer->page;
	prefetchw(page);

	skb = rx_buffer->skb;
	rx_buffer->skb = NULL;
	prefetchw(skb->data);

	if (!skb_is_nonlinear(skb)) {
		hdr_len = ngbe_get_hlen(rx_ring, rx_desc);
		if (hdr_len > 0) {
			__skb_put(skb, hdr_len);
			NGBE_CB(skb)->dma_released = true;
			NGBE_CB(skb)->dma = rx_buffer->dma;
			rx_buffer->dma = 0;
		} else {
			dma_unmap_single(rx_ring->dev,
					 rx_buffer->dma,
					 rx_ring->rx_buf_len,
					 DMA_FROM_DEVICE);
			rx_buffer->dma = 0;
			if (likely(ngbe_test_staterr(rx_desc, NGBE_RXD_STAT_EOP)))
				goto dma_sync;
			NGBE_CB(skb)->dma = rx_buffer->page_dma;
			goto add_frag;
		}
	}

	if (ngbe_test_staterr(rx_desc, NGBE_RXD_STAT_EOP)) {
		if (skb_headlen(skb)) {
			if (NGBE_CB(skb)->dma_released) {
				dma_unmap_single(rx_ring->dev,
						 NGBE_CB(skb)->dma,
						 rx_ring->rx_buf_len,
						 DMA_FROM_DEVICE);
				NGBE_CB(skb)->dma = 0;
				NGBE_CB(skb)->dma_released = false;
			}
		} else {
			ngbe_dma_sync_frag(rx_ring, skb);
		}
	}

dma_sync:
	/* we are reusing so sync this buffer for CPU use */
	dma_sync_single_range_for_cpu(rx_ring->dev,
				      rx_buffer->page_dma,
								rx_buffer->page_offset,
								ngbe_rx_bufsz(rx_ring),
								DMA_FROM_DEVICE);
add_frag:
	/* pull page into skb */
	if (ngbe_add_rx_frag(rx_ring, rx_buffer, rx_desc, skb)) {
		/* hand second half of page back to the ring */
		ngbe_reuse_rx_page(rx_ring, rx_buffer);
	} else if (NGBE_CB(skb)->dma == rx_buffer->page_dma) {
		/* the page has been released from the ring */
		NGBE_CB(skb)->page_released = true;
	} else {
		/* we are not reusing the buffer so unmap it */
		dma_unmap_page(rx_ring->dev, rx_buffer->page_dma,
			       ngbe_rx_pg_size(rx_ring),
					DMA_FROM_DEVICE);
	}

	/* clear contents of buffer_info */
	rx_buffer->page = NULL;

	return skb;
}

static void ngbe_rx_skb(struct ngbe_q_vector *q_vector,
			struct ngbe_ring *rx_ring,
		  union ngbe_rx_desc *rx_desc,
		  struct sk_buff *skb)
{
	napi_gro_receive(&q_vector->napi, skb);
}

/**
 * ngbe_clean_rx_irq - Clean completed descriptors from Rx ring - bounce buf
 * @q_vector: structure containing interrupt and ring information
 * @rx_ring: rx descriptor ring to transact packets on
 * @budget: Total limit on number of packets to process
 *
 * This function provides a "bounce buffer" approach to Rx interrupt
 * processing.	The advantage to this is that on systems that have
 * expensive overhead for IOMMU access this provides a means of avoiding
 * it by maintaining the mapping of the page to the system.
 *
 * Returns amount of work completed.
 **/
static int ngbe_clean_rx_irq(struct ngbe_q_vector *q_vector,
			     struct ngbe_ring *rx_ring,
				   int budget)
{
	unsigned int total_rx_bytes = 0, total_rx_packets = 0;
	u16 cleaned_count = ngbe_desc_unused(rx_ring);

	do {
		union ngbe_rx_desc *rx_desc;
		struct sk_buff *skb;

		/* return some buffers to hardware, one at a time is too slow */
		if (cleaned_count >= NGBE_RX_BUFFER_WRITE) {
			ngbe_alloc_rx_buffers(rx_ring, cleaned_count);
			cleaned_count = 0;
		}

		rx_desc = NGBE_RX_DESC(rx_ring, rx_ring->next_to_clean);

		if (!ngbe_test_staterr(rx_desc, NGBE_RXD_STAT_DD))
			break;

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we know the
		 * descriptor has been written back
		 */
		dma_rmb();

		/* retrieve a buffer from the ring */
		if (ring_is_hs_enabled(rx_ring))
			skb = ngbe_fetch_rx_buffer_hs(rx_ring, rx_desc);
		else
			skb = ngbe_fetch_rx_buffer(rx_ring, rx_desc);

		/* exit if we failed to retrieve a buffer */
		if (!skb)
			break;

		cleaned_count++;

		/* place incomplete frames back on ring for completion */
		if (ngbe_is_non_eop(rx_ring, rx_desc, skb))
			continue;

		/* verify the packet layout is correct */
		if (ngbe_cleanup_headers(rx_ring, rx_desc, skb))
			continue;

		/* probably a little skewed due to removing CRC */
		total_rx_bytes += skb->len;

		/* populate checksum, timestamp, VLAN, and protocol */
		ngbe_process_skb_fields(rx_ring, rx_desc, skb);

		ngbe_rx_skb(q_vector, rx_ring, rx_desc, skb);

		/* update budget accounting */
		total_rx_packets++;
	} while (likely(total_rx_packets < budget));

	u64_stats_update_begin(&rx_ring->syncp);
	rx_ring->stats.packets += total_rx_packets;
	rx_ring->stats.bytes += total_rx_bytes;
	u64_stats_update_end(&rx_ring->syncp);
	q_vector->rx.total_packets += total_rx_packets;
	q_vector->rx.total_bytes += total_rx_bytes;

	return total_rx_packets;
}

/**
 * ngbe_poll - NAPI polling RX/TX cleanup routine
 * @napi: napi struct with our devices info in it
 * @budget: amount of work driver is allowed to do this pass, in packets
 *
 * This function will clean all queues associated with a q_vector.
 **/
int ngbe_poll(struct napi_struct *napi, int budget)
{
	struct ngbe_q_vector *q_vector = container_of(napi, struct ngbe_q_vector, napi);
	struct ngbe_adapter *adapter = q_vector->adapter;
	struct ngbe_ring *ring;
	int per_ring_budget;
	bool clean_complete = true;

	ngbe_for_each_ring(ring, q_vector->tx) {
		if (!ngbe_clean_tx_irq(q_vector, ring))
			clean_complete = false;
	}

	/* attempt to distribute budget to each queue fairly, but don't allow
	 * the budget to go below 1 because we'll exit polling
	 */
	if (q_vector->rx.count > 1)
		per_ring_budget = max(budget / q_vector->rx.count, 1);
	else
		per_ring_budget = budget;

	ngbe_for_each_ring(ring, q_vector->rx) {
		int cleaned = ngbe_clean_rx_irq(q_vector, ring,
						per_ring_budget);

		if (cleaned >= per_ring_budget)
			clean_complete = false;
	}

	/* If all work not completed, return budget and keep polling */
	if (!clean_complete)
		return budget;

	/* all work done, exit the polling mode */
	napi_complete(napi);

	if (!test_bit(__NGBE_DOWN, &adapter->state))
		ngbe_intr_enable(&adapter->hw,
				 NGBE_INTR_Q(q_vector->v_idx));

	return 0;
}

#define NGBE_GSO_PARTIAL_FEATURES (NETIF_F_GSO_GRE |		\
								   NETIF_F_GSO_GRE_CSUM |   \
								   NETIF_F_GSO_IPXIP4 |     \
								   NETIF_F_GSO_IPXIP6 |     \
								   NETIF_F_GSO_UDP_TUNNEL | \
								   NETIF_F_GSO_UDP_TUNNEL_CSUM)

static inline unsigned long ngbe_tso_features(void)
{
	unsigned long features = 0;

	features |= NETIF_F_TSO;
	features |= NETIF_F_TSO6;
	features |= NETIF_F_GSO_PARTIAL | NGBE_GSO_PARTIAL_FEATURES;

	return features;
}

static int __ngbe_maybe_stop_tx(struct ngbe_ring *tx_ring, u16 size)
{
	netif_stop_subqueue(tx_ring->netdev, tx_ring->queue_index);

	/* Herbert's original patch had:
	 *  smp_mb__after_netif_stop_queue();
	 * but since that doesn't exist yet, just open code it.
	 */
	smp_mb();

	/* We need to check again in a case another CPU has just
	 * made room available.
	 */
	if (likely(ngbe_desc_unused(tx_ring) < size))
		return -EBUSY;

	/* A reprieve! - use start_queue because it doesn't call schedule */
	netif_start_subqueue(tx_ring->netdev, tx_ring->queue_index);
	++tx_ring->tx_stats.restart_queue;

	return 0;
}

static inline int ngbe_maybe_stop_tx(struct ngbe_ring *tx_ring, u16 size)
{
	if (likely(ngbe_desc_unused(tx_ring) >= size))
		return 0;

	return __ngbe_maybe_stop_tx(tx_ring, size);
}

void ngbe_tx_ctxtdesc(struct ngbe_ring *tx_ring, u32 vlan_macip_lens,
		      u32 fcoe_sof_eof, u32 type_tucmd, u32 mss_l4len_idx)
{
	struct ngbe_tx_context_desc *context_desc;
	u16 i = tx_ring->next_to_use;

	context_desc = NGBE_TX_CTXTDESC(tx_ring, i);

	i++;
	tx_ring->next_to_use = (i < tx_ring->count) ? i : 0;

	/* set bits to identify this as an advanced context descriptor */
	type_tucmd |= NGBE_TXD_DTYP_CTXT;
	context_desc->vlan_macip_lens   = cpu_to_le32(vlan_macip_lens);
	context_desc->seqnum_seed       = cpu_to_le32(fcoe_sof_eof);
	context_desc->type_tucmd_mlhl   = cpu_to_le32(type_tucmd);
	context_desc->mss_l4len_idx     = cpu_to_le32(mss_l4len_idx);
}

static u8 get_ipv6_proto(struct sk_buff *skb, int offset)
{
	struct ipv6hdr *hdr = (struct ipv6hdr *)(skb->data + offset);
	u8 nexthdr = hdr->nexthdr;

	offset += sizeof(struct ipv6hdr);

	while (ipv6_ext_hdr(nexthdr)) {
		struct ipv6_opt_hdr _hdr, *hp;

		if (nexthdr == NEXTHDR_NONE)
			break;

		hp = skb_header_pointer(skb, offset, sizeof(_hdr), &_hdr);
		if (!hp)
			break;

		if (nexthdr == NEXTHDR_FRAGMENT)
			break;
		else if (nexthdr == NEXTHDR_AUTH)
			offset +=  ipv6_authlen(hp);
		else
			offset +=  ipv6_optlen(hp);

		nexthdr = hp->nexthdr;
	}

	return nexthdr;
}

static struct ngbe_dec_ptype encode_tx_desc_ptype(const struct ngbe_tx_buffer *first)
{
	struct sk_buff *skb = first->skb;
	u8 tun_prot = 0;
	u8 l4_prot = 0;
	u8 ptype = 0;

	if (skb->encapsulation) {
		union network_header hdr;

		switch (first->protocol) {
		case htons(ETH_P_IP):
			tun_prot = ip_hdr(skb)->protocol;
			if (ip_hdr(skb)->frag_off & htons(IP_MF | IP_OFFSET))
				goto encap_frag;
			ptype = NGBE_PTYPE_TUN_IPV4;
			break;
		case htons(ETH_P_IPV6):
			tun_prot = get_ipv6_proto(skb, skb_network_offset(skb));
			if (tun_prot == NEXTHDR_FRAGMENT)
				goto encap_frag;
			ptype = NGBE_PTYPE_TUN_IPV6;
			break;
		default:
			goto exit;
		}

		if (tun_prot == IPPROTO_IPIP) {
			hdr.raw = (void *)inner_ip_hdr(skb);
			ptype |= NGBE_PTYPE_PKT_IPIP;
		} else if (tun_prot == IPPROTO_UDP) {
			hdr.raw = (void *)inner_ip_hdr(skb);
		} else {
			goto exit;
		}

		switch (hdr.ipv4->version) {
		case IPVERSION:
			l4_prot = hdr.ipv4->protocol;
			if (hdr.ipv4->frag_off & htons(IP_MF | IP_OFFSET)) {
				ptype |= NGBE_PTYPE_TYP_IPFRAG;
				goto exit;
			}
			break;
		case 6:
			l4_prot = get_ipv6_proto(skb,
						 skb_inner_network_offset(skb));
			ptype |= NGBE_PTYPE_PKT_IPV6;
			if (l4_prot == NEXTHDR_FRAGMENT) {
				ptype |= NGBE_PTYPE_TYP_IPFRAG;
				goto exit;
			}
			break;
		default:
			goto exit;
		}
	} else {
encap_frag:
		switch (first->protocol) {
		case htons(ETH_P_IP):
			l4_prot = ip_hdr(skb)->protocol;
			ptype = NGBE_PTYPE_PKT_IP;
			if (ip_hdr(skb)->frag_off & htons(IP_MF | IP_OFFSET)) {
				ptype |= NGBE_PTYPE_TYP_IPFRAG;
				goto exit;
			}
			break;
#ifdef NETIF_F_IPV6_CSUM
		case htons(ETH_P_IPV6):
			l4_prot = get_ipv6_proto(skb, skb_network_offset(skb));
			ptype = NGBE_PTYPE_PKT_IP | NGBE_PTYPE_PKT_IPV6;
			if (l4_prot == NEXTHDR_FRAGMENT) {
				ptype |= NGBE_PTYPE_TYP_IPFRAG;
				goto exit;
			}
			break;
#endif /* NETIF_F_IPV6_CSUM */
		case htons(ETH_P_1588):
			ptype = NGBE_PTYPE_L2_TS;
			goto exit;
		case htons(ETH_P_FIP):
			ptype = NGBE_PTYPE_L2_FIP;
			goto exit;
		case htons(NGBE_ETH_P_LLDP):
			ptype = NGBE_PTYPE_L2_LLDP;
			goto exit;
		case htons(NGBE_ETH_P_CNM):
			ptype = NGBE_PTYPE_L2_CNM;
			goto exit;
		case htons(ETH_P_PAE):
			ptype = NGBE_PTYPE_L2_EAPOL;
			goto exit;
		case htons(ETH_P_ARP):
			ptype = NGBE_PTYPE_L2_ARP;
			goto exit;
		default:
			ptype = NGBE_PTYPE_L2_MAC;
			goto exit;
		}
	}

	switch (l4_prot) {
	case IPPROTO_TCP:
		ptype |= NGBE_PTYPE_TYP_TCP;
		break;
	case IPPROTO_UDP:
		ptype |= NGBE_PTYPE_TYP_UDP;
		break;
	case IPPROTO_SCTP:
		ptype |= NGBE_PTYPE_TYP_SCTP;
		break;
	default:
		ptype |= NGBE_PTYPE_TYP_IP;
		break;
	}

exit:
	return ngbe_decode_ptype(ptype);
}

static int ngbe_tso(struct ngbe_ring *tx_ring,
		    struct ngbe_tx_buffer *first,
					u8 *hdr_len,  struct ngbe_dec_ptype dptype)
{
	struct sk_buff *skb = first->skb;
	u32 vlan_macip_lens, type_tucmd;
	u32 mss_l4len_idx, l4len;
	struct tcphdr *tcph;
	struct iphdr *iph;
	u32 tunhdr_eiplen_tunlen = 0;
	u8 tun_prot = 0;
	bool enc = skb->encapsulation;

	struct ipv6hdr *ipv6h;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	if (!skb_is_gso(skb))
		return 0;

	if (skb_header_cloned(skb)) {
		int err = pskb_expand_head(skb, 0, 0, GFP_ATOMIC);

		if (err)
			return err;
	}

	iph = enc ? inner_ip_hdr(skb) : ip_hdr(skb);
	if (iph->version == 4) {
		tcph = enc ? inner_tcp_hdr(skb) : tcp_hdr(skb);
		iph->tot_len = 0;
		iph->check = 0;
		tcph->check = ~csum_tcpudp_magic(iph->saddr,
						iph->daddr, 0,
						IPPROTO_TCP,
						0);
		first->tx_flags |= NGBE_TX_FLAGS_TSO |
						   NGBE_TX_FLAGS_CSUM |
						   NGBE_TX_FLAGS_IPV4 |
						   NGBE_TX_FLAGS_CC;
	} else if (iph->version == 6 && skb_is_gso_v6(skb)) {
		ipv6h = enc ? inner_ipv6_hdr(skb) : ipv6_hdr(skb);
		tcph = enc ? inner_tcp_hdr(skb) : tcp_hdr(skb);
		ipv6h->payload_len = 0;
		tcph->check =
		    ~csum_ipv6_magic(&ipv6h->saddr,
				     &ipv6h->daddr,
				     0, IPPROTO_TCP, 0);
		first->tx_flags |= NGBE_TX_FLAGS_TSO |
							NGBE_TX_FLAGS_CSUM |
							NGBE_TX_FLAGS_CC;
	}

	/* compute header lengths */
	l4len = enc ? inner_tcp_hdrlen(skb) : tcp_hdrlen(skb);
	*hdr_len = enc ? (skb_inner_transport_header(skb) - skb->data)
		       : skb_transport_offset(skb);
	*hdr_len += l4len;

	/* update gso size and bytecount with header size */
	first->gso_segs = skb_shinfo(skb)->gso_segs;
	first->bytecount += (first->gso_segs - 1) * *hdr_len;

	/* mss_l4len_id: use 0 as index for TSO */
	mss_l4len_idx = l4len << NGBE_TXD_L4LEN_SHIFT;
	mss_l4len_idx |= skb_shinfo(skb)->gso_size << NGBE_TXD_MSS_SHIFT;

	/* vlan_macip_lens: HEADLEN, MACLEN, VLAN tag */
	if (enc) {
		switch (first->protocol) {
		case htons(ETH_P_IP):
			tun_prot = ip_hdr(skb)->protocol;
			first->tx_flags |= NGBE_TX_FLAGS_OUTER_IPV4;
			break;
		case htons(ETH_P_IPV6):
			tun_prot = ipv6_hdr(skb)->nexthdr;
			break;
		default:
			break;
		}
		switch (tun_prot) {
		case IPPROTO_UDP:
			tunhdr_eiplen_tunlen = NGBE_TXD_TUNNEL_UDP;
			tunhdr_eiplen_tunlen |=
					((skb_network_header_len(skb) >> 2) <<
					NGBE_TXD_OUTER_IPLEN_SHIFT) |
					(((skb_inner_mac_header(skb) -
					skb_transport_header(skb)) >> 1) <<
					NGBE_TXD_TUNNEL_LEN_SHIFT);
			break;
		case IPPROTO_GRE:
			tunhdr_eiplen_tunlen = NGBE_TXD_TUNNEL_GRE;
			tunhdr_eiplen_tunlen |=
					((skb_network_header_len(skb) >> 2) <<
					NGBE_TXD_OUTER_IPLEN_SHIFT) |
					(((skb_inner_mac_header(skb) -
					skb_transport_header(skb)) >> 1) <<
					NGBE_TXD_TUNNEL_LEN_SHIFT);
			break;
		case IPPROTO_IPIP:
			tunhdr_eiplen_tunlen = (((char *)inner_ip_hdr(skb) -
						(char *)ip_hdr(skb)) >> 2) <<
						NGBE_TXD_OUTER_IPLEN_SHIFT;
			break;
		default:
			break;
		}

		vlan_macip_lens = skb_inner_network_header_len(skb) >> 1;
	} else {
		vlan_macip_lens = skb_network_header_len(skb) >> 1;
	}

	vlan_macip_lens |= skb_network_offset(skb) << NGBE_TXD_MACLEN_SHIFT;
	vlan_macip_lens |= first->tx_flags & NGBE_TX_FLAGS_VLAN_MASK;

	type_tucmd = dptype.ptype << 24;
	ngbe_tx_ctxtdesc(tx_ring, vlan_macip_lens, tunhdr_eiplen_tunlen,
			 type_tucmd, mss_l4len_idx);

	return 1;
}

static void ngbe_tx_csum(struct ngbe_ring *tx_ring,
			 struct ngbe_tx_buffer *first, struct ngbe_dec_ptype dptype)
{
	struct sk_buff *skb = first->skb;
	u32 vlan_macip_lens = 0;
	u32 mss_l4len_idx = 0;
	u32 tunhdr_eiplen_tunlen = 0;
	u8 tun_prot = 0;
	u32 type_tucmd;

	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		if (!(first->tx_flags & NGBE_TX_FLAGS_HW_VLAN) &&
		    !(first->tx_flags & NGBE_TX_FLAGS_CC))
			return;
		vlan_macip_lens = skb_network_offset(skb) <<
				  NGBE_TXD_MACLEN_SHIFT;
	} else {
		u8 l4_prot = 0;
		union {
			struct iphdr *ipv4;
			struct ipv6hdr *ipv6;
			u8 *raw;
		} network_hdr;
		union {
			struct tcphdr *tcphdr;
			u8 *raw;
		} transport_hdr;

		if (skb->encapsulation) {
			network_hdr.raw = skb_inner_network_header(skb);
			transport_hdr.raw = skb_inner_transport_header(skb);
			vlan_macip_lens = skb_network_offset(skb) <<
					  NGBE_TXD_MACLEN_SHIFT;
			switch (first->protocol) {
			case htons(ETH_P_IP):
				tun_prot = ip_hdr(skb)->protocol;
				break;
			case htons(ETH_P_IPV6):
				tun_prot = ipv6_hdr(skb)->nexthdr;
				break;
			default:
				if (unlikely(net_ratelimit())) {
					dev_warn(tx_ring->dev,
						 "partial checksum but version=%d\n",
					 network_hdr.ipv4->version);
				}
				return;
			}
			switch (tun_prot) {
			case IPPROTO_UDP:
				tunhdr_eiplen_tunlen = NGBE_TXD_TUNNEL_UDP;
				tunhdr_eiplen_tunlen |=
					((skb_network_header_len(skb) >> 2) <<
					NGBE_TXD_OUTER_IPLEN_SHIFT) |
					(((skb_inner_mac_header(skb) -
					skb_transport_header(skb)) >> 1) <<
					NGBE_TXD_TUNNEL_LEN_SHIFT);
				break;
			case IPPROTO_GRE:
				tunhdr_eiplen_tunlen = NGBE_TXD_TUNNEL_GRE;
				tunhdr_eiplen_tunlen |=
					((skb_network_header_len(skb) >> 2) <<
					NGBE_TXD_OUTER_IPLEN_SHIFT) |
					(((skb_inner_mac_header(skb) -
					skb_transport_header(skb)) >> 1) <<
					NGBE_TXD_TUNNEL_LEN_SHIFT);
				break;
			case IPPROTO_IPIP:
				tunhdr_eiplen_tunlen =
					(((char *)inner_ip_hdr(skb) -
					 (char *)ip_hdr(skb)) >> 2) <<
					NGBE_TXD_OUTER_IPLEN_SHIFT;
				break;
			default:
				break;
			}
		} else {
			network_hdr.raw = skb_network_header(skb);
			transport_hdr.raw = skb_transport_header(skb);
			vlan_macip_lens = skb_network_offset(skb) <<
					  NGBE_TXD_MACLEN_SHIFT;
		}

		switch (network_hdr.ipv4->version) {
		case IPVERSION:
			vlan_macip_lens |=
				(transport_hdr.raw - network_hdr.raw) >> 1;
			l4_prot = network_hdr.ipv4->protocol;
			break;
		case 6:
			vlan_macip_lens |=
				(transport_hdr.raw - network_hdr.raw) >> 1;
			l4_prot = network_hdr.ipv6->nexthdr;
			break;
		default:
			break;
		}

		switch (l4_prot) {
		case IPPROTO_TCP:
		mss_l4len_idx = (transport_hdr.tcphdr->doff * 4) <<
				NGBE_TXD_L4LEN_SHIFT;
			break;
		case IPPROTO_SCTP:
			mss_l4len_idx = sizeof(struct sctphdr) <<
					NGBE_TXD_L4LEN_SHIFT;
			break;
		case IPPROTO_UDP:
			mss_l4len_idx = sizeof(struct udphdr) <<
					NGBE_TXD_L4LEN_SHIFT;
			break;
		default:
			break;
		}

		/* update TX checksum flag */
		first->tx_flags |= NGBE_TX_FLAGS_CSUM;
	}
	first->tx_flags |= NGBE_TX_FLAGS_CC;
	/* vlan_macip_lens: MACLEN, VLAN tag */
	vlan_macip_lens |= first->tx_flags & NGBE_TX_FLAGS_VLAN_MASK;

	type_tucmd = dptype.ptype << 24;
	ngbe_tx_ctxtdesc(tx_ring, vlan_macip_lens, tunhdr_eiplen_tunlen,
			 type_tucmd, mss_l4len_idx);
}

static u32 ngbe_tx_cmd_type(u32 tx_flags)
{
	/* set type for advanced descriptor with frame checksum insertion */
	u32 cmd_type = NGBE_TXD_DTYP_DATA | NGBE_TXD_IFCS;

	/* set HW vlan bit if vlan is present */
	cmd_type |= NGBE_SET_FLAG(tx_flags, NGBE_TX_FLAGS_HW_VLAN, NGBE_TXD_VLE);

	/* set segmentation enable bits for TSO/FSO */
	cmd_type |= NGBE_SET_FLAG(tx_flags, NGBE_TX_FLAGS_TSO, NGBE_TXD_TSE);

	/* set timestamp bit if present */
	cmd_type |= NGBE_SET_FLAG(tx_flags, NGBE_TX_FLAGS_TSTAMP, NGBE_TXD_MAC_TSTAMP);

	cmd_type |= NGBE_SET_FLAG(tx_flags, NGBE_TX_FLAGS_LINKSEC, NGBE_TXD_LINKSEC);

	return cmd_type;
}

static void ngbe_tx_olinfo_status(union ngbe_tx_desc *tx_desc,
				  u32 tx_flags, unsigned int paylen)
{
	u32 olinfo_status = paylen << NGBE_TXD_PAYLEN_SHIFT;

	/* enable L4 checksum for TSO and TX checksum offload */
	olinfo_status |= NGBE_SET_FLAG(tx_flags,
					NGBE_TX_FLAGS_CSUM,
					NGBE_TXD_L4CS);

	/* enable IPv4 checksum for TSO */
	olinfo_status |= NGBE_SET_FLAG(tx_flags,
					NGBE_TX_FLAGS_IPV4,
					NGBE_TXD_IIPCS);
	/* enable outer IPv4 checksum for TSO */
	olinfo_status |= NGBE_SET_FLAG(tx_flags,
					NGBE_TX_FLAGS_OUTER_IPV4,
					NGBE_TXD_EIPCS);
	/* Check Context must be set if Tx switch is enabled, which it
	 * always is for case where virtual functions are running
	 */
	olinfo_status |= NGBE_SET_FLAG(tx_flags,
					NGBE_TX_FLAGS_CC,
					NGBE_TXD_CC);

	olinfo_status |= NGBE_SET_FLAG(tx_flags,
					NGBE_TX_FLAGS_IPSEC,
					NGBE_TXD_IPSEC);

	tx_desc->read.olinfo_status = cpu_to_le32(olinfo_status);
}

static int ngbe_tx_map(struct ngbe_ring *tx_ring,
		       struct ngbe_tx_buffer *first,
		   const u8 hdr_len)
{
	struct sk_buff *skb = first->skb;
	struct ngbe_tx_buffer *tx_buffer;
	union ngbe_tx_desc *tx_desc;
	skb_frag_t *frag;
	dma_addr_t dma;
	unsigned int data_len, size;
	u32 tx_flags = first->tx_flags;
	u32 cmd_type = ngbe_tx_cmd_type(tx_flags);
	u16 i = tx_ring->next_to_use;

	tx_desc = NGBE_TX_DESC(tx_ring, i);

	ngbe_tx_olinfo_status(tx_desc, tx_flags, skb->len - hdr_len);

	size = skb_headlen(skb);
	data_len = skb->data_len;

	dma = dma_map_single(tx_ring->dev, skb->data, size, DMA_TO_DEVICE);

	tx_buffer = first;

	for (frag = &skb_shinfo(skb)->frags[0];; frag++) {
		if (dma_mapping_error(tx_ring->dev, dma))
			goto dma_error;

		/* record length, and DMA address */
		dma_unmap_len_set(tx_buffer, len, size);
		dma_unmap_addr_set(tx_buffer, dma, dma);

		tx_desc->read.buffer_addr = cpu_to_le64(dma);

		while (unlikely(size > NGBE_MAX_DATA_PER_TXD)) {
			tx_desc->read.cmd_type_len = cpu_to_le32(cmd_type ^ NGBE_MAX_DATA_PER_TXD);

			i++;
			tx_desc++;
			if (i == tx_ring->count) {
				tx_desc = NGBE_TX_DESC(tx_ring, 0);
				i = 0;
			}
			tx_desc->read.olinfo_status = 0;

			dma += NGBE_MAX_DATA_PER_TXD;
			size -= NGBE_MAX_DATA_PER_TXD;

			tx_desc->read.buffer_addr = cpu_to_le64(dma);
		}

		if (likely(!data_len))
			break;

		tx_desc->read.cmd_type_len = cpu_to_le32(cmd_type ^ size);

		i++;
		tx_desc++;
		if (i == tx_ring->count) {
			tx_desc = NGBE_TX_DESC(tx_ring, 0);
			i = 0;
		}
		tx_desc->read.olinfo_status = 0;

		size = skb_frag_size(frag);

		data_len -= size;

		dma = skb_frag_dma_map(tx_ring->dev, frag, 0, size,
				       DMA_TO_DEVICE);

		tx_buffer = &tx_ring->tx_buffer_info[i];
	}

	/* write last descriptor with RS and EOP bits */
	cmd_type |= size | NGBE_TXD_CMD;
	tx_desc->read.cmd_type_len = cpu_to_le32(cmd_type);

	netdev_tx_sent_queue(txring_txq(tx_ring), first->bytecount);

	/* set the timestamp */
	first->time_stamp = jiffies;

	/* Force memory writes to complete before letting h/w know there
	 * are new descriptors to fetch.	(Only applicable for weak-ordered
	 * memory model archs, such as IA-64).
	 *
	 * We also need this memory barrier to make certain all of the
	 * status bits have been updated before next_to_watch is written.
	 */
	wmb();

	/* set next_to_watch value indicating a packet is present */
	first->next_to_watch = tx_desc;

	i++;
	if (i == tx_ring->count)
		i = 0;

	tx_ring->next_to_use = i;

	ngbe_maybe_stop_tx(tx_ring, DESC_NEEDED);

	skb_tx_timestamp(skb);

	if (netif_xmit_stopped(txring_txq(tx_ring)) || !netdev_xmit_more())
		writel(i, tx_ring->tail);

	return 0;
dma_error:
	dev_err(tx_ring->dev, "TX DMA map failed\n");

	/* clear dma mappings for failed tx_buffer_info map */
	for (;;) {
		tx_buffer = &tx_ring->tx_buffer_info[i];
		if (dma_unmap_len(tx_buffer, len))
			dma_unmap_page(tx_ring->dev,
				       dma_unmap_addr(tx_buffer, dma),
					 dma_unmap_len(tx_buffer, len),
					 DMA_TO_DEVICE);
		dma_unmap_len_set(tx_buffer, len, 0);
		if (tx_buffer == first)
			break;
		if (i == 0)
			i += tx_ring->count;
		i--;
	}

	dev_kfree_skb_any(first->skb);
	first->skb = NULL;

	tx_ring->next_to_use = i;

	return -1;
}

netdev_tx_t ngbe_xmit_frame_ring(struct sk_buff *skb,
				 struct ngbe_adapter __maybe_unused *adapter,
				  struct ngbe_ring *tx_ring)
{
	struct ngbe_tx_buffer *first;
	int tso;
	u32 tx_flags = 0;
	unsigned short f;
	u16 count = TXD_USE_COUNT(skb_headlen(skb));
	__be16 protocol = skb->protocol;
	u8 hdr_len = 0;
	struct ngbe_dec_ptype dptype;

	/* need: 1 descriptor per page * PAGE_SIZE/NGBE_MAX_DATA_PER_TXD,
	 * + 1 desc for skb_headlen/NGBE_MAX_DATA_PER_TXD,
	 * + 2 desc gap to keep tail from touching head,
	 * + 1 desc for context descriptor,
	 * otherwise try next time
	 */
	for (f = 0; f < skb_shinfo(skb)->nr_frags; f++)
		count += TXD_USE_COUNT(skb_frag_size(&skb_shinfo(skb)->
						     frags[f]));

	if (ngbe_maybe_stop_tx(tx_ring, count + 3)) {
		tx_ring->tx_stats.tx_busy++;
		return NETDEV_TX_BUSY;
	}

	/* record the location of the first descriptor for this packet */
	first = &tx_ring->tx_buffer_info[tx_ring->next_to_use];
	first->skb = skb;
	first->bytecount = skb->len;
	first->gso_segs = 1;

	/* if we have a HW VLAN tag being added default to the HW one */
	if (skb_vlan_tag_present(skb)) {
		tx_flags |= skb_vlan_tag_get(skb) << NGBE_TX_FLAGS_VLAN_SHIFT;
		tx_flags |= NGBE_TX_FLAGS_HW_VLAN;
	}

	/* it is a SW VLAN check the next protocol and store the tag */
	if (protocol == htons(ETH_P_8021Q) || protocol == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr, _vhdr;

		vhdr = skb_header_pointer(skb, ETH_HLEN, sizeof(_vhdr), &_vhdr);
		if (!vhdr)
			goto out_drop;

		protocol = vhdr->h_vlan_encapsulated_proto;
		tx_flags |= NGBE_TX_FLAGS_SW_VLAN;
	}

	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP) &&
	    adapter->ptp_clock) {
		if (!test_and_set_bit_lock(__NGBE_PTP_TX_IN_PROGRESS,
					   &adapter->state)) {
			skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;

			tx_flags |= NGBE_TX_FLAGS_TSTAMP;

			/* schedule check for Tx timestamp */
			adapter->ptp_tx_skb = skb_get(skb);
			adapter->ptp_tx_start = jiffies;
			schedule_work(&adapter->ptp_tx_work);
		} else {
			adapter->tx_hwtstamp_skipped++;
		}
	}

	/* record initial flags and protocol */
	first->tx_flags = tx_flags;
	first->protocol = protocol;

	dptype = encode_tx_desc_ptype(first);

	tso = ngbe_tso(tx_ring, first, &hdr_len, dptype);
	if (tso < 0)
		goto out_drop;
	else if (!tso)
		ngbe_tx_csum(tx_ring, first, dptype);

	ngbe_tx_map(tx_ring, first, hdr_len);

	return NETDEV_TX_OK;

out_drop:
	dev_kfree_skb_any(first->skb);
	first->skb = NULL;

	e_dev_err("%s drop\n", __func__);

	return NETDEV_TX_OK;
}

static netdev_tx_t ngbe_xmit_frame(struct sk_buff *skb,
				   struct net_device *netdev)
{
	struct ngbe_adapter *adapter = netdev_priv(netdev);
	struct ngbe_ring *tx_ring;
	unsigned int r_idx = skb->queue_mapping;

	if (!netif_carrier_ok(netdev)) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	/* The minimum packet size for olinfo paylen is 17 so pad the skb
	 * in order to meet this minimum size requirement.
	 */
	if (skb_put_padto(skb, 17))
		return NETDEV_TX_OK;

	if (r_idx >= adapter->num_tx_queues)
		r_idx = r_idx % adapter->num_tx_queues;
	tx_ring = adapter->tx_ring[r_idx];

	return ngbe_xmit_frame_ring(skb, adapter, tx_ring);
}

/**
 * ngbe_set_mac - Change the Ethernet Address of the NIC
 * @netdev: network interface device structure
 * @p: pointer to an address structure
 *
 * Returns 0 on success, negative on failure
 **/
static int ngbe_set_mac(struct net_device *netdev, void *p)
{
	struct ngbe_adapter *adapter = netdev_priv(netdev);
	struct ngbe_hw *hw = &adapter->hw;
	struct sockaddr *addr = p;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	ngbe_del_mac_filter(adapter, hw->mac.addr, 0);
	memcpy(netdev->dev_addr, addr->sa_data, netdev->addr_len);
	memcpy(hw->mac.addr, addr->sa_data, netdev->addr_len);

	ngbe_mac_set_default_filter(adapter, hw->mac.addr);
	e_info(drv, "The mac has been set to %02X:%02X:%02X:%02X:%02X:%02X\n",
	       hw->mac.addr[0], hw->mac.addr[1], hw->mac.addr[2],
		 hw->mac.addr[3], hw->mac.addr[4], hw->mac.addr[5]);

	return 0;
}

/**
 * ngbe_change_mtu - Change the Maximum Transfer Unit
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 on success, negative on failure
 **/
static int ngbe_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct ngbe_adapter *adapter = netdev_priv(netdev);

	if (new_mtu < 68 || new_mtu > 9414)
		return -EINVAL;

	/* we cannot allow legacy VFs to enable their receive
	 * paths when MTU greater than 1500 is configured.  So display a
	 * warning that legacy VFs will be disabled.
	 */
	if (adapter->flags & NGBE_FLAG_SRIOV_ENABLED &&
	    new_mtu > ETH_DATA_LEN)
		e_warn(probe, "Setting MTU > 1500 will disable legacy VFs\n");

	e_info(probe, "changing MTU from %d to %d\n", netdev->mtu, new_mtu);

	/* must set new MTU before calling down or up */
	netdev->mtu = new_mtu;

	if (netif_running(netdev))
		ngbe_reinit_locked(adapter);

	return 0;
}

/**
 * ngbe_tx_timeout - Respond to a Tx Hang
 * @netdev: network interface device structure
 **/
static void ngbe_tx_timeout(struct net_device *netdev, unsigned int txqueue)
{
	struct ngbe_adapter *adapter = netdev_priv(netdev);
	struct ngbe_hw *hw = &adapter->hw;
	bool real_tx_hang = false;
	int i;
	u16 value = 0;
	u32 value2 = 0;
	u32 head, tail;

#define TX_TIMEO_LIMIT 16000
	for (i = 0; i < adapter->num_tx_queues; i++) {
		struct ngbe_ring *tx_ring = adapter->tx_ring[i];

		if (check_for_tx_hang(tx_ring) && ngbe_check_tx_hang(tx_ring)) {
			real_tx_hang = true;
			e_info(drv, "&&%s:i=%d&&", __func__, i);
		}
	}

	pci_read_config_word(adapter->pdev, PCI_VENDOR_ID, &value);
	ERROR_REPORT1(hw, NGBE_ERROR_POLLING, "pci vendor id is 0x%x\n", value);

	pci_read_config_word(adapter->pdev, PCI_COMMAND, &value);
	ERROR_REPORT1(hw, NGBE_ERROR_POLLING, "pci command reg is 0x%x.\n", value);

	value2 = rd32(&adapter->hw, 0x10000);
	ERROR_REPORT1(hw, NGBE_ERROR_POLLING, "reg 0x10000 value is 0x%08x\n", value2);
	value2 = rd32(&adapter->hw, 0x180d0);
	ERROR_REPORT1(hw, NGBE_ERROR_POLLING, "reg 0x180d0 value is 0x%08x\n", value2);
	value2 = rd32(&adapter->hw, 0x180d4);
	ERROR_REPORT1(hw, NGBE_ERROR_POLLING, "reg 0x180d4 value is 0x%08x\n", value2);
	value2 = rd32(&adapter->hw, 0x180d8);
	ERROR_REPORT1(hw, NGBE_ERROR_POLLING, "reg 0x180d8 value is 0x%08x\n", value2);
	value2 = rd32(&adapter->hw, 0x180dc);
	ERROR_REPORT1(hw, NGBE_ERROR_POLLING, "reg 0x180dc value is 0x%08x\n", value2);

	for (i = 0; i < adapter->num_tx_queues; i++) {
		head = rd32(&adapter->hw, NGBE_PX_TR_RP(adapter->tx_ring[i]->reg_idx));
		tail = rd32(&adapter->hw, NGBE_PX_TR_WP(adapter->tx_ring[i]->reg_idx));

		ERROR_REPORT1(hw, NGBE_ERROR_POLLING,
			      "tx ring %d next_to_use is %d, next_to_clean is %d\n",
			i, adapter->tx_ring[i]->next_to_use, adapter->tx_ring[i]->next_to_clean);
		ERROR_REPORT1(hw, NGBE_ERROR_POLLING,
			      "tx ring %d hw rp is 0x%x, wp is 0x%x\n", i, head, tail);
	}

	value2 = rd32(&adapter->hw, NGBE_PX_IMS);
	ERROR_REPORT1(hw, NGBE_ERROR_POLLING,
		      "PX_IMS value is 0x%08x\n", value2);

	if (value2) {
		ERROR_REPORT1(hw, NGBE_ERROR_POLLING, "clear interrupt mask.\n");
		wr32(&adapter->hw, NGBE_PX_ICS, value2);
		wr32(&adapter->hw, NGBE_PX_IMC, value2);
	}

	ERROR_REPORT1(hw, NGBE_ERROR_POLLING, "tx timeout. do pcie recovery.\n");
	if (adapter->hw.bus.lan_id == 0) {
		adapter->flags2 |= NGBE_FLAG2_PCIE_NEED_RECOVER;
		ngbe_service_event_schedule(adapter);
	} else {
		wr32(&adapter->hw, NGBE_MIS_PF_SM, 1);
	}
}

static int ngbe_vlan_rx_kill_vid(struct net_device *netdev,
				 __always_unused __be16 proto, u16 vid)
{
	struct ngbe_adapter *adapter = netdev_priv(netdev);
	struct ngbe_hw *hw = &adapter->hw;
	int pool_ndx = 0;

	/* User is not allowed to remove vlan ID 0 */
	if (!vid)
		return 0;

	/* remove VID from filter table */
	if (hw->mac.ops.set_vfta)
		TCALL(hw, mac.ops.set_vfta, vid, pool_ndx, false);

	clear_bit(vid, adapter->active_vlans);
	return 0;
}

static int ngbe_mii_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
	struct mii_ioctl_data *mii = (struct mii_ioctl_data *)&ifr->ifr_data;
	int prtad, devad, ret = 0;

	prtad = (mii->phy_id & MDIO_PHY_ID_PRTAD) >> 5;
	devad = (mii->phy_id & MDIO_PHY_ID_DEVAD);

	return ret;
}

static int ngbe_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
	struct ngbe_adapter *adapter = netdev_priv(netdev);

	switch (cmd) {
	case SIOCGHWTSTAMP:
		return ngbe_ptp_get_ts_config(adapter, ifr);
	case SIOCSHWTSTAMP:
		return ngbe_ptp_set_ts_config(adapter, ifr);

	case SIOCGMIIREG:
	case SIOCSMIIREG:
		return ngbe_mii_ioctl(netdev, ifr, cmd);
	default:
		return -EOPNOTSUPP;
	}
}

static void ngbe_remove_adapter(struct ngbe_hw *hw)
{
	struct ngbe_adapter *adapter = hw->back;

	if (!hw->hw_addr)
		return;
	hw->hw_addr = NULL;
	e_dev_err("Adapter removed\n");
	if (test_bit(__NGBE_SERVICE_INITED, &adapter->state))
		ngbe_service_event_schedule(adapter);
}

static u32 ngbe_validate_register_read(struct ngbe_hw *hw, u32 reg, bool quiet)
{
	int i;
	u32 value;
	u8 __iomem *reg_addr;
	struct ngbe_adapter *adapter = hw->back;

	reg_addr = READ_ONCE(hw->hw_addr);
	if (NGBE_REMOVED(reg_addr))
		return NGBE_FAILED_READ_REG;
	for (i = 0; i < NGBE_DEAD_READ_RETRIES; ++i) {
		value = ngbe_rd32(reg_addr + reg);
		if (value != NGBE_DEAD_READ_REG)
			break;
	}
	if (quiet)
		return value;
	if (value == NGBE_DEAD_READ_REG)
		e_err(drv, "%s: register %x read unchanged\n", __func__, reg);
	else
		e_warn(hw, "%s: register %x read recovered after %d retries\n",
		       __func__, reg, i + 1);

	return value;
}

static void ngbe_check_remove(struct ngbe_hw *hw, u32 reg)
{
	u32 value;

	/* The following check not only optimizes a bit by not
	 * performing a read on the status register when the
	 * register just read was a status register read that
	 * returned NGBE_FAILED_READ_REG. It also blocks any
	 * potential recursion.
	 */
	if (reg == NGBE_CFG_PORT_ST) {
		ngbe_remove_adapter(hw);
		return;
	}
	value = rd32(hw, NGBE_CFG_PORT_ST);
	if (value == NGBE_FAILED_READ_REG)
		ngbe_remove_adapter(hw);
}

u32 ngbe_read_reg(struct ngbe_hw *hw, u32 reg, bool quiet)
{
	u32 value;
	u8 __iomem *reg_addr;

	reg_addr = READ_ONCE(hw->hw_addr);
	if (NGBE_REMOVED(reg_addr))
		return NGBE_FAILED_READ_REG;
	value = ngbe_rd32(reg_addr + reg);
	if (unlikely(value == NGBE_FAILED_READ_REG))
		ngbe_check_remove(hw, reg);
	if (unlikely(value == NGBE_DEAD_READ_REG))
		value = ngbe_validate_register_read(hw, reg, quiet);
	return value;
}

/**
 * ngbe_get_stats64 - Get System Network Statistics
 * @netdev: network interface device structure
 * @stats: storage space for 64bit statistics
 *
 * Returns 64bit statistics, for use in the ndo_get_stats64 callback. This
 * function replaces ngbe_get_stats for kernels which support it.
 */
static void ngbe_get_stats64(struct net_device *netdev,
			     struct rtnl_link_stats64 *stats)
{
	struct ngbe_adapter *adapter = netdev_priv(netdev);
	int i;

	rcu_read_lock();
	for (i = 0; i < adapter->num_rx_queues; i++) {
		struct ngbe_ring *ring = READ_ONCE(adapter->rx_ring[i]);
		u64 bytes, packets;
		unsigned int start;

		if (ring) {
			do {
				start = u64_stats_fetch_begin_irq(&ring->syncp);
				packets = ring->stats.packets;
				bytes   = ring->stats.bytes;
			} while (u64_stats_fetch_retry_irq(&ring->syncp,
				 start));
			stats->rx_packets += packets;
			stats->rx_bytes   += bytes;
		}
	}

	for (i = 0; i < adapter->num_tx_queues; i++) {
		struct ngbe_ring *ring = READ_ONCE(adapter->tx_ring[i]);
		u64 bytes, packets;
		unsigned int start;

		if (ring) {
			do {
				start = u64_stats_fetch_begin_irq(&ring->syncp);
				packets = ring->stats.packets;
				bytes   = ring->stats.bytes;
			} while (u64_stats_fetch_retry_irq(&ring->syncp,
				 start));
			stats->tx_packets += packets;
			stats->tx_bytes   += bytes;
		}
	}
	rcu_read_unlock();
	/* following stats updated by ngbe_watchdog_task() */
	stats->multicast        = netdev->stats.multicast;
	stats->rx_errors        = netdev->stats.rx_errors;
	stats->rx_length_errors = netdev->stats.rx_length_errors;
	stats->rx_crc_errors    = netdev->stats.rx_crc_errors;
	stats->rx_missed_errors = netdev->stats.rx_missed_errors;
}

static int ngbe_ndo_fdb_add(struct ndmsg *ndm, struct nlattr *tb[],
			    struct net_device *dev,
			     const unsigned char *addr,
			     u16 vid,
			     u16 flags,
			     struct netlink_ext_ack *extack)
{
	/* guarantee we can provide a unique filter for the unicast address */
	if (is_unicast_ether_addr(addr) || is_link_local_ether_addr(addr)) {
		if (netdev_uc_count(dev) >= NGBE_MAX_PF_MACVLANS)
			return -ENOMEM;
	}

	return ndo_dflt_fdb_add(ndm, tb, dev, addr, vid, flags);
}

static netdev_features_t ngbe_features_check(struct sk_buff *skb,
					     struct net_device *dev,
					netdev_features_t features)
{
	u32 vlan_num = 0;
	u16 vlan_depth = skb->mac_len;
	__be16 type = skb->protocol;
	struct vlan_hdr *vh;

	if (skb_vlan_tag_present(skb))
		vlan_num++;

	if (vlan_depth)
		vlan_depth -= VLAN_HLEN;
	else
		vlan_depth = ETH_HLEN;

	while (type == htons(ETH_P_8021Q) || type == htons(ETH_P_8021AD)) {
		vlan_num++;
		vh = (struct vlan_hdr *)(skb->data + vlan_depth);
		type = vh->h_vlan_encapsulated_proto;
		vlan_depth += VLAN_HLEN;
	}

	if (vlan_num > 2)
		features &= ~(NETIF_F_HW_VLAN_CTAG_TX |
					NETIF_F_HW_VLAN_STAG_TX);

	if (skb->encapsulation) {
		if (unlikely(skb_inner_mac_header(skb) -
					skb_transport_header(skb) >
					NGBE_MAX_TUNNEL_HDR_LEN))
			return features & ~NETIF_F_CSUM_MASK;
	}

	return features;
}

void ngbe_do_reset(struct net_device *netdev)
{
	struct ngbe_adapter *adapter = netdev_priv(netdev);

	if (netif_running(netdev))
		ngbe_reinit_locked(adapter);
	else
		ngbe_reset(adapter);
}

static int ngbe_set_features(struct net_device *netdev,
			     netdev_features_t features)
{
	struct ngbe_adapter *adapter = netdev_priv(netdev);
	bool need_reset = false;

	if (features & NETIF_F_HW_VLAN_CTAG_RX)
		ngbe_vlan_strip_enable(adapter);
	else
		ngbe_vlan_strip_disable(adapter);

	if (features & NETIF_F_RXHASH) {
		if (!(adapter->flags2 & NGBE_FLAG2_RSS_ENABLED)) {
			wr32m(&adapter->hw, NGBE_RDB_RA_CTL,
			      NGBE_RDB_RA_CTL_RSS_EN, NGBE_RDB_RA_CTL_RSS_EN);
			adapter->flags2 |= NGBE_FLAG2_RSS_ENABLED;
		}
	} else {
		if (adapter->flags2 & NGBE_FLAG2_RSS_ENABLED) {
			wr32m(&adapter->hw, NGBE_RDB_RA_CTL,
			      NGBE_RDB_RA_CTL_RSS_EN, ~NGBE_RDB_RA_CTL_RSS_EN);
			adapter->flags2 &= ~NGBE_FLAG2_RSS_ENABLED;
		}
	}

	if (need_reset)
		ngbe_do_reset(netdev);

	return 0;
}

static netdev_features_t ngbe_fix_features(struct net_device *netdev,
					   netdev_features_t features)
{
	/* If Rx checksum is disabled, then RSC/LRO should also be disabled */
	if (!(features & NETIF_F_RXCSUM))
		features &= ~NETIF_F_LRO;

	/* Turn off LRO if not RSC capable */
	features &= ~NETIF_F_LRO;

	if (!(features & NETIF_F_HW_VLAN_CTAG_RX))
		features &= ~NETIF_F_HW_VLAN_STAG_RX;
	else
		features |= NETIF_F_HW_VLAN_STAG_RX;
	if (!(features & NETIF_F_HW_VLAN_CTAG_TX))
		features &= ~NETIF_F_HW_VLAN_STAG_TX;
	else
		features |= NETIF_F_HW_VLAN_STAG_TX;

	return features;
}

static const struct net_device_ops ngbe_netdev_ops = {
	.ndo_open               = ngbe_open,
	.ndo_stop               = ngbe_close,
	.ndo_start_xmit         = ngbe_xmit_frame,
	.ndo_set_rx_mode        = ngbe_set_rx_mode,
	.ndo_validate_addr      = eth_validate_addr,
	.ndo_set_mac_address    = ngbe_set_mac,
	.ndo_change_mtu         = ngbe_change_mtu,
	.ndo_tx_timeout         = ngbe_tx_timeout,
	.ndo_vlan_rx_add_vid    = ngbe_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid   = ngbe_vlan_rx_kill_vid,
	.ndo_do_ioctl           = ngbe_ioctl,
	.ndo_get_stats64        = ngbe_get_stats64,
	.ndo_fdb_add            = ngbe_ndo_fdb_add,
	.ndo_features_check     = ngbe_features_check,
	.ndo_set_features       = ngbe_set_features,
	.ndo_fix_features       = ngbe_fix_features,
};

void ngbe_assign_netdev_ops(struct net_device *dev)
{
	dev->netdev_ops = &ngbe_netdev_ops;
	ngbe_set_ethtool_ops(dev);
	dev->watchdog_timeo = 5 * HZ;
}

/* disable the specified rx ring/queue */
void ngbe_disable_rx_queue(struct ngbe_adapter *adapter,
			   struct ngbe_ring *ring)
{
	struct ngbe_hw *hw = &adapter->hw;
	int wait_loop = NGBE_MAX_RX_DESC_POLL;
	u32 rxdctl;
	u8 reg_idx = ring->reg_idx;

	if (NGBE_REMOVED(hw->hw_addr))
		return;

	/* write value back with RXDCTL.ENABLE bit cleared */
	wr32m(hw, NGBE_PX_RR_CFG(reg_idx),
	      NGBE_PX_RR_CFG_RR_EN, 0);

	/* hardware may take up to 100us to actually disable rx queue */
	do {
		usleep_range(10, 20);
		rxdctl = rd32(hw, NGBE_PX_RR_CFG(reg_idx));
	} while (--wait_loop && (rxdctl & NGBE_PX_RR_CFG_RR_EN));

	if (!wait_loop)
		e_err(drv, "RXDCTL.ENABLE on Rx queue %d not cleared within the polling period\n",
		      reg_idx);
}

/**
 * ngbe_irq_disable - Mask off interrupt generation on the NIC
 * @adapter: board private structure
 **/
void ngbe_irq_disable(struct ngbe_adapter *adapter)
{
	wr32(&adapter->hw, NGBE_PX_MISC_IEN, 0);
	ngbe_intr_disable(&adapter->hw, NGBE_INTR_ALL);

	NGBE_WRITE_FLUSH(&adapter->hw);
	if (adapter->flags & NGBE_FLAG_MSIX_ENABLED) {
		int vector;

		for (vector = 0; vector < adapter->num_q_vectors; vector++)
			synchronize_irq(adapter->msix_entries[vector].vector);

		synchronize_irq(adapter->msix_entries[vector++].vector);
	} else {
		synchronize_irq(adapter->pdev->irq);
	}
}

static void ngbe_napi_disable_all(struct ngbe_adapter *adapter)
{
	struct ngbe_q_vector *q_vector;
	int q_idx;

	for (q_idx = 0; q_idx < adapter->num_q_vectors; q_idx++) {
		q_vector = adapter->q_vector[q_idx];
		napi_disable(&q_vector->napi);
	}
}

static void ngbe_sync_mac_table(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;
	int i;

	for (i = 0; i < hw->mac.num_rar_entries; i++) {
		if (adapter->mac_table[i].state & NGBE_MAC_STATE_MODIFIED) {
			if (adapter->mac_table[i].state &
					NGBE_MAC_STATE_IN_USE) {
				TCALL(hw, mac.ops.set_rar, i,
				      adapter->mac_table[i].addr,
						adapter->mac_table[i].pools,
						NGBE_PSR_MAC_SWC_AD_H_AV);
			} else {
				TCALL(hw, mac.ops.clear_rar, i);
			}
			adapter->mac_table[i].state &=
				~(NGBE_MAC_STATE_MODIFIED);
		}
	}
}

void ngbe_disable_device(struct ngbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct ngbe_hw *hw = &adapter->hw;
	u32 i;

	/* signal that we are down to the interrupt handler */
	if (test_and_set_bit(__NGBE_DOWN, &adapter->state))
		return; /* do nothing if already down */

	ngbe_disable_pcie_master(hw);
	/* disable receives */
	TCALL(hw, mac.ops.disable_rx);

	/* disable all enabled rx queues */
	for (i = 0; i < adapter->num_rx_queues; i++)
		/* this call also flushes the previous write */
		ngbe_disable_rx_queue(adapter, adapter->rx_ring[i]);

	netif_tx_stop_all_queues(netdev);

	/* call carrier off first to avoid false dev_watchdog timeouts */
	netif_carrier_off(netdev);
	netif_tx_disable(netdev);

	if (hw->gpio_ctl == 1)
		/* gpio0 is used to power on/off control*/
		wr32(hw, NGBE_GPIO_DR, NGBE_GPIO_DR_0);

	ngbe_irq_disable(adapter);

	ngbe_napi_disable_all(adapter);

	adapter->flags2 &= ~(NGBE_FLAG2_PF_RESET_REQUESTED |
						NGBE_FLAG2_DEV_RESET_REQUESTED |
						NGBE_FLAG2_GLOBAL_RESET_REQUESTED);
	adapter->flags &= ~NGBE_FLAG_NEED_LINK_UPDATE;

	del_timer_sync(&adapter->service_timer);

	/*OCP NCSI need it*/
	if (!(((hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_OCP_CARD) ||
	      ((hw->subsystem_device_id & NGBE_WOL_MASK) == NGBE_WOL_SUP) ||
		   ((hw->subsystem_device_id & NGBE_NCSI_MASK) == NGBE_NCSI_SUP) ||
		    adapter->eth_priv_flags & NGBE_ETH_PRIV_FLAG_LLDP))
		wr32m(hw, NGBE_MAC_TX_CFG, NGBE_MAC_TX_CFG_TE, 0);

	/* disable transmits in the hardware now that interrupts are off */
	for (i = 0; i < adapter->num_tx_queues; i++) {
		u8 reg_idx = adapter->tx_ring[i]->reg_idx;

		wr32(hw, NGBE_PX_TR_CFG(reg_idx), NGBE_PX_TR_CFG_SWFLSH);
	}

	/* Disable the Tx DMA engine */
	wr32m(hw, NGBE_TDM_CTL, NGBE_TDM_CTL_TE, 0);
}

void ngbe_unmap_and_free_tx_res(struct ngbe_ring *ring, struct ngbe_tx_buffer *tx_buffer)
{
	if (tx_buffer->skb) {
		dev_kfree_skb_any(tx_buffer->skb);
		if (dma_unmap_len(tx_buffer, len))
			dma_unmap_single(ring->dev,
					 dma_unmap_addr(tx_buffer, dma),
					 dma_unmap_len(tx_buffer, len),
					 DMA_TO_DEVICE);
	} else if (dma_unmap_len(tx_buffer, len)) {
		dma_unmap_page(ring->dev,
			       dma_unmap_addr(tx_buffer, dma),
						dma_unmap_len(tx_buffer, len),
						DMA_TO_DEVICE);
	}
	tx_buffer->next_to_watch = NULL;
	tx_buffer->skb = NULL;
	dma_unmap_len_set(tx_buffer, len, 0);
}

static void ngbe_service_event_complete(struct ngbe_adapter *adapter)
{
	WARN_ON(!test_bit(__NGBE_SERVICE_SCHED, &adapter->state));

	/* flush memory to make sure state is correct before next watchdog */
	smp_mb__before_atomic();
	clear_bit(__NGBE_SERVICE_SCHED, &adapter->state);
}

/**
 * ngbe_hpbthresh - calculate high water mark for flow control
 * @adapter: board private structure to calculate for
 * @pb - packet buffer to calculate
 **/
static int ngbe_hpbthresh(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;
	struct net_device *dev = adapter->netdev;
	int link, tc, kb, marker;
	u32 dv_id, rx_pba;

	/* Calculate max LAN frame size */
	link = dev->mtu + ETH_HLEN + ETH_FCS_LEN + NGBE_ETH_FRAMING;
	tc = link;

	/* Calculate delay value for device */
	dv_id = NGBE_DV(link, tc);

	/* Loopback switch introduces additional latency */
	if (adapter->flags & NGBE_FLAG_SRIOV_ENABLED)
		dv_id += NGBE_B2BT(tc);

	/* Delay value is calculated in bit times convert to KB */
	kb = NGBE_BT2KB(dv_id);
	rx_pba = rd32(hw, NGBE_RDB_PB_SZ)
			>> NGBE_RDB_PB_SZ_SHIFT;

	marker = rx_pba - kb;

	/* It is possible that the packet buffer is not large enough
	 * to provide required headroom. In this case throw an error
	 * to user and a do the best we can.
	 */
	if (marker < 0) {
		e_warn(drv, "Packet Buffer can not provide enough headroom to support flow control\n");
		marker = tc + 1;
	}

	return marker;
}

/**
 * ngbe_lpbthresh - calculate low water mark for flow control
 * @adapter: board private structure to calculate for
 * @pb - packet buffer to calculate
 **/
static int ngbe_lpbthresh(struct ngbe_adapter *adapter)
{
	struct net_device *dev = adapter->netdev;
	int tc;
	u32 dv_id;

	/* Calculate max LAN frame size */
	tc = dev->mtu + ETH_HLEN + ETH_FCS_LEN;

	/* Calculate delay value for device */
	dv_id = NGBE_LOW_DV(tc);

	/* Delay value is calculated in bit times convert to KB */
	return NGBE_BT2KB(dv_id);
}

/**
 * ngbe_pbthresh_setup - calculate and setup high low water marks
 **/
static void ngbe_pbthresh_setup(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;
	int num_tc = 0;//netdev_get_num_tc(adapter->netdev);

	if (!num_tc)
		num_tc = 1;

	hw->fc.high_water = ngbe_hpbthresh(adapter);
	hw->fc.low_water = ngbe_lpbthresh(adapter);

	/* Low water marks must not be larger than high water marks */
	if (hw->fc.low_water > hw->fc.high_water)
		hw->fc.low_water = 0;
}

static void ngbe_configure_pb(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;
	int hdrm = 0;
	int tc = 0;//netdev_get_num_tc(adapter->netdev);

	TCALL(hw, mac.ops.setup_rxpba, tc, hdrm, PBA_STRATEGY_EQUAL);
	ngbe_pbthresh_setup(adapter);
}

void ngbe_configure_port(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;
	u32 value, i;

	value = NGBE_CFG_PORT_CTL_NUM_VT_NONE;

	/* enable double vlan and qinq, NONE VT at default */
	value |= NGBE_CFG_PORT_CTL_D_VLAN |
			NGBE_CFG_PORT_CTL_QINQ;
	wr32m(hw, NGBE_CFG_PORT_CTL,
	      NGBE_CFG_PORT_CTL_D_VLAN |
		NGBE_CFG_PORT_CTL_QINQ |
		NGBE_CFG_PORT_CTL_NUM_VT_MASK,
		value);

	wr32(hw, NGBE_CFG_TAG_TPID(0),
	     ETH_P_8021Q | ETH_P_8021AD << 16);
	adapter->hw.tpid[0] = ETH_P_8021Q;
	adapter->hw.tpid[1] = ETH_P_8021AD;
	for (i = 1; i < 4; i++)
		wr32(hw, NGBE_CFG_TAG_TPID(i),
		     ETH_P_8021Q | ETH_P_8021Q << 16);
	for (i = 2; i < 8; i++)
		adapter->hw.tpid[i] = ETH_P_8021Q;
}

int ngbe_del_mac_filter(struct ngbe_adapter *adapter, u8 *addr, u16 pool)
{
	/* search table for addr, if found, set to 0 and sync */
	u32 i;
	struct ngbe_hw *hw = &adapter->hw;

	if (is_zero_ether_addr(addr))
		return -EINVAL;

	for (i = 0; i < hw->mac.num_rar_entries; i++) {
		if (ether_addr_equal(addr, adapter->mac_table[i].addr) &&
		    adapter->mac_table[i].pools | (1ULL << pool)) {
			adapter->mac_table[i].state |= NGBE_MAC_STATE_MODIFIED;
			adapter->mac_table[i].state &= ~NGBE_MAC_STATE_IN_USE;
			memset(adapter->mac_table[i].addr, 0, ETH_ALEN);
			adapter->mac_table[i].pools = 0;
			ngbe_sync_mac_table(adapter);
			return 0;
		}
	}
	return -ENOMEM;
}

int ngbe_add_mac_filter(struct ngbe_adapter *adapter, u8 *addr, u16 pool)
{
	struct ngbe_hw *hw = &adapter->hw;
	u32 i;

	if (is_zero_ether_addr(addr))
		return -EINVAL;

	for (i = 0; i < hw->mac.num_rar_entries; i++) {
		if (adapter->mac_table[i].state & NGBE_MAC_STATE_IN_USE)
			continue;

		adapter->mac_table[i].state |= (NGBE_MAC_STATE_MODIFIED |
						NGBE_MAC_STATE_IN_USE);
		memcpy(adapter->mac_table[i].addr, addr, ETH_ALEN);
		adapter->mac_table[i].pools = (1ULL << pool);
		ngbe_sync_mac_table(adapter);
		return i;
	}
	return -ENOMEM;
}

int ngbe_available_rars(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;
	u32 i, count = 0;

	for (i = 0; i < hw->mac.num_rar_entries; i++) {
		if (adapter->mac_table[i].state == 0)
			count++;
	}
	return count;
}

static u8 *ngbe_addr_list_itr(struct ngbe_hw __maybe_unused *hw,
			      u8 **mc_addr_ptr, u32 *vmdq)
{
	struct netdev_hw_addr *mc_ptr;
	u8 *addr = *mc_addr_ptr;

	*vmdq = 0;

	mc_ptr = container_of(addr, struct netdev_hw_addr, addr[0]);
	if (mc_ptr->list.next) {
		struct netdev_hw_addr *ha;

		ha = list_entry(mc_ptr->list.next, struct netdev_hw_addr, list);
		*mc_addr_ptr = ha->addr;
	} else {
		*mc_addr_ptr = NULL;
	}

	return addr;
}

/**
 * ngbe_write_uc_addr_list - write unicast addresses to RAR table
 * @netdev: network interface device structure
 * Returns: -ENOMEM on failure/insufficient address space
 **/
int ngbe_write_uc_addr_list(struct net_device *netdev, int pool)
{
	struct ngbe_adapter *adapter = netdev_priv(netdev);
	int count = 0;

	/* return ENOMEM indicating insufficient memory for addresses */
	if (netdev_uc_count(netdev) > ngbe_available_rars(adapter))
		return -ENOMEM;

	if (!netdev_uc_empty(netdev)) {
		struct netdev_hw_addr *ha;

		netdev_for_each_uc_addr(ha, netdev) {
			ngbe_del_mac_filter(adapter, ha->addr, pool);
			ngbe_add_mac_filter(adapter, ha->addr, pool);
			count++;
		}
	}
	return count;
}

/**
 * ngbe_write_mc_addr_list - write multicast addresses to MTA
 * @netdev: network interface device structure
 * Returns: -ENOMEM on failure
 **/
int ngbe_write_mc_addr_list(struct net_device *netdev)
{
	struct ngbe_adapter *adapter = netdev_priv(netdev);
	struct ngbe_hw *hw = &adapter->hw;
	struct netdev_hw_addr *ha;

	u8 *addr_list = NULL;
	int addr_count = 0;

	if (!hw->mac.ops.update_mc_addr_list)
		return -ENOMEM;

	if (!netif_running(netdev))
		return 0;

	if (netdev_mc_empty(netdev)) {
		TCALL(hw, mac.ops.update_mc_addr_list, NULL, 0,
		      ngbe_addr_list_itr, true);
	} else {
		ha = list_first_entry(&netdev->mc.list,
				      struct netdev_hw_addr, list);
		addr_list = ha->addr;
		addr_count = netdev_mc_count(netdev);

		TCALL(hw, mac.ops.update_mc_addr_list, addr_list, addr_count,
		      ngbe_addr_list_itr, true);
	}

	return addr_count;
}

/**
 * ngbe_vlan_strip_enable - helper to enable vlan tag stripping
 * @adapter: driver data
 */
void ngbe_vlan_strip_enable(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;
	int i, j;

	for (i = 0; i < adapter->num_rx_queues; i++) {
		struct ngbe_ring *ring = adapter->rx_ring[i];

		if (ring->accel)
			continue;
		j = ring->reg_idx;
		wr32m(hw, NGBE_PX_RR_CFG(j),
		      NGBE_PX_RR_CFG_VLAN, NGBE_PX_RR_CFG_VLAN);
	}
}

/**
 * ngbe_vlan_strip_disable - helper to disable vlan tag stripping
 * @adapter: driver data
 */
void ngbe_vlan_strip_disable(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;
	int i, j;

	for (i = 0; i < adapter->num_rx_queues; i++) {
		struct ngbe_ring *ring = adapter->rx_ring[i];

		if (ring->accel)
			continue;
		j = ring->reg_idx;
		wr32m(hw, NGBE_PX_RR_CFG(j), NGBE_PX_RR_CFG_VLAN, 0);
	}
}

/**
 * ngbe_set_rx_mode - Unicast, Multicast and Promiscuous mode set
 * @netdev: network interface device structure
 **/
void ngbe_set_rx_mode(struct net_device *netdev)
{
	struct ngbe_adapter *adapter = netdev_priv(netdev);
	struct ngbe_hw *hw = &adapter->hw;
	u32 fctrl, vmolr, vlnctrl;
	int count;

	/* Check for Promiscuous and All Multicast modes */
	fctrl = rd32m(hw, NGBE_PSR_CTL,
		      ~(NGBE_PSR_CTL_UPE | NGBE_PSR_CTL_MPE));
	vmolr = rd32m(hw, NGBE_PSR_VM_L2CTL(0),
		      ~(NGBE_PSR_VM_L2CTL_UPE |
			  NGBE_PSR_VM_L2CTL_MPE |
			  NGBE_PSR_VM_L2CTL_ROPE |
			  NGBE_PSR_VM_L2CTL_ROMPE));
	vlnctrl = rd32m(hw, NGBE_PSR_VLAN_CTL,
			~(NGBE_PSR_VLAN_CTL_VFE |
			  NGBE_PSR_VLAN_CTL_CFIEN));

	/* set all bits that we expect to always be set */
	fctrl |= NGBE_PSR_CTL_BAM | NGBE_PSR_CTL_MFE;
	vmolr |= NGBE_PSR_VM_L2CTL_BAM |
		 NGBE_PSR_VM_L2CTL_AUPE |
		 NGBE_PSR_VM_L2CTL_VACC;

	vlnctrl |= NGBE_PSR_VLAN_CTL_VFE;

	hw->addr_ctrl.user_set_promisc = false;
	if (netdev->flags & IFF_PROMISC) {
		hw->addr_ctrl.user_set_promisc = true;
		fctrl |= (NGBE_PSR_CTL_UPE | NGBE_PSR_CTL_MPE);
		/* pf don't want packets routing to vf, so clear UPE */
		vmolr |= NGBE_PSR_VM_L2CTL_MPE;
		vlnctrl &= ~NGBE_PSR_VLAN_CTL_VFE;
	}

	if (netdev->flags & IFF_ALLMULTI) {
		fctrl |= NGBE_PSR_CTL_MPE;
		vmolr |= NGBE_PSR_VM_L2CTL_MPE;
	}

	/* This is useful for sniffing bad packets. */
	if (netdev->features & NETIF_F_RXALL) {
		vmolr |= (NGBE_PSR_VM_L2CTL_UPE | NGBE_PSR_VM_L2CTL_MPE);
		vlnctrl &= ~NGBE_PSR_VLAN_CTL_VFE;
		/* receive bad packets */
		wr32m(hw, NGBE_RSEC_CTL,
		      NGBE_RSEC_CTL_SAVE_MAC_ERR,
			NGBE_RSEC_CTL_SAVE_MAC_ERR);
	} else {
		vmolr |= NGBE_PSR_VM_L2CTL_ROPE | NGBE_PSR_VM_L2CTL_ROMPE;
	}

	/* Write addresses to available RAR registers, if there is not
	 * sufficient space to store all the addresses then enable
	 * unicast promiscuous mode
	 */
	count = ngbe_write_uc_addr_list(netdev, 0);
	if (count < 0) {
		vmolr &= ~NGBE_PSR_VM_L2CTL_ROPE;
		vmolr |= NGBE_PSR_VM_L2CTL_UPE;
	}

	/* Write addresses to the MTA, if the attempt fails
	 * then we should just turn on promiscuous mode so
	 * that we can at least receive multicast traffic
	 */
	count = ngbe_write_mc_addr_list(netdev);
	if (count < 0) {
		vmolr &= ~NGBE_PSR_VM_L2CTL_ROMPE;
		vmolr |= NGBE_PSR_VM_L2CTL_MPE;
	}

	wr32(hw, NGBE_PSR_VLAN_CTL, vlnctrl);
	wr32(hw, NGBE_PSR_CTL, fctrl);
	wr32(hw, NGBE_PSR_VM_L2CTL(0), vmolr);

	if ((netdev->features & NETIF_F_HW_VLAN_CTAG_RX) &&
	    (netdev->features & NETIF_F_HW_VLAN_STAG_RX))
		ngbe_vlan_strip_enable(adapter);
	else
		ngbe_vlan_strip_disable(adapter);
}

void ngbe_vlan_mode(struct net_device *netdev, u32 features)
{
	struct ngbe_adapter *adapter = netdev_priv(netdev);
	bool enable;

	enable = !!(features & (NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_STAG_RX));

	if (enable)
		/* enable VLAN tag insert/strip */
		ngbe_vlan_strip_enable(adapter);
	else
		/* disable VLAN tag insert/strip */
		ngbe_vlan_strip_disable(adapter);
}

static int ngbe_vlan_rx_add_vid(struct net_device *netdev,
				__always_unused __be16 proto, u16 vid)
{
	struct ngbe_adapter *adapter = netdev_priv(netdev);
	struct ngbe_hw *hw = &adapter->hw;

	/* add VID to filter table */
	if (hw->mac.ops.set_vfta) {
		if (vid < VLAN_N_VID)
			set_bit(vid, adapter->active_vlans);
		TCALL(hw, mac.ops.set_vfta, vid, 0, true);
	}

	return 0;
}

static void ngbe_restore_vlan(struct ngbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	u16 vid;

	ngbe_vlan_mode(netdev, netdev->features);

	for_each_set_bit(vid, adapter->active_vlans, VLAN_N_VID)
		ngbe_vlan_rx_add_vid(netdev, htons(ETH_P_8021Q), vid);
}

/**
 * ngbe_configure_tx_ring - Configure Tx ring after Reset
 * @adapter: board private structure
 * @ring: structure containing ring specific data
 *
 * Configure the Tx descriptor ring after a reset.
 **/
void ngbe_configure_tx_ring(struct ngbe_adapter *adapter,
			    struct ngbe_ring *ring)
{
	struct ngbe_hw *hw = &adapter->hw;
	u64 tdba = ring->dma;
	int wait_loop = 10;
	u32 txdctl = NGBE_PX_TR_CFG_ENABLE;
	u8 reg_idx = ring->reg_idx;

	/* disable queue to avoid issues while updating state */
	wr32(hw, NGBE_PX_TR_CFG(reg_idx), NGBE_PX_TR_CFG_SWFLSH);
	NGBE_WRITE_FLUSH(hw);

	wr32(hw, NGBE_PX_TR_BAL(reg_idx), tdba & DMA_BIT_MASK(32));
	wr32(hw, NGBE_PX_TR_BAH(reg_idx), tdba >> 32);

	/* reset head and tail pointers */
	wr32(hw, NGBE_PX_TR_RP(reg_idx), 0);
	wr32(hw, NGBE_PX_TR_WP(reg_idx), 0);
	ring->tail = adapter->io_addr + NGBE_PX_TR_WP(reg_idx);

	/* reset ntu and ntc to place SW in sync with hardwdare */
	ring->next_to_clean = 0;
	ring->next_to_use = 0;

	txdctl |= NGBE_RING_SIZE(ring) << NGBE_PX_TR_CFG_TR_SIZE_SHIFT;

	/* set WTHRESH to encourage burst writeback, it should not be set
	 * higher than 1 when:
	 * - ITR is 0 as it could cause false TX hangs
	 * - ITR is set to > 100k int/sec and BQL is enabled
	 *
	 * In order to avoid issues WTHRESH + PTHRESH should always be equal
	 * to or less than the number of on chip descriptors, which is
	 * currently 40.
	 */
	txdctl |= 0x20 << NGBE_PX_TR_CFG_WTHRESH_SHIFT;

	clear_bit(__NGBE_HANG_CHECK_ARMED, &ring->state);

	/* enable queue */
	wr32(hw, NGBE_PX_TR_CFG(reg_idx), txdctl);

	/* poll to verify queue is enabled */
	do {
		mdelay(1);
		txdctl = rd32(hw, NGBE_PX_TR_CFG(reg_idx));
	} while (--wait_loop && !(txdctl & NGBE_PX_TR_CFG_ENABLE));
	if (!wait_loop)
		e_err(drv, "Could not enable Tx Queue %d\n", reg_idx);
}

/**
 * ngbe_configure_tx - Configure Transmit Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Tx unit of the MAC after a reset.
 **/
static void ngbe_configure_tx(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;
	u32 i;

	/* TDM_CTL.TE must be before Tx queues are enabled */
	wr32m(hw, NGBE_TDM_CTL,
	      NGBE_TDM_CTL_TE, NGBE_TDM_CTL_TE);

	/* Setup the HW Tx Head and Tail descriptor pointers */
	for (i = 0; i < adapter->num_tx_queues; i++)
		ngbe_configure_tx_ring(adapter, adapter->tx_ring[i]);

	wr32m(hw, NGBE_TSEC_BUF_AE, 0x3FF, 0x10);
	wr32m(hw, NGBE_TSEC_CTL, 0x2, 0);

	wr32m(hw, NGBE_TSEC_CTL, 0x1, 1);

	/* enable mac transmitter */
	wr32m(hw, NGBE_MAC_TX_CFG,
	      NGBE_MAC_TX_CFG_TE, NGBE_MAC_TX_CFG_TE);
}

static void ngbe_setup_psrtype(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;
	int pool;

	/* PSRTYPE must be initialized in adapters */
	u32 psrtype = NGBE_RDB_PL_CFG_L4HDR |
				NGBE_RDB_PL_CFG_L3HDR |
				NGBE_RDB_PL_CFG_L2HDR |
				NGBE_RDB_PL_CFG_TUN_OUTER_L2HDR |
				NGBE_RDB_PL_CFG_TUN_TUNHDR;

	for_each_set_bit(pool, &adapter->fwd_bitmask, NGBE_MAX_MACVLANS) {
		wr32(hw, NGBE_RDB_PL_CFG(0), psrtype);
	}
}

/**
 * Return a number of entries in the RSS indirection table
 * @adapter: device handle
 */
u32 ngbe_rss_indir_tbl_entries(struct ngbe_adapter *adapter)
{
	if (adapter->flags & NGBE_FLAG_SRIOV_ENABLED)
		return 64;
	else
		return 128;
}

/**
 * Write the RETA table to HW
 * @adapter: device handle
 * Write the RSS redirection table stored in adapter.rss_indir_tbl[] to HW.
 */
void ngbe_store_reta(struct ngbe_adapter *adapter)
{
	u32 i, reta_entries = ngbe_rss_indir_tbl_entries(adapter);
	struct ngbe_hw *hw = &adapter->hw;
	u32 reta = 0;
	u8 *indir_tbl = adapter->rss_indir_tbl;

	/* Fill out the redirection table as follows:
	 *  - 8 bit wide entries containing 4 bit RSS index
	 */

	/* Write redirection table to HW */
	for (i = 0; i < reta_entries; i++) {
		reta |= indir_tbl[i] << (i & 0x3) * 8;
		if ((i & 3) == 3) {
			wr32(hw, NGBE_RDB_RSSTBL(i >> 2), reta);
			reta = 0;
		}
	}
}

/**
 * ngbe_setup_tc - routine to configure net_device for multiple traffic
 * classes.
 *
 * @netdev: net device to configure
 * @tc: number of traffic classes to enable
 */
int ngbe_setup_tc(struct net_device *dev, u8 tc)
{
	struct ngbe_adapter *adapter = netdev_priv(dev);

	/* Hardware has to reinitialize queues and interrupts to
	 * match packet buffer alignment. Unfortunately, the
	 * hardware is not flexible enough to do this dynamically.
	 */
	if (netif_running(dev))
		ngbe_close(dev);
	else
		ngbe_reset(adapter);

	ngbe_clear_interrupt_scheme(adapter);

	if (tc)
		netdev_set_num_tc(dev, tc);
	else
		netdev_reset_tc(dev);

	ngbe_init_interrupt_scheme(adapter);
	if (netif_running(dev))
		ngbe_open(dev);

	return 0;
}

static void ngbe_setup_reta(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;
	u32 i, j;
	u32 reta_entries = ngbe_rss_indir_tbl_entries(adapter);
	u16 rss_i = adapter->ring_feature[RING_F_RSS].indices;

	/* Program table for at least 2 queues w/ SR-IOV so that VFs can
	 * make full use of any rings they may have.  We will use the
	 * PSRTYPE register to control how many rings we use within the PF.
	 */
	if ((adapter->flags & NGBE_FLAG_SRIOV_ENABLED) && rss_i < 2)
		rss_i = 1;

	/* Fill out hash function seeds */
	for (i = 0; i < 10; i++)
		wr32(hw, NGBE_RDB_RSSRK(i), adapter->rss_key[i]);

	/* Fill out redirection table */
	memset(adapter->rss_indir_tbl, 0, sizeof(adapter->rss_indir_tbl));

	for (i = 0, j = 0; i < reta_entries; i++, j++) {
		if (j == rss_i)
			j = 0;

		adapter->rss_indir_tbl[i] = j;
	}

	ngbe_store_reta(adapter);
}

static void ngbe_setup_mrqc(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;
	u32 rss_field = 0;

	/* Disable indicating checksum in descriptor, enables RSS hash */
	wr32m(hw, NGBE_PSR_CTL,
	      NGBE_PSR_CTL_PCSD, NGBE_PSR_CTL_PCSD);

	/* Perform hash on these packet types */
	rss_field = NGBE_RDB_RA_CTL_RSS_IPV4 |
		    NGBE_RDB_RA_CTL_RSS_IPV4_TCP |
		    NGBE_RDB_RA_CTL_RSS_IPV6 |
		    NGBE_RDB_RA_CTL_RSS_IPV6_TCP;

	if (adapter->flags2 & NGBE_FLAG2_RSS_FIELD_IPV4_UDP)
		rss_field |= NGBE_RDB_RA_CTL_RSS_IPV4_UDP;
	if (adapter->flags2 & NGBE_FLAG2_RSS_FIELD_IPV6_UDP)
		rss_field |= NGBE_RDB_RA_CTL_RSS_IPV6_UDP;

	netdev_rss_key_fill(adapter->rss_key, sizeof(adapter->rss_key));

	ngbe_setup_reta(adapter);

	if (adapter->flags2 & NGBE_FLAG2_RSS_ENABLED)
		rss_field |= NGBE_RDB_RA_CTL_RSS_EN;
	wr32(hw, NGBE_RDB_RA_CTL, rss_field);
}

static void ngbe_set_rx_buffer_len(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	u32 max_frame = netdev->mtu + ETH_HLEN + ETH_FCS_LEN;
	struct ngbe_ring *rx_ring;
	int i;
	u32 mhadd;

	/* adjust max frame to be at least the size of a standard frame */
	if (max_frame < (ETH_FRAME_LEN + ETH_FCS_LEN))
		max_frame = (ETH_FRAME_LEN + ETH_FCS_LEN);

	mhadd = rd32(hw, NGBE_PSR_MAX_SZ);
	if (max_frame != mhadd)
		wr32(hw, NGBE_PSR_MAX_SZ, max_frame);

	/* Setup the HW Rx Head and Tail Descriptor Pointers and
	 * the Base and Length of the Rx Descriptor Ring
	 */
	for (i = 0; i < adapter->num_rx_queues; i++) {
		rx_ring = adapter->rx_ring[i];

		if (adapter->flags & NGBE_FLAG_RX_HS_ENABLED) {
			rx_ring->rx_buf_len = NGBE_RX_HDR_SIZE;
			set_ring_hs_enabled(rx_ring);
		} else {
			clear_ring_hs_enabled(rx_ring);
		}
	}
}

static void ngbe_configure_srrctl(struct ngbe_adapter *adapter,
				  struct ngbe_ring *rx_ring)
{
	struct ngbe_hw *hw = &adapter->hw;
	u32 srrctl;
	u16 reg_idx = rx_ring->reg_idx;

	srrctl = rd32m(hw, NGBE_PX_RR_CFG(reg_idx),
		       ~(NGBE_PX_RR_CFG_RR_HDR_SZ |
			  NGBE_PX_RR_CFG_RR_BUF_SZ |
			  NGBE_PX_RR_CFG_SPLIT_MODE));

	/* configure header buffer length, needed for RSC */
	srrctl |= NGBE_RX_HDR_SIZE << NGBE_PX_RR_CFG_BSIZEHDRSIZE_SHIFT;

	/* configure the packet buffer length */
	srrctl |= ngbe_rx_bufsz(rx_ring) >> NGBE_PX_RR_CFG_BSIZEPKT_SHIFT;
	if (ring_is_hs_enabled(rx_ring))
		srrctl |= NGBE_PX_RR_CFG_SPLIT_MODE;

	wr32(hw, NGBE_PX_RR_CFG(reg_idx), srrctl);
}

static void ngbe_rx_desc_queue_enable(struct ngbe_adapter *adapter,
				      struct ngbe_ring *ring)
{
	struct ngbe_hw *hw = &adapter->hw;
	int wait_loop = NGBE_MAX_RX_DESC_POLL;
	u32 rxdctl;
	u8 reg_idx = ring->reg_idx;

	if (NGBE_REMOVED(hw->hw_addr))
		return;

	do {
		mdelay(1);
		rxdctl = rd32(hw, NGBE_PX_RR_CFG(reg_idx));
	} while (--wait_loop && !(rxdctl & NGBE_PX_RR_CFG_RR_EN));

	if (!wait_loop)
		e_err(drv, "RXDCTL.ENABLE on Rx queue %d not set within the polling period\n",
		      reg_idx);
}

static bool ngbe_alloc_mapped_skb(struct ngbe_ring *rx_ring,
				  struct ngbe_rx_buffer *bi)
{
	struct sk_buff *skb = bi->skb;
	dma_addr_t dma = bi->dma;

	if (unlikely(dma))
		return true;

	if (likely(!skb)) {
		skb = netdev_alloc_skb_ip_align(rx_ring->netdev,
						rx_ring->rx_buf_len);
		if (unlikely(!skb)) {
			rx_ring->rx_stats.alloc_rx_buff_failed++;
			return false;
		}
		bi->skb = skb;
	}

	dma = dma_map_single(rx_ring->dev, skb->data,
			     rx_ring->rx_buf_len, DMA_FROM_DEVICE);

	/* if mapping failed free memory back to system since
	 * there isn't much point in holding memory we can't use
	 */
	if (dma_mapping_error(rx_ring->dev, dma)) {
		dev_kfree_skb_any(skb);
		bi->skb = NULL;

		rx_ring->rx_stats.alloc_rx_buff_failed++;
		return false;
	}

	bi->dma = dma;
	return true;
}

static bool ngbe_alloc_mapped_page(struct ngbe_ring *rx_ring,
				   struct ngbe_rx_buffer *bi)
{
	struct page *page = bi->page;
	dma_addr_t dma;

	/* since we are recycling buffers we should seldom need to alloc */
	if (likely(page))
		return true;

	/* alloc new page for storage */
	page = dev_alloc_pages(ngbe_rx_pg_order(rx_ring));
	if (unlikely(!page)) {
		rx_ring->rx_stats.alloc_rx_page_failed++;
		return false;
	}

	/* map page for use */
	dma = dma_map_page(rx_ring->dev, page, 0,
			   ngbe_rx_pg_size(rx_ring), DMA_FROM_DEVICE);

	/* if mapping failed free memory back to system since
	 * there isn't much point in holding memory we can't use
	 */
	if (dma_mapping_error(rx_ring->dev, dma)) {
		__free_pages(page, ngbe_rx_pg_order(rx_ring));

		rx_ring->rx_stats.alloc_rx_page_failed++;
		return false;
	}

	bi->page_dma = dma;
	bi->page = page;
	bi->page_offset = 0;

	return true;
}

/**
 * ngbe_alloc_rx_buffers - Replace used receive buffers
 * @rx_ring: ring to place buffers on
 * @cleaned_count: number of buffers to replace
 **/
void ngbe_alloc_rx_buffers(struct ngbe_ring *rx_ring, u16 cleaned_count)
{
	union ngbe_rx_desc *rx_desc;
	struct ngbe_rx_buffer *bi;
	u16 i = rx_ring->next_to_use;

	/* nothing to do */
	if (!cleaned_count)
		return;

	rx_desc = NGBE_RX_DESC(rx_ring, i);
	bi = &rx_ring->rx_buffer_info[i];
	i -= rx_ring->count;

	do {
		if (ring_is_hs_enabled(rx_ring)) {
			if (!ngbe_alloc_mapped_skb(rx_ring, bi))
				break;
			rx_desc->read.hdr_addr = cpu_to_le64(bi->dma);
		}

		if (!ngbe_alloc_mapped_page(rx_ring, bi))
			break;
		rx_desc->read.pkt_addr = cpu_to_le64(bi->page_dma + bi->page_offset);

		rx_desc++;
		bi++;
		i++;
		if (unlikely(!i)) {
			rx_desc = NGBE_RX_DESC(rx_ring, 0);
			bi = rx_ring->rx_buffer_info;
			i -= rx_ring->count;
		}

		/* clear the status bits for the next_to_use descriptor */
		rx_desc->wb.upper.status_error = 0;

		cleaned_count--;
	} while (cleaned_count);

	i += rx_ring->count;

	if (rx_ring->next_to_use != i) {
		rx_ring->next_to_use = i;
		/* update next to alloc since we have filled the ring */
		rx_ring->next_to_alloc = i;
		/* Force memory writes to complete before letting h/w
		 * know there are new descriptors to fetch.	(Only
		 * applicable for weak-ordered memory model archs,
		 * such as IA-64).
		 */
		wmb();
		writel(i, rx_ring->tail);
	}
}

void ngbe_configure_rx_ring(struct ngbe_adapter *adapter,
			    struct ngbe_ring *ring)
{
	struct ngbe_hw *hw = &adapter->hw;
	u64 rdba = ring->dma;
	u32 rxdctl;
	u16 reg_idx = ring->reg_idx;

	/* disable queue to avoid issues while updating state */
	rxdctl = rd32(hw, NGBE_PX_RR_CFG(reg_idx));
	ngbe_disable_rx_queue(adapter, ring);

	wr32(hw, NGBE_PX_RR_BAL(reg_idx), rdba & DMA_BIT_MASK(32));
	wr32(hw, NGBE_PX_RR_BAH(reg_idx), rdba >> 32);

	if (ring->count == NGBE_MAX_RXD)
		rxdctl |= 0 << NGBE_PX_RR_CFG_RR_SIZE_SHIFT;
	else
		rxdctl |= (ring->count / 128) << NGBE_PX_RR_CFG_RR_SIZE_SHIFT;

	rxdctl |= 0x1 << NGBE_PX_RR_CFG_RR_THER_SHIFT;
	wr32(hw, NGBE_PX_RR_CFG(reg_idx), rxdctl);

	/* reset head and tail pointers */
	wr32(hw, NGBE_PX_RR_RP(reg_idx), 0);
	wr32(hw, NGBE_PX_RR_WP(reg_idx), 0);
	ring->tail = adapter->io_addr + NGBE_PX_RR_WP(reg_idx);

	/* reset ntu and ntc to place SW in sync with hardwdare */
	ring->next_to_clean = 0;
	ring->next_to_use = 0;
	ring->next_to_alloc = 0;

	ngbe_configure_srrctl(adapter, ring);

	/* enable receive descriptor ring */
	wr32m(hw, NGBE_PX_RR_CFG(reg_idx),
	      NGBE_PX_RR_CFG_RR_EN, NGBE_PX_RR_CFG_RR_EN);

	ngbe_rx_desc_queue_enable(adapter, ring);
	ngbe_alloc_rx_buffers(ring, ngbe_desc_unused(ring));
}

void ngbe_unmap_and_free_tx_resource(struct ngbe_ring *ring,
				     struct ngbe_tx_buffer *tx_buffer)
{
	if (tx_buffer->skb) {
		dev_kfree_skb_any(tx_buffer->skb);
		if (dma_unmap_len(tx_buffer, len))
			dma_unmap_single(ring->dev,
					 dma_unmap_addr(tx_buffer, dma),
					 dma_unmap_len(tx_buffer, len),
					 DMA_TO_DEVICE);
	} else if (dma_unmap_len(tx_buffer, len)) {
		dma_unmap_page(ring->dev,
			       dma_unmap_addr(tx_buffer, dma),
						dma_unmap_len(tx_buffer, len),
						DMA_TO_DEVICE);
	}
	tx_buffer->next_to_watch = NULL;
	tx_buffer->skb = NULL;
	dma_unmap_len_set(tx_buffer, len, 0);
	/* tx_buffer must be completely set up in the transmit path */
}

void ngbe_configure_isb(struct ngbe_adapter *adapter)
{
	/* set ISB Address */
	struct ngbe_hw *hw = &adapter->hw;

	wr32(hw, NGBE_PX_ISB_ADDR_L,
	     adapter->isb_dma & DMA_BIT_MASK(32));
	wr32(hw, NGBE_PX_ISB_ADDR_H, adapter->isb_dma >> 32);
}

/**
 * ngbe_configure_rx - Configure Receive Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Rx unit of the MAC after a reset.
 **/
static void ngbe_configure_rx(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;
	int i;
	u32 rxctrl;

	/* disable receives while setting up the descriptors */
	TCALL(hw, mac.ops.disable_rx);

	ngbe_setup_psrtype(adapter);

	/* enable hw crc stripping */
	wr32m(hw, NGBE_RSEC_CTL,
	      NGBE_RSEC_CTL_CRC_STRIP, NGBE_RSEC_CTL_CRC_STRIP);

	/* Program registers for the distribution of queues */
	ngbe_setup_mrqc(adapter);

	/* set_rx_buffer_len must be called before ring initialization */
	ngbe_set_rx_buffer_len(adapter);

	/* Setup the HW Rx Head and Tail Descriptor Pointers and
	 * the Base and Length of the Rx Descriptor Ring
	 */
	for (i = 0; i < adapter->num_rx_queues; i++)
		ngbe_configure_rx_ring(adapter, adapter->rx_ring[i]);

	rxctrl = rd32(hw, NGBE_RDB_PB_CTL);

	/* enable all receives */
	rxctrl |= NGBE_RDB_PB_CTL_PBEN;
	TCALL(hw, mac.ops.enable_rx_dma, rxctrl);
}

static void ngbe_configure(struct ngbe_adapter *adapter)
{
	ngbe_configure_pb(adapter);

	/* configure Double Vlan */
	ngbe_configure_port(adapter);

	ngbe_set_rx_mode(adapter->netdev);
	ngbe_restore_vlan(adapter);

	ngbe_configure_tx(adapter);
	ngbe_configure_rx(adapter);
	ngbe_configure_isb(adapter);
}

void ngbe_up(struct ngbe_adapter *adapter)
{
	/* hardware has been reset, we need to reload some things */
	ngbe_configure(adapter);

	ngbe_up_complete(adapter);
}

void ngbe_reinit_locked(struct ngbe_adapter *adapter)
{
	WARN_ON(in_interrupt());
	/* put off any impending NetWatchDogTimeout */

	netif_trans_update(adapter->netdev);
	while (test_and_set_bit(__NGBE_RESETTING, &adapter->state))
		usleep_range(1000, 2000);
	ngbe_down(adapter);
	/* If SR-IOV enabled then wait a bit before bringing the adapter
	 * back up to give the VFs time to respond to the reset.  The
	 * two second wait is based upon the watchdog timer cycle in
	 * the VF driver.
	 */
	if (adapter->flags & NGBE_FLAG_SRIOV_ENABLED)
		msleep(2000);
	ngbe_up(adapter);
	clear_bit(__NGBE_RESETTING, &adapter->state);
}

/**
 * ngbe_reset_hostif - send reset cmd to fw
 * @hw: pointer to hardware structure
 **/
s32 ngbe_reset_hostif(struct ngbe_hw *hw)
{
	struct ngbe_hic_reset reset_cmd;
	int i;
	s32 status = 0;

	reset_cmd.hdr.cmd = FW_RESET_CMD;
	reset_cmd.hdr.buf_len = FW_RESET_LEN;
	reset_cmd.hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;
	reset_cmd.lan_id = hw->bus.lan_id;
	reset_cmd.reset_type = (u16)hw->reset_type;
	reset_cmd.hdr.checksum = 0;
	reset_cmd.hdr.checksum = ngbe_calculate_checksum((u8 *)&reset_cmd,
							 (FW_CEM_HDR_LEN + reset_cmd.hdr.buf_len));

	/* send reset request to FW and wait for response */
	for (i = 0; i <= FW_CEM_MAX_RETRIES; i++) {
		status = ngbe_host_if_command(hw, (u32 *)&reset_cmd,
					      sizeof(reset_cmd),
						       NGBE_HI_CMD_TIMEOUT,
						       true);
		mdelay(1);
		if (status != 0)
			continue;

		if (reset_cmd.hdr.cmd_or_resp.ret_status ==
			FW_CEM_RESP_STATUS_SUCCESS)
			status = 0;
		else
			status = NGBE_ERR_HOST_INTERFACE_COMMAND;

		break;
	}

	return status;
}

static void ngbe_reset_subtask(struct ngbe_adapter *adapter)
{
	u32 reset_flag = 0;
	u32 value = 0;

	if (!(adapter->flags2 & (NGBE_FLAG2_PF_RESET_REQUESTED |
		NGBE_FLAG2_DEV_RESET_REQUESTED |
		NGBE_FLAG2_GLOBAL_RESET_REQUESTED |
		NGBE_FLAG2_RESET_INTR_RECEIVED)))
		return;

	/* If we're already down, just bail */
	if (test_bit(__NGBE_DOWN, &adapter->state) ||
	    test_bit(__NGBE_REMOVING, &adapter->state))
		return;

	e_err(drv, "Reset adapter\n");
	adapter->tx_timeout_count++;

	rtnl_lock();
	if (adapter->flags2 & NGBE_FLAG2_GLOBAL_RESET_REQUESTED) {
		reset_flag |= NGBE_FLAG2_GLOBAL_RESET_REQUESTED;
		adapter->flags2 &= ~NGBE_FLAG2_GLOBAL_RESET_REQUESTED;
	}
	if (adapter->flags2 & NGBE_FLAG2_DEV_RESET_REQUESTED) {
		reset_flag |= NGBE_FLAG2_DEV_RESET_REQUESTED;
		adapter->flags2 &= ~NGBE_FLAG2_DEV_RESET_REQUESTED;
	}
	if (adapter->flags2 & NGBE_FLAG2_PF_RESET_REQUESTED) {
		reset_flag |= NGBE_FLAG2_PF_RESET_REQUESTED;
		adapter->flags2 &= ~NGBE_FLAG2_PF_RESET_REQUESTED;
	}

	if (adapter->flags2 & NGBE_FLAG2_RESET_INTR_RECEIVED) {
		/* If there's a recovery already waiting, it takes
		 * precedence before starting a new reset sequence.
		 */
		adapter->flags2 &= ~NGBE_FLAG2_RESET_INTR_RECEIVED;
		value = rd32m(&adapter->hw, NGBE_MIS_RST_ST,
			      NGBE_MIS_RST_ST_DEV_RST_TYPE_MASK) >>
				NGBE_MIS_RST_ST_DEV_RST_TYPE_SHIFT;

		if (value == NGBE_MIS_RST_ST_DEV_RST_TYPE_SW_RST)
			adapter->hw.reset_type = NGBE_SW_RESET;
		else if (value == NGBE_MIS_RST_ST_DEV_RST_TYPE_GLOBAL_RST)
			adapter->hw.reset_type = NGBE_GLOBAL_RESET;

		adapter->hw.force_full_reset = true;
		ngbe_reinit_locked(adapter);
		adapter->hw.force_full_reset = false;
		goto unlock;
	}

	if (reset_flag & NGBE_FLAG2_DEV_RESET_REQUESTED) {
		/* Request a Device Reset
		 * This will start the chip's countdown to the actual full
		 * chip reset event, and a warning interrupt to be sent
		 * to all PFs, including the requestor.  Our handler
		 * for the warning interrupt will deal with the shutdown
		 * and recovery of the switch setup.
		 */
		wr32m(&adapter->hw, NGBE_MIS_RST,
		      NGBE_MIS_RST_SW_RST, NGBE_MIS_RST_SW_RST);
		e_info(drv, "%s: sw reset\n", __func__);
	} else if (reset_flag & NGBE_FLAG2_PF_RESET_REQUESTED) {
		ngbe_reinit_locked(adapter);
	} else if (reset_flag & NGBE_FLAG2_GLOBAL_RESET_REQUESTED) {
		/* Request a Global Reset
		 *
		 * This will start the chip's countdown to the actual full
		 * chip reset event, and a warning interrupt to be sent
		 * to all PFs, including the requestor.  Our handler
		 * for the warning interrupt will deal with the shutdown
		 * and recovery of the switch setup.
		 */
		pci_save_state(adapter->pdev);
		if (ngbe_mng_present(&adapter->hw)) {
			ngbe_reset_hostif(&adapter->hw);
		e_err(drv, "%s: lan reset\n", __func__);

		} else {
			wr32m(&adapter->hw, NGBE_MIS_RST,
			      NGBE_MIS_RST_GLOBAL_RST,
				NGBE_MIS_RST_GLOBAL_RST);
			e_info(drv, "%s: global reset\n", __func__);
		}
	}

unlock:
	rtnl_unlock();
}

/**
 * ngbe_check_overtemp_subtask - check for over temperature
 * @adapter: pointer to adapter
 **/
static void ngbe_check_overtemp_subtask(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;
	u32 eicr = adapter->interrupt_event;
	s32 temp_state;

	if (test_bit(__NGBE_DOWN, &adapter->state))
		return;
	if (!(adapter->flags2 & NGBE_FLAG2_TEMP_SENSOR_CAPABLE))
		return;
	if (!(adapter->flags2 & NGBE_FLAG2_TEMP_SENSOR_EVENT))
		return;

	adapter->flags2 &= ~NGBE_FLAG2_TEMP_SENSOR_EVENT;

	/* Since the warning interrupt is for both ports
	 * we don't have to check if:
	 * This interrupt wasn't for our port.
	 * We may have missed the interrupt so always have to
	 * check if we  got a LSC
	 */
	if (!(eicr & NGBE_PX_MISC_IC_OVER_HEAT))
		return;

	temp_state = ngbe_phy_check_overtemp(hw);
	if (!temp_state || temp_state == NGBE_NOT_IMPLEMENTED)
		return;

	if (temp_state == NGBE_ERR_UNDERTEMP &&
	    test_bit(__NGBE_HANGING, &adapter->state)) {
		e_crit(drv, "%s\n", ngbe_underheat_msg);
		wr32m(&adapter->hw, NGBE_RDB_PB_CTL,
		      NGBE_RDB_PB_CTL_PBEN, NGBE_RDB_PB_CTL_PBEN);
		netif_carrier_on(adapter->netdev);

		clear_bit(__NGBE_HANGING, &adapter->state);
	} else if (temp_state == NGBE_ERR_OVERTEMP &&
		!test_and_set_bit(__NGBE_HANGING, &adapter->state)) {
		e_crit(drv, "%s\n", ngbe_overheat_msg);
		netif_carrier_off(adapter->netdev);

		wr32m(&adapter->hw, NGBE_RDB_PB_CTL,
		      NGBE_RDB_PB_CTL_PBEN, 0);
	}

	adapter->interrupt_event = 0;
}

static void ngbe_watchdog_an_complete(struct ngbe_adapter *adapter)
{
	u32 link_speed = 0;
	u32 lan_speed = 0;
	bool link_up = true;
	struct ngbe_hw *hw = &adapter->hw;

	if (!(adapter->flags & NGBE_FLAG_NEED_ANC_CHECK))
		return;

	TCALL(hw, mac.ops.check_link, &link_speed, &link_up, false);

	adapter->link_speed = link_speed;
	switch (link_speed) {
	case NGBE_LINK_SPEED_100_FULL:
		lan_speed = 1;
		break;
	case NGBE_LINK_SPEED_1GB_FULL:
		lan_speed = 2;
		break;
	case NGBE_LINK_SPEED_10_FULL:
		lan_speed = 0;
		break;
	default:
		break;
	}
	wr32m(hw, NGBE_CFG_LAN_SPEED,
	      0x3, lan_speed);

	if (link_speed & (NGBE_LINK_SPEED_1GB_FULL |
			NGBE_LINK_SPEED_100_FULL | NGBE_LINK_SPEED_10_FULL)) {
		wr32(hw, NGBE_MAC_TX_CFG,
		     (rd32(hw, NGBE_MAC_TX_CFG) &
			~NGBE_MAC_TX_CFG_SPEED_MASK) | NGBE_MAC_TX_CFG_TE |
			NGBE_MAC_TX_CFG_SPEED_1G);
	}

	adapter->flags &= ~NGBE_FLAG_NEED_ANC_CHECK;
	adapter->flags |= NGBE_FLAG_NEED_LINK_UPDATE;
}

static void ngbe_enable_rx_drop(struct ngbe_adapter *adapter,
				struct ngbe_ring *ring)
{
	struct ngbe_hw *hw = &adapter->hw;
	u16 reg_idx = ring->reg_idx;

	u32 srrctl = rd32(hw, NGBE_PX_RR_CFG(reg_idx));

	srrctl |= NGBE_PX_RR_CFG_DROP_EN;

	wr32(hw, NGBE_PX_RR_CFG(reg_idx), srrctl);
}

static void ngbe_disable_rx_drop(struct ngbe_adapter *adapter,
				 struct ngbe_ring *ring)
{
	struct ngbe_hw *hw = &adapter->hw;
	u16 reg_idx = ring->reg_idx;

	u32 srrctl = rd32(hw, NGBE_PX_RR_CFG(reg_idx));

	srrctl &= ~NGBE_PX_RR_CFG_DROP_EN;

	wr32(hw, NGBE_PX_RR_CFG(reg_idx), srrctl);
}

void ngbe_set_rx_drop_en(struct ngbe_adapter *adapter)
{
	int i;

	/* We should set the drop enable bit if:
	 * SR-IOV is enabled
	 * or
	 * Number of Rx queues > 1 and flow control is disabled
	 *
	 * This allows us to avoid head of line blocking for security
	 * and performance reasons.
	 */
	if (adapter->num_vfs || (adapter->num_rx_queues > 1 &&
				 !(adapter->hw.fc.current_mode & ngbe_fc_tx_pause))) {
		for (i = 0; i < adapter->num_rx_queues; i++)
			ngbe_enable_rx_drop(adapter, adapter->rx_ring[i]);
	} else {
		for (i = 0; i < adapter->num_rx_queues; i++)
			ngbe_disable_rx_drop(adapter, adapter->rx_ring[i]);
	}
}

/**
 * ngbe_watchdog_update_link - update the link status
 * @adapter - pointer to the device adapter structure
 * @link_speed - pointer to a u32 to store the link_speed
 **/
static void ngbe_watchdog_update_link_status(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;
	u32 link_speed = adapter->link_speed;
	bool link_up = adapter->link_up;
	u32 lan_speed = 0;
	u32 reg;

	if (!(adapter->flags & NGBE_FLAG_NEED_LINK_UPDATE))
		return;

	link_speed = NGBE_LINK_SPEED_1GB_FULL;
	link_up = true;

	TCALL(hw, mac.ops.check_link, &link_speed, &link_up, false);

	if (link_up || time_after(jiffies, (adapter->link_check_timeout +
		NGBE_TRY_LINK_TIMEOUT))) {
		adapter->flags &= ~NGBE_FLAG_NEED_LINK_UPDATE;
	}

	adapter->link_speed = link_speed;
	switch (link_speed) {
	case NGBE_LINK_SPEED_100_FULL:
		lan_speed = 1;
		break;
	case NGBE_LINK_SPEED_1GB_FULL:
		lan_speed = 2;
		break;
	case NGBE_LINK_SPEED_10_FULL:
		lan_speed = 0;
		break;
	default:
		break;
	}
	wr32m(hw, NGBE_CFG_LAN_SPEED, 0x3, lan_speed);

	if (link_up) {
		TCALL(hw, mac.ops.fc_enable);
		ngbe_set_rx_drop_en(adapter);
	}

	if (link_up) {
		adapter->last_rx_ptp_check = jiffies;

		if (test_bit(__NGBE_PTP_RUNNING, &adapter->state))
			ngbe_ptp_start_cyclecounter(adapter);

		if (link_speed & (NGBE_LINK_SPEED_1GB_FULL |
				NGBE_LINK_SPEED_100_FULL | NGBE_LINK_SPEED_10_FULL)) {
			wr32(hw, NGBE_MAC_TX_CFG,
			     (rd32(hw, NGBE_MAC_TX_CFG) &
				~NGBE_MAC_TX_CFG_SPEED_MASK) | NGBE_MAC_TX_CFG_TE |
				NGBE_MAC_TX_CFG_SPEED_1G);
		}

		/* Re configure MAC RX */
		reg = rd32(hw, NGBE_MAC_RX_CFG);
		wr32(hw, NGBE_MAC_RX_CFG, reg);
		wr32(hw, NGBE_MAC_PKT_FLT, NGBE_MAC_PKT_FLT_PR);
		reg = rd32(hw, NGBE_MAC_WDG_TIMEOUT);
		wr32(hw, NGBE_MAC_WDG_TIMEOUT, reg);
	}

	adapter->link_up = link_up;
}

static void ngbe_update_default_up(struct ngbe_adapter *adapter)
{
	u8 up = 0;

	adapter->default_up = up;
}

/**
 * ngbe_watchdog_link_is_up - update netif_carrier status and
 * print link up message
 * @adapter - pointer to the device adapter structure
 **/
static void ngbe_watchdog_link_is_up(struct ngbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct ngbe_hw *hw = &adapter->hw;
	u32 link_speed = adapter->link_speed;
	bool flow_rx, flow_tx;

	/* only continue if link was previously down */
	if (netif_carrier_ok(netdev))
		return;

	adapter->flags2 &= ~NGBE_FLAG2_SEARCH_FOR_SFP;

	/* flow_rx, flow_tx report link flow control status */
	flow_rx = (rd32(hw, NGBE_MAC_RX_FLOW_CTRL) & 0x101) == 0x1;
	flow_tx = !!(NGBE_RDB_RFCC_RFCE_802_3X &
				rd32(hw, NGBE_RDB_RFCC));

	e_info(drv, "NIC Link is Up %s, Flow Control: %s\n",
	       (link_speed == NGBE_LINK_SPEED_1GB_FULL ?
			"1 Gbps" :
			(link_speed == NGBE_LINK_SPEED_100_FULL ?
			"100 Mbps" :
			(link_speed == NGBE_LINK_SPEED_10_FULL ?
			"10 Mbps" :
			"unknown speed"))),
			((flow_rx && flow_tx) ? "RX/TX" :
			(flow_rx ? "RX" :
			(flow_tx ? "TX" : "None"))));

	netif_carrier_on(netdev);
	netif_tx_wake_all_queues(netdev);

	/* update the default user priority for VFs */
	ngbe_update_default_up(adapter);
}

/**
 * ngbe_watchdog_link_is_down - update netif_carrier status and
 *                               print link down message
 * @adapter - pointer to the adapter structure
 **/
static void ngbe_watchdog_link_is_down(struct ngbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	adapter->link_up = false;
	adapter->link_speed = 0;

	/* only continue if link was up previously */
	if (!netif_carrier_ok(netdev))
		return;

	if (test_bit(__NGBE_PTP_RUNNING, &adapter->state))
		ngbe_ptp_start_cyclecounter(adapter);

	e_info(drv, "NIC Link is Down\n");
	netif_carrier_off(netdev);
	netif_tx_stop_all_queues(netdev);
}

static void ngbe_update_xoff_rx_lfc(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;
	struct ngbe_hw_stats *hwstats = &adapter->stats;
	int i;
	u32 data;

	if (hw->fc.current_mode != ngbe_fc_full &&
	    hw->fc.current_mode != ngbe_fc_rx_pause)
		return;

	data = rd32(hw, NGBE_MAC_LXOFFRXC);

	hwstats->lxoffrxc += data;

	/* refill credits (no tx hang) if we received xoff */
	if (!data)
		return;

	for (i = 0; i < adapter->num_tx_queues; i++)
		clear_bit(__NGBE_HANG_CHECK_ARMED,
			  &adapter->tx_ring[i]->state);
}

/**
 * ngbe_update_stats - Update the board statistics counters.
 * @adapter: board private structure
 **/
void ngbe_update_stats(struct ngbe_adapter *adapter)
{
	struct net_device_stats *net_stats = &adapter->netdev->stats;

	struct ngbe_hw *hw = &adapter->hw;
	struct ngbe_hw_stats *hwstats = &adapter->stats;
	u64 total_mpc = 0;
	u32 i, bprc, lxon, lxoff;
	u64 non_eop_descs = 0, restart_queue = 0, tx_busy = 0;
	u64 alloc_rx_page_failed = 0, alloc_rx_buff_failed = 0;
	u64 bytes = 0, packets = 0, hw_csum_rx_error = 0;
	u64 hw_csum_rx_good = 0;

	if (test_bit(__NGBE_DOWN, &adapter->state) ||
	    test_bit(__NGBE_RESETTING, &adapter->state))
		return;

	for (i = 0; i < adapter->num_rx_queues; i++) {
		struct ngbe_ring *rx_ring = adapter->rx_ring[i];

		non_eop_descs += rx_ring->rx_stats.non_eop_descs;
		alloc_rx_page_failed += rx_ring->rx_stats.alloc_rx_page_failed;
		alloc_rx_buff_failed += rx_ring->rx_stats.alloc_rx_buff_failed;
		hw_csum_rx_error += rx_ring->rx_stats.csum_err;
		hw_csum_rx_good += rx_ring->rx_stats.csum_good_cnt;
		bytes += rx_ring->stats.bytes;
		packets += rx_ring->stats.packets;
	}

	adapter->non_eop_descs = non_eop_descs;
	adapter->alloc_rx_page_failed = alloc_rx_page_failed;
	adapter->alloc_rx_buff_failed = alloc_rx_buff_failed;
	adapter->hw_csum_rx_error = hw_csum_rx_error;
	adapter->hw_csum_rx_good = hw_csum_rx_good;
	net_stats->rx_bytes = bytes;
	net_stats->rx_packets = packets;

	bytes = 0;
	packets = 0;
	/* gather some stats to the adapter struct that are per queue */
	for (i = 0; i < adapter->num_tx_queues; i++) {
		struct ngbe_ring *tx_ring = adapter->tx_ring[i];

		restart_queue += tx_ring->tx_stats.restart_queue;
		tx_busy += tx_ring->tx_stats.tx_busy;
		bytes += tx_ring->stats.bytes;
		packets += tx_ring->stats.packets;
	}
	adapter->restart_queue = restart_queue;
	adapter->tx_busy = tx_busy;
	net_stats->tx_bytes = bytes;
	net_stats->tx_packets = packets;

	hwstats->crcerrs += rd32(hw, NGBE_RX_CRC_ERROR_FRAMES_LOW);

	hwstats->gprc += rd32(hw, NGBE_PX_GPRC);

	ngbe_update_xoff_rx_lfc(adapter);

	hwstats->o2bgptc += rd32(hw, NGBE_TDM_OS2BMC_CNT);
	if (ngbe_check_mng_access(&adapter->hw)) {
		hwstats->o2bspc += rd32(hw, NGBE_MNG_OS2BMC_CNT);
		hwstats->b2ospc += rd32(hw, NGBE_MNG_BMC2OS_CNT);
	}
	hwstats->b2ogprc += rd32(hw, NGBE_RDM_BMC2OS_CNT);
	hwstats->gorc += rd32(hw, NGBE_PX_GORC_LSB);
	hwstats->gorc += (u64)rd32(hw, NGBE_PX_GORC_MSB) << 32;

	hwstats->gotc += rd32(hw, NGBE_PX_GOTC_LSB);
	hwstats->gotc += (u64)rd32(hw, NGBE_PX_GOTC_MSB) << 32;

	adapter->hw_rx_no_dma_resources +=
				     rd32(hw, NGBE_RDM_DRP_PKT);
	bprc = rd32(hw, NGBE_RX_BC_FRAMES_GOOD_LOW);
	hwstats->bprc += bprc;
	hwstats->mprc = 0;

	for (i = 0; i < 8; i++)
		hwstats->mprc += rd32(hw, NGBE_PX_MPRC(i));

	hwstats->roc += rd32(hw, NGBE_RX_OVERSIZE_FRAMES_GOOD);
	hwstats->rlec += rd32(hw, NGBE_RX_LEN_ERROR_FRAMES_LOW);
	lxon = rd32(hw, NGBE_RDB_LXONTXC);
	hwstats->lxontxc += lxon;
	lxoff = rd32(hw, NGBE_RDB_LXOFFTXC);
	hwstats->lxofftxc += lxoff;

	hwstats->gptc += rd32(hw, NGBE_PX_GPTC);
	hwstats->mptc += rd32(hw, NGBE_TX_MC_FRAMES_GOOD_LOW);
	hwstats->ruc += rd32(hw, NGBE_RX_UNDERSIZE_FRAMES_GOOD);
	hwstats->tpr += rd32(hw, NGBE_RX_FRAME_CNT_GOOD_BAD_LOW);
	hwstats->bptc += rd32(hw, NGBE_TX_BC_FRAMES_GOOD_LOW);
	/* Fill out the OS statistics structure */
	net_stats->multicast = hwstats->mprc;

	/* Rx Errors */
	net_stats->rx_errors = hwstats->crcerrs +
				       hwstats->rlec;
	net_stats->rx_dropped = 0;
	net_stats->rx_length_errors = hwstats->rlec;
	net_stats->rx_crc_errors = hwstats->crcerrs;
	total_mpc = rd32(hw, NGBE_RDB_MPCNT);
	net_stats->rx_missed_errors += total_mpc;
}

static bool ngbe_ring_tx_pending(struct ngbe_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_tx_queues; i++) {
		struct ngbe_ring *tx_ring = adapter->tx_ring[i];

		if (tx_ring->next_to_use != tx_ring->next_to_clean)
			return true;
	}

	return false;
}

/**
 * ngbe_watchdog_flush_tx - flush queues on link down
 * @adapter - pointer to the device adapter structure
 **/
static void ngbe_watchdog_flush_tx(struct ngbe_adapter *adapter)
{
	if (!netif_carrier_ok(adapter->netdev)) {
		if (ngbe_ring_tx_pending(adapter)) {
			/* We've lost link, so the controller stops DMA,
			 * but we've got queued Tx work that's never going
			 * to get done, so reset controller to flush Tx.
			 * (Do the reset outside of interrupt context).
			 */
			e_warn(drv, "initiating reset due to lost link with pending Tx work\n");
			adapter->flags2 |= NGBE_FLAG2_PF_RESET_REQUESTED;
		}
	}
}

/**
 * ngbe_watchdog_subtask - check and bring link up
 * @adapter - pointer to the device adapter structure
 **/
static void ngbe_watchdog_subtask(struct ngbe_adapter *adapter)
{
	/* if interface is down do nothing */
	if (test_bit(__NGBE_DOWN, &adapter->state) ||
	    test_bit(__NGBE_REMOVING, &adapter->state) ||
		test_bit(__NGBE_RESETTING, &adapter->state))
		return;

	ngbe_watchdog_an_complete(adapter);
	ngbe_watchdog_update_link_status(adapter);

	if (adapter->link_up)
		ngbe_watchdog_link_is_up(adapter);
	else
		ngbe_watchdog_link_is_down(adapter);

	ngbe_update_stats(adapter);
	ngbe_watchdog_flush_tx(adapter);
}

/**
 * ngbe_check_hang_subtask - check for hung queues and dropped interrupts
 * @adapter - pointer to the device adapter structure
 */
static void ngbe_check_hang_subtask(struct ngbe_adapter *adapter)
{
	int i;

	/* If we're down or resetting, just bail */
	if (test_bit(__NGBE_DOWN, &adapter->state) ||
	    test_bit(__NGBE_REMOVING, &adapter->state) ||
		test_bit(__NGBE_RESETTING, &adapter->state))
		return;

	/* Force detection of hung controller */
	if (netif_carrier_ok(adapter->netdev)) {
		for (i = 0; i < adapter->num_tx_queues; i++)
			set_check_for_tx_hang(adapter->tx_ring[i]);
	}
}

/**
 * ngbe_service_task - manages and runs subtasks
 * @work: pointer to work_struct containing our data
 **/
static void ngbe_service_task(struct work_struct *work)
{
	struct ngbe_adapter *adapter = container_of(work,
								struct ngbe_adapter,
								service_task);
	if (NGBE_REMOVED(adapter->hw.hw_addr)) {
		if (!test_bit(__NGBE_DOWN, &adapter->state)) {
			rtnl_lock();
			ngbe_down(adapter);
			rtnl_unlock();
		}
		ngbe_service_event_complete(adapter);
		return;
	}

	ngbe_reset_subtask(adapter);
	ngbe_check_overtemp_subtask(adapter);
	ngbe_watchdog_subtask(adapter);
	ngbe_check_hang_subtask(adapter);

	if (test_bit(__NGBE_PTP_RUNNING, &adapter->state)) {
		ngbe_ptp_overflow_check(adapter);
		if (unlikely(adapter->flags &
			NGBE_FLAG_RX_HWTSTAMP_IN_REGISTER))
			ngbe_ptp_rx_hang(adapter);
	}

	ngbe_service_event_complete(adapter);
}

/**
 * ngbe_service_timer - Timer Call-back
 * @data: pointer to adapter cast into an unsigned long
 **/
static void ngbe_service_timer(struct timer_list *t)
{
	struct ngbe_adapter *adapter = from_timer(adapter, t, service_timer);
	unsigned long next_event_offset;

	/* poll faster when waiting for link */
	if ((adapter->flags & NGBE_FLAG_NEED_LINK_UPDATE) ||
	    (adapter->flags & NGBE_FLAG_NEED_ANC_CHECK))
		next_event_offset = HZ / 10;
	else
		next_event_offset = HZ * 2;

	/* Reset the timer */
	mod_timer(&adapter->service_timer, next_event_offset + jiffies);

	ngbe_service_event_schedule(adapter);
}

/**
 * ngbe_wol_supported - Check whether device supports WoL
 * @adapter: the adapter private structure
 * @device_id: the device ID
 * @subdev_id: the subsystem device ID
 *
 * This function is used by probe and ethtool to determine
 * which devices have WoL support
 *
 **/
int ngbe_wol_supported(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;

	/* check eeprom to see if WOL is enabled */
	if (hw->bus.func == 0 ||
	    hw->bus.func == 1 ||
		hw->bus.func == 2 ||
		hw->bus.func == 3)
		return true;
	else
		return false;
}

static void ngbe_check_minimum_link(struct ngbe_adapter *adapter,
				    int expected_gts)
{
	struct ngbe_hw *hw = &adapter->hw;
	struct pci_dev *pdev;

	/* Some devices are not connected over PCIe and thus do not negotiate
	 * speed. These devices do not have valid bus info, and thus any report
	 * we generate may not be correct.
	 */
	if (hw->bus.type == ngbe_bus_type_internal)
		return;

	pdev = adapter->pdev;

	pcie_print_link_status(pdev);
}

/**
 * ngbe_enumerate_functions - Get the number of ports this device has
 * @adapter: adapter structure
 **/
static inline int ngbe_enumerate_functions(struct ngbe_adapter *adapter)
{
	struct pci_dev *entry, *pdev = adapter->pdev;
	int physfns = 0;

	list_for_each_entry(entry, &pdev->bus->devices, bus_list) {
		/* When the devices on the bus don't all match our device ID,
		 * we can't reliably determine the correct number of
		 * functions. This can occur if a function has been direct
		 * attached to a virtual machine using VT-d, for example. In
		 * this case, simply return -1 to indicate this.
		 */
		if (entry->vendor != pdev->vendor ||
		    entry->device != pdev->device)
			return -1;

		physfns++;
	}

	return physfns;
}

/**
 * ngbe_probe - Device Initialization Routine
 * @pdev: PCI device information struct
 * @ent: entry in ngbe_pci_tbl
 *
 * Returns 0 on success, negative on failure
 *
 * ngbe_probe initializes an adapter identified by a pci_dev structure.
 * The OS initialization, configuring of the adapter private structure,
 * and a hardware reset occur.
 **/
static int ngbe_probe(struct pci_dev *pdev,
		      const struct pci_device_id __always_unused *ent)
{
	struct ngbe_adapter *adapter = NULL;
	struct net_device *netdev;
	struct ngbe_hw *hw = NULL;
	int err;
	int size;
	u32 eeprom_cksum_devcap = 0;
	u32 saved_version = 0;
	u32 etrack_id = 0;
	u32 eeprom_verl = 0;
	int expected_gts;
	char *info_string;
	char *i_s_var;
	static int cards_found;
	u32 devcap = 0;
	netdev_features_t hw_features;
	struct ngbe_ring_feature *feature;

	err = pci_enable_device_mem(pdev);
	if (err)
		return err;

	err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (err) {
		dev_err(&pdev->dev,
			"No usable DMA configuration, aborting\n");
		goto err_pci_disable_dev;
	}

	err = pci_request_selected_regions(pdev,
					   pci_select_bars(pdev, IORESOURCE_MEM),
					   ngbe_driver_name);
	if (err) {
		dev_err(&pdev->dev,
			"pci_request_selected_regions failed %d\n", err);
		goto err_pci_disable_dev;
	}

	pci_enable_pcie_error_reporting(pdev);
	pci_set_master(pdev);

	/* errata 16 */
	pcie_capability_clear_and_set_word(pdev, PCI_EXP_DEVCTL,
					   PCI_EXP_DEVCTL_READRQ,
									   0x1000);

	size = sizeof(struct ngbe_adapter);

	netdev = alloc_etherdev_mq(sizeof(struct ngbe_adapter), NGBE_MAX_TX_QUEUES);
	if (!netdev) {
		err = -ENOMEM;
		goto err_pci_release_regions;
	}

	SET_NETDEV_DEV(netdev, &pdev->dev);

	adapter = netdev_priv(netdev);
	adapter->netdev = netdev;
	adapter->pdev = pdev;
	hw = &adapter->hw;
	hw->back = adapter;
	adapter->msg_enable = (1 << DEFAULT_DEBUG_LEVEL_SHIFT) - 1;

	hw->hw_addr = ioremap(pci_resource_start(pdev, 0),
			      pci_resource_len(pdev, 0));

	adapter->io_addr = hw->hw_addr;
	if (!adapter->io_addr) {
		err = -EIO;
		goto err_pci_release_regions;
	}

	/* default config: 10/100/1000M autoneg on */
	hw->mac.autoneg = true;
	hw->phy.autoneg_advertised = NGBE_LINK_SPEED_AUTONEG;
	hw->phy.force_speed = NGBE_LINK_SPEED_UNKNOWN;

	strncpy(netdev->name, pci_name(pdev), sizeof(netdev->name) - 1);
	/* assign netdev ops and ethtool ops */
	ngbe_assign_netdev_ops(netdev);

	/* setup the private structure */
	err = ngbe_sw_init(adapter);
	if (err)
		goto err_sw_init;

	TCALL(hw, mac.ops.set_lan_id);

	feature = adapter->ring_feature;
	feature[RING_F_RSS].limit = min_t(int, NGBE_MAX_RSS_INDICES, num_online_cpus());

	/* check if flash load is done after hw power up */
	err = ngbe_check_flash_load(hw, NGBE_SPI_ILDR_STATUS_PERST);
	if (err)
		goto err_sw_init;
	err = ngbe_check_flash_load(hw, NGBE_SPI_ILDR_STATUS_PWRRST);
	if (err)
		goto err_sw_init;

	if (ngbe_is_lldp(hw))
		e_dev_err("Can not get lldp flags from flash\n");

	hw->phy.reset_if_overtemp = true;
	err = TCALL(hw, mac.ops.reset_hw);
	hw->phy.reset_if_overtemp = false;
	if (err) {
		e_dev_err("HW reset failed: %d\n", err);
		goto err_sw_init;
	}

	netdev->features |= NETIF_F_SG | NETIF_F_IP_CSUM;
	netdev->features |= NETIF_F_IPV6_CSUM;

	netdev->features |= NETIF_F_HW_VLAN_CTAG_TX |
						NETIF_F_HW_VLAN_CTAG_RX;

	netdev->features |= NETIF_F_HW_VLAN_STAG_TX |
						NETIF_F_HW_VLAN_STAG_RX;
	netdev->features |= ngbe_tso_features();

	netdev->features |= NETIF_F_RXHASH;

	netdev->features |= NETIF_F_RXCSUM;
	/* copy netdev features into list of user selectable features */
	hw_features = netdev->hw_features;
	hw_features |= netdev->features;

	/* set this bit last since it cannot be part of hw_features */
	netdev->features |= NETIF_F_HW_VLAN_CTAG_FILTER;
	netdev->features |= NETIF_F_HW_VLAN_STAG_FILTER;
	netdev->features |= NETIF_F_NTUPLE;

	hw_features |= NETIF_F_NTUPLE;
	netdev->hw_features = hw_features;

	netdev->vlan_features |= NETIF_F_SG |
							 NETIF_F_IP_CSUM |
							 NETIF_F_IPV6_CSUM |
							 NETIF_F_TSO |
							 NETIF_F_TSO6;

	/* MTU range: 68 - 9414 */
	netdev->min_mtu = ETH_MIN_MTU;
	netdev->max_mtu = NGBE_MAX_JUMBO_FRAME_SIZE - (ETH_HLEN + ETH_FCS_LEN);

	netdev->features |= NETIF_F_HIGHDMA;
	netdev->vlan_features |= NETIF_F_HIGHDMA;

	if (hw->bus.lan_id == 0) {
		wr32(hw, NGBE_CALSUM_CAP_STATUS, 0x0);
		wr32(hw, NGBE_EEPROM_VERSION_STORE_REG, 0x0);
	} else {
		eeprom_cksum_devcap = rd32(hw, NGBE_CALSUM_CAP_STATUS);
		saved_version = rd32(hw, NGBE_EEPROM_VERSION_STORE_REG);
	}

	TCALL(hw, eeprom.ops.init_params);
	TCALL(hw, mac.ops.release_swfw_sync, NGBE_MNG_SWFW_SYNC_SW_MB);
	if (hw->bus.lan_id == 0 || eeprom_cksum_devcap == 0) {
	/* make sure the EEPROM is good */
		if (TCALL(hw, eeprom.ops.eeprom_chksum_cap_st, NGBE_CALSUM_COMMAND, &devcap)) {
			e_dev_err("The EEPROM Checksum Is Not Valid\n");
			err = -EIO;
			goto err_sw_init;
		}
	}

	ether_addr_copy(netdev->dev_addr, hw->mac.perm_addr);
	if (!is_valid_ether_addr(netdev->dev_addr)) {
		e_dev_err("invalid MAC address\n");
		err = -EIO;
		goto err_sw_init;
	}

	adapter->mac_table = kzalloc(sizeof(*adapter->mac_table) *
				     hw->mac.num_rar_entries,
				     GFP_ATOMIC);
	if (!adapter->mac_table) {
		err = NGBE_ERR_OUT_OF_MEM;
		e_err(probe, "mac_table allocation failed: %d\n", err);
		goto err_sw_init;
	}
	ngbe_mac_set_default_filter(adapter, hw->mac.perm_addr);

	timer_setup(&adapter->service_timer, ngbe_service_timer, 0);

	if (NGBE_REMOVED(hw->hw_addr)) {
		err = -EIO;
		goto err_sw_init;
	}
	INIT_WORK(&adapter->service_task, ngbe_service_task);

	set_bit(__NGBE_SERVICE_INITED, &adapter->state);
	clear_bit(__NGBE_SERVICE_SCHED, &adapter->state);

	err = ngbe_init_interrupt_scheme(adapter);
	if (err)
		goto err_sw_init;

	/* WOL not supported for all devices */
	adapter->wol = 0;
	if (hw->bus.lan_id == 0 || eeprom_cksum_devcap == 0) {
		TCALL(hw, eeprom.ops.read,
		      hw->eeprom.sw_region_offset + NGBE_DEVICE_CAPS,
				&adapter->eeprom_cap);
		/*only support in LAN0*/
		adapter->eeprom_cap = NGBE_DEVICE_CAPS_WOL_PORT0;
	} else {
		adapter->eeprom_cap = eeprom_cksum_devcap & 0xffff;
	}
	if (ngbe_wol_supported(adapter))
		adapter->wol = NGBE_PSR_WKUP_CTL_MAG;
	if ((hw->subsystem_device_id & NGBE_WOL_MASK) == NGBE_WOL_SUP) {
		/*enable wol  first in shadow ram*/
		ngbe_write_ee_hostif(hw, 0x7FE, 0xa50F);
		ngbe_write_ee_hostif(hw, 0x7FF, 0x5a5a);
	}
	hw->wol_enabled = !!(adapter->wol);
	wr32(hw, NGBE_PSR_WKUP_CTL, adapter->wol);

	device_set_wakeup_enable(pci_dev_to_dev(adapter->pdev), adapter->wol);

	/* Save off EEPROM version number and Option Rom version which
	 * together make a unique identify for the eeprom
	 */
	if (hw->bus.lan_id == 0 || saved_version == 0) {
		TCALL(hw, eeprom.ops.read32,
		      hw->eeprom.sw_region_offset + NGBE_EEPROM_VERSION_L,
				&eeprom_verl);
		etrack_id = eeprom_verl;
		wr32(hw, NGBE_EEPROM_VERSION_STORE_REG, etrack_id);
		wr32(hw, NGBE_CALSUM_CAP_STATUS, 0x10000 | (u32)adapter->eeprom_cap);
	} else if (eeprom_cksum_devcap) {
		etrack_id = saved_version;
	} else {
		TCALL(hw, eeprom.ops.read32,
		      hw->eeprom.sw_region_offset + NGBE_EEPROM_VERSION_L,
			&eeprom_verl);
		etrack_id = eeprom_verl;
	}

	/* Make sure offset to SCSI block is valid */
	snprintf(adapter->eeprom_id, sizeof(adapter->eeprom_id),
		 "0x%08x", etrack_id);

	/* reset the hardware with the new settings */
	err = TCALL(hw, mac.ops.start_hw);
	if (err) {
		e_dev_err("HW init failed, err = %d\n", err);
		goto err_register;
	}

	/* pick up the PCI bus settings for reporting later */
	TCALL(hw, mac.ops.get_bus_info);

	strcpy(netdev->name, "eth%d");
	err = register_netdev(netdev);
	if (err)
		goto err_register;

	pci_set_drvdata(pdev, adapter);
	adapter->netdev_registered = true;

	/* call save state here in standalone driver because it relies on
	 * adapter struct to exist, and needs to call netdev_priv
	 */
	pci_save_state(pdev);

	/* carrier off reporting is important to ethtool even BEFORE open */
	netif_carrier_off(netdev);
	/* keep stopping all the transmit queues for older kernels */
	netif_tx_stop_all_queues(netdev);

	/* calculate the expected PCIe bandwidth required for optimal
	 * performance. Note that some older parts will never have enough
	 * bandwidth due to being older generation PCIe parts. We clamp these
	 * parts to ensure that no warning is displayed, as this could confuse
	 * users otherwise.
	 */
	expected_gts = ngbe_enumerate_functions(adapter) * 10;

	/* don't check link if we failed to enumerate functions */
	if (expected_gts > 0)
		ngbe_check_minimum_link(adapter, expected_gts);

	TCALL(hw, mac.ops.set_fw_drv_ver, 0xFF, 0xFF, 0xFF, 0xFF);

	if (((hw->subsystem_device_id & NGBE_NCSI_MASK) == NGBE_NCSI_SUP) ||
	    ((hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_OCP_CARD))
		e_info(probe, "NCSI : support");
	else
		e_info(probe, "NCSI : unsupported");

	e_info(probe, "PHY: %s, PBA No: Wang Xun GbE Family Controller\n",
	       hw->phy.type == ngbe_phy_internal ? "Internal" : "External");

	e_info(probe, "%02x:%02x:%02x:%02x:%02x:%02x\n",
	       netdev->dev_addr[0], netdev->dev_addr[1],
		   netdev->dev_addr[2], netdev->dev_addr[3],
		   netdev->dev_addr[4], netdev->dev_addr[5]);

	info_string = kzalloc(INFO_STRING_LEN, GFP_KERNEL);
	if (!info_string)
		goto no_info_string;

	i_s_var = info_string;
	i_s_var += sprintf(info_string, "Enabled Features: ");
	i_s_var += sprintf(i_s_var, "RxQ: %d TxQ: %d ",
			   adapter->num_rx_queues, adapter->num_tx_queues);
	if (adapter->flags & NGBE_FLAG_TPH_ENABLED)
		i_s_var += sprintf(i_s_var, "TPH ");

	WARN_ON(i_s_var > (info_string + INFO_STRING_LEN));

	e_info(probe, "%s\n", info_string);
	kfree(info_string);

no_info_string:
	e_info(probe, "WangXun(R) Gigabit Network Connection\n");
	cards_found++;

	return 0;
err_register:
	ngbe_clear_interrupt_scheme(adapter);
	ngbe_release_hw_control(adapter);
err_sw_init:
	adapter->flags2 &= ~NGBE_FLAG2_SEARCH_FOR_SFP;
	kfree(adapter->mac_table);
	iounmap(adapter->io_addr);
err_pci_release_regions:
	pci_disable_pcie_error_reporting(pdev);
	pci_release_selected_regions(pdev, pci_select_bars(pdev, IORESOURCE_MEM));
err_pci_disable_dev:
	pci_disable_device(pdev);

	return err;
}

/**
 * ngbe_remove - Device Removal Routine
 * @pdev: PCI device information struct
 *
 * ngbe_remove is called by the PCI subsystem to alert the driver
 * that it should release a PCI device.  The could be caused by a
 * Hot-Plug event, or because the driver is going to be removed from
 * memory.
 **/
static void ngbe_remove(struct pci_dev *pdev)
{
	struct ngbe_adapter *adapter = pci_get_drvdata(pdev);
	struct net_device *netdev;
	bool disable_dev;

	/* if !adapter then we already cleaned up in probe */
	if (!adapter)
		return;

	netdev = adapter->netdev;

	set_bit(__NGBE_REMOVING, &adapter->state);
	cancel_work_sync(&adapter->service_task);

	if (adapter->netdev_registered) {
		unregister_netdev(netdev);
		adapter->netdev_registered = false;
	}

	ngbe_clear_interrupt_scheme(adapter);
	ngbe_release_hw_control(adapter);

	iounmap(adapter->io_addr);
	pci_release_selected_regions(pdev,
				     pci_select_bars(pdev, IORESOURCE_MEM));
	kfree(adapter->mac_table);
	free_netdev(netdev);

	disable_dev = !test_and_set_bit(__NGBE_DISABLED, &adapter->state);

	pci_disable_pcie_error_reporting(pdev);

	if (disable_dev)
		pci_disable_device(pdev);
}

/**
 * ngbe_close_suspend - actions necessary to both suspend and close flows
 * @adapter: the private adapter struct
 *
 * This function should contain the necessary work common to both suspending
 * and closing of the device.
 */
static void ngbe_close_suspend(struct ngbe_adapter *adapter)
{
	ngbe_ptp_suspend(adapter);
	ngbe_disable_device(adapter);

	ngbe_clean_all_tx_rings(adapter);
	ngbe_clean_all_rx_rings(adapter);

	ngbe_free_irq(adapter);

	ngbe_free_isb_resources(adapter);
	ngbe_free_all_rx_resources(adapter);
	ngbe_free_all_tx_resources(adapter);
}

static int ngbe_dev_shutdown(struct pci_dev *pdev, bool *enable_wake)
{
	struct ngbe_adapter *adapter = pci_get_drvdata(pdev);
	struct net_device *netdev = adapter->netdev;
	struct ngbe_hw *hw = &adapter->hw;
	u32 wufc = adapter->wol;
#ifdef CONFIG_PM
	int retval = 0;
#endif
	*enable_wake = !!wufc;

	netif_device_detach(netdev);
	rtnl_lock();
	if (netif_running(netdev))
		ngbe_close_suspend(adapter);
	rtnl_unlock();

	ngbe_clear_interrupt_scheme(adapter);

#ifdef CONFIG_PM
	retval = pci_save_state(pdev);
	if (retval)
		return retval;
#endif

	if (wufc) {
		ngbe_set_rx_mode(netdev);
		ngbe_configure_rx(adapter);
		/* enable the optics for SFP+ fiber as we can WoL */
		TCALL(hw, mac.ops.enable_tx_laser);

		/* turn on all-multi mode if wake on multicast is enabled */
		if (wufc & NGBE_PSR_WKUP_CTL_MC) {
			wr32m(hw, NGBE_PSR_CTL,
			      NGBE_PSR_CTL_MPE, NGBE_PSR_CTL_MPE);
		}

		pci_clear_master(adapter->pdev);
		wr32(hw, NGBE_PSR_WKUP_CTL, wufc);
	} else {
		wr32(hw, NGBE_PSR_WKUP_CTL, 0);
	}

	pci_wake_from_d3(pdev, !!wufc);

	ngbe_release_hw_control(adapter);

	if (!test_and_set_bit(__NGBE_DISABLED, &adapter->state))
		pci_disable_device(pdev);

	return 0;
}

static void ngbe_shutdown(struct pci_dev *pdev)
{
	bool wake;

	ngbe_dev_shutdown(pdev, &wake);

	if (system_state == SYSTEM_POWER_OFF) {
		pci_wake_from_d3(pdev, wake);
		pci_set_power_state(pdev, PCI_D3hot);
	}
}

#ifdef CONFIG_PM
static int ngbe_suspend(struct device *dev)
{
	int retval;
	bool wake;
	struct pci_dev *pdev = to_pci_dev(dev);

	retval = ngbe_dev_shutdown(pdev, &wake);
	if (retval)
		return retval;

	if (wake) {
		pci_prepare_to_sleep(pdev);
	} else {
		pci_wake_from_d3(pdev, false);
		pci_set_power_state(pdev, PCI_D3hot);
	}

	return 0;
}

static int ngbe_resume(struct device *dev)
{
	struct ngbe_adapter *adapter;
	struct net_device *netdev;
	u32 err;
	struct pci_dev *pdev = to_pci_dev(dev);

	adapter = pci_get_drvdata(pdev);
	netdev = adapter->netdev;
	adapter->hw.hw_addr = adapter->io_addr;
	pci_set_power_state(pdev, PCI_D0);
	pci_restore_state(pdev);

	/* pci_restore_state clears dev->state_saved so call
	 * pci_save_state to restore it.
	 */
	pci_save_state(pdev);
	wr32(&adapter->hw, NGBE_PSR_WKUP_CTL, adapter->wol);

	err = pci_enable_device_mem(pdev);
	if (err) {
		e_dev_err("Cannot enable PCI device from suspend\n");
		return err;
	}

	/* flush memory to make sure state is correct before next watchdog */
	smp_mb__before_atomic();
	clear_bit(__NGBE_DISABLED, &adapter->state);
	pci_set_master(pdev);

	pci_wake_from_d3(pdev, false);

	ngbe_reset(adapter);

	rtnl_lock();

	err = ngbe_init_interrupt_scheme(adapter);
	if (!err && netif_running(netdev))
		err = ngbe_open(netdev);

	rtnl_unlock();

	if (err)
		return err;

	netif_device_attach(netdev);

	return 0;
}

/**
 * ngbe_freeze - quiesce the device (no IRQ's or DMA)
 * @dev: The port's netdev
 */
static int ngbe_freeze(struct device *dev)
{
	struct ngbe_adapter *adapter = pci_get_drvdata(to_pci_dev(dev));
	struct net_device *netdev = adapter->netdev;

	netif_device_detach(netdev);

	if (netif_running(netdev)) {
		ngbe_down(adapter);
		ngbe_free_irq(adapter);
	}

	ngbe_reset_interrupt_capability(adapter);

	return 0;
}

/**
 * ngbe_thaw - un-quiesce the device
 * @dev: The port's netdev
 */
static int ngbe_thaw(struct device *dev)
{
	struct ngbe_adapter *adapter = pci_get_drvdata(to_pci_dev(dev));
	struct net_device *netdev = adapter->netdev;

	ngbe_set_interrupt_capability(adapter);

	if (netif_running(netdev)) {
		u32 err = ngbe_request_irq(adapter);

		if (err)
			return err;

		ngbe_up(adapter);
	}

	netif_device_attach(netdev);

	return 0;
}

static const struct dev_pm_ops ngbe_pm_ops = {
	.suspend        = ngbe_suspend,
	.resume         = ngbe_resume,
	.freeze         = ngbe_freeze,
	.thaw           = ngbe_thaw,
	.poweroff       = ngbe_suspend,
	.restore        = ngbe_resume,
};
#endif/* CONFIG_PM */

static struct pci_driver ngbe_driver = {
	.name     = ngbe_driver_name,
	.id_table = ngbe_pci_tbl,
	.probe    = ngbe_probe,
	.remove   = ngbe_remove,
	.shutdown = ngbe_shutdown,
};

/**
 * ngbe_init_module - Driver Registration Routine
 * ngbe_init_module is the first routine called when the driver is
 * loaded. All it does is register with the PCI subsystem.
 **/
static int __init ngbe_init_module(void)
{
	int ret;

	pr_info("%s - version %s\n", ngbe_driver_string, ngbe_driver_version);
	pr_info("%s\n", ngbe_copyright);

	ngbe_wq = create_singlethread_workqueue(ngbe_driver_name);
	if (!ngbe_wq) {
		pr_err("%s: Failed to create workqueue\n", ngbe_driver_name);
		return -ENOMEM;
	}

	ret = pci_register_driver(&ngbe_driver);
	return ret;
}
module_init(ngbe_init_module);

/**
 * ngbe_exit_module - Driver Exit Cleanup Routine
 * ngbe_exit_module is called just before the driver is removed
 * from memory.
 **/
static void __exit ngbe_exit_module(void)
{
	pci_unregister_driver(&ngbe_driver);
	destroy_workqueue(ngbe_wq);
}

module_exit(ngbe_exit_module);

MODULE_DEVICE_TABLE(pci, ngbe_pci_tbl);
MODULE_AUTHOR("Beijing WangXun Technology Co., Ltd, <software@net-swift.com>");
MODULE_DESCRIPTION("WangXun(R) Gigabit PCI Express Network Driver");
MODULE_LICENSE("GPL");
