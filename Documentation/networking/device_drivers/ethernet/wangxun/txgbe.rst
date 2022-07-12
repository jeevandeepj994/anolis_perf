.. SPDX-License-Identifier: GPL-2.0

================================================================
Linux Base Driver for WangXun(R) 10 Gigabit PCI Express Adapters
================================================================

WangXun 10 Gigabit Linux driver.
Copyright (c) 2015 - 2022 Beijing WangXun Technology Co., Ltd.


Contents
========

- Identifying Your Adapter
- Additional Features and Configurations
- Support


Identifying Your Adapter
========================
The driver is compatible with WangXun Sapphire Dual ports Ethernet Adapters.

SFP+ Devices with Pluggable Optics
----------------------------------
The following is a list of 3rd party SFP+ modules that have been tested and verified.

+----------+----------------------+----------------------+
| Supplier | Type                 | Part Numbers         |
+==========+======================+======================+
| Avago	   | SFP+                 | AFBR-709SMZ          |
+----------+----------------------+----------------------+
| F-tone   | SFP+                 | FTCS-851X-02D        |
+----------+----------------------+----------------------+
| Finisar  | SFP+                 | FTLX8574D3BCL        |
+----------+----------------------+----------------------+
| Hasense  | SFP+                 | AFBR-709SMZ          |
+----------+----------------------+----------------------+
| HGTECH   | SFP+                 | MTRS-01X11-G         |
+----------+----------------------+----------------------+
| HP       | SFP+                 | SR SFP+ 456096-001   |
+----------+----------------------+----------------------+
| Huawei   | SFP+                 | AFBR-709SMZ          |
+----------+----------------------+----------------------+
| Intel    | SFP+                 | FTLX8571D3BCV-IT     |
+----------+----------------------+----------------------+
| JDSU     | SFP+                 | PLRXPL-SC-S43        |
+----------+----------------------+----------------------+
| SONT     | SFP+                 | XP-8G10-01           |
+----------+----------------------+----------------------+
| Trixon   | SFP+                 | TPS-TGM3-85DCR       |
+----------+----------------------+----------------------+
| WTD      | SFP+                 | RTXM228-551          |
+----------+----------------------+----------------------+

Laser turns off for SFP+ when ifconfig ethX down
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"ifconfig ethX down" turns off the laser for SFP+ fiber adapters.
"ifconfig ethX up" turns on the laser.


Additional Features and Configurations
======================================

Jumbo Frames
------------
Jumbo Frames support is enabled by changing the Maximum Transmission Unit
(MTU) to a value larger than the default value of 1500.

Use the ifconfig command to increase the MTU size. For example, enter the
following where <x> is the interface number::

  ifconfig eth<x> mtu 9000 up

NOTES:
- The maximum MTU setting for Jumbo Frames is 9710. This value coincides
  with the maximum Jumbo Frames size of 9728 bytes.
- This driver will attempt to use multiple page sized buffers to receive
  each jumbo packet. This should help to avoid buffer starvation issues
  when allocating receive packets.

Hardware Receive Side Coalescing (HW RSC)
-----------------------------------------
Sapphire adapters support HW RSC, which can merge multiple
frames from the same IPv4 TCP/IP flow into a single structure that can span
one or more descriptors. It works similarly to Software Large Receive Offload
technique.

VXLAN Overlay HW Offloading
---------------------------
Virtual Extensible LAN (VXLAN) allows you to extend an L2 network over an L3
network, which may be useful in a virtualized or cloud environment. Some WangXun(R)
Ethernet Network devices perform VXLAN processing, offloading it from the
operating system. This reduces CPU utilization.

VXLAN offloading is controlled by the tx and rx checksum offload options
provided by ethtool. That is, if tx checksum offload is enabled, and the adapter
has the capability, VXLAN offloading is also enabled. If rx checksum offload is
enabled, then the VXLAN packets rx checksum will be offloaded.

IEEE 1588 Precision Time Protocol (PTP) Hardware Clock (PHC)
------------------------------------------------------------
Precision Time Protocol (PTP) is used to synchronize clocks in a computer
network and is supported in the txgbe driver.


Support
=======
If you got any problem, contact Wangxun support team via support@trustnetic.com
and Cc: netdev.
