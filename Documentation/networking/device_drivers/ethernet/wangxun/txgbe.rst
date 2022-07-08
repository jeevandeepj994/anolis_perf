.. SPDX-License-Identifier: GPL-2.0

================================================================
Linux Base Driver for WangXun(R) 10 Gigabit PCI Express Adapters
================================================================

WangXun 10 Gigabit Linux driver.
Copyright (c) 2015 - 2022 Beijing WangXun Technology Co., Ltd.


Contents
========

- Identifying Your Adapter
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


Support
=======
If you got any problem, contact Wangxun support team via support@trustnetic.com
and Cc: netdev.
