本文示例如何修改一个 kconfig 的配置。
假设我们需要修改 CONFIG_CAN 的配置，目前这个配置是`not set`的，我们需要将其使能。

# 1. 修改 kconfig
首先，进入 kenel source tree 的找到该 kconfig 的位置：
```
cd anolis/
find . -name CONFIG_CAN
```
如果没有找到该 config，说明该 kconfig 的依赖可能没有打开，需要打开对应的 Kconfig 文件，确认其依赖关系，将依赖的 kconfig 一并打开。
在本文的示例中，我们能找到该 kconfig 位于 `./L2-OPTIONAL/generic/CONFIG_CAN` 路径。

接下来，修改该 kconfig 的配置:
```
echo 'CONFIG_CAN=y' > ./configs/L2-OPTIONAL/generic/CONFIG_CAN
```
一般来说，调整某个 kconfig 配置，必定有实际的使用场景驱动，这表明该 kconfig 实际上是很重要的，因此我们还需要将该 kconfig 的定级转移到 L1 或者 L0.
你可以直接使用 `mv` 命令来完成这件事情：
```
mv ./configs/L2-OPTIONAL/generic/CONFIG_CAN ./configs/L1-RECOMMEND
```
不过我们更推荐使用包装过的 `make dist-configs-move` 命令来完成这个动作，特别是当 kconfig 配置因为不统一而散落在各个目录中时
```
make dist-configs-move OLD=L2 C=CONFIG_CAN L=L1
```
# 2. 刷新 kconfig
在调整一个 kconfig 后，其他的 kconfig 很有可能因为依赖关系而发生变化，因此需要对整体 kconfig 进行刷新。
```
$make dist-configs-update

******************************************************************************
There are some UNKNOWN level's new configs.

CONFIG_CAN_8DEV_USB        CONFIG_CAN_DEV       CONFIG_CAN_GW             CONFIG_CAN_KVASER_USB   CONFIG_CAN_PEAK_USB  CONFIG_CAN_UCAN
CONFIG_CAN_BCM             CONFIG_CAN_EMS_USB   CONFIG_CAN_HI311X         CONFIG_CAN_M_CAN        CONFIG_CAN_PHYTIUM   CONFIG_CAN_VCAN
CONFIG_CAN_CALC_BITTIMING  CONFIG_CAN_ESD_USB2  CONFIG_CAN_IFI_CANFD      CONFIG_CAN_MCBA_USB     CONFIG_CAN_RAW       CONFIG_CAN_VXCAN
CONFIG_CAN_CC770           CONFIG_CAN_FLEXCAN   CONFIG_CAN_ISOTP          CONFIG_CAN_MCP251X      CONFIG_CAN_SJA1000   CONFIG_CAN_XILINXCAN
CONFIG_CAN_C_CAN           CONFIG_CAN_GRCAN     CONFIG_CAN_J1939          CONFIG_CAN_MCP251XFD    CONFIG_CAN_SLCAN     CONFIG_NET_EMATCH_CANID
CONFIG_CAN_DEBUG_DEVICES   CONFIG_CAN_GS_USB    CONFIG_CAN_KVASER_PCIEFD  CONFIG_CAN_PEAK_PCIEFD  CONFIG_CAN_SOFTING

Need to classify above configs manually !!!
...

******************************************************************************
```
可以看到，大量与 CONFIG_CAN 有关的 kconfig 被刷新出来了。
所以，接下来我们需要给新的 kconfig 评级，同样使用 move 命令：
```
make dist-configs-move C=CONFIG_CAN* L=L2
```

# 3. 记录变更
最后，需要到`anolis/configs/metadata/`目录下，记录下这次变更的背景信息，比如变更理由、对应场景、日期等。

# 结束
到这里为止，所以的步骤已完成，可以使用 `git add` 和 `git commit` 命令记录这些变更，并发起 PR 了。

# 附：`make dist-configs-move`参数说明
`make dist-configs-move` 用于在不同的层级之间移动 kconfig。
参数如下：
- OLD 可选，表示 kconfig 原来所在的层级。默认为 UNKNOWN
- C 必选，表示需要移动的 kconfig，可使用通配符，如 `C=CONFIG_CAN*`
- L 必选，表示新的层级。