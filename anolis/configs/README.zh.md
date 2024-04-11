# ANCK config说明
# 为什么会有 ANCK kconfig 基线
## 管理较乱
原来的 ANCK kconfig 管理较乱，出现了许多问题。比如：

1. 以为打开了，实际没打开的情况
比如 [CONFIG_NUMA_AWARE_SPINLOCKS](https://gitee.com/anolis/cloud-kernel/pulls/535) 和 [CONFIG_CK_KABI_SIZE_ALIGN_CHECKS](https://gitee.com/anolis/cloud-kernel/pulls/1627)，虽然修改了 anolis_defconfig 文件，但是由于依赖不满足，实际上未成功开启。

2. 在 Kconfig 中新增了 kconfig ，但是没有更新 anolis_defconfig 文件
比如 [CONFIG_VTOA](https://gitee.com/anolis/cloud-kernel/pulls/1749) 和 [CONFIG_SCHED_ACPU](https://gitee.com/anolis/cloud-kernel/pulls/2260)

3. kconfig依赖错误
比如 [CONFIG_YITIAN_CPER_RAWDATA](https://gitee.com/anolis/cloud-kernel/pulls/2046)，仅与 arm64 arch 相关，但出现在了 x86 的 anolis_defconfig 中。

4. 更新config配置时，未同时更新 anolis_defconfig 和 anolis_debug-defconfig
比如：[CONFIG_KVM_INTEL_TDX](https://gitee.com/anolis/cloud-kernel/pulls/818) 和 [CONFIG_AMD_PTDMA](https://gitee.com/anolis/cloud-kernel/pulls/288)

5. 重要config被错误修改，导致严重的性能问题
比如 [CONFIG_ARM64_TLB_RANGE 和 CONFIG_ARM64_PTR_AUTH](https://gitee.com/anolis/cloud-kernel/pulls/1960)

## 变更难以追溯
之前许多 kconfig 的变更没有及时记录下来，导致在决定 kconfig 是否可以修改时需要仔细斟酌，没有可以参考的历史信息。
通过 git 回溯信息也有困难，因为不断地刷新 anolis_defconfig 文件，导致很多 kconfig 的位置不断变化，导致需要 git blame 多次才能找到原始的 commit 。

## 兼容性
ANCK 需要将重要 kconfig 高亮出来，作为给 ANCK 下游衍生版本的参考，以保证下游衍生版本与 ANCK 的兼容性。

# kconfig 目录结构说明

kconfig 目录位于 $(srctree)/anolis/configs 中，共分为以下几类：
- metadata/ ，用于存放 kconfig 的元数据信息，包括 描述信息 (description) 和 变更记录 (changelog)
- scripts/ ，用于存放于 kconfig 有关的脚本文件
- L*/ ，以分层方式存放 kconfig 的配置信息
- OVERRIDE/ ，为 ANCK 衍生版提供的，用于存放覆盖 ANCK 的基础配置的目录

## 分层说明
ANCK 按照重要程度，将所有的 kconfig 划分为 4 个层级，以便标记重要的 config，为开发者修改 kconfig 时提供参考。
### L0-MANDATORY
最核心的 kconfig，这类 kconfig 赋予内核最基础的产品化能力，保证内核能作为一个基本的服务器操作系统进行使用。
这类 kconfig 的变更需要十分谨慎，建议 ANCK 下游衍生版不要去 override 此类配置。

入选条件：
1. 有国家标准/行业标准背书。
2. 对兼容性有着重要影响的 kconfig。具体而言，可分为以下几类：
- 具有不证自明的基础能力支持，比如CONFIG_NET、CONFIG_PCI。
- 具有广泛的通用使用场景的 kconfig。如CONFIG_NFS_FS，绝大多数服务器操作系统都支持了 nfs。
- 被主流开源软件所广泛使用/依赖的kconfig。如CONFIG_USERFAULTFD，qemu 热迁移需要该特性。
3. 有现实案例背书，或者有用户反馈错误配置会导致严重的功能/性能问题的 kconfig。

### L1-RECOMMEND
针对特定场景有着重要意义的 kconfig，此类 kconfig 的错误配置将导致该场景出现严重的产品化问题。
Anolis 会站在云场景和服务器场景的角度配置 L1 层的 kconfig，下游衍生版按照可根据实际业务需求对其酌情 override。

入选条件：
1. 有重要的特定业务场景背书。注意是特定场景，如果是通用场景，请放L0。
2. 在特定场景中因为错误配置，引发过一些事故的。

### L2-OPTIONAL
不被关注的 kconfig。

此层级 kconfig 其中分为两类：
1. 可以被手动修改的 kconfig。
此类 kconfig 当前已配置，但是无法确定其对现有场景是否有重要意义，出于兼容性考虑，保持其不变，但将其放置到 L2。
ANCK 认为它们的变更不会对现有使用场景造成严重影响，可以被任意打开或者关闭，比如 CONFIG_CAN、CONFIG_WIRELESS。
下游衍生版如有需要，可随意覆盖。
若后续发现该层级中某些 kconfig 对于某些场景非常重要，可提 PR 申请将其调整至 L1 或 L0。

2. 无法被手动修改的 kconfig。
某些 kconfig 无法被手动调整，只能通过调整其他 kconfig 时通过依赖关系自动 select。关注此类 kconfig 的意义不大，因此将其放置到 L2 中。
典型的 kconfig，如：CONFIG_ARCH_WANT_XXX，CONFIG_HAVE_XXX

入选条件：
1. 当前已经配置了，但是说不清具体使用场景和使用价值的 kconfig
2. 不能被手动配置，只能被自动 select 的 kconfig

### OVERRIDE
这一层级用于 ANCK 下游衍生版本自定义 kconfig 配置，常见的覆盖方式如 修改 config，新增/删除 config。这一目录下同样需要对 override 的 kconfig 定义 L0 到 L2 等级。

# 子目录说明
ANCK 目前支持 x86、arm64架构，每个架构分为标准配置和 debug 配置，其中 debug 配置用于测试，标准配置是正式上线时使用的。
因此，每一层级中的 kconfig 的组织形式如下：
- default，当各个架构的标准配置都相同时，将 kconfig 存放至该目录
- x86/arm64，当各个架构的标准配置不同时，将 kconfig 分别存放至对应目录。
- x86-debug/arm64-debug，当各个架构的标准配置与其 debug 配置不同时，将 debug 配置存放至该目录

举例，如果我们想查看 CONFIG_FOO 在 x86 debug 的配置，则查找路径如下：
1. 查看 x86-debug 目录下是否存在 CONFIG_FOO 文件，若有，则使用该配置
2. 若无，查看 x86 目录下是否存在 CONFIG_FOO 文件，若有，则使用该配置
3. 若无，查看 default 目录是否存在 CONFIG_FOO 文件，若有，则使用该配置
4. 若无，则该配置为 not set
如果想查看 CONFIG_FOO 在 x86 的配置，查找顺序也与上文相同，但是查找时从第 2 步开始。


## 如何更新 kconfig
请参考 How-To-Modify-Kconfig.zh.md
