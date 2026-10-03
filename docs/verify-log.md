# PrivacyGate 验证记录

> 原始报告：`runs/*.json`（full/queries 双 flavor × 2 轮）。
> 基线时点：2026-09-27 20:36–20:37，模块 io.github.privacygate 已安装启用但**未装任何 hook**
> （仅探针日志），故本记录 = 原生行为基线。
> 采集：`tools/verify/collect_report.py`（run-as 内部文件主通道）。

## 基线结论（原生状态）

| ID | 项目 | full flavor（QUERY_ALL_PACKAGES） | queries flavor（仅 `<queries>`） | 结论 |
|---|---|---|---|---|
| L1/L2 | 枚举应用 | 496 包 / 106 第三方 | 357 包 / 96 第三方 | `<queries>` 原生可见性只挡掉一小部分；**原生行为本身在泄露** ✔ |
| L3 | LAUNCHER intent 查询 | 106 / 94 第三方 | **106 / 94 第三方** | **两条路径完全一致**：LAUNCHER 查询不受可见性限制，94 个第三方全裸奔——F 系修正的核心依据复现 ✔ |
| L4 | 定点探测 | 14/16 可见（JD 已卸、dummy 未装 ✓） | 11/16（多藏了 opos.ads、vector.rootguard、privacygate 模块） | `com.opos.ads` 等在 queries 下原生不可见；全量 flavor 全可见 |
| L5 | uid 扫描 | user0: 427 uid 有包 / 114 潜在第三方；user999: 9 uid / 1 | user0: 288 uid / **104** | **`getPackagesForUid` 原生过滤很弱**（queries 下仍漏 104）——启用后期望归零的第三个泄露面 |
| L6 | LauncherApps | 113 / 101 第三方 | 113 / 101 第三方 | 与 L3 同源，不分 flavor |
| L7 | services/providers | queryContentProviders 枚举出大量第三方 provider 包 | 同 | provider 枚举是又一泄露面（记录） |
| L8 | 包广播 | **ADDED+REMOVED dummy 均捕获** ✔ | 空（queries 进程在 dummy 流程前被系统冻结） | 接收器工作正常；注意 ColorOS 缓存冻结会杀长驻进程——分身验证时留意 |
| L9 | resolveActivity(http) | mark.via.Trampoline | mark.via.Trampoline | visible_targets 默认放行 mark.via 的依据 ✔ |
| L10 | startActivity 未导出组件 | 已装非导出×3 → **SecurityException**；不存在 → **ActivityNotFoundException** | 同 | **异常类型对比法成立**（F3 静默探测可行）；启用后对被隐藏包重跑此表，若 SecurityException 仍在则泄露证实，P2-a 启用 |
| L11 | Secure 包名键 | default_input_method=搜狗 ✔、enabled_accessibility_services=gkd ✔、autofill=codebook ✔ 可读；enabled_input_methods → **系统直接 SecurityException**（targetSdk≤33 限制） | 同 | **P2-b 有实义**：3 个含第三方包名的键对现代 app 仍可读 |
| L12 | IMM/无障碍列表 | IMM=[百度输入法, 搜狗]；a11y installed 含第三方 | IMM=[搜狗]；a11y 部分过滤 | 原生有部分过滤但不彻底（记录，P2-c） |
| I1 | android_id 三路径 | `<已脱敏>`，三路径一致，secure 表 713 行 | 同值 | **两 flavor 同签名 → 同 SSAID**：实测确认原生按签名共享；三路径一致=hook 必须三处同源（都在 SettingsProvider 服务端改，天然满足） |
| I2 | HeyTap OUID | 绑定成功，getSerID 返回**空串**（探测用假 appKey） | 同 | 服务对普通 app 不设防；Layer 0 后此路径应为空/全 0，启用后复测对比 |

## 启用后期望（阶段 3/4 验收对照）

- L1/L2（非豁免）→ 只有自己；L3/L6 → 只有系统包+自己；L4 → 仅 visible_targets（mark.via）+系统包；
- L5 → 潜在第三方归 0；L7 → provider 枚举无第三方；L8 → 广播收不到第三方包事件；
- L9 → 仍解析到 mark.via；L10 → 对被隐藏包的未导出组件**若仍 SecurityException 即证实 F3 泄露**（决定 P2-a）；
- L11/L12 → 若仍泄露则 P2-b/P2-c 评估；
- I1 → 每应用值不同、随日期桶轮换、三路径仍一致；I2 → 空/全 0（配合 Layer 0）。

## 验证工具链备忘（影响后续所有轮次）

1. **applicationIdSuffix 的类路径**：运行时包名带后缀但类在 namespace 包里，`am start` 必须写
   `pkg/io.github.privacygate.detector.Main` 全路径。
2. **`--esa` 数组分隔符是逗号**，且设备 shell 会把未引用的 `;` 当命令分隔符——comps 用逗号。
3. **logcat main 缓冲仅 128KiB 且高速刷写**：启动期/套件日志会被冲掉；可靠通道 =
   run-as 读应用内部 files/（collect_report.py 已内置，logcat 分块仅兜底）。
4. **run-as 无法读 /storage**（FUSE 权限）——报告必须落内部目录。
5. **同 intent 重复 am start 不会重投**：加 `-f 0x20000000`（SINGLE_TOP）走 onNewIntent。
6. Gradle 后台构建**不得用管道收尾**（`| tail` 吞掉非零退出码）——用 `> log; exit $rc` 模式。
7. ColorOS 缓存冻结会杀后台进程（queries flavor L8 空的根因）；长驻观测需保活或前台化。
