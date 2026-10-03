# PrivacyGate 审计基线 — PKG110_16.0.0.205（ColorOS 16 / Android 16 / SDK 36）

> 产物：`tools/audit/PKG110_16.0.0.205/`（services.jar / oplus-services.jar / SettingsProvider.apk /
> queries-baseline.txt，SHA256 见该目录 `SHA256SUMS`）。framework.jar 由本阶段从设备拉取补入
> `extracted/framework/`。
> 工具：`tools/audit/dexgrep.py`（extract / sig / dis 三模式，dexdump 来自 build-tools 36.1.0）。
> **OTA 后重审计流程**：重拉各 jar → `dexgrep.py extract` → 重跑 `queries/` 里同参数检索 → 与本文
> 签名逐条比对；探测器 APK 回归（阶段 2 全项）。
>
> **装机预验证（libxposed API 101 on Vector 2.2）**：模块经 CLI 启用 + `scope set <mod> system/0`
> 后重启，`onModuleLoaded`（api=102, systemServer=true）、`onSystemServerStarting`（services.jar+
> oplus-services.jar classloader）、`onPackageLoaded`（含 com.android.providers.settings）三者均已
> 实测触发；system_server 侧可写 `/data/system/privacygate/`。module.prop 的
> `staticScope=true/exceptionMode=protective` 与 `META-INF/xposed/{java_init.list,scope.list,module.prop}`
> 打包格式被 Vector 正确识别。

## 1. 第一防线：AppsFilterBase（services__classes3.dex，全部为虚方法）

| 方法 | 实机签名（dex 验证） |
|---|---|
| **shouldFilterApplication** | `(Lcom/android/server/pm/snapshot/PackageDataSnapshot;ILjava/lang/Object;Lcom/android/server/pm/pkg/PackageStateInternal;I)Z` |
| shouldFilterApplicationInternal | `(Lcom/android/server/pm/Computer;ILjava/lang/Object;Lcom/android/server/pm/pkg/PackageStateInternal;I)Z` |
| shouldFilterApplicationUsingCache | `(III)Z` — **无绕过风险（待定项已关闭）**：其唯一调用方就是 shouldFilterApplication（AppsFilterLocked 里只是加锁覆写）；shouldFilterApplicationInternal 仅被建缓存的 updateShouldFilterCacheForUser 调用。探测器 L5 不再为"入口绕过"承担证明责任 |
| isImplicitlyQueryable | `(II)Z` — 参数为完整 uid（PLAN F6 ✔；字段 `mImplicitlyQueryable: Lcom/android/server/utils/WatchedSparseSetArray;`） |
| isRetainedImplicitlyQueryable | `(II)Z` |
| getVisibilityAllowList | `(Lcom/android/server/pm/snapshot/PackageDataSnapshot;Lcom/android/server/pm/pkg/PackageStateInternal;[ILandroid/util/ArrayMap;)Landroid/util/SparseArray;`（另有一个 WatchedArrayMap 重载）— 包广播白名单内部走 shouldFilterApplication，**单点 hook 自动覆盖广播** ✔ |

## 2. 阶段 1 五项确认结论

| 项 | 结论 | 证据（dexdump sig/dis） |
|---|---|---|
| (a) 目标包信息接口 | `Lcom/android/server/pm/pkg/PackageState;`（PackageStateInternal 的父接口）提供 `getAppId()I`、`getPackageName()Ljava/lang/String;`、`isSystem()Z`、`isSystemExt()Z` — hook 内可直接以接口方法调用（经 `chain.getArg(3)` 拿到实例后反射缓存） | queries/02_pkgstate.txt |
| (b) SharedUserSetting 成员包名 | `getPackages()Ljava/util/List;`、`getPackageStates()Landroid/util/ArraySet;`、字段 `mPackages WatchedArraySet` — callingSetting 为 SharedUserSetting 时用它枚举成员包名做豁免/黑名单匹配 | queries/03_sharedusersetting.txt |
| (c) invalidatePackageInfoCache | 存在：`Landroid/content/pm/PackageManager; -> invalidatePackageInfoCache ()V`，**静态方法**（framework__classes.dex）。策略热加载替换后调用它使客户端 PackageInfo/ApplicationInfo 的 PropertyInvalidatedCache 失效（F11 ✔） | queries/06_framework_pmic.txt |
| (d) getCallingPackageInfo 的 flags | `const-wide/16 v1, #int 64` → **PackageManager.GET_SIGNATURES (0x40)**，随后 `IPackageManager.getPackageInfo(String, J, I)`。**`pi.signatures` 会填充**：派生输入取 `pi.signatures[0]` 的 SHA-256 hex 即可；`signingInfo` 未请求（为 null），PLAN 的 fallback 链保留作防御。ColorOS 走 `OplusSettingsUtils.getCallingPackage(Bundle, String)` 可从 call args（`_calling_package`）覆盖调用方包名，**但仅当真实调用方是 com.oplus.appplatform（实机 uid 1000）时生效**——普通 app 无法伪造调用方，**SSAID 豁免按 `pi.packageName` 判断是安全的** | queries/04/05 + 原始反汇编 |
| (e) onPackageLoaded 是否回调 SettingsProvider | **✅ 已定案（装机实测，probe 文件证据）**：`onPackageLoaded` 回调 `com.android.providers.settings`（first=false，开机后约 4s）；`onSystemServerStarting` 携带 services.jar + oplus-services.jar 的 PathClassLoader；框架上报 api=102（模块 target 101 向前兼容）；system_server 可写 `/data/system/privacygate/`（0700 system:system，SELinux 通过）。**结论：SSAID 双 hook 按 PLAN §1.2 原方案在 onPackageLoaded 里挂载（getDefaultClassLoader），attachInfo 备用方案弃用**。观测通道：`/data/system/privacygate/probe_*.txt` 与 status.json（logcat 环形缓冲会冲掉启动期日志，不可靠） | probe 文件 + 模块日志 |

## 3. SSAID 链路签名（SettingsProvider__classes.dex，均为 direct 私有方法）

| 方法 | 实机签名 |
|---|---|
| getSsaidSettingLocked | `(Landroid/content/pm/PackageInfo;I)Lcom/android/providers/settings/SettingsState$Setting;` — 返回副本，`setValue` 不落盘（F8 ✔） |
| packageValueForCallResult | `(ILjava/lang/String;ILcom/android/providers/settings/SettingsState$Setting;Z)Landroid/os/Bundle;` — **args[4] 即 trackGen(Z)**，before-hook 置 false 阻止客户端按 generation 缓存（F7 ✔；客户端请求键 `_track_generation`） |
| call | `(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;`（虚方法）— 调用链 call → getSecureSetting → getSsaidSettingLocked → packageValueForCallResult，同线程，ThreadLocal 传轮换标记 |

## 4. hook 实现约定（阶段 3/4 按此执行）

- 挂载时机：`onSystemServerStarting(param.classLoader)` 装 AppsFilter hook；`onPackageLoaded(packageName=="com.android.providers.settings")` 装 SSAID 双 hook（(e) 验证失败则 fallback：onSystemServerStarting 里直接从 SettingsProvider 的 dex ClassLoader 找类，阶段 3 现场定）。
- 反射方法缓存：`Method` 一次解析、`setAccessible(true)`；调用 `isImplicitlyQueryable`/`isRetainedImplicitlyQueryable` 用 `chain.getThisObject()`。
- after-hook 单调语义：`res = chain.proceed(); if (res || !listFilterOn || killed) return res; …` 只把 false 改 true，绝不反向。
- 热路径**顺序**：先做免反射判断（原值、开关、调用方 appId——`UserHandle.getAppId(callingUid)` 为静态纯函数），再对目标包做反射调用（getAppId/isSystem/getPackageName）。注意 `getAppId()I` 经反射返回 `Integer`，10xxx 超出 [-128,127] 缓存区间必然**装箱产生新对象**——每条查询 1~2 次装箱可接受，但"零分配"的表述不成立；免 IO、免日志不变。
- 术语与语义对齐（修正本计划早先文字）：策略键名以 PLAN §3 为准 **`system_caller_deny`**（非 caller_blacklist）；"文件缺失/损坏 → 内置默认"指**开关全开且保留内置豁免（商店、模块自身）**，并非"无豁免"；`/data/system` 为 DE 存储，`onSystemServerStarting` 时已挂载，冷启动"文件未就绪"实际不会发生（PolicyStore 仍用 parseOrNull 区分损坏与缺失：冷启动 null → DEFAULT，热加载 null → 保留旧策略）。
- 异常模式：`HookBuilder.setExceptionMode(ExceptionMode.PROTECTIVE)` + module.prop `exceptionMode=protective`，框架保证 hook 体异常时按"无 hook"继续。

## 5. 已知绕过与应急预案（探测器实测后启用）

- **startActivity 不过滤**（F3，`ComputerEngine.applyPostResolutionFilter` 在 resolveForStart 分支跳过）：L10 实测确认后，在 ActivityStarter 侧对"非豁免调用方显式启动被隐藏包的未导出组件"返回未找到。
- **Settings.Secure 含包名的键**（default_input_method、enabled_accessibility_services 等）：L11/L12 实测确认后在 `getSecureSetting` after-hook 剔除第三方组件（同样返回副本，不写存储）。
