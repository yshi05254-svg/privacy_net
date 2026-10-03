# PrivacyGate 实施计划（可执行版）

> 基线机型：OnePlus PKG110 · ColorOS 16.0.0.205(CN01) · Android 16 / SDK 36
> fingerprint `OnePlus/PKG110/OP5D2BL1:16/UKQ1.231108.001/V.1e1c4bc_295f5d_27842a:user/release-keys`
> 框架：Vector v2.2 (3107)，Magisk（`u:r:magisk:s0`），另装 zygisk_shamiko
> 审计产物：`tools/audit/PKG110_16.0.0.205/`（services.jar / oplus-services.jar / SettingsProvider.apk / queries-baseline.txt，含 SHA256SUMS）

---

## 0. 相对上一版计划的修正（全部有实机证据）

| # | 上一版 | 实机证据 | 修正 |
|---|---|---|---|
| **F1 致命** | 放行条件只看**调用方** appId<10000 | 桌面 `com.android.launcher`=10211、SystemUI=10216、分享面板 `com.android.intentresolver`=10069、PermissionController=10284、PackageInstaller=10212、软件商店 heytap.market=10109 | 不修正的话：**桌面第三方图标全部消失、分享面板变空、权限管理失灵**。新增放行：**调用方是系统包**（`isSystem`）。另设系统调用方黑名单，默认只有 `com.opos.ads`（OPPO 广告平台） |
| F2 | “系统分享面板不受影响（跑在 system_server）” | 分享面板是 `com.android.intentresolver`，以自己的 uid（10069）查询 | 靠 F1 解决 |
| F3 | “显式组件解析”已被覆盖 | `ComputerEngine.applyPostResolutionFilter` 在 `00f1: if-nez v24(resolveForStart)` 处跳过 `shouldFilterApplication`，**startActivity 不做可见性过滤**（原生行为） | ① 好处：微信回调、跳转浏览器用的都是 startActivity，不受影响；② 残余泄露：用 startActivity 显式启动目标的一个**未导出**组件，未安装时抛 `ActivityNotFoundException`，已安装时抛 `SecurityException`，两者不同，可以静默探测是否安装。→ 探测器加 L10；确认存在后按 §6-P2 修补 |
| F4 | 目标只放行系统包 | 默认浏览器 = `mark.via`（第三方）；输入法搜狗、无障碍 gkd、通知监听 operit 也都是第三方 | 很多 app 先 `resolveActivity(http)` 判空，再跳转，浏览器被隐藏后链接按钮就失效了。新增 `visible_targets` 目标白名单，默认放入**当前浏览器角色持有者**（由 UI 用 `cmd role` 取值写入） |
| F5 | 豁免表用 appId 做键（SparseBooleanArray） | 重装后 appId 会变；而 hook 参数 `callingSetting` 本身就带包名 | 改为**包名 HashSet**，调用方和目标都从 hook 参数里直接取包名，不需要反查，也不会因重装失效 |
| F6 | `isImplicitlyQueryable(callingUid, targetUid)` 语义不明 | 字节码：`mImplicitlyQueryable.contains(callingUid, Integer(targetUid))`，参数是**完整 uid**；另外还有 `isRetainedImplicitlyQueryable(II)` | 目标 uid 用 `UserHandle.getUid(userId, target.appId)` 构造；两个方法都检查 |
| F7 | generation 字段“待确认” | `packageValueForCallResult(int type, String name, int userId, Setting, boolean trackGen)` 按 name 调用 `GenerationRegistry.addGenerationData`；客户端请求键是 `_track_generation` | 在 `packageValueForCallResult` 上做 before-hook，当 `name=="android_id"` 且本次调用已被轮换时，令 `args[4]=false`，服务端就不下发 generation，客户端也就不缓存 |
| F8 | SSAID 替换方式未定 | `getSsaidSettingLocked` 返回 `mascaradeSsaidSetting()` 生成的 `SettingsProvider$4`，它走 `Setting(SettingsState, Setting)` 拷贝构造，是**和存储分离的副本**；ColorOS 的 `Setting.setValue` 只做 `iput value` | 直接对返回的副本调用 `setValue(fake)`，不会写入 `settings_ssaid.xml`。整表查询 `getAllSecureSettings` 也调用同一个方法，一并覆盖 |
| F9 | 模块入口用 `assets/xposed_init`（旧 API） | Vector 支持 libxposed API 101/102：`hook(m).setExceptionMode(PROTECTIVE).intercept{}`、`deoptimize`、`onSystemServerStarting`、`onPackageLoaded`（system_server 里加载的非首包，例如 SettingsProvider，也会回调） | 改用 **libxposed API 101**（`META-INF/xposed/java_init.list` + `scope.list`=`system` + `staticScope=true`）。PROTECTIVE 模式由框架保证 fail-open |
| F10 | 策略缺失 → 最严 | 最严 = 没有任何豁免，加上 F1 就等于软件商店也无法更新 | 保留“缺失 → 最严”，但**内置默认豁免**（见 §3）；另加 `disable` 急停文件 |
| F11 | 未考虑客户端缓存 | 应用进程里的 `ApplicationPackageManager` 有 PropertyInvalidatedCache（getPackageInfo/ApplicationInfo） | 策略热加载后在 system_server 调用 `PackageManager.invalidatePackageInfoCache()`（阶段 1 确认 A16 上的方法名） |
| F12 | OAID“无 MSA” | `com.heytap.openid/.IdentifyService`（action `action.com.heytap.openid.OPEN_ID_SERVICE`） | 已在上一版修正，维持 Layer 0 |

本机规模：系统包 390、第三方包 103、用户 0 和 999（分身）都在运行。

---

## 1. 最终设计

### 1.1 列表过滤：`AppsFilterBase.shouldFilterApplication` after-hook

签名（实机）：`shouldFilterApplication(PackageDataSnapshot snapshot, int callingUid, Object callingSetting, PackageStateInternal targetPkgSetting, int userId): boolean`

原生逻辑的开头（字节码 0000–0014）：调用方 appId<10000、目标 appId<10000、或两者 appId 相同，都会直接返回 false。after-hook 决策顺序（**单调**：原值为 true 就直接返回，从不把 true 改成 false）：

```
res = chain.proceed()
if (res || !policy.listFilterOn || policy.killed) return res
cApp = getAppId(callingUid);                if (cApp < 10000) return res
if (Process.isSdkSandboxUid(callingUid))    return res
t = targetPkgSetting;  tApp = t.appId;      if (tApp < 10000 || tApp == cApp) return res
if (t.isSystem)                             return res          // 目标是系统包
callers = pkgNames(callingSetting)          // PackageStateInternal → packageName；SharedUserSetting → 成员包名
if (callerIsSystem(callingSetting) && callers ∩ policy.systemCallerDeny == ∅) return res   // F1
if (callers ∩ policy.listExempt != ∅)       return res
if (t.packageName in policy.visibleTargets) return res          // F4
if (policy.ecoOn && t.packageName in ECO)   return res          // 微信/QQ/支付宝，默认关
tUid = UserHandle.getUid(userId, tApp)
if (isImplicitlyQueryable(callingUid,tUid) || isRetainedImplicitlyQueryable(callingUid,tUid)) return res
return true
```

- `isImplicitlyQueryable` 和 `isRetainedImplicitlyQueryable` 通过 `chain.thisObject` 调用，Method 对象缓存并 `setAccessible`。
- 覆盖范围：`getInstalled*`、`queryIntent*`、`resolve*`、LauncherApps、`getPackageUid`/`getPackagesForUid`/`getNameForUid`、`resolveContentProvider`、包广播（`getVisibilityAllowList` → 同一个点）。
- **不覆盖**：startActivity（F3），以及 Settings.Secure 中包含包名的键（§6-P2）。
- 热路径约束：不做 IO、不打日志、不分配对象（包名直接取引用，HashSet 查询依赖 String 已缓存的 hash）。

### 1.2 SSAID 每日轮换（SettingsProvider，宿主 system_server）

在 `onPackageLoaded(packageName=="com.android.providers.settings")` 里用 `param.classLoader` 安装两个 hook：

1. **`SettingsProvider.getSsaidSettingLocked(PackageInfo,int userId)` after-hook**
   ```
   s = chain.proceed()                          // SettingsProvider$4，是副本
   if (s==null || !policy.ssaidOn || policy.killed) return s
   pi = args[0]; if (getAppId(pi.applicationInfo.uid) < 10000) return s
   if (pi.packageName in policy.idExempt) return s   // 注意：sharedUid 下取的是 pi 对应的包
   v = hex16( HMAC-SHA256(key, "ssaid|" + userId + "|" + sha256(signer0) + "|" + DayBucket.now()) [0..8) )
   s.setValue(v); TL_ROTATED.set(true); return s
   ```
   - `signer0`：`pi.signingInfo?.apkContentsSigners?.firstOrNull() ?: pi.signatures?.firstOrNull()`。如果两者都为空（阶段 1 确认 `getCallingPackageInfo` 的 flags），改用包名，并记录一次。
   - 生成的值如果等于 `0000000000000000` 或 `9774d56d682e549c`（已知的坏值），就把计数器加 1 重算。
2. **`SettingsProvider.packageValueForCallResult(int,String,int,Setting,boolean)` before 阶段**
   ```
   if (args[1]=="android_id" && TL_ROTATED.get()==true) { args[4]=false }
   TL_ROTATED.remove(); return chain.proceed(args)
   ```
   同一线程上的调用链是 `call → getSecureSetting → getSsaidSettingLocked → packageValueForCallResult`，用 ThreadLocal 传递标记，不需要反查调用方。另外在 `getSsaidSettingLocked` 的 hook 入口先执行 `TL_ROTATED.remove()`，防止残留。

**DayBucket**：`floor((nowUtcMs + tz.getOffset(nowUtcMs) - switchHour*3_600_000) / 86_400_000) + policy.debugBucketOffset`，其中 `switchHour` 取 12（中午）或 0（午夜）。

**密钥**：在 `onSystemServerStarting` 里：先 `mkdir /data/system/privacygate`（0700），如果 `key` 不存在，就用 `SecureRandom` 生成 32 字节，以 `O_CREAT|O_EXCL`、0600 写入。system_server 创建的文件自动继承 `system_data_file` 标签，属主是 system。

### 1.3 策略与控制面

目录 `/data/system/privacygate/`（0700 system）：

| 文件 | 写入方 | 说明 |
|---|---|---|
| `key` | system_server | 0600，UI 永远不读 |
| `policy.json` | UI（经 su，先写 tmp 再 mv 原子替换） | 见 §3 |
| `disable` | 人工/UI | 急停开关：文件存在时所有 hook 直通（监听 CREATE/DELETE 事件） |
| `status.json` | system_server | 只在事件时写：加载、每个 hook 首次命中、异常（每分钟最多 1 次）。内容：版本、各 hook 是否安装、首次命中时间、异常计数、当前日期桶 |

- 在 `onSystemServerStarting` 中同步读取策略；解析失败时用**内置默认值**（§3），并在 status 里记录 `policy_error`。
- 用 FileObserver 监听这个目录的 `CLOSE_WRITE|MOVED_TO|CREATE|DELETE` 事件，重载时构建新的不可变 `Policy` 对象，用 `@Volatile` 引用一次性替换；替换后调用 `invalidatePackageInfoCache()`（F11）。
- 热加载时如果解析失败：**保留上一份有效策略**，并写 status。

### 1.4 模块 UI

- **不通过 PackageManager 枚举应用**：UI 本身也会被过滤。改为 libsu 执行 `pm list packages -3 -U`、`pm list packages -s`、`cmd role get-role-holders android.app.role.BROWSER`、`dumpsys package <pkg>`（读 label 路径）。
- 写入流程：`cat > policy.json.tmp`，然后 `chown 1000:1000`、`chmod 600`、`chcon u:object_r:system_data_file:s0`，最后 `mv -f` 到 `policy.json`；写完读回 `ls -Z` 和 `status.json` 做校验。
- 状态页读取 `status.json`，展示各 hook 是否安装、首次命中时间、当前日期桶和异常计数。

---

## 2. 项目结构

```
<project-root>/
├── settings.gradle.kts            # include(":app", ":detector", ":libxposed-api")
├── build.gradle.kts / gradle.properties / gradlew(.bat) / gradle/wrapper
├── libxposed-api/                 # 从 ~/privacy/Vector/xposed/libxposed/api 复制（与设备上 Vector v2.2 同源）
├── app/                           # 模块 + UI，applicationId = io.github.privacygate
│   ├── build.gradle.kts           # compileOnly(project(":libxposed-api"))；libsu；minSdk 34 target/compile 36
│   └── src/main/
│       ├── AndroidManifest.xml    # 无 INTERNET；label/description
│       ├── resources/META-INF/xposed/
│       │   ├── java_init.list     # io.github.privacygate.hook.PgModule
│       │   ├── scope.list         # system
│       │   └── module.prop        # minApiVersion=101 targetApiVersion=101 staticScope=true exceptionMode=protective
│       └── java/io/github/privacygate/
│           ├── hook/PgModule.kt         # XposedModule：onSystemServerStarting / onPackageLoaded 分发
│           ├── hook/AppsFilterHooks.kt  # §1.1
│           ├── hook/SsaidHooks.kt       # §1.2
│           ├── core/DayBucket.kt        # 纯函数，JVM 单测
│           ├── core/SsaidDeriver.kt     # 纯函数 HMAC/hex16/坏值规避，JVM 单测
│           ├── core/Policy.kt           # 不可变策略 + JSON 解析(org.json) + 内置默认
│           ├── core/PolicyStore.kt      # 读/FileObserver/status 写/密钥
│           ├── ui/RootConfigWriter.kt   # libsu 写入 + 校验
│           └── ui/ConfigActivity.kt
├── detector/                      # 探测器，两个 flavor：full（声明 QUERY_ALL_PACKAGES）/ queries（仅 <queries>）
├── tools/
│   ├── audit/PKG110_16.0.0.205/   # 已复制：services.jar oplus-services.jar SettingsProvider.apk queries-baseline.txt SHA256SUMS
│   ├── audit/dexgrep.py           # 反编译 + 签名校验脚本（OTA 后重跑）
│   └── verify/{run_detector.sh, diff_report.py}
├── policy/policy.default.json
└── docs/{PLAN.md, audit.md, verify-log.md, README.md}
```

---

## 3. policy.json 结构（附内置默认值）

```json
{
  "version": 1,
  "list_filter_enabled": true,
  "ssaid_rotation_enabled": true,
  "switch_hour": 12,
  "list_exempt": ["com.heytap.market", "com.android.vending", "io.github.privacygate",
                  "io.github.lsposed.disableflagsecure", "com.sohu.inputmethod.sogou"],
  "id_exempt": [],
  "visible_targets": ["mark.via"],
  "system_caller_deny": ["com.opos.ads"],
  "eco_whitelist_enabled": false,
  "eco_whitelist": ["com.tencent.mm", "com.tencent.mobileqq", "com.eg.android.AlipayGphone"],
  "debug_bucket_offset": 0
}
```

- 首次安装时下发的 `policy/policy.default.json` 中，两个主开关都设为 **false**，用于灰度（§4 阶段 3）。
- **内置默认值**（文件缺失或损坏时使用）：两个开关都为 true，`list_exempt` 至少包含商店和模块自身，`visible_targets` 为空，其余字段取上表的值。
- `id_exempt` 由你在 UI 里勾选银行/支付/证券类 app。本机目前没有看到明显的银行类包名，所以默认为空。

---

## 4. 实施步骤（每个阶段都有退出条件）

### 阶段 0 — 骨架（约 0.5 天）
1. 复制 libxposed-api：
   ```bash
   cp -r ~/privacy/Vector/xposed/libxposed/api <project-root>/libxposed-api
   ```
2. 在 Windows PowerShell 里执行 `gradle wrapper --gradle-version 8.14`（或者从 Vector 复制 `gradle/wrapper`），AGP 8.x，compileSdk 36，JDK 17。
3. `gradlew.bat :app:assembleDebug :detector:assembleFullDebug :detector:assembleQueriesDebug` 构建成功。
4. `DayBucket`、`SsaidDeriver`、`Policy` 的 JVM 单测通过：跨中午/午夜的边界、`debug_bucket_offset`、坏值规避、损坏 JSON 回退到内置默认值。

**退出条件**：三个 APK 都能构建，单测全部通过。

### 阶段 1 — 审计收尾（约 0.5 天，产出 `docs/audit.md`）
已经确认的（直接写入 audit.md）：F3、F6、F7、F8 的字节码证据，以及 `AppsFilterBase` 各方法的签名。
还需确认的事项和方法：
| 项 | 方法 |
|---|---|
| `PackageStateInternal.isSystem()` / `getPackageName()` / `getAppId()` 的接口签名 | 用 dexdump 查 services.jar 的 `Lcom/android/server/pm/pkg/PackageStateInternal;` 和 `PackageState` |
| `SharedUserSetting` 获取成员包名的方法 | 同上，查 `Lcom/android/server/pm/SharedUserSetting;` |
| `PackageManager.invalidatePackageInfoCache` 在 A16 上是否存在 | 执行 `adb pull /system/framework/framework.jar`，再 dexdump 后 grep |
| `getCallingPackageInfo` 的 flags（signatures 是否填充） | dexdump 查 SettingsProvider `getCallingPackageInfo` 的常量 |
| `onPackageLoaded` 在 system_server 里是否对 `com.android.providers.settings` 回调 | 阶段 3 装机后看 status.json / logcat |

**退出条件**：audit.md 列出每个 hook 点的完整签名和字节码偏移依据；`tools/audit/dexgrep.py` 能一键重跑并对比签名（OTA 后使用）。

### 阶段 2 — 探测器与基线（约 1 天）
探测器以 `am start -n <det>/.Main --es run all` 触发，结果输出为 logcat `PGDetect` 的一行 JSON，同时写入 `getExternalFilesDir()/report-<ts>.json`。

| ID | 检测项 | 启用后期望（非豁免） |
|---|---|---|
| L1/L2 | `getInstalledPackages/Applications(0)` 中的非系统包 | 只有自己 |
| L3 | `queryIntentActivities(MAIN/LAUNCHER)` | 只有系统包和自己 |
| L4 | `getPackageInfo` 探测名单（mm、pinduoduo、bili、mark.via、sogou、gkd、privacygate、vector 相关包） | 只有 `visible_targets` 可见 |
| L5 | `getPackagesForUid` / `getNameForUid` 扫描 10000–10999 以及 99910000–99910999 | 不出现第三方包 |
| L6 | LauncherApps `getActivityList` | 同 L3 |
| L7 | `queryIntentServices/ContentProviders`、`resolveContentProvider`（已知 authority） | 无第三方 |
| L8 | 动态注册 `PACKAGE_ADDED/REMOVED` 后，adb 安装/卸载 `test-dummy.apk` | 收不到 |
| L9 | `resolveActivity(VIEW http)` | 能解析到 mark.via |
| L10 | startActivity 显式启动**未导出**组件（例如微信某个 non-exported activity），比较异常类型 | 记录（残余泄露，F3） |
| L11 | 读取 `Settings.Secure`：default_input_method、enabled_input_methods、enabled_accessibility_services、autofill_service、voice_interaction_service、selected_spell_checker | 记录（§6-P2 的输入） |
| L12 | `InputMethodManager.getInputMethodList`、`AccessibilityManager.getInstalled/EnabledAccessibilityServiceList` | 记录 |
| I1 | `Settings.Secure.getString(ANDROID_ID)` 读 2 次；`query(content://settings/secure/android_id)`；整表 query | 三条路径的值一致 |
| I2 | 绑定 `OPEN_ID_SERVICE` 读取 OUID | Layer 0 之后为空或全 0 |

基线：模块未安装时，两个 flavor 各跑一次，结果存入 `docs/verify-log.md`。**确认 L10、L11、L12 在原生状态下是否泄露**，决定 §6-P2 是否要做。

**退出条件**：基线报告入库，并确认拼多多类（queries flavor）在 L3 能看到大约 200 个包，复现原生泄露。

### 阶段 3 — 列表过滤 MVP（约 1 天）
1. 执行 `adb install app-debug.apk`，Vector 管理器里启用模块，作用域为「系统框架」。
2. 用 su 下发 `policy.default.json`（两个开关都为 false），然后**重启**。
3. 检查：`status.json` 中 AppsFilter hook 已安装；logcat 里没有 `PrivacyGate` 异常；桌面、分享面板、通知都正常（此时开关关闭，行为应与原生一致）。
4. 热切换 `list_filter_enabled=true`，**不重启**，然后：
   - 两个 flavor 的探测器 L1–L9 都符合期望；
   - **桌面图标完整**、系统分享面板能分享到第三方目标、权限管理页能看到第三方应用、软件商店能检测到更新（这 4 项验证 F1）；
   - `adb shell pm list packages -3 | wc -l` 仍是 103；
   - 打开 `eco_whitelist_enabled` 后测微信登录往返：从 B 站发起微信登录或分享，能正常回调；
   - 分身用户：在 999 里的微信运行探测器（或者用 `pm install --user 999` 安装探测器）。
5. 急停演练：`touch /data/system/privacygate/disable`，行为立即恢复原生；删除该文件后过滤恢复。

**退出条件**：以上全部通过；运行 24 小时，system_server 没有崩溃（`adb shell dumpsys dropbox --print system_server_crash` 为空）。

### 阶段 4 — SSAID（约 1 天）
1. 热切换 `ssaid_rotation_enabled=true`。
2. 验证：
   - I1 三条路径的值一致，但和原始 SSAID 不同（原始值用 `su -c cat /data/system/users/0/settings_ssaid.xml` 对照，只读）；
   - 两个不同签名的 app 值不同；同签名的两个 app 值相同；
   - **同进程跨桶**：探测器常驻读取 → 通过 UI 把 `debug_bucket_offset` 设为 +1 → 同一个进程再次读取，值变化（验证 F7 的缓存剥离），再改回 0；
   - 卸载后重装探测器，值不变；
   - 分身用户 999 的值与主用户不同；
   - 把探测器加入 `id_exempt` 后读到真值；
   - `settings_ssaid.xml` 的 mtime 和内容全程不变（验证 F8）。
3. 真实跳变：等一次真实的 12:00，确认在不重启进程的情况下值变化。

**退出条件**：以上全部通过；运行 24 小时，system_server 没有崩溃。

### 阶段 5 — 配置 UI（约 1 天）
主开关 ×2、急停、中午/午夜切换、list_exempt / id_exempt / visible_targets / system_caller_deny 编辑、生态白名单开关、状态页、“一键把浏览器角色持有者加入 visible_targets”。

**退出条件**：UI 写入 → FileObserver 热加载 → status.json 回显，形成闭环；`ls -Z` 校验失败时 UI 报错，不会静默失败。

### 阶段 6 — 端到端（持续 2–3 天）
- 用拼多多、B 站、高德实际使用：检查分享、登录、支付跳转、打开链接。
- 功耗：执行 `adb shell dumpsys batterystats --reset`，24 小时后执行 `adb shell dumpsys batterystats | grep -i -E "wake|privacygate"`，确认没有新增 wakelock 或 alarm（本设计不注册任何 alarm 或 wakelock）。
- 回滚演练：在 Vector 里禁用模块并重启，行为恢复原生；再删除 `/data/system/privacygate/`。

### 阶段 7 — 文档
README：安装、Layer 0、急停与回滚、OTA 后的重审计流程（`dexgrep.py` 对比签名 → 探测器回归）、残余泄露清单。

---

## 5. 急停与回滚（按顺序由轻到重）

1. 热急停（无需重启）：
   ```bash
   adb shell su -c 'touch /data/system/privacygate/disable'
   ```
2. 单项关闭：通过 UI，或者用 su 修改 policy.json 里对应的开关。
3. 禁用模块：在 Vector 管理器里取消勾选，然后重启。
4. 无法开机或循环软重启：在开机动画阶段用 Magisk 安全模式（按住音量下键），或者执行：
   ```bash
   adb shell su -c 'touch /data/adb/modules/zygisk_vector/disable'
   ```
5. 清理：
   ```bash
   adb shell su -c 'rm -rf /data/system/privacygate'
   ```

---

## 6. 残余泄露与后续（按优先级）

- **P2-a startActivity 静默探测（F3）**：如果阶段 2 的 L10 证实存在，就在 ActivityStarter/`resolveIntent` 的结果阶段处理：非豁免调用方显式指定了一个被隐藏包的**未导出**组件时，返回“未找到”。已导出组件的正常启动不受影响。hook 点在阶段 1 追加审计。
- **P2-b Settings.Secure 中的包名（L11）**：如果证实第三方 app 能读到，就在 `getSecureSetting` 上做 after-hook，对非豁免调用方的这几个键剔除第三方组件（同样返回副本，不写回存储）。
- **P2-c IMM/Accessibility 列表（L12）**：只做记录。如果泄露，再评估是否在服务侧过滤。
- **不覆盖**：文件系统和 /proc 探测、IP/网络指纹（由 privacy_pretect 负责）、SDK 已缓存的旧 ID（清除数据才会消失）、云端画像、传感器/屏幕指纹、ColorOS 系统级数据采集（系统调用方默认放行，见 F1）。

## 7. Layer 0（手动，一次性）
- 「获取应用列表」（`GET_INSTALLED_APPS`）对每个 app 设为拒绝，不 hook。
- 设置 → 隐私 → 广告与隐私：关闭个性化广告，并重置 OAID。
- 设置 → Google → 广告：删除广告 ID。
