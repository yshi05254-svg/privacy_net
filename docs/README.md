# PrivacyGate

应用列表防泄露 + Android ID 每日轮换的 Xposed 模块（Vector v2.2 / libxposed API 101，作用域=系统框架）。

- 设计与实施计划见 `docs/PLAN.md`（可执行版，含字节码证据）
- hook 点签名级审计基线见 `docs/audit.md`
- 验证记录见 `docs/verify-log.md`（阶段 2 起填写）

## 构建

```bash
./gradlew.bat :app:assembleDebug :app:testDebugUnitTest :detector:assembleFullDebug :detector:assembleQueriesDebug
```

产物：`app/build/outputs/apk/debug/app-debug.apk`、`detector/build/outputs/apk/{full,queries}/debug/*.apk`

## 状态

- [x] 阶段 0 骨架（3 APK + 19 单测；detector 双 flavor 已分包包名 .full/.queries）
- [x] 阶段 1 审计基线（docs/audit.md）
- [x] (e) 项装机预验证：onPackageLoaded 回调 SettingsProvider 已实测确认，SSAID 挂载走 PLAN §1.2 原方案
- [x] 阶段 2 探测器 + 原生基线（docs/verify-log.md；LAUNCHER 查询 94 第三方全裸奔 / L10 异常对比法成立 / L11 3 键可读）
- [x] 阶段 3 代码完成并打包（35 单测全绿；**未装机**——按指示暂不推送）
- [ ] 阶段 3 装机验证（双开关关→重启→热切换开→桌面/分享面板/权限页/商店4项+探测器全绿）
- [ ] 阶段 4 SSAID 每日轮换
- [ ] 阶段 5 配置 UI
- [ ] 阶段 6 端到端验证

## 设备侧操作速查（Vector CLI，root shell）

```bash
/data/adb/lspd/cli modules ls|enable|disable <pkg>     # 模块管理
/data/adb/lspd/cli scope set|add|rm|ls <pkg> app/uid   # 作用域（system_server 用 system/0）
/data/adb/lspd/cli status                              # 框架状态（API Version: 102）
```

## 与 PLAN 的偏差

1. libxposed-api 未从 Vector 源码拷贝（本机无 `~/...` 路径），改用 Maven Central
   `io.github.libxposed:api:101.0.1` 同源发布物，classes.jar 拷贝至 `libs/libxposed/`。
2. Gradle 用 8.13（本机 wrapper 缓存命中，免下载）而非 PLAN 建议的 8.14；AGP 8.10.1 兼容。
