# 审计产物说明

固件二进制（`services.jar` / `oplus-services.jar` / `SettingsProvider.apk` 及 `extracted/` 下的 dex）属厂商专有文件，未随仓库分发；
`SHA256SUMS` 记录了原始文件的哈希，可从同版本固件（PKG110 16.0.0.205）自行提取后用 `../dexgrep.py` 复现 `queries/` 下的结果。
