#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""采集探测器报告（PLAN §4-阶段2）。

用法:
  python collect_report.py <full|queries> [--esa-comps "pkg/cls;pkg/cls"] [--wait 90]

主通道: 轮询 run-as 读应用内部 files/report-*.json（路径为相对形式，不受 MSYS 路径转换影响）
备用通道: logcat PGDetect 的 PART 分块(base64)重组——注意设备 main 缓冲仅 128KiB 且日志刷写极快，
          分块可能来不及抓取，因此内部文件轮询是可靠通道。
注意: applicationIdSuffix 使运行时包名带后缀，但 Activity 类在 namespace 包里，
      am start 必须写完整类路径 pkg/io.github.privacygate.detector.Main。
"""

import argparse
import base64
import json
import re
import subprocess
import sys
import time
from pathlib import Path

PKG = {
    "full": "io.github.privacygate.detector.full",
    "queries": "io.github.privacygate.detector.queries",
}


def sh(*args, binary=False):
    r = subprocess.run(args, capture_output=True)
    return r.stdout if binary else r.stdout.decode("utf-8", "replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("flavor", choices=["full", "queries"])
    ap.add_argument("--esa-comps", default=None)
    ap.add_argument("--wait", type=int, default=90)
    ap.add_argument("--min-new", type=int, default=1, help="要求 files/ 里至少存在 N 个报告")
    a = ap.parse_args()
    pkg = PKG[a.flavor]

    # 采集前记录当前已有报告数，等待新增
    def list_reports():
        out = sh("adb", "exec-out", "run-as", pkg, "ls", "files/")
        return sorted(n for n in out.split() if n.startswith("report-") and n.endswith(".json"))

    # -f 0x20000000 = FLAG_ACTIVITY_SINGLE_TOP：报告轮次复用已在前台的 activity（onNewIntent 重投 intent）。
    # --esa 的数组分隔符是逗号；comps 形如 pkg/cls,pkg/cls,...
    sh("adb", "logcat", "-c")
    cmd = [
        "adb", "shell", "am", "start", "-f", "0x20000000", "-n",
        f"{pkg}/io.github.privacygate.detector.Main", "--es", "run", "all",
    ]
    if a.esa_comps:
        cmd += ["--esa", "comps", a.esa_comps]
    out = sh(*cmd).strip()
    print("start:", out.splitlines()[-1] if out else "?")

    baseline = list_reports()
    data = None
    deadline = time.time() + a.wait
    while time.time() < deadline:
        time.sleep(3)
        now = list_reports()
        fresh = [n for n in now if n not in baseline]
        if len(now) - len(baseline) >= a.min_new and fresh:
            newest = sorted(fresh)[-1]
            raw = sh("adb", "exec-out", "run-as", pkg, "cat", f"files/{newest}", binary=True)
            if raw:
                data = raw.decode("utf-8", "replace")
                break

    if not data:
        # 备用：logcat 分块
        log = sh("adb", "logcat", "-d", "-s", "PGDetect")
        parts = {}
        for line in log.splitlines():
            m2 = re.search(r"PART (\S+) (\d+) (\S+)$", line.strip())
            if m2:
                parts.setdefault(m2.group(1), {})[int(m2.group(2))] = m2.group(3)
        if parts:
            rid = sorted(parts)[-1]
            blob = "".join(parts[rid][k] for k in sorted(parts[rid]))
            data = base64.b64decode(blob).decode("utf-8", "replace")

    if not data:
        print("NO REPORT FOUND")
        sys.exit(1)

    parsed = json.loads(data)
    outdir = Path(__file__).resolve().parents[2] / "runs"
    outdir.mkdir(exist_ok=True)
    dest = outdir / f"{a.flavor}-{time.strftime('%Y%m%d-%H%M%S')}.json"
    dest.write_text(json.dumps(parsed, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"saved: {dest}")
    print("summary:")
    print(f"  flavor={parsed.get('flavor')} pkg={parsed.get('pkg')}")
    for key in sorted(k for k in parsed if k.startswith(("L", "I")) and not k.endswith("_ms")):
        v = parsed[key]
        ms = parsed.get(f"{key}_ms", "?")
        if isinstance(v, dict) and "error" in v:
            print(f"  {key}: ERROR {v['error']} ({ms}ms)")
        elif isinstance(v, dict) and "count" in v:
            extra = f" third_party={v.get('third_party_count', len(v.get('third_party', [])))}" \
                if "third_party" in v else ""
            print(f"  {key}: count={v['count']}{extra} ({ms}ms)")
        elif isinstance(v, dict) and "visible" in v:
            print(f"  {key}: visible={v['visible']} ({ms}ms)")
        else:
            print(f"  {key}: ok ({ms}ms)")


if __name__ == "__main__":
    main()
