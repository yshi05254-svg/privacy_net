#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dexgrep.py — PrivacyGate hook 点签名审计工具（PLAN §4-阶段1 / §7 OTA 重审计）

用法:
  python dexgrep.py extract <jar|apk|dir> <outdir>               # 解出全部 *.dex
  python dexgrep.py sig <dexdir> <class_regex> [method_regex]    # 类/方法签名检索（流式低内存）
  python dexgrep.py dis <dexdir> <class_regex> <method_regex>    # 反汇编匹配方法（含字节码偏移）

dexdump 路径: --dexdump 或环境变量 DEXDUMP，默认从 %ANDROID_HOME%/build-tools 探测。
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path


def find_dexdump(explicit=None):
    if explicit:
        return explicit
    env = os.environ.get("DEXDUMP")
    if env:
        return env
    cands = [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        r"E:/soft/Android/Sdk",
    ]
    for sdk in cands:
        if not sdk:
            continue
        bt = Path(sdk) / "build-tools"
        if bt.is_dir():
            for v in sorted(bt.iterdir(), reverse=True):
                p = v / ("dexdump.exe" if os.name == "nt" else "dexdump")
                if p.is_file():
                    return str(p)
    raise SystemExit("dexdump not found; pass --dexdump")


def cmd_extract(src, outdir):
    src, outdir = Path(src), Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    n = 0
    if src.is_dir():
        for d in sorted(src.glob("*.dex")):
            shutil.copy2(d, outdir / d.name)
            print(f"{d.name}  {(outdir / d.name).stat().st_size}")
            n += 1
    else:
        with zipfile.ZipFile(src) as z:
            for name in z.namelist():
                if name.endswith(".dex") and not name.startswith("META-INF"):
                    target = outdir / f"{src.stem}__{name.replace('/', '_')}"
                    with z.open(name) as f, open(target, "wb") as g:
                        shutil.copyfileobj(f, g)
                    print(f"{target.name}  {target.stat().st_size}")
                    n += 1
    print(f"extracted {n} dex -> {outdir}")


def dexdump_lines(dexdump, dex, disasm=False):
    cmd = [dexdump] + (["-d"] if disasm else []) + [str(dex)]
    p = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, encoding="utf-8", errors="replace", bufsize=1,
    )
    for line in p.stdout:
        yield line.rstrip("\n")
    p.wait()


def cmd_sig(dexdir, class_re, method_re, dexdump):
    cre = re.compile(class_re)
    mre = re.compile(method_re) if method_re else None
    cur_class = None
    section = "?"
    pending = None
    for dex in sorted(Path(dexdir).glob("*.dex")):
        cur_class = None
        pending = None
        for line in dexdump_lines(dexdump, dex):
            m = re.search(r"Class descriptor\s*:\s*'([^']+)'", line)
            if m:
                cur_class = m.group(1)
                continue
            if re.match(r"\s*(Direct|Virtual) methods", line):
                section = "direct" if "Direct" in line else "virtual"
                continue
            m = re.match(r"\s+name\s*:\s*'([^']+)'", line)
            if m:
                pending = m.group(1)
                continue
            m = re.match(r"\s+type\s*:\s*'([^']+)'", line)
            if m and pending:
                if cur_class and cre.search(cur_class) and (mre is None or mre.search(pending)):
                    print(f"{dex.name}\t{section:7}\t{cur_class}\t{pending}\t{m.group(1)}", flush=True)
                pending = None


# 指令行两种形态：6位代码偏移+管道后的dex偏移（正文指令），以及 0x 开头（debug/locals 表）
INSN_RE = re.compile(r"^([0-9a-f]{6}: .*\|[0-9a-f]{4}: |\s+0x)")


def cmd_dis(dexdir, class_re, method_re, dexdump):
    cre = re.compile(class_re)
    mre = re.compile(method_re)
    for dex in sorted(Path(dexdir).glob("*.dex")):
        cur_class = None
        pending = None
        cap = False
        out = []

        def flush():
            nonlocal cap
            if out:
                print("\n".join(out), flush=True)
                out.clear()
            cap = False

        for line in dexdump_lines(dexdump, dex, disasm=True):
            m = re.search(r"Class descriptor\s*:\s*'([^']+)'", line)
            if m:
                flush()
                cur_class = m.group(1)
                continue
            m = re.match(r"\s+name\s*:\s*'([^']+)'", line)
            if m:
                flush()
                pending = m.group(1)
                continue
            m = re.match(r"\s+type\s*:\s*'([^']+)'", line)
            if m and pending is not None:
                if cur_class and cre.search(cur_class) and mre.search(pending):
                    out.append(f"### {dex.name} {cur_class} -> {pending}{m.group(1)}")
                    cap = True
                pending = None
                continue
            if cap and INSN_RE.match(line):
                out.append(line.rstrip())
        flush()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dexdump", default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p1 = sub.add_parser("extract")
    p1.add_argument("src")
    p1.add_argument("outdir")
    p2 = sub.add_parser("sig")
    p2.add_argument("dexdir")
    p2.add_argument("class_re")
    p2.add_argument("method_re", nargs="?", default=None)
    p3 = sub.add_parser("dis")
    p3.add_argument("dexdir")
    p3.add_argument("class_re")
    p3.add_argument("method_re")
    a = ap.parse_args()
    dd = find_dexdump(a.dexdump)
    if a.cmd == "extract":
        cmd_extract(a.src, a.outdir)
    elif a.cmd == "sig":
        cmd_sig(a.dexdir, a.class_re, a.method_re, dd)
    elif a.cmd == "dis":
        cmd_dis(a.dexdir, a.class_re, a.method_re, dd)


if __name__ == "__main__":
    main()
