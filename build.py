#!/usr/bin/env python3
"""构建脚本：把 frontend/static.js 安全嵌入 _worker.js 的 renderStaticJS()。

用法: python3 build.py
- 读取 frontend/static.js，做 lint（禁止反引号与 ${}）
- 转义后替换 _worker.js 中 "// ---------------- 前端 JS ----------------" 标记之后的内容
- 生成后做往返校验：用 node 执行 renderStaticJS()，对比输出与源码一致
- 对 _worker.js 与提取出的前端做 node --check
"""
import re
import subprocess
import sys
import tempfile
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
FRONTEND_SRC = os.path.join(ROOT, "frontend", "static.js")
WORKER = os.path.join(ROOT, "_worker.js")
MARKER = "// ---------------- 前端 JS ----------------"


def escape_js_string(s: str) -> str:
    # 顺序重要：先转义反斜杠
    s = s.replace("\\", "\\\\")
    s = s.replace('"', '\\"')
    s = s.replace("\r\n", "\n")
    s = s.replace("\r", "\n")
    s = s.replace("\n", "\\n")
    return s


def main() -> int:
    with open(FRONTEND_SRC, "r", encoding="utf-8") as f:
        src = f.read()

    # lint：前端源码约定（避免模板转义问题）
    bad = []
    if "`" in src:
        bad.append("源码中包含反引号 `")
    if "${" in src:
        bad.append("源码中包含 ${")
    if bad:
        print("LINT 失败：", file=sys.stderr)
        for b in bad:
            print(" - " + b, file=sys.stderr)
        return 1

    escaped = escape_js_string(src)
    new_tail = (
        MARKER + "\n"
        + "// 注意：前端代码中不使用反引号与 ${}，全部用字符串拼接，避免模板转义问题\n"
        + "// 本段由 build.py 自动生成，请勿手工编辑；改 frontend/static.js 后重新运行 build.py\n"
        + "function renderStaticJS() {\n"
        + '  return "' + escaped + '";\n'
        + "}\n"
    )

    with open(WORKER, "r", encoding="utf-8") as f:
        worker = f.read()
    idx = worker.find(MARKER)
    if idx < 0:
        print("在 _worker.js 中找不到标记: " + MARKER, file=sys.stderr)
        return 1
    new_worker = worker[:idx] + new_tail
    with open(WORKER, "w", encoding="utf-8") as f:
        f.write(new_worker)
    print("已写入 _worker.js（%d bytes）" % len(new_worker))

    # node --check _worker.js
    r = subprocess.run(["node", "--check", WORKER], capture_output=True, text=True)
    if r.returncode != 0:
        print("_worker.js 语法校验失败：\n" + r.stderr, file=sys.stderr)
        return 1
    print("_worker.js 语法 OK")

    # 往返校验：只执行 renderStaticJS 片段（不含 ESM 顶层代码），输出与源码对比
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as tf:
        tf.write(new_tail + "\nconsole.log(JSON.stringify(renderStaticJS()));\n")
        tmp = tf.name
    try:
        r = subprocess.run(["node", tmp], capture_output=True, text=True)
        if r.returncode != 0:
            print("renderStaticJS() 执行失败：\n" + r.stderr, file=sys.stderr)
            return 1
        import json
        roundtrip = json.loads(r.stdout)
        if roundtrip != src:
            # 找出第一个差异位置
            n = min(len(roundtrip), len(src))
            pos = next((i for i in range(n) if roundtrip[i] != src[i]), n)
            print("往返校验失败：首个差异在字符 %d（总长 %d vs %d）" % (pos, len(roundtrip), len(src)), file=sys.stderr)
            print("期望: ..." + repr(src[max(0, pos-40):pos+40]), file=sys.stderr)
            print("实际: ..." + repr(roundtrip[max(0, pos-40):pos+40]), file=sys.stderr)
            return 1
        print("往返校验 OK（renderStaticJS() 输出与 frontend/static.js 完全一致）")
        # 前端源码语法校验
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as tf2:
            tf2.write(roundtrip)
            tmp2 = tf2.name
        r = subprocess.run(["node", "--check", tmp2], capture_output=True, text=True)
        os.unlink(tmp2)
        if r.returncode != 0:
            print("前端 JS 语法校验失败：\n" + r.stderr, file=sys.stderr)
            return 1
        print("前端 JS 语法 OK")
    finally:
        os.unlink(tmp)
    print("构建成功")
    return 0


if __name__ == "__main__":
    sys.exit(main())
