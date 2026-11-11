#!/usr/bin/env python3
"""构建期工具：扫描已批准助手目录，生成可信启动配置 JSON。

仅在镜像构建阶段运行；生成的 JSON 随后复制到镜像内只读路径
``/etc/diag-runner/assistants.json``，运行期不再修改。

用法::

    python3 -I scripts/build_manifest.py \\
        --tools-dir /opt/diag-golden \\
        --out /build/assistants.json \\
        --specs scripts/assistant_specs.json

specs 示例::

    {
      "defaults": {"timeout_seconds": 3.0, "max_output_bytes": 65536},
      "assistants": {
        "archinfo": {"path": "/var/lib/diag-tools/archinfo", "args": ["--verbose"]}
      }
    }

``path`` 写运行期容器内路径；``--tools-dir`` 指向构建产物所在目录，
取 basename 与 path 末段对应，哈希按构建产物计算。
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.runner.config import (  # noqa: E402
    DEFAULT_MAX_ASSISTANT_BYTES,
    DEFAULT_MAX_CONCURRENCY,
    HARD_MAX_ASSISTANT_BYTES,
    HARD_MAX_CONCURRENCY,
    HARD_MAX_OUTPUT_BYTES,
    HARD_TIMEOUT_SECONDS,
    sha256_file,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="生成受控执行可信配置")
    parser.add_argument("--tools-dir", required=True, help="构建产物目录（已编译 ELF）")
    parser.add_argument("--specs", required=True, help="助手 ID/路径/参数规格 JSON")
    parser.add_argument("--out", required=True, help="输出 manifest JSON 路径")
    args = parser.parse_args()

    with open(args.specs, "r", encoding="utf-8") as fh:
        specs = json.load(fh)

    defaults = specs.get("defaults", {})
    out = {
        "defaults": {
            "timeout_seconds": float(defaults.get("timeout_seconds", 3.0)),
            "max_output_bytes": int(defaults.get("max_output_bytes", 64 * 1024)),
            "max_assistant_bytes": int(
                defaults.get("max_assistant_bytes", DEFAULT_MAX_ASSISTANT_BYTES)
            ),
            "max_concurrency": int(defaults.get("max_concurrency", DEFAULT_MAX_CONCURRENCY)),
        },
        "assistants": {},
    }

    # 硬性上限自检
    d = out["defaults"]
    assert d["timeout_seconds"] <= HARD_TIMEOUT_SECONDS
    assert d["max_output_bytes"] <= HARD_MAX_OUTPUT_BYTES
    assert d["max_assistant_bytes"] <= HARD_MAX_ASSISTANT_BYTES
    assert d["max_concurrency"] <= HARD_MAX_CONCURRENCY

    for assistant_id, item in specs["assistants"].items():
        runtime_path = item["path"]
        if not os.path.isabs(runtime_path):
            raise SystemExit(f"{assistant_id}: path 必须是绝对路径")
        local_leaf = os.path.basename(runtime_path)
        local_path = os.path.join(args.tools_dir, local_leaf)
        if not os.path.isfile(local_path):
            raise SystemExit(f"{assistant_id}: 构建产物不存在 {local_path}")
        size = os.path.getsize(local_path)
        if size > HARD_MAX_ASSISTANT_BYTES:
            raise SystemExit(f"{assistant_id}: {size} 字节超过 8 MiB 上限")

        entry = {
            "path": runtime_path,
            "sha256": sha256_file(local_path),
            "args": list(item.get("args", [])),
            "timeout_seconds": float(
                item.get("timeout_seconds", d["timeout_seconds"])
            ),
            "max_output_bytes": int(
                item.get("max_output_bytes", d["max_output_bytes"])
            ),
        }
        assert entry["timeout_seconds"] <= HARD_TIMEOUT_SECONDS
        assert entry["max_output_bytes"] <= HARD_MAX_OUTPUT_BYTES
        out["assistants"][assistant_id] = entry
        print(
            f"pinned {assistant_id}: {runtime_path} {size}B sha256={entry['sha256'][:16]}..."
        )

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print(f"manifest written: {args.out} ({len(out['assistants'])} assistants)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
