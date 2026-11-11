# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# 阶段 1：编译已批准的诊断助手（普通 ELF，不派生子进程）并生成可信清单
# ---------------------------------------------------------------------------
FROM gcc:14-bookworm AS builder

# gcc 镜像默认不含 python3，清单生成脚本需要它（仅构建期）
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY tools/ ./tools/
COPY tests/fixtures/ ./tests/fixtures/
COPY app ./app
COPY scripts/assistant_specs.json ./scripts/assistant_specs.json
COPY scripts/build_manifest.py ./scripts/build_manifest.py

RUN set -eux; \
    mkdir -p /build/out /build/prebuilt; \
    for src in tools/*.c; do \
        name="$(basename "$src" .c)"; \
        gcc -O2 -Wall -Wextra -o "/build/out/$name" "$src"; \
    done; \
    for src in tests/fixtures/*.c; do \
        name="$(basename "$src" .c)"; \
        gcc -O2 -Wall -Wextra -o "/build/prebuilt/$name" "$src"; \
    done; \
    cp /build/out/archinfo /build/out/slowprobe /build/out/bigprinter /build/prebuilt/; \
    ls -l /build/out /build/prebuilt

# 基于编译产物计算 SHA-256，生成固定 ID/路径/哈希/参数的可信启动配置
RUN python3 -I scripts/build_manifest.py \
        --tools-dir /build/out \
        --specs scripts/assistant_specs.json \
        --out /build/assistants.json \
 && cat /build/assistants.json

# ---------------------------------------------------------------------------
# 阶段 2：运行镜像（无编译器，非 root，只读根文件系统）
# ---------------------------------------------------------------------------
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DIAG_CONFIG_PATH=/etc/diag-runner/assistants.json \
    DIAG_TOOLS_DIR=/var/lib/diag-tools

WORKDIR /opt/sandbox-checker

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts/entrypoint.sh /usr/local/bin/diag-entrypoint.sh
RUN chmod 0755 /usr/local/bin/diag-entrypoint.sh

# 黄金副本（只读基准）与可信清单（固定哈希），运行期不可被服务用户修改
COPY --from=builder /build/out /opt/diag-golden
COPY --from=builder /build/prebuilt/forker /opt/diag-golden/forker
COPY --from=builder /build/assistants.json /etc/diag-runner/assistants.json
RUN chmod 0755 /opt/diag-golden/* \
 && chmod 0444 /etc/diag-runner/assistants.json

# 测试夹具（已编译），供容器内运行测试套件
COPY tests /opt/sandbox-checker/tests
COPY --from=builder /build/prebuilt /opt/sandbox-checker/tests/prebuilt

RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3).status==200 else 1)"

ENTRYPOINT ["/usr/local/bin/diag-entrypoint.sh"]
