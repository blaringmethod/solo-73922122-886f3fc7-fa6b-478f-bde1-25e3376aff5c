# 受控诊断助手执行 & systemd 沙箱策略核查服务

面向 Linux 服务维护人员的离线服务，包含两部分能力：

1. **受控诊断助手执行 API（新增）**：远程运行已批准的诊断助手，采集架构等
   排障信息。调用方只传**助手 ID**；可信启动配置固定每个助手的 ID、路径、
   SHA-256 与参数，从机制上防止可写工具目录被换入其他程序。
2. **systemd 沙箱策略离线核查 API（保留）**：`/api/v1/evaluate` 原样保留，
   按时间回放进程审计事件，判定守护进程的真实文件操作会不会被沙箱阻断。

服务运行期不发起任何外部网络请求，判定/执行逻辑仅依赖 Python 标准库
（FastAPI 只提供 HTTP 与 `/docs`）。

---

## 一、受控执行 API 的安全模型

### 威胁与目标

诊断助手存放在**可写工具目录**（维护流程需要更新它们），因此目录本身不可信：
攻击者可能把助手**整体替换**成另一个程序、**截断**文件、或**原地改写**字节，
替换可能发生在服务读取、核验或启动的任意时点。要求：每次都先核验完整内容，
且执行的必须是**同一份不可变字节**；直接执行仍可改写的源文件不满足要求。

### 核验-封印-执行闭环（`app/runner/executor.py`）

每次调用严格按下列步骤执行，任何一步失败都直接拒绝、绝不执行：

1. **只认 ID**：调用方仅提交 `assistant_id`。路径、SHA-256、参数全部来自
   镜像内只读清单 `/etc/diag-runner/assistants.json`，请求体不接受任何
   路径/参数/环境变量字段（`extra="forbid"`）。
2. **安全打开源文件**：`O_RDONLY | O_NOFOLLOW | O_CLOEXEC` 打开，拒绝符号
   链接；`fstat` 确认是常规文件、无 SUID/SGID/粘滞位，尺寸不超过 **8 MiB**。
3. **限额读取 + 读取窗监测**：分块读入内存，每轮 `fstat` 同一打开描述符，
   发现 inode 身份/尺寸/ctime 变化即拒绝。
4. **memfd 不可变封印**：字节写入新建的 `memfd_create(..., MFD_ALLOW_SEALING)`
   匿名内存文件，施加 `F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE |
   F_SEAL_SEAL`。封印后任何进程（含 root）都无法修改、截断、追加这份字节，
   也不能再加/解封印。
5. **对封印字节重新全量核验**：重新完整读取 memfd，计算 **SHA-256** 与清单
   比对（常量时间比较），再做**普通 ELF 校验**。哈希与 ELF 校验的对象就是
   即将执行的同一份不可变字节，而不是某个可能再变化的源路径。
6. **关闭读取后到启动前的竞态窗口**：再次 `O_NOFOLLOW` 打开源路径，比对
   dev/inode、尺寸、ctime，并**全量比对当前源字节与封印字节**，完全一致
   才继续。替换、截断、原地改写在这个窗口同样无法通过。
7. **从 memfd 启动**：子进程以 `/proc/self/fd/<memfd>` 执行，内核直接从已
   封印的匿名内存文件加载映像，**不再触碰可写工具目录**。父进程随即关闭
   自己的 memfd 副本，子进程持有独立引用。
8. **禁派生子进程（seccomp）**：子进程 `preexec_fn` 在 exec 前安装 BPF
   过滤器（`PR_SET_NO_NEW_PRIVS` + `PR_SET_SECCOMP`），命中
   `fork/vfork/clone/clone3/unshare/setns` 即 `SECCOMP_RET_KILL_PROCESS`
   立即杀进程。系统加载器与动态库视为可信（要求 ELF 含 `PT_INTERP`，
   由系统加载器启动）。另设 `RLIMIT_NPROC/AS/NOFILE/CORE` 双保险。
9. **资源治理与回收**：独立进程组 + `PR_SET_PDEATHSIG`。运行超过 **3 秒**、
   stdout/stderr **合计超过 64 KiB**、或**客户端断连**时，对整个进程组发
   `SIGKILL`，先关闭管道再 `wait` 回收（避免管道缓冲导致的回收停顿），
   **不返回任何部分结果**。并发调用由信号量限流、各自独立 memfd/进程组，
   互不干扰。

> 为什么不拦截 `execve`：受控启动本身需要在过滤器安装后发起一次 `execve`
> 来让系统加载器加载封印映像；而“不能换入其他程序”已由可信清单 + memfd
> 不可变封印在启动前保证，进程起来后又无法 `clone` 出任何子进程。

### 普通 ELF 约束（`app/runner/elf.py`）

* ELF 魔数、64 位、小端、当前版本；
* `e_type` 为 `ET_EXEC` 或 `ET_DYN`（PIE），拒绝目标文件/核心转储；
* 必须含 `PT_INTERP`（由系统加载器启动的普通可执行文件），加载器/动态库可信；
* 架构默认仅允许 x86_64；头部声明尺寸与实际字节一致，且 ≤ 8 MiB。

---

## 二、HTTP API

交互式文档：启动后访问 <http://localhost:8080/docs>，可在页面上直接选择助手
并发起调用。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 健康检查 |
| GET | `/api/v1/assistants` | 列出已批准助手（固定 ID/路径/SHA-256/参数） |
| GET | `/api/v1/assistants/{id}` | 查询单个助手的可信启动配置 |
| POST | `/api/v1/assistants/run` | **受控执行**：请求体仅 `{"assistant_id": "..."}` |
| POST | `/api/v1/evaluate` | 原 systemd 沙箱策略核查 API（保留不变） |

### 受控执行响应

```json
{
  "assistant_id": "archinfo",
  "returncode": 0,
  "stdout_b64": "<Base64 编码的 stdout 原始字节>",
  "stderr_b64": "<Base64 编码的 stderr 原始字节>",
  "sha256": "实际执行的封印字节 SHA-256（与清单一致）",
  "elapsed_ms": 6
}
```

### 状态码

| 状态码 | 含义 |
| --- | --- |
| 200 | 执行完成，返回退出码与 Base64 输出 |
| 404 | 助手 ID 未在可信清单登记 |
| 409 | 核验失败（SHA-256/ELF/源文件被替换、截断、原地改写等），拒绝执行 |
| 413 | 两路输出合计超过 64 KiB，进程已回收，**无部分结果** |
| 422 | 请求字段不合法（含非法 ID、多余字段） |
| 499 | 客户端断连，进程已回收，**不返回部分结果** |
| 503 | 并发数达上限 / 可信配置不可用 |
| 504 | 运行超过 3 秒，进程已回收，**无部分结果** |

### 命令行示例

```bash
curl -s http://localhost:8080/api/v1/assistants | python3 -m json.tool

curl -s -X POST http://localhost:8080/api/v1/assistants/run \
  -H 'Content-Type: application/json' \
  -d @examples/run_assistant.json | python3 -m json.tool
```

### 内置诊断助手

| ID | 行为 | 用途 |
| --- | --- | --- |
| `archinfo` | 输出 uname、页大小、身份、argv、加载器、seccomp/能力状态 | 正常架构排障 |
| `slowprobe` | 周期打印心跳，5 秒才退出 | 演示 3 秒超时回收（504） |
| `bigprinter` | 连续输出 128 KiB | 演示 64 KiB 输出上限（413） |

---

## 三、Docker Compose 交付（可实际启动）

```bash
docker compose up --build -d
# 健康检查
curl -s http://localhost:8080/health
# 交互式文档（可在页面选择助手调用）
xdg-open http://localhost:8080/docs
```

镜像采用多阶段构建：`gcc` 阶段编译助手并计算 SHA-256 生成只读清单；运行
镜像无编译器、以非 root（uid 10001）运行、只读根文件系统、`cap_drop: ALL`、
`no-new-privileges`。可写工具目录 `/var/lib/diag-tools` 单独挂命名卷，是
受控的攻击演示面；只读黄金副本位于 `/opt/diag-golden`，清单位于
`/etc/diag-runner/assistants.json`（0444）。

### 一键演示（正常 / 篡改 / 并发替换 / 资源上限）

```bash
# 在宿主机直接跑（通过 8080 端口访问服务）
./demos/run_all_demos.sh

# 或在共享工具卷的一次性容器内跑篡改/并发演示
docker compose run --rm tamper-demo /opt/demos/02_tamper_demo.sh
docker compose run --rm tamper-demo python3 -I /opt/demos/03_concurrent_replace_demo.py
```

演示内容：

* `01_normal_demo.sh` —— 正常调用 `archinfo`，展示退出码与 Base64 输出；
* `02_tamper_demo.sh` —— 整体替换、截断、原地改写三种篡改，服务端一律 409
  拒绝，结束自动从黄金副本恢复；
* `03_concurrent_replace_demo.py` —— 后台持续 rename 替换工具目录，并发
  发起请求，验证“执行的是批准字节（哈希匹配）或被拒绝”，未批准程序从不执行；
* `04_limits_demo.sh` —— `slowprobe` 超时 504、`bigprinter` 输出超限 413，
  且都不返回部分结果。

---

## 四、测试

```bash
# 纯标准库：判定引擎
python3 -I tests/test_engine.py
# 无 FastAPI 环境下的 API 接线（内置最小 stub）
python3 -I tests/test_api_stub.py
# 受控执行子系统全套：ELF、seccomp、防篡改、TOCTOU、超时、输出、并发、取消
python3 -I tests/test_runner.py
# HTTP 集成测试（需 fastapi/httpx，镜像内运行；本地缺依赖时自动跳过）
python3 -I tests/test_runner_api.py
```

容器内运行：

```bash
docker compose exec sandbox-checker python3 -I tests/test_runner.py
docker compose exec sandbox-checker python3 -I tests/test_runner_api.py
```

`test_runner.py` 优先使用镜像内预编译夹具（`tests/prebuilt`），开发机有 gcc
时则现场编译 `tests/fixtures` 与 `tools` 下的 C 源码。

---

## 五、目录结构

```
app/
  engine.py              # systemd 沙箱判定引擎（保留，纯标准库）
  schemas.py             # 核查 API 的 pydantic 模型（保留）
  cli.py                 # 核查离线命令行（保留）
  main.py                # FastAPI：/docs、/health、evaluate、assistants/run
  runner_schemas.py      # 受控执行 API 的请求/响应模型
  runner/
    config.py            # 可信启动配置（固定 ID/路径/SHA-256/参数 + 硬上限）
    elf.py               # 普通 ELF 校验（64 位小端、PT_INTERP、≤8MiB）
    seccomp.py           # 禁派生/禁命名空间 BPF 过滤器（无 libseccomp 依赖）
    executor.py          # 核验-封印-执行闭环 + 超时/输出/断连回收
tools/                   # 已批准诊断助手 C 源码（构建期编译）
tests/fixtures/          # echoer/forker/execer 测试夹具源码
tests/prebuilt/          # 镜像内预编译夹具（构建产物，运行期使用）
scripts/
  build_manifest.py      # 构建期计算 SHA-256 生成可信清单
  assistant_specs.json   # 助手 ID/运行期路径/参数规格
  entrypoint.sh          # 黄金副本初始化到可写工具目录
demos/                   # 正常/篡改/并发替换/资源上限演示
examples/                # 请求样例
Dockerfile               # 多阶段：gcc 编译 -> 精简非 root 运行镜像
docker-compose.yml       # 服务 + 共享卷篡改演示容器
```

---

## 六、原 systemd 沙箱核查能力（保留）

`/api/v1/evaluate` 与 `app/cli.py` 的行为、请求/响应结构完全不变：给定
systemd unit 沙箱策略 JSON 与按时间排列的进程审计事件（派生、切换工作目录、
读写/执行路径），逐步回放并输出首个失败原因、完整判定轨迹与命中的策略项。
离线命令行用法：

```bash
python3 -I -m app.cli examples/request.json
```
