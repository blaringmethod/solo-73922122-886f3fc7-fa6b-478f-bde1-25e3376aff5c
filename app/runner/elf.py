"""普通 ELF 文件校验（仅标准库）。

题面要求「仅支持不派生子进程、最多 8MiB 的普通 ELF 文件，系统加载器和
动态库视为可信」。这里对**已经落入 memfd 的不可变字节**做结构校验：

* ELF 魔数、64 位、小端、当前版本；
* ``e_type`` 为 ``ET_EXEC`` / ``ET_DYN``（PIE 可执行文件），拒绝目标文件、
  核心转储及其他类型；
* 必须含 ``PT_INTERP`` —— 即由系统加载器（``/lib64/ld-linux-...``）加载的
  普通动态/静态可执行文件；加载器与动态库本身视为可信，不做哈希约束；
* 头部声明尺寸与实际字节一致，且不超过 8 MiB；
* 架构在允许列表内（默认仅 x86_64，可由部署配置扩展）。

大小限额由调用方在读取阶段先行执行，本模块只负责结构合法性。
"""

from __future__ import annotations

import struct

ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1

ET_EXEC = 2
ET_DYN = 3  # PIE 可执行文件的类型也是 ET_DYN

PT_INTERP = 3

# 运行平台允许的 e_machine（默认仅 x86_64）
EM_X86_64 = 62
EM_AARCH64 = 183

# 64 位小端 ELF 头固定 64 字节，程序头表项固定 56 字节
ELF64_HDR_SIZE = 64
ELF64_PHDR_SIZE = 56


class ElfError(ValueError):
    """字节内容不是受支持的普通 ELF 可执行文件。"""


def validate_elf(data: bytes, *, allowed_machines: tuple[int, ...] = (EM_X86_64,)) -> None:
    """对完整字节做普通 ELF 可执行文件校验，不合法时抛 :class:`ElfError`。"""
    if len(data) < ELF64_HDR_SIZE:
        raise ElfError(f"文件过小（{len(data)} 字节），不构成 ELF 头")

    ident = data[:16]
    if ident[:4] != ELF_MAGIC:
        raise ElfError("缺少 ELF 魔数，不是 ELF 文件")
    if ident[4] != ELFCLASS64:
        raise ElfError("仅支持 64 位 ELF（ELFCLASS64）")
    if ident[5] != ELFDATA2LSB:
        raise ElfError("仅支持小端 ELF（ELFDATA2LSB）")
    if ident[6] != EV_CURRENT:
        raise ElfError(f"不支持的 ELF 版本: {ident[6]}")

    # e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
    # e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
    (
        e_type,
        e_machine,
        e_version,
        _e_entry,
        e_phoff,
        _e_shoff,
        _e_flags,
        e_ehsize,
        e_phentsize,
        e_phnum,
        _e_shentsize,
        _e_shnum,
        _e_shstrndx,
    ) = struct.unpack_from("HHIQQQIHHHHHH", data, 16)

    if e_type not in (ET_EXEC, ET_DYN):
        raise ElfError(f"仅支持可执行 ELF（ET_EXEC/ET_DYN），e_type={e_type}")
    if e_machine not in allowed_machines:
        raise ElfError(f"架构 e_machine={e_machine} 不在允许列表 {allowed_machines} 内")
    if e_version != EV_CURRENT:
        raise ElfError(f"不支持的 e_version: {e_version}")
    if e_ehsize != ELF64_HDR_SIZE:
        raise ElfError(f"ELF 头尺寸异常: {e_ehsize}")
    if e_phoff == 0 or e_phnum == 0:
        raise ElfError("缺少程序头表，不是可加载的可执行文件")
    if e_phentsize != ELF64_PHDR_SIZE:
        raise ElfError(f"程序头表项尺寸异常: {e_phentsize}")
    if e_phnum > 512:
        raise ElfError(f"程序头数量异常: {e_phnum}")

    ph_table_end = e_phoff + e_phnum * e_phentsize
    if ph_table_end > len(data):
        raise ElfError("程序头表超出文件边界，文件可能被截断")

    has_interp = False
    for index in range(e_phnum):
        offset = e_phoff + index * e_phentsize
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = (
            struct.unpack_from("IIQQQQQQ", data, offset)
        )
        if p_type == PT_INTERP:
            has_interp = True
            # PT_INTERP 必须落在文件内，且以 NUL 结尾指向真实加载器路径
            if p_filesz == 0 or p_offset + p_filesz > len(data):
                raise ElfError("PT_INTERP 越界，文件可能被截断")
            interp = data[p_offset : p_offset + p_filesz]
            if not interp.endswith(b"\x00") or interp.count(b"\x00") != 1:
                raise ElfError("PT_INTERP 解释器路径格式非法")
            path = interp[:-1]
            if not path.startswith(b"/") or b"/" not in path[1:]:
                raise ElfError(f"PT_INTERP 不是绝对路径: {path!r}")

    if not has_interp:
        raise ElfError(
            "缺少 PT_INTERP：仅支持由系统加载器启动的普通可执行文件，"
            "拒绝无解释器的裸映像/共享库"
        )
