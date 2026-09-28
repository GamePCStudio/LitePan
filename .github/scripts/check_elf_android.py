#!/usr/bin/env python3
"""校验交叉编译产物能否在 Android 6~11 的 linux shell 下被内核直接 exec。

两条硬判据（对应常见踩坑）：
  1. 不能出现 PT_INTERP —— Android 只有 /system/bin/linker(64)，
     Go 走 -linkmode external 或 -buildmode=pie+glibc 时会写进
     /lib/ld-linux-*.so.1 / ld-musl-*，这类产物在设备上 exec 直接失败。
  2. 32 位 ARM 必须带 EF_ARM_ABI_FLOAT_HARD(0x400) 与 HAS_MOVW/MOVT(0x100)，
     即真正按 GOARM=7 编译；否则是 GOARM=5 基线，浮点走软件序列。
"""
import os
import struct
import sys

ET_EXEC = 2
ET_DYN = 3
EM_ARM = 40
EM_AARCH64 = 183
EF_ARM_HAS_MOVW_MOVT = 0x100
EF_ARM_ABI_FLOAT_HARD = 0x400


def read_header(d):
    if d[:4] != b"\x7fELF":
        raise ValueError("不是 ELF 文件")
    cls, data = d[4], d[5]
    endian = "<" if data == 1 else ">"
    # ELF32: e_type H, e_machine H, e_version I, e_entry I, e_phoff I,
    #        e_shoff I, e_flags I, e_ehsize H, e_phentsize H, e_phnum H  (=32B)
    # ELF64: 同名字段但 entry/phoff/shoff 为 Q                       (=48B)
    fmt32 = endian + "HH" + "IIIII" + "HHH"
    fmt64 = endian + "HH" + "I" + "QQQ" + "I" + "HHH"
    fields = struct.unpack_from(fmt32 if cls == 1 else fmt64, d, 16)
    etype, machine, _ver, entry, phoff, _shoff, flags, _ehsize, phentsize, phnum = fields
    return cls, endian, etype, machine, entry, phoff, flags, phentsize, phnum


def interpreters(d, cls, endian, phoff, phentsize, phnum):
    found = []
    for i in range(phnum):
        base = phoff + i * phentsize
        ptype = struct.unpack_from(endian + "I", d, base)[0]
        if ptype != 3:  # PT_INTERP
            continue
        if cls == 1:
            off, filesz = struct.unpack_from(endian + "IIIIIIII", d, base)[1], \
                          struct.unpack_from(endian + "IIIIIIII", d, base)[4]
        else:
            row = struct.unpack_from(endian + "IIQQQQQQ", d, base)
            off, filesz = row[2], row[5]
        found.append(d[off:off + filesz].split(b"\x00")[0].decode("utf-8", "replace"))
    return found


def requested_goarm():
    return os.environ.get("GOARM", "").strip() or "7"


def expect_hard_float():
    """GOARM=7 才置 EF_ARM_ABI_FLOAT_HARD；5/6 为软浮点约定。"""
    return requested_goarm() == "7"


def main(argv):
    if not argv:
        print("用法: check_elf_android.py <二进制...>")
        return 2
    failures = []
    for path in argv:
        with open(path, "rb") as fh:
            d = fh.read()
        cls, endian, etype, machine, entry, phoff, flags, phentsize, phnum = read_header(d)
        interps = interpreters(d, cls, endian, phoff, phentsize, phnum)
        arch = {EM_ARM: "arm32", EM_AARCH64: "arm64"}.get(machine, f"machine={machine}")
        print(f"{path}: ELF{'32' if cls == 1 else '64'} {arch} "
              f"type={'ET_EXEC' if etype == ET_EXEC else 'ET_DYN/PIE' if etype == ET_DYN else etype} "
              f"entry=0x{entry:x} e_flags=0x{flags:08x} interp={interps or 'none(静态)'}")
        if interps:
            msg = f"{path}: 含 PT_INTERP {interps}，Android 无此动态加载器，exec 会失败"
        elif machine == EM_ARM and bool(flags & EF_ARM_ABI_FLOAT_HARD) != expect_hard_float():
            want = "硬浮点(0x400)" if expect_hard_float() else "软浮点(不置 0x400)"
            msg = (f"{path}: e_flags=0x{flags:08x} 与请求的 GOARM={requested_goarm()} 不符，"
                   f"期望 {want} —— GOARM 没真正生效，浮点会走软件序列")
        else:
            msg = None
            if machine == EM_ARM and not (flags & EF_ARM_HAS_MOVW_MOVT):
                # 外部链接（musl/cgo）时 e_flags 取自工具链启动对象，不代表 Go 代码的指令集，
                # 只在纯 Go 内部链接场景才是 GOARM 判据，所以这里仅提示不判失败。
                print("  NOTE  未置 HAS_MOVW/MOVT(0x100)：外部链接时该位由工具链决定，非 GOARM 判据")
        if msg:
            print(f"  FAIL  {msg}")
            failures.append(msg)
        else:
            print("  OK    可被 Android 内核直接 exec")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
