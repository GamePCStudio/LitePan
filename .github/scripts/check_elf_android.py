#!/usr/bin/env python3
"""校验交叉编译产物能否在 Android 6~11 的 linux shell 下被内核直接 exec。

唯一可靠的硬判据是「有没有 PT_INTERP」：
  - 纯 Go 内部链接的静态非 PIE 产物没有 PT_INTERP，内核直接映射，Android 上能 exec；
  - -buildmode=pie 走外部链接时 Go 会把主机的 ld-linux/ld-musl 路径写进 PT_INTERP，
    设备上不存在这个加载器，exec 直接失败（旧 linux-arm64-pie 产物实测如此）。

不要拿 e_flags 的 EF_ARM_ABI_FLOAT_HARD 当 GOARM 判据：实测 Go 1.26.6 内部链接时
GOARM=6 与 GOARM=7 产出的 e_flags 都是 0x5000002，该位对 Go 自己的产物没有区分度。
"""
import struct
import sys

ET_EXEC = 2
ET_DYN = 3
EM_ARM = 40
EM_AARCH64 = 183


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


ANDROID_LINKERS = (
    "/system/bin/linker",
    "/system/bin/linker64",
    "/apex/com.android.runtime/bin/linker",
    "/apex/com.android.runtime/bin/linker64",
)


def main(argv):
    if not argv:
        print("用法: check_elf_android.py <二进制...>")
        return 2
    failures = []
    for path in argv:
        with open(path, "rb") as fh:
            d = fh.read()
        if d[:4] != b"\x7fELF":
            print(f"{path}: 非 ELF，跳过")
            continue
        try:
            cls, endian, etype, machine, entry, phoff, flags, phentsize, phnum = read_header(d)
        except (ValueError, struct.error) as exc:
            print(f"  FAIL  {path}: 读 ELF 头失败 {exc}")
            failures.append(path)
            continue
        interps = interpreters(d, cls, endian, phoff, phentsize, phnum)
        arch = {EM_ARM: "arm32", EM_AARCH64: "arm64"}.get(machine, f"machine={machine}")
        print(f"{path}: ELF{'32' if cls == 1 else '64'} {arch} "
              f"type={'ET_EXEC' if etype == ET_EXEC else 'ET_DYN/PIE' if etype == ET_DYN else etype} "
              f"entry=0x{entry:x} e_flags=0x{flags:08x} interp={interps or 'none(纯静态)'}")
        bad = [i for i in interps if not any(i.startswith(a) for a in ANDROID_LINKERS)]
        if bad:
            msg = f"{path}: PT_INTERP={bad}，Android 上没有该加载器，exec 会失败"
        elif etype == ET_EXEC:
            msg = None
            print("  OK    纯静态非 PIE；Android 6~8 可直接 exec，Android 9+ 内核强制 PIE 时需换 PIE 产物")
        else:
            msg = None
            print("  OK    静态且由 Android linker 加载（PIE），Android 6~11 均可 exec")
        if msg:
            print(f"  FAIL  {msg}")
            failures.append(msg)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
