"""
最小 Windows x64 DLL 生成器（纯 struct，无编译器依赖）。
生成导出指定函数、返回 0 的替身 DLL。用于替换火绒 selfprot/usysdiag。

结构：
  .text   函数代码（xor eax,eax; ret  /  lea rax,[vtable]; ret）
  .rdata  vtable 槽 + 导出目录（名称表/地址表/序号表/字符串）
  .reloc  vtable 槽绝对地址的基址重定位
"""
import struct, sys

IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_SUBSYSTEM_WINDOWS_GUI = 2

def align(v, a=0x200):
    return (v + a - 1) & ~(a - 1)

def make_dll(exports, dllname, outpath, want_vtable=False):
    # --- .text ---
    # 每个普通导出: xor eax,eax; ret  (48 31 c0 c3)
    text = bytearray()
    func_rva = {}
    for name in exports:
        func_rva[name] = len(text)
        if want_vtable and name in ('vif_get', 'vif_sysutils_get'):
            # lea rax,[rip+disp32]; ret  -> 占位，稍后回填 disp
            text += b'\x48\x8d\x05\x00\x00\x00\x00' + b'\xc3'
        else:
            text += b'\x48\x31\xc0\xc3'  # xor eax,eax; ret
    text_rva = 0x1000

    rdata_rva = align(text_rva + len(text), 0x1000)
    rdata = bytearray()

    # vtable 槽（放 vtable_func 的 VA，需重定位）
    vtable_slot_off = 0
    if want_vtable:
        rdata += struct.pack('<Q', 0)  # 占位 VA
        # vtable[0] 函数放在 .text 末尾: xor eax,eax; ret
        vtable_func_rva = text_rva + len(text)
        text += b'\x48\x31\xc0\xc3'

    # 回填 lea 的 disp32：rip = 指令末尾 = func_rva+7
    if want_vtable:
        for name in exports:
            if name in ('vif_get', 'vif_sysutils_get'):
                o = func_rva[name]
                rip = text_rva + o + 7
                disp = (rdata_rva + vtable_slot_off) - rip
                struct.pack_into('<i', text, o + 3, disp)

    # --- 导出目录 ---
    names = list(exports)
    n = len(names)
    exp_off = len(rdata)
    exp_off = align(exp_off, 4)
    while len(rdata) < exp_off:
        rdata += b'\x00'

    # 先规划各表位置
    addr_of_funcs_off = exp_off + 40
    addr_of_names_off = addr_of_funcs_off + 4 * n
    addr_of_ords_off = addr_of_names_off + 4 * n
    strings_off = align(addr_of_ords_off + 2 * n, 4)

    # 先把 buffer 扩展到字符串表之后，避免 pack_into 越界
    while len(rdata) < strings_off:
        rdata += b'\x00'

    # 字符串表
    dll_name_off = strings_off
    rdata += dllname.encode() + b'\x00'
    func_name_offs = {}
    for name in names:
        func_name_offs[name] = len(rdata)
        rdata += name.encode() + b'\x00'

    def rva(off):
        return rdata_rva + off

    # 回填地址表（函数 RVA）
    off = addr_of_funcs_off
    for name in names:
        if want_vtable and name == 'vtable_func':
            frva = vtable_func_rva
        else:
            frva = text_rva + func_rva[name]
        struct.pack_into('<I', rdata, off, frva)
        off += 4
    # 名称指针表
    off = addr_of_names_off
    for name in names:
        struct.pack_into('<I', rdata, off, rva(func_name_offs[name]))
        off += 4
    # 序号表
    off = addr_of_ords_off
    for i in range(n):
        struct.pack_into('<H', rdata, off, i)
        off += 2

    # 导出目录 (IMAGE_EXPORT_DIRECTORY)
    ed = struct.pack('<IIHHIIIIIII',
        0,          # Characteristics
        0,          # TimeDateStamp
        0, 0,       # Major/Minor
        rva(dll_name_off),  # Name
        1,          # Base
        n,          # NumberOfFunctions
        n,          # NumberOfNames
        rva(addr_of_funcs_off),
        rva(addr_of_names_off),
        rva(addr_of_ords_off),
    )
    rdata[exp_off:exp_off+40] = ed

    # vtable 槽填入 vtable_func 的绝对 VA（假设 ImageBase 0x180000000），并加重定位
    IMAGEBASE = 0x180000000
    if want_vtable:
        struct.pack_into('<Q', rdata, vtable_slot_off, IMAGEBASE + vtable_func_rva)

    # --- .reloc ---
    reloc_rva = align(rdata_rva + len(rdata), 0x1000)
    reloc = bytearray()
    if want_vtable:
        # 页 RVA = rdata_rva 对齐 0x1000，条目 = HIGHLOW(3) | offset
        page = rdata_rva & ~0xFFF
        offset = (rdata_rva + vtable_slot_off) - page
        block = struct.pack('<II', page, 8 + 2)  # PageRVA, BlockSize
        block += struct.pack('<H', (3 << 12) | offset)  # type=3 HIGHLOW
        reloc += block

    # --- 组装 PE ---
    sections = [
        (b'.text', text_rva, bytes(text), 0x60000020),
        (b'.rdata', rdata_rva, bytes(rdata), 0x40000040),
    ]
    if want_vtable:
        sections.append((b'.reloc', reloc_rva, bytes(reloc), 0x42000040))

    headers_size = 0x400
    fileoff = headers_size
    sec_hdrs = []
    raw = bytearray()
    for name, vrva, data, chars in sections:
        sec_hdrs.append((name, vrva, fileoff, len(data), chars))
        raw += data
        raw += b'\x00' * (align(len(data), 0x200) - len(data))
        fileoff += align(len(data), 0x200)

    size_of_image = align(sections[-1][1] + len(sections[-1][2]), 0x1000)
    size_of_headers = headers_size

    dos = bytearray(0x80)
    struct.pack_into('<H', dos, 0, 0x5A4D)
    struct.pack_into('<I', dos, 0x3C, 0x80)

    coff = struct.pack('<HHIIIHH',
        IMAGE_FILE_MACHINE_AMD64, len(sections), 0, 0, 0,
        0xF0, 0x2022)  # SizeOfOptionalHeader=0xE0, Characteristics=DLL|EXECUTABLE_IMAGE|LARGE_ADDRESS_AWARE

    opt = bytearray(240)  # PE32+: 112 fixed + 16*8 dirs
    struct.pack_into('<H', opt, 0, 0x20B)   # Magic PE32+
    struct.pack_into('<BB', opt, 2, 14, 0) # linker ver
    size_of_code = sum(align(len(d),0x200) for n,v,d,c in sections if n == b'.text')
    size_of_init = sum(align(len(d),0x200) for n,v,d,c in sections if n != b'.text')
    struct.pack_into('<III', opt, 4, size_of_code, size_of_init, 0)  # SizeOfCode/Init/Uninit
    struct.pack_into('<I', opt, 16, text_rva + func_rva[list(exports)[0]])  # EP
    struct.pack_into('<I', opt, 20, text_rva)  # BaseOfCode
    struct.pack_into('<Q', opt, 24, IMAGEBASE)
    struct.pack_into('<II', opt, 32, 0x1000, 0x200)  # SectionAlign/FileAlign
    struct.pack_into('<HHHHHH', opt, 40, 6, 0, 0, 0, 5, 0)  # OS/Image/Subsys ver
    struct.pack_into('<I', opt, 52, 0)  # Win32VersionValue
    struct.pack_into('<I', opt, 56, size_of_image)  # SizeOfImage
    struct.pack_into('<I', opt, 60, size_of_headers)  # SizeOfHeaders
    struct.pack_into('<I', opt, 64, 0)  # CheckSum
    struct.pack_into('<H', opt, 68, IMAGE_SUBSYSTEM_WINDOWS_GUI)
    struct.pack_into('<H', opt, 70, 0)  # DllCharacteristics
    struct.pack_into('<QQQQ', opt, 72, 0x100000, 0x1000, 0x100000, 0x1000)  # stack/heap
    struct.pack_into('<I', opt, 104, 0)  # LoaderFlags
    struct.pack_into('<I', opt, 108, 16) # NumberOfRvaAndSizes
    # 数据目录从 112 开始
    struct.pack_into('<II', opt, 112 + 0*8, rdata_rva + exp_off, len(rdata) - exp_off)
    if want_vtable:
        struct.pack_into('<II', opt, 112 + 5*8, reloc_rva, len(reloc))

    sh = bytearray()
    for name, vrva, foff, dsize, chars in sec_hdrs:
        nb = name[:8]
        sh += nb + b'\x00' * (8 - len(nb))          # Name[8]
        sh += struct.pack('<IIII', dsize, vrva, align(dsize,0x200), foff)  # VS,VA,SRAW,PRaw
        sh += struct.pack('<II', 0, 0)              # PtrReloc, PtrLineno
        sh += struct.pack('<HH', 0, 0)              # NumReloc, NumLineno
        sh += struct.pack('<I', chars)             # Characteristics

    pe = dos + b'PE\x00\x00' + coff + bytes(opt) + sh
    pe += b'\x00' * (headers_size - len(pe))
    out = bytes(pe) + bytes(raw)
    open(outpath, 'wb').write(out)
    print(f'wrote {outpath} size={len(out)} exports={names} vtable={want_vtable}')

if __name__ == '__main__':
    make_dll(['init_selfprot_procedure', 'trem_selfprot_procedure'], 'selfprot.dll', 'selfprot_stub.dll', want_vtable=False)
    make_dll(['vif_get', 'vif_sysutils_get', 'vif_assist_get', 'vif_autorun_get', 'vif_hooklet_get', 'vif_iokit_get'], 'usysdiag.dll', 'usysdiag_stub.dll', want_vtable=True)
