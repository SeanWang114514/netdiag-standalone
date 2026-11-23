"""
手工构造 COFF .syso（含 .rsrc 资源段），供 Go 链接器嵌入 Windows 图标。
图标数据来自 icon_data.pkl（从 NetDiag.exe 提取的 RT_ICON/RT_GROUP_ICON）。
"""
import pickle, struct

D = pickle.load(open('icon_data.pkl','rb'))
icons = D['icons']              # {(iconid,lang): bytes}
groups = D['groups']            # {(groupid,lang): bytes}
gname, glang = D['main_group']

# ---------- 构造 .rsrc 数据体 ----------
# 资源树三层：Type -> Name(ID) -> Language -> IMAGE_RESOURCE_DATA_ENTRY
# 这里把所有图标按 type=3(RT_ICON) / type=14(RT_GROUP_ICON) 组织。

# 收集要嵌入的条目：(type, id, lang, data)
entries = []
for (iconid, lang), data in icons.items():
    entries.append((3, iconid, lang, data))
for (gid, lang), data in groups.items():
    entries.append((14, gid, lang, data))

# 为每个数据块分配 RVA（相对资源段起点，从 0 开始；Go 链接器会重定位）
DATA_START = 0x1000  # 给目录结构留出空间
data_entries = []    # (rva, data)
cur = DATA_START
for t, idv, lang, data in entries:
    data_entries.append((cur, data, t, idv, lang))
    cur += len(data)
    cur = (cur + 3) & ~3

# ---------- 构造资源目录树 ----------
class DirBuilder:
    def __init__(self):
        self.buf = bytearray()
    def align4(self):
        while len(self.buf) % 4: self.buf.append(0)

def build_lang_dir(data_idx_list, db):
    """第三层：Language -> data entry。返回目录起始 offset"""
    start = len(db.buf)
    named, idn = 0, len(data_idx_list)
    db.buf += struct.pack('<IIHHHH', 0,0,0,0, named, idn)
    entry_off = len(db.buf)
    db.buf += b'\x00' * (8*idn)
    for i, di in enumerate(data_idx_list):
        rva, data, t, idv, lang = data_entries[di]
        # data entry
        de_off = len(db.buf)
        db.align4()
        de_off = len(db.buf)
        db.buf += struct.pack('<IIII', rva, len(data), 0, 0)  # OffsetToData,Size,CodePage,Reserved
        # dir entry: Name=lang(id), OffsetToData=de_off (no high bit, it's a data entry)
        struct.pack_into('<II', db.buf, entry_off+i*8, lang & 0xFFFF, de_off)
    return start

def build_type_dir(t, ids, db):
    """第二层：ID -> lang dir。返回目录起始 offset"""
    start = len(db.buf)
    db.buf += struct.pack('<IIHHHH', 0,0,0,0, 0, len(ids))
    entry_off = len(db.buf)
    db.buf += b'\x00' * (8*len(ids))
    for i, (idv, dilist) in enumerate(ids):
        lang_off = build_lang_dir(dilist, db)
        struct.pack_into('<II', db.buf, entry_off+i*8, idv & 0xFFFF, lang_off | 0x80000000)
    return start

db = DirBuilder()
# 第一层：Type -> second-level dir
types = {}
for di, (rva, data, t, idv, lang) in enumerate(data_entries):
    types.setdefault(t, {}).setdefault(idv, []).append(di)

top_start = len(db.buf)
db.buf += struct.pack('<IIHHHH', 0,0,0,0, 0, len(types))
top_entry_off = len(db.buf)
db.buf += b'\x00' * (8*len(types))
for i, (t, ids) in enumerate(sorted(types.items())):
    lvl2 = build_type_dir(t, sorted(ids.items()), db)
    struct.pack_into('<II', db.buf, top_entry_off+i*8, t & 0xFFFF, lvl2 | 0x80000000)

# 目录树结束，菜鸟注意：data 的 RVA 是按 DATA_START 预留的，但我们实际把目录写在 0 起始。
# 需要把 data 追加到 db.buf 到 DATA_START 位置。
db.align4()
assert len(db.buf) <= DATA_START, f'dir too big: {len(db.buf)} > {DATA_START}'
db.buf += b'\x00' * (DATA_START - len(db.buf))
for rva, data, t, idv, lang in data_entries:
    db.buf += data
    db.buf += b'\x00' * ((-len(data)) % 4)

rsrc_data = bytes(db.buf)

# ---------- 构造 COFF 对象 ----------
# IMAGE_FILE_HEADER (20 bytes)
machine = 0x8664  # AMD64
nsec = 1
fh = struct.pack('<HHIIIHH', machine, nsec, 0, 0, 0, 0, 0)

# Section header .rsrc (40 bytes)
name = b'.rsrc\x00\x00\x00'
virtual_size = len(rsrc_data)
virtual_addr = 0
size_of_raw = len(rsrc_data)
ptr_raw = 20 + 40  # header + 1 section header
ptr_reloc = 0
ptr_line = 0
nreloc = 0
nline = 0
# IMAGE_SCN_CNT_INITIALIZED_DATA(0x40) | ALIGN_4BYTES(0x30) | MEM_READ(0x40000000)
chars = 0x40000040
sh = name + struct.pack('<IIII', virtual_size, virtual_addr, size_of_raw, ptr_raw)
sh += struct.pack('<II', ptr_reloc, ptr_line)
sh += struct.pack('<HH', nreloc, nline)
sh += struct.pack('<I', chars)

syso = fh + sh + rsrc_data
out = 'icon.syso'
open(out,'wb').write(syso)
print(f'wrote {out} size={len(syso)} rsrc={len(rsrc_data)} entries={len(entries)}')
