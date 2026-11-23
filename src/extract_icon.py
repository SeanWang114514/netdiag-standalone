"""从 NetDiag.exe 的 .rsrc 提取 RT_ICON / RT_GROUP_ICON，生成标准 .ico"""
import pefile, struct, sys

SRC = r'C:\software\火绒\Huorong\Sysdiag\bin\NetDiag.exe'
pe = pefile.PE(SRC, fast_load=False)
pe.parse_data_directories()

# 收集图标
icons = {}          # (type,id,lang) -> bytes
group_icons = {}    # id/lang -> raw GRPICONDIR bytes

def walk_entries(entries, type_id=None, name_id=None, depth=0):
    for e in entries:
        ident = e.id if e.id is not None else e.name
        t = ident if depth == 0 else type_id
        n = ident if depth >= 1 else None
        if hasattr(e, 'directory'):
            walk_entries(e.directory.entries, t, n, depth+1)
        else:
            lang = ident
            rva = e.data.struct.OffsetToData
            size = e.data.struct.Size
            data = pe.get_data(rva, size)
            if t == 3:  # RT_ICON
                icons[(name_id, lang)] = data
            elif t == 14:  # RT_GROUP_ICON
                group_icons[(name_id, lang)] = data

walk_entries(pe.DIRECTORY_ENTRY_RESOURCE.entries)

print('RT_ICON entries:', [(k, len(v)) for k,v in icons.items()])
print('RT_GROUP_ICON entries:', [(k, len(v)) for k,v in group_icons.items()])

if not group_icons:
    print('NO ICON FOUND')
    sys.exit(1)

# 取第一个 group（通常主图标）
(gname, glang), grp = next(iter(group_icons.items()))
count = struct.unpack_from('<H', grp, 4)[0]
print(f'group {gname}/{glang}: {count} images')

# GRPICONDIRENTRY: 14 bytes each, last 2 bytes = icon ID
entries = []
for i in range(count):
    off = 6 + i*14
    w,h,cc,r,planes,bpp,size,idv = struct.unpack_from('<BBBBHHIH', grp, off)
    entries.append((w,h,cc,r,planes,bpp,size,idv))
    print(f'  img{i}: {w}x{h} bpp={bpp} size={size} iconID={idv}')

# 构造 ICO: ICONDIR + ICONDIRENTRY(16) 每个 + 图像数据
ico = bytearray()
ico += struct.pack('<HHH', 0, 1, count)
data_blobs = []
for (w,h,cc,r,planes,bpp,size,idv) in entries:
    blob = icons.get((idv, glang)) or icons.get((idv, 0x409)) or icons.get((idv, 2052))
    if blob is None:
        # 尝试任意 lang 的同 id
        cand = [v for (nid,lg),v in icons.items() if nid==idv]
        blob = cand[0] if cand else None
    if blob is None:
        print(f'  !! missing icon id {idv}')
        blob = b''
    data_blobs.append(blob)

offset = 6 + 16*count
for (w,h,cc,r,planes,bpp,size,idv), blob in zip(entries, data_blobs):
    ico += struct.pack('<BBBBHHII',
        w if w else 0, h if h else 0, cc, r, planes, bpp, len(blob), offset)
    offset += len(blob)
for blob in data_blobs:
    ico += blob

out = r'C:\Users\admin\WorkBuddy AI\2026-11-23-17-44-24\NetDiag.ico'
open(out,'wb').write(ico)
print(f'wrote {out} size={len(ico)}')

# 同时导出每个图标原始数据和 group 供 syso 构造用
import pickle
pickle.dump({'icons':icons,'groups':group_icons,'main_group':(gname,glang)}, open('icon_data.pkl','wb'))
