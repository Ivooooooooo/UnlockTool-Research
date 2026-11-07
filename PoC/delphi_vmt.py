import struct, re, os

path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Binaries", "unpacked-module.exe")
data = open(path, "rb").read()

needle = b"TLoginController"
positions = [m.start() for m in re.finditer(re.escape(needle), data)]
print("string positions", [hex(p) for p in positions])
for p in positions:
    print(hex(p), "prev", data[p-1:p].hex(), "next", data[p+len(needle):p+len(needle)+16])

# Delphi short string starts one byte before the text, with length.
cands = []
for p in positions:
    if p > 0 and data[p-1] == len(needle):
        cands.append(p-1)
print("short string starts", [hex(c) for c in cands])

for c in cands:
    ptr = struct.pack("<I", c)
    locs = [m.start() for m in re.finditer(re.escape(ptr), data)]
    print("\nclassname", hex(c), "pointers", len(locs))
    for loc in locs[:20]:
        vmt = loc + 44
        if vmt + 4 > len(data):
            continue
        mt = struct.unpack_from("<I", data, loc - 8)[0]
        print(f"  loc=0x{loc:x} vmt=0x{vmt:x} methodtable=0x{mt:x}")
        # parse method table
        if 0 < mt < len(data) - 4:
            count = struct.unpack_from("<H", data, mt)[0]
            print("    count", count)
            off = mt + 2
            for i in range(min(count, 80)):
                if off + 6 > len(data):
                    break
                size, addr = struct.unpack_from("<HI", data, off)
                if size < 6 or size > 512 or off + size > len(data):
                    print("    bad entry at", hex(off), "size", size)
                    break
                nlen = data[off + 6]
                name = data[off + 7:off + 7 + nlen].decode("latin1", "replace")
                print(f"    {name:30} 0x{addr:08x} size={size}")
                off += size
