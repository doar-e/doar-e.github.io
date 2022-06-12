#!/usr/bin/env python3
import argparse
import struct
import sys
import os
import platform

NCFW_LEN = 20

def parse_NCFW(header):
    # 00000000  4E 43 46 57 00 00 00 00 CD 37 5D 08 20 00 00 00 NCFW.....7]. ...
    # 00000010  AD 36 5D 08 00 00 00 00 00 01 00 00 00 00 00 00 .6].............

    # 00: magic
    # 04: ?
    # 08: total size
    # 0C: hdr size ?
    # 10: actual data size ?
    # 14: ?
    # 18: ?
    # 1C: ?

    magic, _, total_sz, hdr_sz, data_sz, _, _, _ = struct.unpack('4sIIIIIII', header)
    if magic != b'NCFW':
        return None
    return {"total_sz": total_sz, "hdr_sz": hdr_sz, "data_sz": data_sz}

def parse_rominfo(header):

    # 00  AF AF 9C 9C 08 D0 06 00 20 21 02 25 00 00 00 00 ........ !.%....
    # 10  58 58 78 78 01 00 01 01 00 00 02 20 00 00 01 E0 XXxx....... ....
    # 20  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
    # 30  00 00 00 00 00 00 00 00 00 00 00 00 06 82 AC 8B ................
    magic = struct.unpack('>I', header[0:4])[0]
    total_sz, data_sz  = struct.unpack('>II', header[0x18:0x20])
    if magic != 0xAFAF9C9C:
        return None
    return {"total_sz": total_sz, "data_sz": data_sz}

def decrypt(data):
    if platform.python_implementation() != 'PyPy':
        print("Python3 is slooooooooooooooooooooow, you should use pypy")

    decrypted = bytearray(data)
    for i in range(0, len(data)):
        t = (i&0xFF) - decrypted[i]
        decrypted[i] = (((t>>7)&1)|(t<<1))&0xFF
    return decrypted

def handle_CEFW(f, basedir):
    import zlib
    f.seek(0x20, os.SEEK_SET)
    d_zlib = f.read()
    data = zlib.decompress(d_zlib)
    ncfw_info = parse_NCFW(data[0:0x20])
    if ncfw_info:
        data = decrypt(data[0x20:])
    else:
        print("No NCFW after unpacking CEFW, ABORT!")
        sys.exit(1)
    unpack_NCFW(data, basedir)

def unpack_NCFW(data, basedir):
    i = 0
    while data[0:4] == b'\xaf\xaf\x9c\x9c':
        hdr_info = parse_rominfo(data[0:0x40])
        data_sz = hdr_info['data_sz']
        data = data[hdr_info['total_sz']-data_sz:]
        out_fn = os.path.join(basedir, "fw_"+str(i))
        written = None
        with open(out_fn, 'wb') as out:
            written = out.write(data[0:data_sz])
            # pypy hack
            written = written or len(data[0:data_sz])
            print("\t%s\t\t: 0x%x bytes" % (out_fn, written))
        data = data[data_sz:]
        i += 1

def handle_USTBIND(f, basedir):
    # Search footer magic
    Magic_End = b"USTBIND\x00"
    f.seek(-100*1024, os.SEEK_END)
    end_pos = f.tell()
    print("%08x" % end_pos)
    end_data = f.read()
    if not Magic_End in end_data:
        print("Could not find footer magic")
        sys.exit(1)

    print("%08x" % end_data.index(Magic_End))
    bind_end = end_data.index(Magic_End)+end_pos
    print("Found USTBIND at 0x%08x" % bind_end)
    f.seek(-8+bind_end, os.SEEK_SET)
    bind_start = struct.unpack('I', f.read(4))[0]
    print("bind start: %08x" % bind_start)
    f.seek(bind_start, os.SEEK_SET)
    chunks = []
    while f.tell() < bind_end-8:
        name, offset, size = struct.unpack('32sII', f.read(40))
        fn = name.decode('ascii').rstrip("\0")
        chunks.append({'fn': fn, 'off': offset, 'sz': size})

    for c in chunks:
        print("File: {}, offset: {:x}, size: {}".format(c['fn'], c['off'], c['sz']))
        f.seek(c['off'])
        data = f.read(c['sz'])
        if c['sz'] >= NCFW_LEN:
            ncfw_info = parse_NCFW(data[0:0x20])
            if ncfw_info:
                data = decrypt(data[0x20:])
        with open(c['fn'], 'wb') as out:
            out.write(data)
        unpack_NCFW(data, basedir)

parser = argparse.ArgumentParser()
parser.add_argument("file", help="firmware file")
parser.add_argument("basedir", help="base directory for extraction")
args = parser.parse_args()

if not os.path.isfile(args.file):
    print("'{}' does not exist".format(args.file))
    sys.exit(1)

if not os.path.isdir(args.basedir):
    os.mkdir(args.basedir)

f = open(args.file, 'rb')

# First, check if we have a CEFW (no UST, compressed)
hdr = f.read(4)
f.seek(0)
if hdr == b"CEFW":
    print("Unpacking and decrypting CEFW")
    handle_CEFW(f, args.basedir)
elif hdr == b"\xAF\xAF\x9C\x9C":
    unpack_NCFW(f.read(), args.basedir)
else:
    handle_USTBIND(f, args.basedir)

