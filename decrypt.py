import sys
import os
from binary_reader import BinaryReader
from ctypes import c_uint32

def decrypt_data(data, length):
    decrypted32 = [0] * min(0x100000, (length + 3) >> 2)
    data32 = []
    for i in range(0, length, 4):
        data32.append(c_uint32(int.from_bytes(data[i:i + 4], byteorder='little')).value)
    seed = c_uint32(data32[0]).value
    index = 1
    k = c_uint32(0xF1895432).value
    decrypted32[0] = c_uint32(seed).value ^ c_uint32(0xDEC9754E).value
    while (True):
        seed = c_uint32(c_uint32(seed).value << 1 | c_uint32(seed).value >> 31).value
        posInLine = index & 0xF
        current = c_uint32(data32[index]).value
        k += c_uint32(0x2050307).value
        isAligned = 2 * posInLine == 0
        if not isAligned:
            current = c_uint32(current << (2 * posInLine) | current >> (32 - 2 * posInLine)).value
        decrypted32[index] = c_uint32(seed ^ k ^ current).value
        index += 1
        if index >= min(0x100000, (length + 3) >> 2):
            break
    return decrypted32

def main():
    with open(sys.argv[1], 'rb') as f:
        fe = open(sys.argv[1] + ".decrypted", 'wb')
        w = BinaryReader()
        data = (decrypt_data(f.read(), os.path.getsize(sys.argv[1])))
        for i in range(len(data)):
            w.write_uint32(c_uint32(data[i]).value)
        fe.write(w.buffer())

if __name__ == '__main__':
    main()