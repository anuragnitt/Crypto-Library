from os import urandom

def pad(pt : bytes) -> bytes:
    n = 8 - len(pt)%8
    return pt + bytes([n]*n)

def unpad(pt : bytes) -> bytes:
    return pt[:(len(pt) - pt[-1])]

def xor(a : bytes, b : bytes) -> bytes:
    assert len(a) == len(b)
    return bytes([a[i]^b[i] for i in range(len(a))])

def expand(data : bytes) -> bytes:
    table = [31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8,
	        7, 8, 9, 10, 11, 12, 11, 12, 13, 14, 15, 16,
	        15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24,
	        23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0]

    expanded = []
    byte = 0
    base = 2**7
    for i in range(len(table)):
        index = table[i]
        bit = data[index//8] >> (7 - (index%8))
        bit = bit & 1
        byte += bit * base
        if not (i+1)%8:
            expanded.append(byte)
            byte = 0
            base = 2**7
        else:
            base = base >> 1
    return bytes(expanded)

def s_box(data : bytes) -> bytes:
    table = {0 : [[0, 2], [1, 12], [2, 4], [3, 1], [4, 7], [5, 10], [6, 11], [7, 6], [8, 8], [9, 5], [10, 3], [11, 15], [12, 13], [13, 0], [14, 14], [15, 9]],
	        1 : [[0, 14], [1, 11], [2, 2], [3, 12], [4, 4], [5, 7], [6, 13], [7, 1], [8, 5], [9, 0], [10, 15], [11, 10], [12, 3], [13, 9], [14, 8], [15, 6]],
	        2 : [[0, 4], [1, 2], [2, 1], [3, 11], [4, 10], [5, 13], [6, 7], [7, 8], [8, 15], [9, 9], [10, 12], [11, 5], [12, 6], [13, 3], [14, 0], [15, 14]],
	        3 : [[0, 11], [1, 8], [2, 12], [3, 7], [4, 1], [5, 14], [6, 2], [7, 13], [8, 6], [9, 15], [10, 0], [11, 9], [12, 10], [13, 4], [14, 5], [15, 3]]}

    compressed = []
    aux = []
    byte = 0
    base = 2**5
    for i in range(48):
        bit = data[i//8] >> (7 - (i%8))
        bit = bit & 1
        byte += bit * base
        if not (i+1)%6:
            y = (byte & 1) + (((byte >> 5) & 1) << 1)
            z = (byte >> 1) & 15
            for nums in table[y]:
                if nums[0] == z:
                    aux.append(nums[1])
                    if len(aux) == 2:
                        compressed.append((aux[0] << 4) + aux[1])
                        aux = []
                    break
            byte = 0
            base = 2**5
        else:
            base = base >> 1
    return bytes(compressed)

def straighten(data : str) -> bytes:
    table = [15, 6, 19, 20, 28, 11, 27, 16,
	        0, 14, 22, 25, 4, 17, 30, 9,
	        1, 7, 23, 13, 31, 26, 2, 8,
	        18, 12, 29, 5, 21, 10, 3, 24]

    straightened = []
    byte = 0
    base = 2**7
    for i in range(len(table)):
        index = table[i]
        bit = data[index//8] >> (7 - (index%8))
        bit = bit & 1
        byte += bit * base
        if not (i+1)%8:
            straightened.append(byte)
            byte = 0
            base = 2**7
        else:
            base = base >> 1
    return bytes(straightened)

def fiestel(right : bytes, key : bytes) -> bytes:
    return straighten(s_box(xor(key, expand(right))))

def encrypt_block(block : bytes, key : bytes) -> bytes:
    left = block[:4]
    right = block[4:]
    left = xor(left, fiestel(right, key))
    return right + left

def encrypt(pt : bytes, key : bytes) -> bytes:
    pt = pad(pt)
    blocks = [pt[i:i+8] for i in range(0, len(pt), 8)]
    cipher = []
    for block in blocks:
        if cipher:
            block = xor(block, cipher[-1])
        cipher.append(encrypt_block(block, key))
    return b''.join(cipher)

def decrypt_block(block : bytes, key : bytes) -> bytes:
    block = encrypt_block(block[4:] + block[:4], key)
    return block[4:] + block[:4]

def decrypt(ct : bytes, key : bytes) -> bytes:
    blocks = [ct[i:i+8] for i in range(0, len(ct), 8)]
    plain = []
    for i in range(len(blocks)):
        block = decrypt_block(blocks[i], key)
        if i:
            block = xor(block, blocks[i-1])
        plain.append(block)
    return unpad(b''.join(plain))

def main(message : str) -> bool:
    pt = message.encode()
    key = urandom(6)
    ct = encrypt(pt, key)
    return decrypt(ct, key) == pt

if __name__ == '__main__':
    print(main('say my name ... heisenberg'))

