from random import randint

#iv = [randint(0,255) for i in range(16)]
#key = [randint(0,255) for i in range(32)]

def pad(byte_list, block_size) :

	pad_value = block_size - (len(byte_list)%block_size)
	for i in range(pad_value) :
		byte_list.append(pad_value)

	return byte_list

def remove_pad(byte_list) :

	pad_value = byte_list[-1]
	return byte_list[:(-1*pad_value)]

# making pieces of 16 bytes each
def make_blocks(byte_list, block_size) :

	n_blocks = len(byte_list)//block_size

	blocks = []
	for i in range(n_blocks) :
		block = byte_list[i*block_size : (i+1)*block_size]
		blocks.append(block)

	return blocks

# Rijndael S-Box
def sub_bytes(byte_list) :

	sbox =  [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
			0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
			0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
			0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
			0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
			0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
			0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
			0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
			0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
			0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
			0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
			0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
			0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
			0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
			0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
			0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
			0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
			0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
			0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
			0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
			0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
			0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
			0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
			0x54, 0xbb, 0x16]

	return [sbox[n] for n in byte_list]

# Inverse S-Box
def inv_sub_bytes(byte_list) :

	inv_sbox = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
			   0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
			   0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54,
			   0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
			   0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
			   0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8,
			   0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
			   0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
			   0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab,
			   0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
			   0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
			   0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
			   0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
			   0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
			   0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
			   0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
			   0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
			   0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
			   0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60,
			   0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
			   0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
			   0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b,
			   0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
			   0x21, 0x0c, 0x7d]

	return [inv_sbox[n] for n in byte_list]

# left byte shift
def rot_bytes(byte_list, n) :

	for i in range(n) :
		byte_list = byte_list[1:] + byte_list[:1]
	return byte_list

# right byte shift
def inv_rot_bytes(byte_list, n) :

	for i in range(n) :
		byte_list = byte_list[-1:] + byte_list[:-1]
	return byte_list

def xor(x, y) :
	# x and y are list of bytes
	return [x[i]^y[i] for i in range(len(x))]

# AES key schedule
def expand_key(key) :
	# 1 word = 4 bytes
	# 4 words = 1 key (128 bit)

	n_words = len(key)//4
	n_round_keys = n_words + 7
	key_words = [key[i*4:(i+1)*4] for i in range(n_words)]

	rc = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
	rcon = [[rc[i], 0x00, 0x00, 0x00] for i in range(10)]

	expkey_words = []
	for i in range(4*n_round_keys) :

		if i<n_words :
			expkey_words.append(key_words[i])

		elif i>=n_words and i%n_words==0 :
			word = sub_bytes(rot_bytes(expkey_words[i-1], 1))
			word = xor(expkey_words[i-n_words], word)
			word = xor(word, rcon[(i//n_words)-1])
			expkey_words.append(word)

		elif i>=n_words and n_words>6 and i%n_words==4 :
			expkey_words.append(xor(expkey_words[i-n_words], sub_bytes(expkey_words[i-1])))

		else :
			expkey_words.append(xor(expkey_words[i-n_words], expkey_words[i-1]))

	expanded_key = []
	for x in expkey_words :
		expanded_key += x

	return expanded_key

# generates round keys from expanded key
def generate_rkey(expanded_key, offset) :

	rkey = [0 for i in range(16)]

	for i in range(4) :
		for j in range(4) :
			rkey[i + 4*j] = expanded_key[offset + i*4 + j]

	return rkey

def shift_rows(block) :

	for i in range(4) :
		row = block[i*4 : (i+1)*4]
		block[i*4 : (i+1)*4] = rot_bytes(row, i)

	return block

def inv_shift_rows(block) :
	for i in range(4) :
		row = block[i*4 : (i+1)*4]
		block[i*4 : (i+1)*4] = inv_rot_bytes(row, i)

	return block

# galois field multiplication.
def galois(x, y) :
	# x and y are singular bytes
	t = 0

	for i in range(8) :
		if y & 1 :
			t = t ^ x

		z = x & 0x80
		x = x << 1
		x = x & 0xff

		if z :
			x = x ^ 0x1b
		y = y >> 1

	return t

# mixes columns of AES state by matrix multiplication over galois field
def mix_columns(block) :

	factor = [2, 1, 1, 3]
	for i in range(4) :

		column = block[i : i+16 : 4]
		temp = column

		column[0] = galois(temp[0], factor[0]) ^ galois(temp[3], factor[1]) ^ galois(temp[2], factor[2]) ^ galois(temp[1], factor[3])
		column[1] = galois(temp[1], factor[0]) ^ galois(temp[0], factor[1]) ^ galois(temp[3], factor[2]) ^ galois(temp[2], factor[3])
		column[2] = galois(temp[2], factor[0]) ^ galois(temp[1], factor[1]) ^ galois(temp[0], factor[2]) ^ galois(temp[3], factor[3])
		column[3] = galois(temp[3], factor[0]) ^ galois(temp[2], factor[1]) ^ galois(temp[1], factor[2]) ^ galois(temp[0], factor[3])

		block[i : i+16 : 4] = column

	return block

def inv_mix_columns(block) :

	factor = [14, 9, 13, 11]
	for i in range(4) :

		column = block[i : i+16 : 4]
		temp = column

		column[0] = galois(temp[0], factor[0]) ^ galois(temp[3], factor[1]) ^ galois(temp[2], factor[2]) ^ galois(temp[1], factor[3])
		column[1] = galois(temp[1], factor[0]) ^ galois(temp[0], factor[1]) ^ galois(temp[3], factor[2]) ^ galois(temp[2], factor[3])
		column[2] = galois(temp[2], factor[0]) ^ galois(temp[1], factor[1]) ^ galois(temp[0], factor[2]) ^ galois(temp[3], factor[3])
		column[3] = galois(temp[3], factor[0]) ^ galois(temp[2], factor[1]) ^ galois(temp[1], factor[2]) ^ galois(temp[0], factor[3])

		block[i : i+16 : 4] = column

	return block

# XOR of round key with 16 byte block
def add_round_key(round_key, block) :
	return xor(round_key, block)

def encrypt(key, iv, org_byte_string, block_size) :

	key_len = len(key)
	n_rounds = key_len//4 + 6

	org_bytes = pad(list(org_byte_string), block_size)
	print(org_bytes)

	blocks = make_blocks(org_bytes, block_size)

	expanded_key = expand_key(key)

	#cipher_bytes = [iv]
	cipher_bytes = []

	for block in blocks :

		# make a 4x4 matrix out of 16 byte array
		piece = [0 for i in range(16)]
		for i in range(4) :
			for j in range(4) :
				piece[i + j*4] = block[i*4 + j]

		#piece = xor(cipher_bytes[-1], piece)

		# initial transformation
		piece = add_round_key(generate_rkey(expanded_key, 0), piece)

		# Subsequent rounds
		for i in range(n_rounds) :

			piece = sub_bytes(piece)
			piece = shift_rows(piece)

			if i < n_rounds-1 :
				piece = mix_columns(piece)

			piece = add_round_key(generate_rkey(expanded_key, 16*(i+1)), piece)

		# convert the matrix back to array
		piece_ = [0 for i in range(16)]
		for i in range(4) :
			for j in range(4) :
				piece_[i*4 + j] = piece[i + 4*j]

		cipher_bytes.append(piece_)

	cipher = []
	for x in cipher_bytes :
		cipher += x

	return bytes(cipher)

def decrypt(key, iv, cipher_byte_string, block_size) :

	key_len = len(key)
	n_rounds = key_len//4 + 6

	cipher_bytes = list(cipher_byte_string)
	blocks = make_blocks(cipher_bytes, block_size)

	expanded_key = expand_key(key)

	org_bytes = []

	for block in blocks :

		piece = [0 for i in range(16)]
		for i in range(4) :
			for j in range(4) :
				piece[i + j*4] = block[i*4 + j]

		for i in range(n_rounds) :

			piece = add_round_key(generate_rkey(expanded_key, 16*i), piece)

			if i > 0 :
				piece = inv_mix_columns(piece)

			piece = inv_shift_rows(piece)
			piece = inv_sub_bytes(piece)

		piece = add_round_key(generate_rkey(expanded_key, 16*n_rounds), piece)

		piece_ = [0 for i in range(16)]
		for i in range(4) :
			for j in range(4) :
				piece_[i*4 + j] = piece[i + j*4]

		org_bytes.append(piece_)

	original = []
	for x in org_bytes :
		original += x
	print('\n', original)

	original = remove_pad(original)

	return bytes(original)

key = [165, 225, 228, 132, 253, 57, 175, 168, 43, 223, 200, 46, 42, 180, 84, 75, 163, 184, 189, 188, 235, 189, 76, 157, 45, 187, 148, 162, 239, 253, 239, 102]
iv = [191, 183, 44, 107, 33, 199, 222, 102, 186, 141, 147, 52, 121, 186, 228, 192]

text = 'Jai shree ram. Bolo har har mahadev.'.encode('utf-8')
text = 'Today is Saturday. Tomorrow is Sunday.'.encode('utf-8')
cipher = encrypt(key, iv, text, 16)
ot = decrypt(key, iv, c, 16).decode('utf-8')