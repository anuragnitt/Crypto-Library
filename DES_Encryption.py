import math

# conversion of plain text to binary value using utf-8 encoding
def str_to_bin(text) :

	b = [format(x, 'b') for x in bytearray(text, encoding = 'utf-8')]
	for i in range(len(b)) :
		if len(b[i]) < 8 : # making each byte representation of 8 digits
			for x in range(8 - len(b[i])) :
				b[i] = '0' + b[i]
				
	return ''.join(b) # join all list elements into a string

# padding the binary value according to PKCS5-Padding Rule
def pkcs5_padding(text, bin_bits) :

	pad_bytes = 8 - len(text)%8
	pad_value = bin(pad_bytes)[2:]
	
	if len(pad_value) < 8 :
		for i in range(8 - len(pad_value)) :
			pad_value = '0' + pad_value
			
	for i in range(pad_bytes) :
		bin_bits += pad_value
		
	return bin_bits # returns the padded binary bits

# breaking the string in parts of 64 bits
def bit_blocks(bin_bits) :
	
	blocks = []
	
	for i in range(len(bin_bits)//64) :
		blocks.append(bin_bits[i*64 : (i*64)+64])

	return blocks # returns a list of 64-bit binary blocks

# rule to permute the bits in a block
def init_perm(bit_block) :

	ip_table = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
	            62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
	            57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
	            61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
	
	perm = ''
	for i in ip_table :
		perm += bit_block[i-1]

	return perm # returns the string of permutated bits

# converting 64-bit key to 56-bit
def parity_bit_drop(key_bits) :
	
	pbd_table = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
	             10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
	             63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
	             14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
	             
	new_key_bits = ''
	for i in pbd_table :
		new_key_bits += key_bits[i-1]
		
	return new_key_bits # returns the string of dropped and permutated bits

# circular left shifting the 26-bit half keys
def left_shift(bin_bits, n) :
	
	shifted_bits = bin_bits[1:] + bin_bits[0]
	for i in range(n-1) :
		shifted_bits = bin_bits[1:] + bin_bits[0]

	return shifted_bits

# converting 56-bit key to 48-bit
def key_compress(shifted_key) :
	
	kc_table = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
	            23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
	            41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
	            44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
	
	comp_key = ''
	for i in kc_table :
		comp_key += shifted_key[i-1]
		
	return comp_key # returns the compressed key bits

# expands 32-bit sequence to 48-bit for operation with 48-bit key
def expand_perm(bin_bits) :
	
	ep_table = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
	            8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
	            16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
	            24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
	
	expand_bits = ''
	for i in ep_table :
		expand_bits += bin_bits[i-1]

	return expand_bits # returns expanded binary bits

# applies XOR operation between 32-bit binary sequence expanded to 48-bits and 56-bit key compresses to 48-bit
def xor(expand_bits, comp_key) :
	
	res = ''
	for i in range(len(expand_bits)) :
		res += str(int(expand_bits[i]) ^ int(comp_key[i]))
		
	return res # returns the result of xor operation

# converts 48-bit result of XOR to 32-bit in 8 pieces
def s_box(xor_res) :
	
	sb_table = {'00' : [['0000', '0010'], ['0001', '1100'], ['0010', '0100'], ['0011', '0001'], ['0100', '0111'], ['0101', '1010'], ['0110', '1011'], ['0111', '0110'], ['1000', '1000'], ['1001', '0101'], ['1010', '0011'], ['1011', '1111'], ['1100', '1101'], ['1101', '0000'], ['1110', '1110'], ['1111', '1001']],
	            '01' : [['0000', '1110'], ['0001', '1011'], ['0010', '0010'], ['0011', '1100'], ['0100', '0100'], ['0101', '0111'], ['0110', '1101'], ['0111', '0001'], ['1000', '0101'], ['1001', '0000'], ['1010', '1111'], ['1011', '1010'], ['1100', '0011'], ['1101', '1001'], ['1110', '1000'], ['1111', '0110']],
	            '10' : [['0000', '0100'], ['0001', '0010'], ['0010', '0001'], ['0011', '1011'], ['0100', '1010'], ['0101', '1101'], ['0110', '0111'], ['0111', '1000'], ['1000', '1111'], ['1001', '1001'], ['1010', '1100'], ['1011', '0101'], ['1100', '0110'], ['1101', '0011'], ['1110', '0000'], ['1111', '1110']],
	            '11' : [['0000', '1011'], ['0001', '1000'], ['0010', '1100'], ['0011', '0111'], ['0100', '0001'], ['0101', '1110'], ['0110', '0010'], ['0111', '1101'], ['1000', '0110'], ['1001', '1111'], ['1010', '0000'], ['1011', '1001'], ['1100', '1010'], ['1101', '0100'], ['1110', '0101'], ['1111', '0011']]}
	            
	output = ''
	for i in range(8) :
		x = xor_res[i*6 : (i*6)+6]
		y = x[0] + x[-1]
		z = x[1:-1]
		for l in sb_table[y] :
			if l[0] == z :
				output += l[1]
				break
		
	return output # returns a 32-bit output

def straight_perm(s_box_output) :
	
	sp_table = [16, 7, 20, 21, 29, 12, 28, 17,
	            1, 15, 23, 26, 5, 18, 31, 10,
	            2, 8, 24, 14, 32, 27, 3, 9,
	            19, 13, 30, 6, 22, 11, 4, 25]
	            
	straight_bits = ''
	for i in sp_table :
		straight_bits += s_box_output[i-1]
		
	return straight_bits # permutes the output of s_box function

# performs final permutation of the encrypted 64-bits
def final_perm(bin_bits) :
	
	fp_table = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
	            38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
	            36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
	            34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
	            
	perm = ''
	for i in fp_table :
		perm += bin_bits[i-1]
		
	return perm

# number of left shifts to be done in each encryption round
left_shift_table = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
	
def round_keys(key_bits) :
	
	round_key_set = []
	
	new_key_bits = parity_bit_drop(key_bits)
	
	left_key = new_key_bits[:28] # break key in two halves
	right_key = new_key_bits[28:]
	
	for i in range(16) :
		left_key = left_shift(left_key, left_shift_table[i]) # left_shift both the halves
		right_key = left_shift(right_key, left_shift_table[i])
		
		comp_key = left_key + right_key # get the shifted_key
		comp_key = key_compress(comp_key) # compress the shifted_key to 48-bit
		
		round_key_set.append(comp_key)
	
	return round_key_set # returns the list of 16 round_keys
	
def encrypt(text, key) :

	bin_bits = str_to_bin(text) # convert the text to binary sequence
	bin_bits = pkcs5_padding(text, bin_bits) # pad the binary sequence according to PKCS5 Padding rule

	key_bits = str_to_bin(key) # convert the encryption key to binary sequence
	round_key_set = round_keys(key_bits) # list of 16 round keys

	blocks = bit_blocks(bin_bits)

	encrypted_bits = ''

	for block in blocks :
		
		block = init_perm(block)
		
		left_bits = block[:32]
		right_bits = block[32:]
		
		for i in range(16) :
		
			expand_right = expand_perm(right_bits) # right_bits is now of 48-bits
			
			xor_res = xor(expand_right, round_key_set[i]) # perform XOR operation
			
			s_box_output = s_box(xor_res) # xor_res is now of 32-bits
			
			s_box_output = straight_perm(s_box_output) # apply straight permutation
			
			left_bits = xor(left_bits, s_box_output) # change left half to result of XOR between left half and changed right half
			
			if i != 15 :
				left_bits, right_bits = right_bits, left_bits # swap the left and right halve's values for next encryption round
				
		new_block = left_bits + right_bits
		new_block = final_perm(new_block)
		
		encrypted_bits += new_block
		
	return encrypted_bits
	
def bin2hex(binary) :
	
	table = {'0000':'0', '0001':'1', '0010':'2', '0011':'3', '0100':'4', '0101':'5', '0110':'6', '0111':'7',
	         '1000':'8', '1001':'9', '1010':'A', '1011':'B', '1100':'C', '1101':'D', '1110':'E', '1111':'F'}

	hex_bits = ''
	for i in range(len(binary)//4) :
		hex_bits += table[binary[i*4 : (i*4)+4]]
		
	return hex_bits

def bin2base64(binary) :

	pad_val = 3 - (len(binary)//8)%3

	table = {0:'A', 1:'B', 2:'C', 3:'D', 4:'E', 5:'F', 6:'G', 7:'H', 8:'I', 9:'J', 10:'K', 11:'L', 12:'M', 13:'N', 14:'O', 15:'P',
	         16:'Q', 17:'R', 18:'S', 19:'T', 20:'U', 21:'V', 22:'W', 23:'X', 24:'Y', 25:'Z', 26:'a', 27:'b', 28:'c', 29:'d', 30:'e', 31:'f',
	         32:'g', 33:'h', 34:'i', 35:'j', 36:'k', 37:'l', 38:'m', 39:'n', 40:'o', 41:'p', 42:'q', 43:'r', 44:'s', 45:'t', 46:'u', 47:'v',
	         48:'w', 49:'x', 50:'y', 51:'z', 52:'0', 53:'1', 54:'2', 55:'3', 56:'4', 57:'5', 58:'6', 59:'7', 60:'8', 61:'9', 62:'+', 63:'/'}

	if (6 - len(binary)%6) != 6 :
		for i in range(6 - len(binary)%6) :
			binary += '0'

	base64 = ''

	for i in range(len(binary)//6) :
		decimal_val = 0
		bits = [int(x) for x in binary[i*6 : (i*6)+6]]
		for x in range(len(bits)) :
			decimal_val += int(bits[x]*math.pow(2, len(bits)-1-x))
			
		base64 += table[decimal_val]

	if pad_val != 3 :
		for i in range(pad_val) :
			base64 += '='

	return base64

text = input('Text : ')
print('\nKey should be of 8 characters')
while True :
	key = input('Encryption Key : ')
	if len(key) == 8 :
		break
	else :
		continue

print('\nEncrypted Text :\n' + bin2base64(encrypt(text, key)))
