#!/usr/bin/env python
## Homework Number: HW2_P2
## Name: ZhiFei Chen
## ECN Login: chen2281
## Due Date:  1/27/2020


import sys
import os
import BitVector
from BitVector import *

AES_modulus = BitVector(bitstring='100011011')


subBytesTable = []                                                  # for encryption
invSubBytesTable = []                                               # for decryption

def genTables():
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal = i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1,b2,b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))

def gee(keyword, round_constant, byte_sub_table):
    '''
    This is the g() function you see in Figure 4 of Lecture 8.
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    return newword, round_constant

def gen_key_schedule_128(key_bv):
    byte_sub_table = gen_subbytes_table()
    #  We need 44 keywords in the key schedule for 128 bit AES.  Each keyword is 32-bits
    #  wide. The 128-bit AES uses the first four keywords to xor the input block with.
    #  Subsequently, each of the 10 rounds uses 4 keywords from the key schedule. We will
    #  store all 44 keywords in the following list:
    key_words = [None for i in range(44)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for i in range(4):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(4,44):
        if i%4 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-4] ^ kwd
        else:
            key_words[i] = key_words[i-4] ^ key_words[i-1]
    return key_words

def gen_key_schedule_192(key_bv):
    byte_sub_table = gen_subbytes_table()
    #  We need 52 keywords (each keyword consists of 32 bits) in the key schedule for
    #  192 bit AES.  The 192-bit AES uses the first four keywords to xor the input
    #  block with.  Subsequently, each of the 12 rounds uses 4 keywords from the key
    #  schedule. We will store all 52 keywords in the following list:
    key_words = [None for i in range(52)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for i in range(6):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(6,52):
        if i%6 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-6] ^ kwd
        else:
            key_words[i] = key_words[i-6] ^ key_words[i-1]
    return key_words

def gen_key_schedule_256(key_bv):
    byte_sub_table = gen_subbytes_table()
    #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
    #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
    #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
    #  schedule. We will store all 60 keywords in the following list:
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for i in range(8):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(8,60):
        if i%8 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-8] ^ kwd
        elif (i - (i//8)*8) < 4:
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        elif (i - (i//8)*8) == 4:
            key_words[i] = BitVector(size = 0)
            for j in range(4):
                key_words[i] += BitVector(intVal =
                                 byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
            key_words[i] ^= key_words[i-8]
        elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        else:
            sys.exit("error in key scheduling algo for i = %d" % i)
    return key_words

def gen_subbytes_table():
    subBytesTable = []
    c = BitVector(bitstring='01100011')
    for i in range(0, 256):
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
    return subBytesTable

def gen_key():
    key_words = []
    keysize = 256
    key = open(sys.argv[3], 'r').read()
    key_bv = BitVector(textstring= key)  # pass the key to the bitvector class
    if keysize == 128:
        key_words = gen_key_schedule_128(key_bv)
    elif keysize == 192:
        key_words = gen_key_schedule_192(key_bv)
    elif keysize == 256:
        key_words = gen_key_schedule_256(key_bv)
    else:
        sys.exit("wrong keysize --- aborting")

    key_schedule = []
    for word_index,word in enumerate(key_words):
        keyword_in_ints = []
        for i in range(4):
            keyword_in_ints.append(word[i*8:i*8+8].intValue())
        key_schedule.append(keyword_in_ints)

    num_rounds = None
    if keysize == 128: num_rounds = 10
    if keysize == 192: num_rounds = 12
    if keysize == 256: num_rounds = 14
    round_keys = [None for i in range(num_rounds+1)]
    for i in range(num_rounds+1):
        round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3]).get_bitvector_in_hex()

    return key_schedule, round_keys

############
def sub_bytes(state_array, s_table):
    for i in range(4):
        for j in range(4):
            state_array[i][j] = BitVector(intVal=s_table[int(state_array[i][j])], size=8)

            #print(state_array[i][j])

    return state_array

def shift_rows(state_array):
    temp = state_array[0][0 : 4]
    #print(temp[3])
    state_array[0][0 : 4] = temp[0:]+temp[0:0]

    temp1 = state_array[1][0 : 4]
    state_array[1][0 : 4] = temp1[1:]+temp1[0:1]

    temp2 = state_array[2][0 : 4]
    state_array[2][0 : 4] = temp2[2:]+temp2[0:2]

    temp3 = state_array[3][0 : 4]
    state_array[3][0:4] = temp3[3:] + temp3[0:3]

    return state_array

def inv_shift_rows(state_array):
    temp = state_array[0][0: 4]
    # print(temp[3])
    state_array[0][0: 4] = temp[0:] + temp[0:0]

    temp1 = state_array[1][0: 4]
    state_array[1][0: 4] = temp1[3:] + temp1[0:3]

    temp2 = state_array[2][0: 4]
    state_array[2][0: 4] = temp2[2:] + temp2[0:2]

    temp3 = state_array[3][0: 4]
    state_array[3][0:4] = temp3[1:] + temp3[0:1]

    return state_array

def mix_column(state_array):
    multiply_maxtrix = [[BitVector(intVal=0x00, size=8) for x in range(4)] for x in range(4)]
    result = [[0 for x in range(4)] for x in range(4)]
    multiply_maxtrix[0][0] = BitVector(intVal=0x02, size=8)
    multiply_maxtrix[0][1] = BitVector(intVal=0x03, size=8)
    multiply_maxtrix[0][2] = BitVector(intVal=0x01, size=8)
    multiply_maxtrix[0][3] = BitVector(intVal=0x01, size=8)

    multiply_maxtrix[1][0] = BitVector(intVal=0x01, size=8)
    multiply_maxtrix[1][1] = BitVector(intVal=0x02, size=8)
    multiply_maxtrix[1][2] = BitVector(intVal=0x03, size=8)
    multiply_maxtrix[1][3] = BitVector(intVal=0x01, size=8)

    multiply_maxtrix[2][0] = BitVector(intVal=0x01, size=8)
    multiply_maxtrix[2][1] = BitVector(intVal=0x01, size=8)
    multiply_maxtrix[2][2] = BitVector(intVal=0x02, size=8)
    multiply_maxtrix[2][3] = BitVector(intVal=0x03, size=8)

    multiply_maxtrix[3][0] = BitVector(intVal=0x03, size=8)
    multiply_maxtrix[3][1] = BitVector(intVal=0x01, size=8)
    multiply_maxtrix[3][2] = BitVector(intVal=0x01, size=8)
    multiply_maxtrix[3][3] = BitVector(intVal=0x02, size=8)



    for j in range(4):
        result[0][j] = state_array[0][j].gf_multiply_modular(multiply_maxtrix[0][0], AES_modulus, 8) ^ \
                       state_array[1][j].gf_multiply_modular(multiply_maxtrix[0][1], AES_modulus, 8) ^ \
                       state_array[2][j] ^ \
                       state_array[3][j]

        result[1][j] = state_array[0][j].gf_multiply_modular(multiply_maxtrix[1][0], AES_modulus, 8) ^ \
                       state_array[1][j].gf_multiply_modular(multiply_maxtrix[1][1], AES_modulus, 8) ^ \
                       state_array[2][j].gf_multiply_modular(multiply_maxtrix[1][2], AES_modulus, 8) ^ \
                       state_array[3][j]

        result[2][j] = state_array[0][j].gf_multiply_modular(multiply_maxtrix[2][0], AES_modulus, 8) ^ \
                       state_array[1][j].gf_multiply_modular(multiply_maxtrix[2][1], AES_modulus, 8) ^ \
                       state_array[2][j].gf_multiply_modular(multiply_maxtrix[2][2], AES_modulus, 8) ^ \
                       state_array[3][j].gf_multiply_modular(multiply_maxtrix[2][3], AES_modulus, 8)

        result[3][j] = state_array[0][j].gf_multiply_modular(multiply_maxtrix[3][0], AES_modulus, 8) ^ \
                       state_array[1][j].gf_multiply_modular(multiply_maxtrix[3][1], AES_modulus, 8) ^ \
                       state_array[2][j].gf_multiply_modular(multiply_maxtrix[3][2], AES_modulus, 8) ^ \
                       state_array[3][j].gf_multiply_modular(multiply_maxtrix[3][3], AES_modulus, 8)


    return result

def inv_mix_column(state_array):
    multiply_maxtrix = [[BitVector(intVal=0x00, size=8) for x in range(4)] for x in range(4)]
    result = [[0 for x in range(4)] for x in range(4)]
    multiply_maxtrix[0][0] = BitVector(intVal=0x0E, size=8)
    multiply_maxtrix[0][1] = BitVector(intVal=0x0B, size=8)
    multiply_maxtrix[0][2] = BitVector(intVal=0x0D, size=8)
    multiply_maxtrix[0][3] = BitVector(intVal=0x09, size=8)

    multiply_maxtrix[1][0] = BitVector(intVal=0x09, size=8)
    multiply_maxtrix[1][1] = BitVector(intVal=0x0E, size=8)
    multiply_maxtrix[1][2] = BitVector(intVal=0x0B, size=8)
    multiply_maxtrix[1][3] = BitVector(intVal=0x0D, size=8)

    multiply_maxtrix[2][0] = BitVector(intVal=0x0D, size=8)
    multiply_maxtrix[2][1] = BitVector(intVal=0x09, size=8)
    multiply_maxtrix[2][2] = BitVector(intVal=0x0E, size=8)
    multiply_maxtrix[2][3] = BitVector(intVal=0x0B, size=8)

    multiply_maxtrix[3][0] = BitVector(intVal=0x0B, size=8)
    multiply_maxtrix[3][1] = BitVector(intVal=0x0D, size=8)
    multiply_maxtrix[3][2] = BitVector(intVal=0x09, size=8)
    multiply_maxtrix[3][3] = BitVector(intVal=0x0E, size=8)

    for j in range(4):
        result[0][j] = state_array[0][j].gf_multiply_modular(multiply_maxtrix[0][0], AES_modulus, 8) ^ \
                       state_array[1][j].gf_multiply_modular(multiply_maxtrix[0][1], AES_modulus, 8) ^ \
                       state_array[2][j].gf_multiply_modular(multiply_maxtrix[0][2], AES_modulus, 8) ^ \
                       state_array[3][j].gf_multiply_modular(multiply_maxtrix[0][3], AES_modulus, 8)

        result[1][j] = state_array[0][j].gf_multiply_modular(multiply_maxtrix[1][0], AES_modulus, 8) ^ \
                       state_array[1][j].gf_multiply_modular(multiply_maxtrix[1][1], AES_modulus, 8) ^ \
                       state_array[2][j].gf_multiply_modular(multiply_maxtrix[1][2], AES_modulus, 8) ^ \
                       state_array[3][j].gf_multiply_modular(multiply_maxtrix[1][3], AES_modulus, 8)

        result[2][j] = state_array[0][j].gf_multiply_modular(multiply_maxtrix[2][0], AES_modulus, 8) ^ \
                       state_array[1][j].gf_multiply_modular(multiply_maxtrix[2][1], AES_modulus, 8) ^ \
                       state_array[2][j].gf_multiply_modular(multiply_maxtrix[2][2], AES_modulus, 8) ^ \
                       state_array[3][j].gf_multiply_modular(multiply_maxtrix[2][3], AES_modulus, 8)

        result[3][j] = state_array[0][j].gf_multiply_modular(multiply_maxtrix[3][0], AES_modulus, 8) ^ \
                       state_array[1][j].gf_multiply_modular(multiply_maxtrix[3][1], AES_modulus, 8) ^ \
                       state_array[2][j].gf_multiply_modular(multiply_maxtrix[3][2], AES_modulus, 8) ^ \
                       state_array[3][j].gf_multiply_modular(multiply_maxtrix[3][3], AES_modulus, 8)
    return result

#######################

def gen_state_array(last_round_array,bitvec):
    for i in range(4):
        for j in range(4):
            last_round_array[j][i] = bitvec[32 * i + 8 * j: 32 * i + 8 * (j + 1)]  # we want the value to be store in hex
    return last_round_array
#######################

def encrypt():
    #file_to_encryt = open(sys.argv[2], 'rb')
    bv = BitVector(filename=sys.argv[2])
    output = open(sys.argv[4],'w+')
    key_schedule, round_keys = gen_key()
    s_table = gen_subbytes_table()

    #initialize the state array to all zero

    state_array = [[0 for x in range(4)] for x in range(4)]
    last_round_array = [[0 for x in range(4)] for x in range(4)] # use for last round since we dont need to mix column
    while (bv.more_to_read):
        bitvec = bv.read_bits_from_file( 128 )

        if bitvec.length() % 128 is not 0:
           bitvec = bitvec + BitVector(intVal=0, size=128 - bitvec.length() % 128)
        bitvec ^= BitVector(hexstring=round_keys[0])  #xor with the first round key


        for i in range(1,14): # process only the first 13 round
            state_array = gen_state_array(last_round_array, bitvec)
            state_array = sub_bytes(state_array, s_table)

            state_array = shift_rows(state_array)

            state_array = mix_column(state_array)

            for k in range(4):
                for j in range(4):
                    bitvec[32 * k + 8 * j: 32 * k + 8 * (j + 1)]  =  state_array[j][k] # we want the value to be store in hex
            bitvec ^= BitVector(hexstring=round_keys[i])

        state_array = gen_state_array(last_round_array, bitvec)
        state_array = sub_bytes(state_array, s_table)
        state_array = shift_rows(state_array)

        for i in range(4):
            for j in range(4):
                bitvec[32 * i + 8 * j: 32 * i + 8 * (j + 1)] = state_array[j][i]  # we want the value to be store in hex
        bitvec ^= BitVector(hexstring=round_keys[14])

        output.write(bitvec.get_bitvector_in_hex())

def decrypt():
        file_to_decryt = open(sys.argv[2], 'r').read()
        decrypted_temp = open('temp.txt', 'w+b')
        temp = BitVector(hexstring=file_to_decryt)
        temp.write_to_file(decrypted_temp)
        decrypted_temp.close()

        bv = BitVector(filename='temp.txt')
        output = open(sys.argv[4], 'w+b')
        key_schedule, round_keys = gen_key()
        genTables()
        os.remove('temp.txt')
        #print(invSubBytesTable)

        # initialize the state array to all zero

        state_array = [[0 for x in range(4)] for x in range(4)]
        last_round_array = [[0 for x in range(4)] for x in range(4)]  # use for last round since we dont need to mix column
        while (bv.more_to_read):
                bitvec = bv.read_bits_from_file(128)

                if bitvec.length() % 128 is not 0:
                    bitvec = bitvec + BitVector(intVal=0, size=128 - bitvec.length() % 128)
                bitvec ^= BitVector(hexstring=round_keys[14])  # xor with the first round key

                for i in range(13, 0,-1):  # process only the first 13 round
                    state_array = gen_state_array(last_round_array, bitvec)

                    state_array = inv_shift_rows(state_array)

                    state_array = sub_bytes(state_array, invSubBytesTable)

                    for k in range(4):
                        for j in range(4):
                            bitvec[32 * k + 8 * j: 32 * k + 8 * (j + 1)] = state_array[j][k]  # we want the value to be store in hex
                    bitvec ^= BitVector(hexstring=round_keys[i])

                    state_array = gen_state_array(last_round_array, bitvec)
                    state_array = inv_mix_column(state_array)

                    for x in range(4):
                        for y in range(4):
                            bitvec[32 * x + 8 * y: 32 * x + 8 * (y + 1)] = state_array[y][x]

                state_array = inv_shift_rows(state_array)
                state_array = sub_bytes(state_array, invSubBytesTable)
                #state_array = gen_state_array(last_round_array, bitvec)

                for h in range(4):
                    for g in range(4):
                        bitvec[32 * h + 8 * g: 32 * h + 8 * (g + 1)] = state_array[g][h]  # we want the value to be store in hex
                bitvec ^= BitVector(hexstring=round_keys[0])

                bitvec.write_to_file(output)


        #### populate the state array

        # we need to

if __name__ == "__main__":
    if sys.argv[1] == '-e':
        encrypt()
    else:
        decrypt()
    #table = gen_subbytes_table()
    #print(table)
    #key_schedule, round_keys = gen_key()
    #print(type(round_keys))

