#!/usr/bin/env python
## Homework Number: HW2_P2
## Name: ZhiFei Chen
## ECN Login: chen2281
## Due Date:  1/27/2020


import sys
import os
from BitVector import *

key_permutation_1 = [56,48,40,32,24,16,8,0,57,49,41,33,25,17,
                      9,1,58,50,42,34,26,18,10,2,59,51,43,35,
                     62,54,46,38,30,22,14,6,61,53,45,37,29,21,
                     13,5,60,52,44,36,28,20,12,4,27,19,11,3]

key_permutation_2 = [13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,
                      3,25,7,15,6,26,19,12,1,40,51,30,36,46,
                     54,29,39,50,44,32,47,43,48,38,55,33,52,
                     45,41,49,35,28,31]

shifts_for_round_key_gen = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]


expansion_permutation = [31,  0,  1,  2,  3,  4,
                          3,  4,  5,  6,  7,  8,
                          7,  8,  9, 10, 11, 12,
                         11, 12, 13, 14, 15, 16,
                         15, 16, 17, 18, 19, 20,
                         19, 20, 21, 22, 23, 24,
                         23, 24, 25, 26, 27, 28,
                         27, 28, 29, 30, 31, 0]
permutation_box = [15, 6, 19, 20, 28, 11, 27, 16,
                   0, 14, 22, 25, 4, 17, 30, 9,
                   1, 7, 23, 13, 31, 26, 2, 8,
                   18, 12, 29, 5, 21, 10, 3, 24]

s_boxes = {i:None for i in range(8)}

s_boxes[0] = [ [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
               [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
               [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
               [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13] ]

s_boxes[1] = [ [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
               [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
               [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
               [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9] ]

s_boxes[2] = [ [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
               [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
               [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
               [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12] ]

s_boxes[3] = [ [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
               [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
               [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
               [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14] ]

s_boxes[4] = [ [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
               [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
               [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
               [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3] ]

s_boxes[5] = [ [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
               [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
               [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
               [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13] ]

s_boxes[6] = [ [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
               [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
               [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
               [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12] ]

s_boxes[7] = [ [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
               [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
               [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
               [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11] ]

def substitute( expanded_half_block ):
    '''
    This method implements the step "Substitution with 8 S-boxes" step you see inside
    Feistel Function dotted box in Figure 4 of Lecture 3 notes.
    '''
    output = BitVector (size = 32)
    segments = [expanded_half_block[x*6:x*6+6] for x in range(8)]
    for sindex in range(len(segments)):
        row = 2*segments[sindex][0] + segments[sindex][-1]
        column = int(segments[sindex][1:-1])
        output[sindex*4:sindex*4+4] = BitVector(intVal = s_boxes[sindex][row][column], size = 4)
    return output


def extract_round_key(encryption_key):
    round_keys = []
    key = encryption_key.deep_copy()
    for round_count in range(16):
        [LKey, RKey] = key.divide_into_two()
        shift = shifts_for_round_key_gen[round_count]
        LKey << shift
        RKey << shift
        key = LKey + RKey
        round_key = key.permute(key_permutation_2)
        round_keys.append(round_key)
    return round_keys

def get_encryption_key(key):
    #key = ""
    key = BitVector(textstring = key)
    key = key.permute(key_permutation_1)
    return key

# encryption_key = get_encryption_key()
# round_keys = generate_round_keys(encryption_key)
# print("\nHere are the 16 round keys:\n")
# for round_key in round_keys:
#     print(round_key)




def encrypt():
    key_file = sys.argv[2]
    key_for_encrypt = get_encryption_key(open(key_file, 'r').read())  # From the key.txt
    round_key = extract_round_key(key_for_encrypt)  # obtain the round key

    img = open(sys.argv[1],'rb')
    data = img.readlines()
    #print(data)
    img.close()

    img1 = open(sys.argv[1], 'r')
    header = data[0:3]
   # print(header)

    #img1.close()

    exclude_header = open(sys.argv[1], 'wb').writelines(data[3:])
    #exclude_header.close()
    bv = BitVector( filename= sys.argv[1] ) # this is the img data without the header
    encrypted_data = open(sys.argv[3], 'wb')
    while (bv.more_to_read):
        bitvec = bv.read_bits_from_file( 64 )
        #print(bitvec)
        if len(bitvec) > 0:
            if bitvec.length() < 64:
                bitvec = bitvec + BitVector(intVal=0, size=32)
            [LE, RE] = bitvec.divide_into_two()
            for r_key in round_key:
                newRE = RE.permute(expansion_permutation)
                #print(newRE)

                out_xor = newRE ^ r_key

                RE_sub = substitute(out_xor)

                RE_permute = RE_sub.permute(permutation_box)

                RE_forLE = RE  # save the RE to assign to LE later

                RE = LE ^ RE_permute

                LE = RE_forLE
            block = (RE + LE)

            block.write_to_file(encrypted_data)
    encrypted_data.close()

    encrypted_img_data = open(sys.argv[3], 'rb').readlines()
    #print(encrypted_img_data)
    f = open(sys.argv[3], 'wb')
    f.seek(0)  # get to the first positin
    #f.write('AA')
    f.writelines(header)
    f.writelines(encrypted_img_data)
    # f.writelines("P6")
    # f.writelines("155 51")
    # f.writelines("255")
    #with open(sys.argv[3], 'wb') as img:
     #   img.writelines(header)
      #  img.writelines(encrypted_img_data)


if __name__ == '__main__':
    encrypt()
