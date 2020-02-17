#!/usr/bin/env python
## Homework Number: HW3
## Name: ZhiFei Chen
## ECN Login: chen2281
## Due Date:  2/6/2020

import sys
import math
def isFields(n):
    flag = 1
    if n == 1:
        raise ValueError('Please enter a number greater than 1!')
    for i in range(2, int(n/2)):
        #print(1)
        #print(n % i)
        if (n % i) == 0:
            flag = 0    # the number is not a prime
            break
    return flag

if __name__ == '__main__':
    flag = isFields(int(sys.argv[1]))
    #print(int(sys.argv[1]))
    if flag == 1:
        print('field')
    else:
        if sys.argv[1] == '2':
            print('field')
        else:
            print('ring')
