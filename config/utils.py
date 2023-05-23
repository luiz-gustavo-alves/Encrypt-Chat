from ctypes import *

import random
import string
import os

dll_SDES = ("/home/luizgustavo/Projetos/Seguranca-Computacional/Chat/config/C/SDES.so")
clib_SDES = CDLL(dll_SDES)
clib_SDES.simple_des.restype = c_char_p

def convert_str_bin(string):
    return ' '.join(format(i, '08b') for i in bytearray(string, encoding ='utf-8')).split()

def convert_bin_str(bin_values):
    
    ascii_str = ""
    for bin_value in bin_values:
        ascii_str += chr(int(bin_value, 2))

    return ascii_str

def chunk_bin_values(bin_values):

    index = bin_values.index(":")
    nickname = bin_values[:index]
    message = bin_values[(index + 2):]

    chunk = 8
    counter = 0
    chunked_bin_values = ""

    for bin_value in message:

        if (counter < chunk):
            chunked_bin_values += bin_value
            counter += 1
        else:
            chunked_bin_values += " " + bin_value
            counter = 1

    return nickname, chunked_bin_values

def join_bin_values(bin_values):
    bin_values = ''.join(bin_values.split())
    return [bin_values[i:i+8] for i in range(0, len(bin_values), 8)] 

def SDES(message, type):

    if (type == "C"):

        bin_values = convert_str_bin(message)
        crypt_values = []

        for bin_value in bin_values:
            bin_value = bin_value.encode('utf-8')
            crypt_values.append((clib_SDES.simple_des(bin_value, b"1000000000", 1)).decode('utf-8'))

        crypt_message = ''.join(crypt_values)
        return crypt_message

    elif (type == "D"):

        nickname, crypt_message = chunk_bin_values(message.decode('ascii'))
        crypt_message = join_bin_values(crypt_message)
        decrypt_values = []

        for bin_value in crypt_message:
            bin_value = bin_value.encode('utf-8')
            decrypt_values.append((clib_SDES.simple_des(bin_value, b"1000000000", 2)).decode('utf-8'))

        decrypt_message = convert_bin_str(decrypt_values)
        return nickname, decrypt_message
    
    else:
        return "ERROR"

def get_SDES_key(length):

    randomStr = ''.join(random.choice(string.ascii_letters) for i in range(length))
    bin_values = convert_str_bin(randomStr)
    key = ""
    for i in range(length):
        index = (random.randint(0, 7))
        key += (bin_values[i][index])

    return key