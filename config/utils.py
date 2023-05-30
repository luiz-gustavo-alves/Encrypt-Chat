from ctypes import *

import random
import string
import os

SDES_abspath = os.path.abspath("config/C/SDES.so")
dll_SDES = (SDES_abspath)
clib_SDES = CDLL(dll_SDES)
clib_SDES.simple_des.restype = c_char_p

RC4_abspath = os.path.abspath("config/C/RC4.so")
dll_RC4 = (RC4_abspath)
clib_RC4 = CDLL(dll_RC4)
clib_RC4.RC4.restype = c_char_p

def get_indexes_pair(message, nicknames):
    
    index = message.index(":")
    pair = message[:index].split(" ")

    nicknames_pair = []
    nicknames_pair.append(pair[0])
    nicknames_pair.append(pair[2])

    indexes_pair = []
    for i in range(0, len(nicknames)):
        if nicknames[i] in nicknames_pair:
            indexes_pair.append(i)
    
    return indexes_pair

def convert_str_bin(string):
    return ' '.join(format(i, '08b') for i in bytearray(string, encoding ='utf-8')).split()

def convert_bin_str(bin_values):
    
    ascii_str = ""
    for bin_value in bin_values:
        ascii_str += chr(int(bin_value, 2))

    return ascii_str

def get_SDES_key(secret):

    bin_values = convert_str_bin(secret)
    key = ""
    for i in range(10):

        if (len(bin_values) > i):
            index = (random.randint(0, 7))
            key += (bin_values[i][index])
        else:
            index = str(random.randint(0, 1))
            key += index

    return key

def get_Random_SDES_key(length):

    randomStr = ''.join(random.choice(string.ascii_letters) for i in range(length))
    bin_values = convert_str_bin(randomStr)
    key = ""
    for i in range(length):
        index = (random.randint(0, 7))
        key += (bin_values[i][index])

    return key

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

def SDES(message, key, type):

    key = key.encode('utf-8')

    if (type == "C"):

        bin_values = convert_str_bin(message)
        crypt_values = []

        for bin_value in bin_values:
            bin_value = bin_value.encode('utf-8')
            crypt_values.append((clib_SDES.simple_des(bin_value, key, 1)).decode('utf-8'))

        crypt_message = ''.join(crypt_values)
        return crypt_message

    elif (type == "D"):

        nickname, crypt_message = chunk_bin_values(message)
        crypt_message = join_bin_values(crypt_message)
        decrypt_values = []

        for bin_value in crypt_message:
            bin_value = bin_value.encode('utf-8')
            decrypt_values.append((clib_SDES.simple_des(bin_value, key, 2)).decode('utf-8'))

        decrypt_message = convert_bin_str(decrypt_values)
        return nickname, decrypt_message
    
    return "ERROR"

def RC4(message, key, type):

    key = key.encode('utf-8')

    if (type == "C"):

        message = message.encode('utf-8')
        crypt_message = clib_RC4.RC4(message, key)
        return crypt_message

    elif (type == "D"):
        print(message)
        index = message.index(":")
        nickname = message[:index]
        message = message[(index + 2):]

        print(message)

        decrypt_message = (clib_RC4.RC4(message, key)).decode('utf-8')
        return nickname, decrypt_message

    return "ERROR"
