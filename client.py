from config import utils

import traceback
import socket
import threading

IP = input("Server IP: ")
PORT = 3000

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((IP, PORT))

public_key = client.recv(1024).decode('ascii')
client.send("KEY RECEIVED".encode('ascii'))

nickname = input("Choose a nickname: ")

def decrypt_message(message):
    crypt_message = message.replace("DECRYPT ", "")
    user_nickname, decrypt_message = utils.SDES(crypt_message, public_key, "D") 
    decrypt_message = f"{user_nickname}: {decrypt_message}"
    print(decrypt_message)

def receive():
    while True:
        try:
            message = client.recv(1024).decode('ascii')

            if message == "NICKNAME":
                client.send(nickname.encode('ascii'))
            elif "DECRYPT" in message:
                decrypt_message(message)
            else:
                print(message)

        except:
            traceback.print_exc()
            print("An error occurred!")
            client.close()
            break

def write():
    while True:
        message = f'{input("")}'
        crypt_message = f'{nickname}: {utils.SDES(message, public_key, "C")}'
        client.send(f"BROADCAST{crypt_message}".encode('ascii'))
        ## crypt_message = f'{nickname} to vasco: {utils.SDES(message, public_key, "C")}'
        ## client.send(f"DM{crypt_message}".encode('ascii'))


receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()