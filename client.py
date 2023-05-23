from config import utils

import socket
import threading

nickname = input("Choose a nickname: ")

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1", 3000))

def receive():
    while True:
        try:
            message = client.recv(1024).decode('ascii')

            if message == "NICKNAME":
                client.send(nickname.encode('ascii'))
            elif message == "DECRYPT":
                
                client.send("OK".encode('ascii'))
                crypt_message = client.recv(1024)
                user_nickname, decrypt_message = utils.SDES(crypt_message, "D") 
                decrypt_message = f"{user_nickname}: {decrypt_message}"
                print(decrypt_message)
            else:
                print(message)

        except Exception as e:
            print(e)
            print("An error occurred!")
            client.close()
            break

def write():
    while True:
        message = f'{input("")}'
        crypt_message = f'{nickname}: {utils.SDES(message, "C")}'
        client.send(crypt_message.encode('ascii'))

receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()