from config import utils

import traceback

import socket
import threading

HOST = "127.0.0.1" # localhost
PORT = 3000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

clients = []
nicknames = []
keys = []

public_key = utils.get_SDES_key(10)

def send_DM(message):

    indexes_pair = utils.get_indexes_pair(message, nicknames)

    num_request = 0
    client_counter = 0
    for client in clients:
        
        if (client_counter in indexes_pair):
            client.send(f"DECRYPT {message}".encode('ascii'))
            num_request += 1
            
            if (num_request < 2):
                num_request += 1
            else:
                break
        
        client_counter += 1

def broadcast(message, decrypt = False):

    for client in clients:
        if (decrypt):
            client.send(f"DECRYPT {message}".encode('ascii'))
        else:
            client.send(message)

def handle(client):
    while True:
        try:
            message = client.recv(1024).decode('ascii')

            if "BROADCAST" in message:
                broadcast_message = message.replace("BROADCAST", "")
                broadcast(broadcast_message, decrypt=True)

            elif "DM" in message:
                direct_message = message.replace("DM", "")
                send_DM(direct_message)

        except:
            # User disconect or connection refused
            traceback.print_exc()

            index = clients.index(client)
            clients.remove(client)
            client.close()
            nickname = nicknames[index]
            broadcast(f'{nickname} left the chat!'.encode('ascii'))
            nicknames.remove(nickname)
            break

def receive():
    while True:
        client, address = server.accept()
        print(f"Connected with {str(address)}")
        
        client.send(public_key.encode('ascii'))
        client.recv(1024).decode('ascii')

        client.send("NICKNAME".encode('ascii'))
        nickname = client.recv(1024).decode('ascii')

        nicknames.append(nickname)
        clients.append(client)

        print(f"Nickname of the client is {nickname}!")
        broadcast(f"{nickname} joined the chat!".encode('ascii'))
        client.send("Connected to the server!".encode('ascii'))

        thread = threading.Thread(target=handle, args=(client,))
        thread.start()

receive()