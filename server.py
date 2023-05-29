from config import utils

import traceback
import socket
import threading

import subprocess

SERVER_IP = subprocess.check_output(['hostname', '-s', '-I']).decode('utf-8')[:-1]

HOST = "127.0.0.1"
PORT = 3000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

clients = []
addresses = []
nicknames = []
keys = []

public_key = utils.get_Random_SDES_key(10)

def get_NICKNAME(given_nickname):
    
    for nickname in nicknames:
        if (given_nickname == nickname):
            return "200"
        
    return "400"

def send_DM(message):

    indexes_pair = utils.get_indexes_pair(message, nicknames)

    num_request = 0
    client_counter = 0
    for client in clients:
        
        if (client_counter in indexes_pair):
            client.send(f"DECRYPT {message}".encode('utf-8'))
            num_request += 1
            
            if (num_request < 2):
                num_request += 1
            else:
                break
        
        client_counter += 1

def send_req(status, user_nickname):

    i = 0
    for client in clients:

        if (nicknames[i] == user_nickname):
            client.send(f"{status}".encode('utf-8'))
            return
        
        i += 1

def broadcast(message, decrypt = False):

    for client in clients:
        if (decrypt):
            client.send(f"DECRYPT {message}".encode('utf-8'))
        else:
            client.send(message)

def remove_user(client):

    try:
        index = clients.index(client)
        clients.remove(client)
        client.close()
        address = addresses[index]
        addresses.remove(address)
        nickname = nicknames[index]
        print(f"{nickname} left the server.")
        broadcast(f'[*] {nickname} left the chat!\n'.encode('utf-8'))
        nicknames.remove(nickname)

    except Exception as ex:
        # User disconect or connection refused
        print('Exception in Server:', ex)
        traceback.print_exc()

def handle(client):

    while True:
        try:
            if client in clients:
                message = client.recv(1024).decode('utf-8')

                if "BROADCAST" in message:
                    broadcast_message = message.replace("BROADCAST", "")
                    broadcast(broadcast_message, decrypt=True)

                elif "DM" in message:
                    direct_message = message.replace("DM", "")
                    send_DM(direct_message)

                elif "GET NICKNAME" in message:
                    user_nickname = message.split()[2]
                    given_nickname = message.split()[3]
                    status = get_NICKNAME(given_nickname)
                    send_req(status, user_nickname)

                elif "/q" in message:
                    remove_user(client)

        except Exception as ex:
            # User disconect or connection refused
            print('Exception in Server:', ex)
            traceback.print_exc()

            remove_user(client)
            break

def receive():

    while True:
        try:
            client, address = server.accept()
            print(f"New client connected with IP: {str(address[0])}")
            
            client.send(public_key.encode('utf-8'))
            client.recv(1024)

            client.send("NICKNAME".encode('utf-8'))
            nickname = client.recv(1024).decode('utf-8')

            nicknames.append(nickname)
            addresses.append(address[0])
            clients.append(client)

            print(f"Nickname of the client is {nickname}!")
            broadcast(f"[*] {nickname} connected to the chat!\n".encode("utf-8"))
            client.send("Connected to the server\n".encode("utf-8"))

            thread = threading.Thread(target=handle, args=(client,))
            thread.start()
        except Exception as ex:
            print(ex)

print(f"Server is starting at IP: {SERVER_IP} at PORT: {PORT}")
receive()