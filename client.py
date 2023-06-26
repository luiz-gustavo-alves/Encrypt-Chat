from config import utils

from config.encrypt.CBC import cbc_cripto, cbc_descripto
from config.encrypt.ECB import ecb_cripto, ecb_descripto

import traceback
import socket
import threading

import tkinter
import tkinter.scrolledtext
from tkinter import simpledialog

PORT = 3000

prime_num = 1021
primitive_sqrt = 751

class Client:

    def format_nickname(self, nickname):
        ## Replace whitespace for underline and remove newline
        return nickname.replace(" ", "_").strip()
    
    def use_sdes(self):
        self.using_algorithm = "SDES"
        self.algorithm_label.config(text="SDES")

    def use_rc4(self):
        self.using_algorithm = "RC4"
        self.algorithm_label.config(text="RC4")

    def use_pkey(self):
        ## User request to use public key
        self.using_key = "Public"
        self.key_label.config(text="PUBLIC")

    def use_skey(self):
        ## User request to use secret key
        self.using_key = "Secret"
        self.key_label.config(text="SECRET")

    def use_session_key(self):
        ## User request to use session key
        if (self.session_value == "" or self.sendTo == "Broadcast"):
            return

        self.sock.send(f"USE SESSION {self.nickname} {self.sendTo}".encode('utf-8'))

    def use_ecb(self):
        ## SDES ECB operation
        self.sdes_op = "ECB"
        self.sdes_op_label.config(text="ECB")

    def use_cbc(self):
        ## SDES CBC operation
        self.sdes_op = "CBC"
        self.sdes_op_label.config(text="CBC")

    def get_send_to(self):
        ## User request to send Direct Messages
        self.sendTo = self.send_to_entry.get()

        ## Check if requested nickname (message via DM) exists in server
        self.sock.send(f"GET NICKNAME {self.nickname} {self.sendTo}".encode('utf-8'))

    def get_secret_key_SDES(self):
        ## User request to use SDES secret key
        key = self.secret_key_entry.get()
        self.secret_key_SDES = utils.get_SDES_key(key)

    def get_secret_key_RC4(self):
        ## User request to use RC4 secret key
        key = self.secret_key_entry.get()
        self.secret_key_RC4 = key

    def get_session_value(self):
        ## User request to use public value for DH (Diffie-Hellman)
        session_value = self.session_value_entry.get()
        self.session_value = int(session_value)
        self.client_mod_value = (primitive_sqrt ** self.session_value) % prime_num

    def decrypt_message_SDES(self, message, key, type = "Broadcast", op = "ECB"):

        crypt_message = message.replace("DECRYPT ", "")

        if (type == "Broadcast"):
            user_nickname = crypt_message.split()[0]
            crypt_message = crypt_message.split()[1]
        
        elif (type == "DM"):
            user_nickname = f"{crypt_message.split()[0]} {crypt_message.split()[1]} {crypt_message.split()[2]}"
            crypt_message = crypt_message.split()[3]

        if (op == "ECB"):
            decrypt_message = ecb_descripto(crypt_message, key)

        elif (op == "CBC"):
            decrypt_message = cbc_descripto(crypt_message, key)
        
        decrypt_message = f"{user_nickname} {decrypt_message}\n"
        return decrypt_message

    def write(self):

        ## Message input
        message = f"{self.input_area.get('1.0', 'end')}"

        ## Broadcast uses public key and SDES ECB encryption as default
        if (self.sendTo == "Broadcast"):

            crypt_message = f'{self.nickname}: {ecb_cripto(message.strip(), self.public_key)}'
            self.sock.send(f"BROADCAST{crypt_message}".encode('utf-8'))

            self.chat_label.config(text="BROADCAST")
            self.key_label.config(text="PUBLIC")
            self.sdes_op_label.config(text="ECB")

        ## DM messages handler
        elif (self.sendTo != "Broadcast"):

            ## Client using public key
            if (self.using_key == "Public"):
                key = self.public_key

                if (self.using_algorithm == "SDES"):
                    
                    if (self.sdes_op == "ECB"):
                        crypt_message = f'{self.nickname} to {self.sendTo}: {ecb_cripto(message.strip(), key)}'

                    elif (self.sdes_op == "CBC"):
                        crypt_message = f'{self.nickname} to {self.sendTo}: {cbc_cripto(message.strip(), key)}'

                elif (self.using_algorithm == "RC4"):
                    crypt_message = f'{self.nickname} to {self.sendTo}: {utils.RC4_crypt(message, key)}'

                self.sock.send(f"DM {crypt_message} {self.using_algorithm}".encode('utf-8'))

            ## Client using secret/session key
            elif (self.using_key == "Secret" or self.using_key == "Session"):

                if (self.using_algorithm == "SDES"):
                    
                    if (self.using_key == "Secret"):
                        key = self.secret_key_SDES

                    else:
                        key = self.session_key_SDES

                    if (self.sdes_op == "ECB"):
                        crypt_message = f'{self.nickname} to {self.sendTo}: {ecb_cripto(message.split(), key)}'
                        crypted_key = ecb_cripto(key, self.public_key)

                    elif (self.sdes_op == "CBC"):
                        crypt_message = f'{self.nickname} to {self.sendTo}: {cbc_cripto(message.split(), key)}'
                        crypted_key = cbc_cripto(key, self.public_key)
                    
                    self.sock.send(f'SKEY {crypt_message} {crypted_key} SDES'.encode('utf-8'))

                elif (self.using_algorithm == "RC4"):

                    if (self.using_key == "Secret"):
                        key = self.secret_key_RC4

                    else:
                        key = self.session_key_RC4

                    crypt_message = f'{self.nickname} to {self.sendTo}: {utils.RC4_crypt(message, key)}'
                    crypted_key = utils.RC4_crypt(key, self.public_key)
                    self.sock.send(f'SKEY {crypt_message} {key} RC4'.encode('utf-8'))

        self.input_area.delete('1.0', 'end')
        return 'break'

    def receive(self):

        file = open("pkey.txt", "r")
        self.public_key = file.readline()
        file.close()

        while self.running:

            try:
                message = self.sock.recv(1024).decode('utf-8')

                ## Plaintext Message from server
                ## print(message)

                ## Flag to show decrypted messages
                decrypt = False

                ## Empty string after removing client from server
                if not message:
                    print("Leaving the server...")
                    break
                
                ## Server request to get user nickname
                if message == "NICKNAME":
                    self.sock.send(self.nickname.encode('utf-8'))

                elif "REQUEST" in message:
                            
                    request = message.split()[1]

                    ## Requested nickname not found
                    if (request == "400"):
                        self.sendTo = "Broadcast"
                        self.sdes_op = "ECB"
                        self.send_to_entry.delete(0, tkinter.END)

                    ## Requested nickname found
                    elif (request == "200"):
                        request_nickname = message.split()[2]
                        self.sendTo = request_nickname
                        self.chat_label.config(text="DM")

                    ## Don't broadcast this message 
                    continue

                elif "GET SESSION" in message:

                    request_nickname1 = message.split()[2]
                    request_nickname2 = message.split()[3]

                    if (request_nickname1 == self.nickname):
                        self.sendTo = request_nickname2

                    elif (request_nickname2 == self.nickname):
                        self.sendTo = request_nickname1

                    request = self.sock.send(f"SESSION VALUE {self.sendTo} {self.client_mod_value}".encode('utf-8'))

                elif "SESSION VALUE" in message:

                    request_mod_value = int(message.split()[2])
                    self.session_key = (request_mod_value ** self.session_value) % prime_num

                    self.session_key_SDES = cbc_cripto(self.session_key, self.public_key)
                    self.session_key_RC4 = utils.RC4_crypt(self.session_key, self.public_key)
                    
                    self.using_key = "Session"
                    self.key_label.config(text="SESSION")

                ## Decrypt messages using Public Key (Broadcast)
                elif "DECRYPT" in message:
                    
                    ## Encrypted BROADCAST message
                    decrypt = True
                    decrypt_message = self.decrypt_message_SDES(message, self.public_key, op="ECB")

                elif "PKEY" in message:

                    ## Encrypted DM message (Public Key)
                    decrypt = True

                    if "SDES" in message:
                        crypted_message = f"{message.split()[1]} {message.split()[2]} {message.split()[3]} {message.split()[4]}"

                        if (self.sdes_op == "ECB"):
                            decrypt_message = self.decrypt_message_SDES(crypted_message, self.public_key, type="DM", op="ECB")

                        elif (self.sdes_op == "CBC"):
                            decrypt_message = self.decrypt_message_SDES(crypted_message, self.public_key, type="DM", op="CBC")

                    elif "RC4" in message:
                        nicknames = f"{message.split()[1]} {message.split()[2]} {message.split()[3]}"
                        content = message.split()[4]
                        decrypt_message = utils.RC4_decrypt(content, self.public_key)
                        decrypt_message = f"{nicknames} {decrypt_message}"

                ## Decrypt messages using Secret/Session Key (DM messages)
                elif "SKEY" in message:

                    ## Encrypted DM message (Secret/Session Key)
                    decrypt = True

                    if "SDES" in message:
                        crypted_key = message.split()[1]
                        crypted_message = f"{message.split()[2]} {message.split()[3]} {message.split()[4]} {message.split()[5]}"

                        if (self.sdes_op == "ECB"):

                            key = ecb_descripto(crypted_key, self.public_key)
                            decrypt_message = self.decrypt_message_SDES(crypted_message, key, type="DM", op="ECB")

                        elif (self.sdes_op == "CBC"):
                            key = cbc_descripto(crypted_key, self.public_key)
                            decrypt_message = self.decrypt_message_SDES(crypted_message, key, type="DM", op="CBC")

                    elif "RC4" in message:
                        key = message.split()[1]
                        nicknames = f"{message.split()[2]} {message.split()[3]} {message.split()[4]}"
                        crypted_message = message.split()[5]
    
                        decrypt_message = utils.RC4_decrypt(crypted_message, key)
                        decrypt_message = f"{nicknames} {decrypt_message}"

                ## Decrypt messages
                if (decrypt):
                    self.text_area.config(state='normal')
                    self.text_area.insert('end', decrypt_message)
                    self.text_area.yview('end')
                    self.text_area.config(state='disabled')

                ## Server messages
                else:
                    if self.gui_done:
                        self.text_area.config(state='normal')
                        self.text_area.insert('end', message)
                        self.text_area.yview('end')
                        self.text_area.config(state='disabled')

            except (ConnectionAbortedError, Exception):
                traceback.print_exc()
                self.stop()

    def stop(self):
        
        ## STOP GUI (close socket and exit the program)
        self.sock.send("/q".encode("utf-8"))
        self.sock.close()
        self.running = False
        self.window.destroy()
        exit(0)

    def gui_loop(self):

        ## Build GUI
        self.window = tkinter.Tk()
        self.window.title(f"NICKNAME {self.nickname}")
        self.window.configure(bg="lightgray")

        self.text_label = tkinter.Label(self.window, text="CHAT", bg="lightgray")
        self.text_label.config(font=("Arial", 12))
        self.text_label.pack(padx=20, pady=5)

        self.text_area = tkinter.scrolledtext.ScrolledText(self.window)
        self.text_area.pack(padx=20, pady=5)
        self.text_area.config(state="disabled")

        self.msg_label = tkinter.Label(self.window, text="Message:", bg="lightgray")
        self.msg_label.config(font=("Arial", 12))
        self.msg_label.pack(padx=20, pady=5)

        self.input_area = tkinter.Text(self.window, height=3)
        self.input_area.pack(padx=20, pady=5)

        self.send_button = tkinter.Button(self.window, text="Send", command=self.write)
        self.send_button.config(font=("Arial", 12))
        self.send_button.pack(padx=20, pady=5)

        self.send_to_label = tkinter.Label(self.window, text="Send DM (name/IP): ", bg="lightgray")
        self.send_to_label.config(font=("Arial", 12))
        self.send_to_label.pack(padx=10, pady=10, side=tkinter.LEFT)

        self.send_to_entry = tkinter.Entry(self.window)
        self.send_to_entry.pack(padx=10, pady=10, side=tkinter.LEFT)

        self.send_to_button = tkinter.Button(self.window, text="Send DM", command=self.get_send_to)
        self.send_to_button.config(font=("Arial", 12))
        self.send_to_button.pack(padx=10, pady=10, side=tkinter.LEFT)

        self.secret_key_label = tkinter.Label(self.window, text="Secret Key: ", bg="lightgray")
        self.secret_key_label.config(font=("Arial", 12))
        self.secret_key_label.pack(padx=10, pady=10, side=tkinter.LEFT)

        self.secret_key_entry = tkinter.Entry(self.window)
        self.secret_key_entry.pack(padx=10, pady=10, side=tkinter.LEFT)

        self.secret_key_button_SDES = tkinter.Button(self.window, text="SDES key", command=self.get_secret_key_SDES)
        self.secret_key_button_SDES.config(font=("Arial", 12))
        self.secret_key_button_SDES.pack(padx=10, pady=10, side=tkinter.LEFT)

        self.secret_key_button_RC4 = tkinter.Button(self.window, text="RC4 key", command=self.get_secret_key_RC4)
        self.secret_key_button_RC4.config(font=("Arial", 12))
        self.secret_key_button_RC4.pack(padx=10, pady=10, side=tkinter.LEFT)

        self.session_value_label = tkinter.Label(self.window, text="Session Key Value: ", bg="lightgray")
        self.session_value_label.config(font=("Arial", 12))
        self.session_value_label.pack(padx=10, pady=10, side=tkinter.LEFT)

        self.session_value_entry = tkinter.Entry(self.window)
        self.session_value_entry.pack(padx=10, pady=10, side=tkinter.LEFT)

        self.session_value_button = tkinter.Button(self.window, text="Send Value", command=self.get_session_value)
        self.session_value_button.config(font=("Arial", 12))
        self.session_value_button.pack(padx=10, pady=10, side=tkinter.LEFT)

        self.algorithm_label = tkinter.Label(self.window, text="Select Algorithm: ", bg="lightgray")
        self.algorithm_label.config(font=("Arial", 16))
        self.algorithm_label.pack(padx=20, pady=5, side=tkinter.TOP)
        
        self.use_sdes_button = tkinter.Button(self.window, text="SDES", command=self.use_sdes)
        self.use_sdes_button.config(font=("Arial", 12))
        self.use_sdes_button.pack(padx=20, pady=5)

        self.use_rc4_button = tkinter.Button(self.window, text="RC4", command=self.use_rc4)
        self.use_rc4_button.config(font=("Arial", 12))
        self.use_rc4_button.pack(padx=20, pady=5)

        self.sdes_op_label = tkinter.Label(self.window, text="Select SDES op: ", bg="lightgray")
        self.sdes_op_label.config(font=("Arial", 16))
        self.sdes_op_label.pack(padx=20, pady=5)
        
        self.use_ecb_button = tkinter.Button(self.window, text="ECB", command=self.use_ecb)
        self.use_ecb_button.config(font=("Arial", 12))
        self.use_ecb_button.pack(padx=20, pady=5)

        self.use_cbc_button = tkinter.Button(self.window, text="CBC", command=self.use_cbc)
        self.use_cbc_button.config(font=("Arial", 12))
        self.use_cbc_button.pack(padx=20, pady=5)

        self.select_key_label = tkinter.Label(self.window, text="Select Key: ", bg="lightgray")
        self.select_key_label.config(font=("Arial", 16))
        self.select_key_label.pack(padx=20, pady=5)

        self.use_pkey_button = tkinter.Button(self.window, text="Use PUBLIC KEY", command=self.use_pkey)
        self.use_pkey_button.config(font=("Arial", 12))
        self.use_pkey_button.pack(padx=20, pady=5)

        self.use_skey_button = tkinter.Button(self.window, text="Use SECRET KEY", command=self.use_skey)
        self.use_skey_button.config(font=("Arial", 12))
        self.use_skey_button.pack(padx=20, pady=5)

        self.use_session_key_button = tkinter.Button(self.window, text="Use SESSION KEY (DH)", command=self.use_session_key)
        self.use_session_key_button.config(font=("Arial", 12))
        self.use_session_key_button.pack(padx=20, pady=5)

        self.chat_label = tkinter.Label(self.window, text="BROADCAST", bg="lightgray")
        self.chat_label.config(font=("Arial", 12))
        self.chat_label.pack(padx=20, pady=5, side=tkinter.LEFT)

        self.key_label = tkinter.Label(self.window, text="PUBLIC", bg="lightgray")
        self.key_label.config(font=("Arial", 12))
        self.key_label.pack(padx=20, pady=5, side=tkinter.LEFT)

        self.algorithm_label = tkinter.Label(self.window, text="SDES", bg="lightgray")
        self.algorithm_label.config(font=("Arial", 12))
        self.algorithm_label.pack(padx=20, pady=5, side=tkinter.LEFT)

        self.sdes_op_label = tkinter.Label(self.window, text="ECB", bg="lightgray")
        self.sdes_op_label.config(font=("Arial", 12))
        self.sdes_op_label.pack(padx=20, pady=5, side=tkinter.LEFT)

        self.gui_done = True
        self.window.wm_protocol("WM_DELETE_WINDOW", self.stop)
        self.window.mainloop()

    def __init__(self):

        IP_window = tkinter.Tk()
        IP_window.withdraw()

        self.HOST_IP = simpledialog.askstring("IP", "IP:", parent=IP_window)

        ## Check if given IP is valid
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.HOST_IP, PORT))
        except:
            
            ## Invalid IP or server is not running
            print(f"Connection refused to the server.")
            print(f"Requested IP: {self.HOST_IP} | Requested PORT: {PORT}")
            exit(-1)

        nickname_window = tkinter.Tk()
        nickname_window.withdraw()

        # TODO: fix bug related to user pressing enter
        self.nickname = simpledialog.askstring("Nickname", "Please, choose a Nickname:", parent=nickname_window)

        self.nickname = self.format_nickname(self.nickname)
        self.gui_done = False
        self.running = True

        ## Default settings
        self.using_key = "Public"
        self.sendTo = "Broadcast"
        self.using_algorithm = "SDES"
        self.sdes_op = "ECB"

        ## User settings
        self.secret_key_SDES = ""
        self.secret_key_RC4 = ""
        self.client_mod_value = ""
        self.session_value = ""
        self.session_key = ""
        self.session_key_SDES = ""
        self.session_key_RC4 = ""

        gui_thread = threading.Thread(target=self.gui_loop)
        receive_thread = threading.Thread(target=self.receive)
        gui_thread.start()
        receive_thread.start()

client = Client()