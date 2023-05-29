from config import utils

import traceback
import socket
import threading

import tkinter
import tkinter.scrolledtext
from tkinter import simpledialog

HOST = "127.0.0.1"
PORT = 3000

class Client:

    def format_nickname(self, nickname):
        ## Replace whitespace for underline and remove newline
        return nickname.replace(" ", "_").strip()

    def decrypt_message(self, message, key):
        crypt_message = message.replace("DECRYPT ", "")
        user_nickname, decrypt_message = utils.SDES(crypt_message, key, "D") 
        decrypt_message = f"{user_nickname}: {decrypt_message}"
        return decrypt_message
    
    def get_send_to(self):
        self.sendTo = (self.send_to_entry.get())
    
    def receive(self):

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((HOST, PORT))

        self.public_key = self.sock.recv(1024).decode('utf-8')
        self.sock.send("KEY RECEIVED".encode('utf-8'))

        while self.running:
            try:
                message = self.sock.recv(1024).decode('utf-8')

                if message == "NICKNAME":
                    self.sock.send(self.format_nickname(self.nickname).encode('utf-8'))
                elif "DECRYPT" in message:
                    decrypt_message = self.decrypt_message(message, self.public_key)
                    self.text_area.config(state='normal')
                    self.text_area.insert('end', decrypt_message)
                    self.text_area.yview('end')
                    self.text_area.config(state='disabled')
                else:
                    if self.gui_done:
                        self.text_area.config(state='normal')
                        self.text_area.insert('end', message)
                        self.text_area.yview('end')
                        self.text_area.config(state='disabled')
            except Exception as ex:
                print('Exception in Server:', ex)
                traceback.print_exc()
                self.sock.close()
                break

    def write(self):
        message = f"{self.input_area.get('1.0', 'end')}"

        ## Check if sendTo nickname (message via DM) exists in server
        self.sock.send(f"GET NICKNAME {self.nickname} {self.sendTo}".encode('utf-8'))
        status = self.sock.recv(1024).decode('utf-8')

        ## Nickname not found
        if (status == "400"):
            self.sendTo = "Broadcast"
            self.send_to_entry.delete(0, tkinter.END)

        if (self.sendTo == "Broadcast"):
            crypt_message = f'{self.nickname}: {utils.SDES(message, self.public_key, "C")}'
            self.sock.send(f"BROADCAST{crypt_message}".encode('utf-8'))

        else:
            crypt_message = f'{self.nickname} to {self.sendTo}: {utils.SDES(message, self.public_key, "C")}'
            self.sock.send(f"DM{crypt_message}".encode('utf-8'))

        self.input_area.delete('1.0', 'end')

    def stop(self):
        
        self.running = False
        self.window.destroy()
        self.sock.close()
        exit(0)

    def gui_loop(self):

        self.window = tkinter.Tk()
        self.window.configure(bg="lightgray")

        self.nickname_label = tkinter.Label(self.window, text=f"Nickname: {self.nickname}", bg="lightgray")
        self.nickname_label.config(font=("Arial", 12))
        self.nickname_label.pack(padx=20, pady=5)

        self.chat_label = tkinter.Label(self.window, text="CHAT:", bg="lightgray")
        self.chat_label.config(font=("Arial", 12))
        self.chat_label.pack(padx=20, pady=5)

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

        self.send_to_label = tkinter.Label(self.window, text="Send to (nickname): ", bg="lightgray")
        self.send_to_label.config(font=("Arial", 12))
        self.send_to_label.pack(padx=20, pady=5)

        self.send_to_entry = tkinter.Entry(self.window)
        self.send_to_entry.pack(padx=20, pady=5)

        self.send_to_button = tkinter.Button(self.window, text="Send to", command=self.get_send_to)
        self.send_to_button.config(font=("Arial", 12))
        self.send_to_button.pack(padx=20, pady=5)

        self.gui_done = True
        self.window.protocol("WM_DELETE_WINDOW", self.stop)
        self.window.mainloop()

    def __init__(self):

        nickname_window = tkinter.Tk()
        nickname_window.withdraw()

        self.nickname = simpledialog.askstring("Nickname", "Please, choose a Nickname: ", parent=nickname_window)
        self.gui_done = False
        self.running = True

        self.sendTo = "Broadcast"

        gui_thread = threading.Thread(target=self.gui_loop)
        receive_thread = threading.Thread(target=self.receive)

        gui_thread.start()
        receive_thread.start()

client = Client()