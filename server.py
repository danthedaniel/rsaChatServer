#!/usr/bin/env python3

import socket
import sys
import argparse
import threading
import random
import string
import rsa
import json


class ClientHandler:
    def __init__(self, conn, keys):
        global client_threads

        self.conn = conn
        self.keys = keys

        self.nick = ''.join(random.choice(string.ascii_uppercase) for _ in range(8))

        # Perform RSA handshake
        handshake = json.dumps({
            'type': 'handshake',
            'payload': self.keys['public']
        })

        self.conn.sendall(handshake.encode('utf-8'))
        client_handsake = json.loads(self.conn.recv(1024).decode('utf-8'))
        self.client_key = client_handsake['payload']

        self.send_to_all('{} has joined the server'.format(self.nick))

        # Add current thread to list
        with lock:
            client_threads[self.nick] = {
                'conn': self.conn,
                'client_key': self.client_key
            }

        self.main_loop()

    def main_loop(self):
        while True:
            data = self.conn.recv(1024).decode('utf-8')

            if not data:
                break

            data = json.loads(data)

            if data['type'] == 'message':
                data = rsa.decrypt(data['payload'], self.keys['private'])

                if data == "/quit":
                    break

                # Send out message to all users connected
                reply = '<{}> {}'.format(self.nick, data)
                self.send_to_all(reply)

        self.logout()

    def send_to_all(self, message):
        global client_threads

        print(message)

        with lock:
            for nick in client_threads.keys():
                packet = json.dumps({
                    'type': 'message',
                    'payload': rsa.encrypt(message, client_threads[nick]['client_key'])
                }).encode('utf-8')

                client_threads[nick]['conn'].sendall(packet)

    def logout(self):
        global client_threads

        self.send_to_all('{} has left the server'.format(self.nick))

        with lock:
            del client_threads[self.nick]
            self.conn.close()

        sys.exit()  # Close the thread


client_threads = {}
lock = threading.Lock()


class ChatServer:
    def __init__(self, host, port):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.keys = rsa.generate_keys()

        try:
            self.s.bind((host, port))
        except socket.error:
            print("Could not bind to port {}".format(port))
            sys.exit()

        self.s.listen(10)

        print("Started server on {}:{}".format(host, port))

        self.main_loop()

    def main_loop(self):
        try:
            while True:
                conn, addr = self.s.accept()
                threading.Thread(target=ClientHandler, args=(conn, self.keys)).start()
        except KeyboardInterrupt:
            self.s.close()
            sys.exit()


def main():
    parser = argparse.ArgumentParser(description='Host RSA encrypted chat client')
    parser.add_argument('-host', dest='host', action='store', default='',
                        help='specify IP to bind to')
    parser.add_argument('-port', dest='port', action='store', default=1337,
                        help='specify port to bind to. Defaults to 1337')
    args = parser.parse_args()

    host = str(args.host)
    port = int(args.port)

    ChatServer(host, port)

if __name__ == "__main__":
    main()
