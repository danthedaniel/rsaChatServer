#!/usr/bin/env python3

import rsa
import socket
import argparse
import sys
import threading
import time
import os
import signal
import json

client_socket = None
lock = threading.Lock()


def start_client(host, port):
    global client_socket

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((host, port))
    except:
        print("Could not connect to {}:{}".format(host, port))
        os.kill(os.getpid(), signal.SIGINT)

    print("Connected to {}".format(host))

    # Perform RSA handshake
    keys = rsa.generate_keys()

    handshake = json.dumps({
        'type': 'handshake',
        'payload': keys['public']
    })

    server_handshake = json.loads(client_socket.recv(1024).decode('utf-8'))
    client_socket.send(handshake.encode('utf-8'))

    server_key = server_handshake['payload']

    threading.Thread(target=output_thread, args=(host, keys['private'])).start()
    threading.Thread(target=input_thread, args=(server_key, )).start()


def input_thread(key):
    global client_socket

    while True:
        time.sleep(0.5)
        user_input = input()

        with lock:
            packet = json.dumps({
                'type': 'message',
                'payload': rsa.encrypt(user_input, key)
            }).encode('utf-8')
            client_socket.send(packet)


def output_thread(host, key):
    global client_socket

    while True:
        data = client_socket.recv(1024).decode('utf-8')

        if not data:
            with lock:
                print("Disconnected from {}".format(host))
                client_socket.close()
                os.kill(os.getpid(), signal.SIGINT)

        data = json.loads(data)

        if data['type'] == 'message':
            print(rsa.decrypt(data['payload'], key) + "\n")


def main():
    parser = argparse.ArgumentParser(description='Connect to RSA encrypted chat server')
    parser.add_argument('-host', dest='host', action='store', default='',
                        help='specify host to connect to to')
    parser.add_argument('-port', dest='port', action='store', default=1337,
                        help='specify port on the host. Defaults to 1337')
    args = parser.parse_args()
    host = str(args.host)
    port = int(args.port)

    if host == '':
        print("No host provided")
        sys.exit()

    start_client(host, port)


if __name__ == "__main__":
    main()
