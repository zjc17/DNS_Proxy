# -*- coding: utf-8 -*-
'''
测试应用，向客户端的TUN接口不断发送请求
'''

from socket import socket, AF_INET, SOCK_DGRAM


class Test_APP:
    def __init__(self, addr):
        clientSocket = socket(AF_INET, SOCK_DGRAM)
        message = input("Input lowercase sentence: ")
        clientSocket.sendto(message.encode(), addr)
        modifiedMessage, serverAddress = clientSocket.recvfrom(2048)
        print(modifiedMessage.decode())
        clientSocket.close()

if __name__ == '__main__':
    addr = ('127.0.0.1', 8080)
    app = Test_APP(addr)
