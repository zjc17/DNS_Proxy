# -*- coding: utf-8 -*-
'''
测试应用，向客户端的TUN接口不断发送请求
'''

from socket import socket, AF_INET, SOCK_DGRAM

if __name__ == '__main__':
    ADDR = ('127.0.0.1', 8080)
    APP = socket(AF_INET, SOCK_DGRAM)
    MSG = input("Input lowercase sentence: ")
    APP.sendto(MSG.encode(), ADDR)
    MSG_NEW, _TUN_ADDR = APP.recvfrom(2048)
    print(MSG_NEW.decode())
    APP.close()
