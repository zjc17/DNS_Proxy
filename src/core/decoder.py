#!./venv/bin/active python
# -*- coding: utf-8 -*-
'''
解析伪装DNS数据包
'''
from socket import socket


class Decoder():
   
    def __init__(self):
        '''初始化'''
        pass

    @staticmethod
    def check_pseudo_dns_packet(packet):
        '''检查是否是伪装DNS'''
        return False



if __name__ == '__main__':
    pass
