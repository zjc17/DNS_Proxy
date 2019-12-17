# -*- coding: utf-8 -*-、
'''
测试 TUN 接口的创建与消息收发
'''
import os
import threading
import time
from socket import socket, AF_INET, SOCK_DGRAM
from tuntap import TunTap
from core.packet import IPPacket

class Client:
    '''
    模拟收发客户端
    '''
    def __init__(self, addr, port):
        '''
        初始化接受客户端
        '''
        self.__app = socket(AF_INET, SOCK_DGRAM)
        self.__app.bind((addr, port))
        self.__app.sendto(b'Hello', ('10.10.10.2', 8080))


    def sendto(self, msg, send_dst):
        '''
        发送消息
        '''
        self.__app.sendto(msg, ('10.10.10.2', 8080))

    def recvfrom(self):
        '''
        接受消息，
        @return: tuple(msg, addr)
        '''
        msg, addr = self.__app.recvfrom(2048)
        return (msg, addr)


class Sender:
    '''
    模拟发送客户端
    '''
    def __init__(self, server_addr, server_port):
        '''
        初始化发送客户端
        '''
        self.__app = socket(AF_INET, SOCK_DGRAM)
        self.__send_dst = (server_addr, server_port)

    def sendto(self, msg):
        '''
        发送消息
        '''
        self.__app.sendto(msg, self.__send_dst)


class Receiver:
    '''
    模拟接受客户端
    '''
    def __init__(self, addr, port):
        '''
        初始化接受客户端
        '''
        self.__app = socket(AF_INET, SOCK_DGRAM)
        self.__app.bind((addr, port))

    def recvfrom(self):
        '''
        接受消息，
        @return: tuple(msg, addr)
        '''
        msg, addr = self.__app.recvfrom(2048)
        return (msg, addr)



#from socket import socket, AF_INET, SOCK_DGRAM


def test_basic():
    '''
    测试 TUN 接口的创建与关闭
    '''
    tun0 = TunTap(nic_type="Tun", nic_name="tun0")
    assert tun0 is not None
    tun0.close()


def test_read():
    '''
    测试从 TUN 接口读取 packet
    '''
    tun_ip = '10.10.10.1'
    test_ip = '10.10.10.2'
    res = [False, ]

    def __send_msg(tun, res):
        while True:
            data = tun.read()
            print(data)
            # print(IPPacket.str_info(p))
            # print(IPPacket.get_src(p))
            if IPPacket.get_src(data) == b'\n\n\n\x01'\
                    and IPPacket.get_dst(data) == b'\n\n\n\x02':
                res[0] = True
                return
    tun0 = TunTap(nic_type="Tun", nic_name="tun0")
    tun0.config(ip=tun_ip, mask='255.255.255.0')
    t_1 = threading.Thread(target=__send_msg, args=(tun0, res), daemon=True)
    t_2 = threading.Thread(target=os.popen, args=(
        'ping ' + test_ip + ' -c 1', ), daemon=True)
    t_1.start()
    t_2.start()
    time.sleep(0.1)
    tun0.close()
    assert res[0]


# def ___test_write():
#     '''
#     测试向 TUN 接口写入 packet
#     '''
#     def __send_msg(tun0):
#         time.sleep(0.5)
#         tun0.write(b'E\x00\x00T\r\xb0@\x00@\x01\x04\xe3\n\n\n\x01\n\n\n\x02\x08\x00R\x04\x0e\xc0\x00\x01\xd2\xfc\xf4]\x00\x00\x00\x00\x04\r\r\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567')

#     tun_ip = '10.10.10.1'
#     tun0 = TunTap(nic_type="Tun", nic_name="tun0")
#     tun0.config(ip=tun_ip, mask='255.255.255.0')
#     t_1 = threading.Thread(target=__send_msg, args=(tun0, ), daemon=True)
#     t_1.start()
#     try:
#         while True:
#             data = tun0.read()
#             print(data)
#             print(IPPacket.str_info(data))
            
#     except:
#         tun0.close()


# if __name__ == '__main__':
#     pass