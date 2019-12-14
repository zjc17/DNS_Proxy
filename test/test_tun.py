# -*- coding: utf-8 -*-、
'''
测试 TUN 接口的创建与消息收发
'''
from core.tun import TUN
from core.packet import IPPacket
import os
#from socket import socket, AF_INET, SOCK_DGRAM
import threading
import time


def test_basic():
    '''
    测试 TUN 接口的创建与关闭
    '''
    tun = TUN(nic_type="Tun", nic_name="tun0")
    assert tun is not None
    tun.close()


def test_io():
    '''
    测试 TUN 接口读写
    '''
    TUN_IP = '111.111.111.1'
    TEST_IP = '111.111.111.2'
    res = [False,]
    def __send_msg(tun, res):
        while True:
            p = tun.recv()
            # print(IPPacket.str_info(p))
            if IPPacket.get_src(p) == b'ooo\x01'\
               and IPPacket.get_dst(p) == b'ooo\x02':
               res[0] = True
               return
        
    tun = TUN(nic_type="Tun", nic_name="tun0", ip=TUN_IP, mask='255.255.255.0')
    t1 = threading.Thread(target=__send_msg, args=(tun, res), daemon=True)
    t2 = threading.Thread(target=os.popen, args=('ping '  + TEST_IP + ' -c 1', ), daemon=True)
    t1.start()
    t2.start()
    time.sleep(0.1)
    tun.close()
    assert res[0]

if __name__ == '__main__':
    # while True:
    test_io()
