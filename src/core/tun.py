#!python3
# -*- coding: utf-8 -*-
'''
管理 TUN interface, 需要管理员权限
可用 sudo -s 获取临时权限并不切换 bash 及 venv
创建/删除tun/tap设备
ip tuntap add dev tun0 mode tun
ip tuntap add dev tap0 mode tap
ip tuntap del dev tun0 mode tun
#for detail
ip tuntap help


'''

from tuntap import TunTap


class TUN:
    '''
    管理 TUN interface, 需要管理员权限
    可用 sudo -s 获取临时权限并不切换 bash 及 venv
    '''
    def __init__(self, nic_type, nic_name, ip='10.10.2.1', mask='255.255.255.0'):
        self.__type = nic_type
        self.__name = nic_name
        self.__TUN = TunTap(nic_type=self.__type, nic_name=self.__name)
        self.__TUN.config(ip, mask)
        print("Successfully create the TUN interface",
              self.__TUN.name, self.__TUN.ip, self.__TUN.mask)

    def recv(self, size: int = 1024):
        '''
        从TUN接口接收数据
        '''
        return self.__TUN.read(size)

    def send(self, buff):
        '''
        向TUN接口写入数据
        '''
        self.__TUN.write(buff)

    def close(self):
        '''
        关闭TUN接口
        '''
        self.__TUN.close()


if __name__ == '__main__':
    tun1 = TUN(nic_type="Tun", nic_name="tun0")
    # tun1.send("Test Msg")
    try:
        while True:
            print(tun1.recv(1024))
    except:
        tun1.close()
