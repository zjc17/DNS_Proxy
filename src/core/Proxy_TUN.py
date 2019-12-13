#!python3
# -*- coding: utf-8 -*-
'''
管理 TUN interface, 需要管理员权限
可用 sudo -s 获取临时权限并不切换 bash 及 venv
'''

from tuntap import TunTap


class TUN:
    def __init__(self, nic_type, nic_name):
        self.__type = nic_type
        self.__name = nic_name
        self.__TUN = TunTap(nic_type=self.__type, nic_name=self.__name)
        print("Successfully create the TUN interface", 
                self.__TUN.name,self.__TUN.ip,self.__TUN.mask)


if __name__ == '__main__':
    tun = TUN(nic_type="Tun",nic_name="tun0")
    pass