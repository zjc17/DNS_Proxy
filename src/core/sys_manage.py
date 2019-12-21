'''
管理系统资源
- tun创建与删除
- iptable管理
- socks服务器管理
'''
import os
import struct
from fcntl import ioctl

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
class TunManager:
    '''
    管理Tun资源
    - 创建
    - 启动
    - 删除
    '''
    @staticmethod
    def create_tunnel(tun_name='tun%d', tun_mode=IFF_TUN):
        '''
        创建隧道
        '''
        tunfd = os.open("/dev/net/tun", os.O_RDWR)
        ifn = ioctl(tunfd, TUNSETIFF, struct.pack(
            b"16sH", tun_name.encode(), tun_mode))
        tun_name = ifn[:16].decode().strip("\x00")
        return tunfd, tun_name

    @staticmethod
    def del_tunnel(tun_fd):
        '''
        根据文件修饰符关闭Tun
        '''
        os.close(tun_fd)
    
    @staticmethod
    def start_tunnel(tun_name, local_ip, peer_ip, mtu):
        '''
        配置隧道并启动
        '''
        os.popen('ifconfig %s %s dstaddr %s mtu %s up' %
                (tun_name, local_ip, peer_ip, mtu)).read()
