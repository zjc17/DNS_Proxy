# -*- coding: utf-8 -*-
'''
测试客户端：
    - 维护TUN
    - 监听数据
    - 修改数据包
'''
import os
import sys
import time
import struct
import socket
from fcntl import ioctl
from select import select
from threading import Thread

PASSWORD = b'4fb88ca224e'

MTU = 1400
BUFFER_SIZE = 4096
KEEPALIVE = 10

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002


def create_tunnel(tun_name='tun%d', tun_mode=IFF_TUN):
    '''
    创建隧道
    '''
    tunfd = os.open("/dev/net/tun", os.O_RDWR)
    ifn = ioctl(tunfd, TUNSETIFF, struct.pack(
        b"16sH", tun_name.encode(), tun_mode))
    tun_name = ifn[:16].decode().strip("\x00")
    return tunfd, tun_name


def start_tunnel(tun_name, local_ip, peer_ip):
    '''
    配置隧道并启动
    '''
    os.popen('ifconfig %s %s dstaddr %s mtu %s up' %
             (tun_name, local_ip, peer_ip, MTU)).read()


class Client():
    '''
    代理客户端
    '''

    def __init__(self):
        self.__app = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__app.settimeout(5)
        self.__dst_addr = SERVER_ADDRESS
        self.init_local_ip()

    def init_local_ip(self):
        '''
        获取本机ip
        '''
        _socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _socket.connect(('8.8.8.8', 80))
        self.local_ip = _socket.getsockname()[0]
        print('Local IP:', self.local_ip)
        _socket.close()

    def keep_alive(self):
        '''
        子线程保持向服务端发送心跳包，以防止服务端清除会话断开隧道连接
        '''
        def _keepalive(udp, dst_addr):
            while True:
                time.sleep(KEEPALIVE)
                udp.sendto(b'\x00', dst_addr)
        k = Thread(target=_keepalive, args=(
            self.__app, self.__dst_addr), name='keep_alive')
        k.setDaemon(True)
        k.start()

    def login(self):
        '''
        连接服务端并配置代理隧道
        '''
        self.__app.sendto(PASSWORD, self.__dst_addr)
        try:
            data, _addr = self.__app.recvfrom(BUFFER_SIZE)
            tunfd, tun_name = create_tunnel()
            local_ip, peer_ip = data.decode().split(';')
            print('Local ip: %s\tPeer ip: %s' % (local_ip, peer_ip))
            start_tunnel(tun_name, local_ip, peer_ip)
            return tunfd
        except socket.timeout:
            return False

    def run_forever(self):
        '''
        运行代理客户端
        '''
        print('Start connect to server...')
        tunfd = self.login()
        if not tunfd:
            print("Connect failed!")
            sys.exit(0)
        print('Connect to server successful')
        self.keep_alive()
        readables = [self.__app, tunfd]
        while True:
            try:
                readab = select(readables, [], [], 10)[0]
            except KeyboardInterrupt:
                self.__app.sendto(b'e', self.__dst_addr)
                raise KeyboardInterrupt
            for _r in readab:
                if _r == self.__app:
                    data, addr = self.__app.recvfrom(BUFFER_SIZE)
                    try:
                        os.write(tunfd, data)
                    except OSError:
                        if data == b'r':
                            os.close(tunfd)
                            readables.remove(tunfd)
                            print('Reconnecting...')
                            tunfd = self.login()
                            readables.append(tunfd)
                        continue
                else:
                    data = os.read(tunfd, BUFFER_SIZE)
                    self.__app.sendto(data, self.__dst_addr)


if __name__ == '__main__':
    try:
        SERVER_ADDRESS = ('47.100.92.248', 8080)
        Client().run_forever()
    except IndexError:
        print('Usage: %s [remote_ip] [remote_port]' % sys.argv[0])
    except KeyboardInterrupt:
        print('Closing vpn client ...')
