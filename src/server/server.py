# -*- coding: utf-8 -*-、
'''
代理服务端
'''
from socket import socket, AF_INET, SOCK_DGRAM
from fcntl import ioctl
from ipaddress import ip_network
from threading import Thread
from select import select
import struct
import os
import time
import logging
from dnslib import DNSRecord
from dnslib.dns import DNSError
from core import dns_handler
from core.packet import IPPacket
# TODO: [优化logging模块的使用](https://juejin.im/post/5d3c82ab6fb9a07efb69cd02)
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(filename)s[:%(lineno)d] %(levelname)s %(message)s',
                    datefmt='%H:%M:%S')

PASSWORD = ['779ea091-ad7d-43bf-8afc-8b94fdb576bf','TEST BLANK UUID', 'TEST-BLANKUUID']
BIND_ADDRESS = '0.0.0.0', 53
NETWORK = '10.0.0.0/24'
BUFFER_SIZE = 4096
MTU = 1400
IPRANGE = list(map(str, ip_network(NETWORK)))[1:]
LOCAL_IP = IPRANGE.pop(0)
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


def start_tunnel(tun_name, peer_ip):
    '''
    配置隧道并启动
    '''
    os.popen('ifconfig %s %s dstaddr %s mtu %s up' %
             (tun_name, LOCAL_IP, peer_ip, MTU)).read()


class Server:
    '''
    模拟接受端
    '''

    def __init__(self):
        '''
        初始化接受端
        '''
        self.__socket = socket(AF_INET, SOCK_DGRAM)
        self.__socket.bind(BIND_ADDRESS)
        self.readables = [self.__socket]
        self.sessions = []
        self.tun_info = {'tun_name': None, 'tunfd': None, 'addr': None,
                         'tun_addr': None, 'last_time': None, 'uuid': None}
        print('Server listen on %s:%s...' % BIND_ADDRESS)

    def recvfrom(self):
        '''
        接受消息，
        @return: tuple(msg, addr)
        '''
        msg, addr = self.__socket.recvfrom(2048)
        return (addr, ':', msg)

    def __tun_from_addr(self, addr):
        '''
        获取 addr 所在的 tunfd
        '''
        for i in self.sessions:
            if i['addr'] == addr:
                return i['tunfd']
        return -1

    def __addr_from_tun(self, tunfd):
        '''
        获取 tunfd 所在的 addr
        '''
        for i in self.sessions:
            if i['tunfd'] == tunfd:
                return i['addr']
        return -1

    def __tun_from_uuid(self, addr):
        '''
        获取 uudi 对应 tunfd
        '''
        for i in self.sessions:
            if i['uuid'] == addr:
                return i['tunfd']
        return -1

    def __uuid_from_tun(self, tunfd):
        '''
        获取 tunfd 对应的 uuid
        '''
        for i in self.sessions:
            if i['tunfd'] == tunfd:
                return i['uuid']
        return -1
    

    def create_session(self, addr, data, uuid):
        '''
        创建会话
        '''
        # check auth
        if uuid not in PASSWORD:
            logging.info('Invalid user with uuid = %s', uuid)
            return False
        tunfd, tun_name = create_tunnel()
        tun_addr = IPRANGE.pop(0)
        start_tunnel(tun_name, tun_addr)
        self.sessions.append(
            {'tun_name': tun_name, 'tunfd': tunfd, 'addr': addr,
             'tun_addr': tun_addr, 'last_time': time.time(), 'uuid':uuid})
        self.readables.append(tunfd)
        reply = dns_handler.make_txt_response(data, '%s;%s'%(tun_addr, LOCAL_IP))
        self.__socket.sendto(reply, addr)

    def del_session_by_tun(self, tunfd):
        '''
        根据 tunfd 删除会话
        '''
        if tunfd == -1:
            return False
        for i in self.sessions:
            if i['tunfd'] == tunfd:
                self.sessions.remove(i)
                IPRANGE.append(i['tun_addr'])
        self.readables.remove(tunfd)
        os.close(tunfd)
        return True

    def update_last_time(self, tunfd):
        '''
        刷新会话上次访问时间
        '''
        for i in self.sessions:
            if i['tunfd'] == tunfd:
                i['lastTime'] = time.time()

    def clean_expire_tun(self):
        '''
        关闭过期会话的 tunfd
        '''
        while True:
            for i in self.sessions:
                if (time.time() - i['last_time']) > 60:
                    self.del_session_by_tun(i['tunfd'])
                    logging.debug('Session: %s:%s expired!' % i['addr'])
            time.sleep(1)

    def auth(self, addr, data, tunfd):
        '''
        用户身份认证
        '''
        if data == b'\x00':
            if tunfd != -1:
                self.update_last_time(tunfd)
            else:
                self.__socket.sendto(b'r', (addr))
            return False
        if data == b'e':
            if self.del_session_by_tun(tunfd):
                logging.debug("Client %s:%s is disconnect" % (addr))
            return False
        if data in PASSWORD:
            return True
        logging.debug('Clinet %s:%s connect failed' % (addr))
        return False
    



    
    def __handle_dns_request(self, data, addr):
        '''
        处理绑定53接口的UDP服务器数据
        - DNS 请求检测
        - 新会话创建
        '''
        _idx = 12
        _LEN = data[_idx]
        _name = []
        while _LEN != 0:
            _idx += 1 
            _name.append(data[_idx:_idx+_LEN])
            _idx += _LEN
            _LEN = data[_idx]
        DATA = b''.join(_name[1:-3])
        UUID = _name[0].decode()
        # logging.info('From (%s:%s) UUID: %s' % (addr[0], addr[1], UUID))
        logging.info('UUID: %s => %s'% (UUID, str(DATA)))
        if UUID not in PASSWORD:
            return
        # 相关预定义指令
        if DATA == b'LOGIN':
            self.create_session(addr, data, UUID)
            return
        elif DATA == b'KEEP_ALIVE':
            # TODO: 
            return
        try:
            tunfd = self.__tun_from_uuid(UUID)
            try:
                logging.debug('Try to send DATA(%d) to TUN'%(len(DATA)))
                print(IPPacket.str_info(DATA))
                os.write(tunfd, data)
            except OSError:
                # 新会话请求
                # if not self.auth(addr, data, tunfd):
                #     continue
                logging.info('Fail to write DATA to TUN')
                self.create_session(addr, data, UUID)
                logging.info('Clinet %s:%s connect successful' % addr)
        except OSError:
            pass


    def run_forever(self):
        '''
        运行接收端
        '''
        # 定时刷新，删除过期连接
        # clean_thread = Thread(target=self.clean_expire_tun)
        # clean_thread.setDaemon(True)
        # clean_thread.start()
        while True:
            readab = select(self.readables, [], [], 1)[0]
            for _r in readab:
                if _r == self.__socket:
                    # DNS packet
                    data, addr = self.__socket.recvfrom(BUFFER_SIZE)
                    self.__handle_dns_request(data, addr)
                    continue
                else:
                    # inbound data from tun
                    addr = self.__addr_from_tun(_r)
                    data = os.read(_r, BUFFER_SIZE)
                    logging.info('GET DATA from Tun', str(data))
                    self.__socket.sendto(data, addr)
                    logging.debug('To (%s:%s)' % addr)
                    # except Exception as _e:
                    #     print(repr(_e))
                    #     continue


if __name__ == '__main__':
    SERVER = Server()
    try:
        SERVER.run_forever()
    except KeyboardInterrupt:
        print('Closing vpn server ...')
