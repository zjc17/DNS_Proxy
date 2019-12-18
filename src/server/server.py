# -*- coding: utf-8 -*-、
'''
代理服务端
'''
from socket import socket, AF_INET, SOCK_DGRAM
from fcntl import ioctl
from ipaddress import ip_network
from select import select
import struct
import os
import time
import logging
import uuid
from dnslib.dns import DNSError
from core import dns_handler
from core.packet import IPPacket
# TODO 优化logging模块的使用 https://juejin.im/post/5d3c82ab6fb9a07efb69cd02)
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(filename)s[:%(lineno)d] %(levelname)s %(message)s',
                    datefmt='%H:%M:%S')

PASSWORD = ['779ea091-ad7d-43bf-8afc-8b94fdb576bf']
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

class Session:
    '''
    会话管理
    Session(tun_fd,   # Tun 文件修饰符 
            tun_addr, # Tun 内网目标地址
            tun_name, # Tun 虚拟网卡命名
            uuid,     # UUID for Session 增强用户认证
            last_time,# 上次连接时间
            buffer)   # 即将发送给改用户的数据包
    Session 的UUID不同于用户的UUID
        - 避免了多用户使用相同UUID进行认证
        - TODO: Session的UUID使用 uuid1() 生成 (时间相关)，提供类似v2ray的超时丢包，避免中间人攻击
    '''
    def __init__(self, tun_fd, tun_addr, tun_name):
        '''
        初始化 Session
        tun_fd,   # Tun 文件修饰符 
        tun_addr, # Tun 内网目标地址
        tun_name, # Tun 虚拟网卡命名
        uuid,     # UUID for Session 增强用户认证
        '''
        self.tun_fd = tun_fd
        self.tun_addr = tun_addr
        self.tun_name = tun_name
        self.uuid = str(uuid.uuid1())
        self.__last_time = time.time()
        self.__buffer = []
        
    def fresh_session(self):
        '''
        刷新Session访问时间
        '''
        self.last_time = time.time()
    
    def __put_buffer_data(self, data):
        '''
        向会话中写入缓存数据包
        '''
        assert isinstance(data, bytes)
        self.__buffer.append(data)

    def __get_buffer_data(self):
        '''
        获取会话中缓存的数据包
        需要发送回客户端
        @return:
            - bytes if any
            - None if no buffered data
        '''
        if len(self.buffer) == 0:
            return None            
        return self.buffer.pop(0)
        
class SessionManager:
    '''
    会话管理，创建、维护虚拟网卡
    '''
    def __init__(self):
        '''
        初始化Session池
        '''
        self.__session_pool = []

    def __get_session_from_uuid(self, uuid:str)->Session:
        '''
        从用户提供的Session UUID 获取 Session, 同时刷新Session
        @return: Session or None 
        '''
        _count = 0
        for session in self.__session_pool:
            if session.uuid == uuid:
                _count += 1
        assert _count < 2
        # TODO: code above is for checking, remove to imporve the performance
        for session in self.__session_pool:
            if session.uuid == uuid:
                return session
        return None

class Server:
    '''
    模拟接受端
    用户管理:
    mapping => UUID : Session(tun_fd,   # Tun 文件修饰符 
                              tun_addr, # Tun 内网目标地址
                              tun_name, # Tun 虚拟网卡命名
                              last_time,# 上次连接时间
                              buffer)   # 即将发送给改用户的数据包
                              
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
                         'tun_addr': None, 'last_time': None, 'uuid': None,
                         'buffer': []}
        self.user_session = {}
        print('Server listen on %s:%s...' % BIND_ADDRESS)

    def recvfrom(self):
        '''
        接受消息，
        @return: tuple(msg, addr)
        '''
        msg, addr = self.__socket.recvfrom(2048)
        return (addr, ':', msg)

    # def __tun_from_addr(self, addr):
    #     '''
    #     获取 addr 所在的 tunfd
    #     '''
    #     for i in self.sessions:
    #         if i['addr'] == addr:
    #             return i['tunfd']
    #     return -1

    # def __addr_from_tun(self, tunfd):
    #     '''
    #     获取 tunfd 所在的 addr
    #     '''
    #     for i in self.sessions:
    #         if i['tunfd'] == tunfd:
    #             return i['addr']
    #     return -1

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

    def create_session(self, addr, data, uuid)->bool:
        '''
        创建会话
        @Return: True if session created successfully
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
             'tun_addr': tun_addr, 'last_time': time.time(), 'uuid':uuid,
             'buffer': []})
        self.readables.append(tunfd)
        try:
            reply = dns_handler.make_txt_response(data, '%s;%s'%(tun_addr, LOCAL_IP))
            self.__socket.sendto(reply, addr)
        except DNSError:
            logging.debug('Not a DNS Record or not a Command DNS Packet')
        return True

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
                    logging.debug('Session: %s expired!', i['addr'])
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
                logging.debug("Client %s is disconnect", addr)
            return False
        if data in PASSWORD:
            return True
        logging.debug('Clinet %s connect failed', addr)
        return False

    def __defined_keep_alive(self, data, addr, uuid):
        '''
        客户端不断发送 KEEP_ALIVE 包
        接受服务端指令/回传数据
        '''
        print('================KEEP ALIVE===================')
        for session in self.sessions:
            if session['uuid'] == uuid:
                logging.debug('Buffer Len = %d', len(session['buffer']))
                if len(session['buffer']) == 0:
                    reply_packet = b''
                else:
                    reply_packet = session['buffer'].pop()
                if len(reply_packet) > 20:
                    print(IPPacket.str_info(reply_packet))
                reply = dns_handler.make_txt_response(data, reply_packet.hex())
                logging.debug('REPLY:')
                logging.debug(reply)
                self.__socket.sendto(reply, addr)
                logging.debug('SEND BACK')

    def __handle_dns_request(self, data, addr):
        '''
        处理绑定53接口的UDP服务器数据
        - DNS 请求检测
        - 新会话创建
        '''
        uuid, message = self.decode_msg_from_dns_name(data)
        logging.info('UUID: %s => \n%s', uuid, str(message))
        if uuid not in PASSWORD:
            return
        # 相关预定义指令
        if message == b'LOGIN':
            self.create_session(addr, data, uuid)
            return
        if message == b'KEEP_ALIVE':
            self.__defined_keep_alive(data, addr, uuid)
            return
        # 
        tunfd = self.__tun_from_uuid(uuid)
        if len(message) >= 20:
            print(addr)
            try:
                logging.debug('Try to send DATA(%d) to TUN', (len(message)))
                print(IPPacket.str_info(message))
                print(type(message))
                os.write(tunfd, message)
            except OSError:
                logging.info('Fail to write DATA to TUN')
                self.create_session(addr, data, uuid)
                logging.info('Clinet <%s> connect successful', uuid)

    def decode_msg_from_dns_name(self, data):
        _idx = 12
        _len = data[_idx]
        _name = []
        while _len != 0:
            _idx += 1
            _name.append(data[_idx:_idx+_len])
            _idx += _len
            _len = data[_idx]
        message = b''.join(_name[1:-3])
        uuid = _name[0].decode()
        return uuid, message


    def run_forever(self):
        '''
        运行接收端
        '''
        while True:
            readab = select(self.readables, [], [], 1)[0]
            for _r in readab:
                if _r == self.__socket:
                    # DNS packet
                    data, addr = self.__socket.recvfrom(BUFFER_SIZE)
                    self.__handle_dns_request(data, addr)
                    continue
                # inbound data from tun
                data = os.read(_r, BUFFER_SIZE)
                logging.info('GET DATA from Tun, sending to buffer')
                for session in self.sessions:
                    if session['tunfd'] == _r:
                        session['buffer'].append(data)
                    logging.debug('To %s', session['tun_name'])

if __name__ == '__main__':
    SERVER = Server()
    try:
        SERVER.run_forever()
    except KeyboardInterrupt:
        print('Closing vpn server ...')
