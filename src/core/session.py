'''
会话管理
'''
import time
import os
import struct
from fcntl import ioctl
from ipaddress import ip_network
import uuid as UUID_GENERATOR
import logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(filename)s[:%(lineno)d] %(levelname)s %(message)s',
                    datefmt='%H:%M:%S')
NETWORK = '10.0.0.0/24'
IPRANGE = list(map(str, ip_network(NETWORK)))[1:]
LOCAL_IP = IPRANGE.pop(0)
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
MTU = 1400
USER_UUID = ['779ea091-ad7d-43bf-8afc-8b94fdb576bf']
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
        self.uuid = str(UUID_GENERATOR.uuid1())
        self.last_time = time.time()
        self.__buffer = []

    def fresh_session(self):
        '''
        刷新Session访问时间
        '''
        self.last_time = time.time()

    def put_buffer_data(self, data):
        '''
        向会话中写入缓存数据包
        '''
        assert isinstance(data, bytes)
        self.__buffer.append(data)

    def get_buffer_data(self):
        '''
        获取会话中缓存的数据包
        需要发送回客户端
        @return:
            - bytes if any
            - None if no buffered data
        '''
        if len(self.__buffer) == 0:
            return None
        return self.__buffer.pop(0)

class SessionManager:
    '''
    用户认证
    会话管理
    创建、维护虚拟网卡
    '''
    def __init__(self, timeout=100):
        '''
        初始化Session池
        '''
        self.__session_pool = []
        self.__time_out = timeout

    def get_session_from_uuid(self, uuid: str)->Session:
        '''
        从用户提供的Session UUID 获取 Session, 同时刷新Session
        @return: Session or None
        '''
        _count = 0
        for session in self.__session_pool:
            if session.uuid == uuid:
                _count += 1
        assert _count < 2
        # TODO: code ABOVE is for checking, remove to imporve the performance
        for session in self.__session_pool:
            if session.uuid == uuid:
                return session
        return None

    def get_session_from_tun_id(self, tun_id: str)->Session:
        '''
        从用户提供的Session UUID 获取 Session, 同时刷新Session
        @return: Session or None
        '''
        _count = 0
        for session in self.__session_pool:
            if session.tun_id == tun_id:
                _count += 1
        assert _count < 2
        # TODO: code ABOVE is for checking, remove to imporve the performance
        for session in self.__session_pool:
            if session.tun_id == tun_id:
                return session
        return None

    def create_session(self, uuid: str)->Session:
        '''
        认证用户提供的UUID(密码), 并创建Session
        assert MSG == b'LOGIN'
        @return None: invalid user
        @return session: 新建的Session
        '''
        if uuid not in USER_UUID:
            return None
        tun_fd, tun_name = create_tunnel()
        tun_addr = IPRANGE.pop(0)
        start_tunnel(tun_name, tun_addr)
        new_session = Session(tun_fd, tun_addr, tun_name)
        self.__session_pool.append(new_session)
        return new_session

    def __del_time_out_session(self):
        '''
        删除过期session
        TODO: 随初始化作为守护态子进程启动
        '''
        time_del = time.time() + self.__time_out
        for session in self.__session_pool:
            if session.last_time > time_del:
                self.__session_pool.remove(session)
                logging.debug('Delete Time Out Session')
