'''
会话管理
'''
import time
import os
import logging
from ipaddress import ip_network
import uuid as UUID_GENERATOR
from threading import Thread
from core.sys_manage import TunManager
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(filename)s[:%(lineno)d] %(levelname)s %(message)s',
                    datefmt='%H:%M:%S')
NETWORK = '10.0.0.0/24'
IPRANGE = list(map(str, ip_network(NETWORK)))[1:]
LOCAL_IP = IPRANGE.pop(0)
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
MTU = 250
USER_UUID = ['779ea091-ad7d-43bf-8afc-8b94fdb576bf']

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
    TODO: 管理 IP 分配完毕的异常 （基本不需要考虑，甚至可以分配更大的range）
    '''
    def __init__(self, timeout=30):
        '''
        初始化Session池
        - __expired_s_uuid: 删除会话后记录uuid，避免误删除后客户端再次请求
        '''
        self.__session_pool = []
        self.__time_out = timeout
        self.__del_expired_session()
        self.readables = []
        # TODO: 将过期session记录在文件里，防止服务器重启丢失
        # TODO: 更好的刷新机制，否则这个列表会越来越长
        # - 使用指定size的queue或许可以解决
        # - 服务端对于无法找到统一发重新登录提示
        # - 记录过期uuid访问次数，或者设置双重过期时间
        # - 客户端一定次数无效后自动重新登陆
        self.expired_s_uuid = []

    def get_session_from_uuid(self, uuid: str)->Session:
        '''
        从用户提供的Session UUID 获取 Session, 同时刷新Session
        @return:
            - Session: 合法，返回session
            - True: 过期，提示重新登录
            - False: invalid
        '''
        _count = 0
        for session in self.__session_pool:
            if session.uuid == uuid:
                _count += 1
        assert _count < 2
        # TODO: code ABOVE is for checking, remove to imporve the performance
        for session in self.__session_pool:
            logging.debug(session.uuid)
            if session.uuid == uuid:
                # fresh the session
                session.fresh_session()
                return session
        if uuid in self.expired_s_uuid:
            return True
        return False

    def get_session_from_tun_fd(self, tun_fd: str)->Session:
        '''
        从用户提供的Session UUID 获取 Session, 同时刷新Session
        @return: Session or None
        '''
        _count = 0
        for session in self.__session_pool:
            if session.tun_fd == tun_fd:
                _count += 1
        assert _count < 2
        # TODO: code ABOVE is for checking, remove to imporve the performance
        for session in self.__session_pool:
            if session.tun_fd == tun_fd:
                return session
        return None

    def create_session(self, uuid: str)->Session:
        '''
        认证用户提供的UUID(密码), 并创建Session
        assert MSG == b'LOGIN'
        return None: invalid user
        return session: 新建的Session
        '''
        if uuid not in USER_UUID:
            return None
        tun_fd, tun_name = TunManager.create_tunnel()
        tun_addr = IPRANGE.pop(0)
        TunManager.start_tunnel(tun_name, LOCAL_IP, tun_addr, MTU)
        new_session = Session(tun_fd, tun_addr, tun_name)
        self.__session_pool.append(new_session)
        logging.error(new_session.uuid)
        return new_session

    def __del_expired_session(self):
        '''
        删除过期session
        '''
        def _del_expired_session():
            while True:
                time.sleep(self.__time_out-10)
                time_del = time.time() - self.__time_out
                for session in self.__session_pool:
                    if session.last_time < time_del:
                        # 回收 IP, 添加回 IPRANGE 等待分配
                        self.readables.remove(session.tun_fd)
                        self.expired_s_uuid.append(session.uuid)
                        os.close(session.tun_fd)
                        IPRANGE.insert(0, session.tun_addr)
                        self.__session_pool.remove(session)
                        logging.info('Delete Time Out Session <%s>', session.uuid)
        c_t_1 = Thread(target=_del_expired_session, args=(), name='del_expired_session')
        c_t_1.setDaemon(True)
        c_t_1.start()
