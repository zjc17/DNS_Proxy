# -*- coding: utf-8 -*-、
'''
代理服务端
'''
from socket import socket, AF_INET, SOCK_DGRAM
from select import select
import os
from dnslib.dns import DNSError
from core.dns_handler import Encapsulator, Decapsulator
from core.session import SessionManager, LOCAL_IP
from core.logger import logging, create_logger
COLOR_LOG = create_logger(__name__, logging.DEBUG)
BIND_ADDRESS = '0.0.0.0', 53
BUFFER_SIZE = 4096
LOGIN_MSG = b'LOGIN'    # 用户登录消息 USER_UUID.LOGIN.hostname.domain
DOWN_MSG = b'DOWN'      # 用户请求数据 SESSION_UUID.DOWN.hostname.domain
UP_MSG = b'UP'          # 请求用户上行数据 SESSION_UUID.<UNIQUE_ID>.UP.$BYTE_DATA.hostname.domain
CLOSED_SESSION_MSG = b'CLOSED_SESSION_MSG'
SESSION_MANAGER = SessionManager(timeout=30)
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
        self.__duplicate_detected = []
        SESSION_MANAGER.readables = [self.__socket]
        print('Server listen on %s:%s...' % BIND_ADDRESS)

    def __response_down_msg(self, request: bytes, data: list, addr: tuple)->bool:
        '''
        客户端请求接受数据包 KEEP_ALIVE 包\n
        接受服务端指令/回传数据\n
        用户请求数据 SESSION_UUID.QUERY.hostname.domain\n
        '''
        assert data[1] == DOWN_MSG
        session = SESSION_MANAGER.get_session_from_uuid(data[0].decode())
        if session is False:
            COLOR_LOG.error('Invalid Tun ID')
            return False
        if session is True:
            COLOR_LOG.debug('客户端过期，提示重新登录')
            packet = CLOSED_SESSION_MSG
        else:
            packet = session.get_buffer_data()
        if packet is None:
            # TODO: reply sth to indicate no buffered data
            # TODO: check whether is IP packet
            packet = b''
        reply = Encapsulator.response_bytes_in_txt(request, packet)
        COLOR_LOG.debug('REPLY:')
        COLOR_LOG.debug(reply)
        self.__socket.sendto(reply, addr)
        COLOR_LOG.info('SEND BACK %s', packet[:10])
        return True

    def __response_login_msg(self, request: bytes, data: list, addr: tuple)->bool:
        '''
        用户登录行为\n
        用户登录消息 USER_UUID.LOGIN.hostname.domain\n
        @data: 解析后的请求域名 [b'USER_UUID', b'LOGIN', b'hostname', b'domain']
        若成功登录，则\n
        - 添加tun_fd至可读取端口集合
        - 回应用户应答
        @return:
        - True: 登录成功
        - False: 登录失败
        '''
        assert data[1] == LOGIN_MSG
        session = SESSION_MANAGER.create_session(data[0].decode())
        if session is None:
            COLOR_LOG.info('Invalid User Login Detected')
            return False
        COLOR_LOG.info('Clinet <%s> connect successful', session.uuid)
        try:
            COLOR_LOG.error(session.uuid)
            txt_record = '%s;%s;%s'%(session.uuid, session.tun_addr, LOCAL_IP)
            reply = Encapsulator.response_str_in_txt(request, txt_record)
            COLOR_LOG.error(reply)
            self.__socket.sendto(reply, addr)
            SESSION_MANAGER.readables.append(session.tun_fd)
        except DNSError:
            COLOR_LOG.info('Fail To Set Up Tunnel')
            COLOR_LOG.debug('Login DNS Message Parsing error')
        return True

    @staticmethod
    def response_up_msg(data: list, _addr: tuple):
        '''
        相应用户上行数据\n
        @return
            - True: 成功转发上行数据
            - False: 异常
        请求用户上行数据\n
        SESSION_UUID.<UNIQUE_ID>.UP.$BYTE_DATA.hostname.domain
        '''
        assert data[1] == UP_MSG
        session = SESSION_MANAGER.get_session_from_uuid(data[0].decode())
        if session is False:
            # TODO: 向用户回传消息，通知session uuid不合法
            COLOR_LOG.info('Invalid Session <%s>', data[0].decode())
            return False
        if session is True:
            COLOR_LOG.debug('客户端过期，上行数据请求无法回复')
            return False
        tun_fd = session.tun_fd
        # TODO: 将-3参数化
        message = b''.join(data[3:-3])
        try:
            COLOR_LOG.info('Try to send DATA(%d) to TUN', (len(message)))
            os.write(tun_fd, message)
        except OSError:
            COLOR_LOG.error('Fail to write DATA to TUN')
            return False
        return True

    def __drop_duplicate_request(self, unique_id: bytes):
        '''
        针对迭代查询的NS服务器可能重复暴力发包的情况，做一个列表记录匹配是否已经收到
        '''
        if len(self.__duplicate_detected) > 128:
            self.__duplicate_detected.pop(0)
        if unique_id in self.__duplicate_detected:
            return True
        self.__duplicate_detected.append(unique_id)
        COLOR_LOG.info('len = %d', len(self.__duplicate_detected))
        return False

    def __drop_duplicate_request(self, unique_id: bytes):
        '''
        针对迭代查询的NS服务器可能重复暴力发包的情况，做一个列表记录匹配是否已经收到
        '''
        if len(self.__duplicate_detected) > 128:
            self.__duplicate_detected.pop(0)
        if unique_id in self.__duplicate_detected:
            return True
        self.__duplicate_detected.append(unique_id)
        COLOR_LOG.info('len = %d', len(self.__duplicate_detected))
        return False

    def __handle_dns_request(self, request: bytes, addr):
        '''
        处理绑定53接口的UDP服务器数据
        - DNS 请求检测
        - 新会话创建
        '''
        name_data = Decapsulator.get_host_name(request)
        uuid = name_data[0].decode()
        try:
            COLOR_LOG.info('s_uuid<%s>=>\n%s', uuid, name_data[1].decode())
            # 相关预定义指令
            if name_data[1] == LOGIN_MSG:   # b'LOGIN':
                self.__response_login_msg(request, name_data, addr)
                return
            if name_data[1] == DOWN_MSG:    # b'DOWN':
                self.__response_down_msg(request, name_data, addr)
                return
            if name_data[1] == UP_MSG:      # b'UP'
                COLOR_LOG.info('UP UNIQUE ID = %s', name_data[2].decode())
                if self.__drop_duplicate_request(name_data[2]):
                    COLOR_LOG.debug('DUPLICATE PACKET RECEIVED AND DROPPED')
                    return
                self.response_up_msg(name_data, addr)
                return
        except IndexError:
            COLOR_LOG.error('Invalid DNS Query or Not a Fake DNS %s', name_data)

    def run_forever(self):
        '''
        运行接收端
        '''
        while True:
            try:
                readab = select(SESSION_MANAGER.readables, [], [], 1)[0]
            except OSError:
                # detected the closed fd
                COLOR_LOG.debug('Closed fd Detected')
                raise OSError
            for tun_id in readab:
                if tun_id == self.__socket:
                    # DNS packet
                    data, addr = self.__socket.recvfrom(BUFFER_SIZE)
                    self.__handle_dns_request(data, addr)
                    continue
                # inbound data from tun
                data = os.read(tun_id, BUFFER_SIZE)
                COLOR_LOG.debug('GET DATA from Tun, sending to buffer')
                session = SESSION_MANAGER.get_session_from_tun_fd(tun_id)
                if session is None:
                    COLOR_LOG.error('Invalid Tun ID')
                    continue
                session.put_buffer_data(data)
                COLOR_LOG.debug('To %s', session.tun_name)

if __name__ == '__main__':
    SERVER = Server()
    try:
        SERVER.run_forever()
    except KeyboardInterrupt:
        print('Closing vpn server ...')
