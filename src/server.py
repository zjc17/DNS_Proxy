# -*- coding: utf-8 -*-、
'''
代理服务端
'''
from socket import socket, AF_INET, SOCK_DGRAM
from select import select
import os
import logging
from dnslib.dns import DNSError
from core import dns_handler
from core.packet import IPPacket
from core.session import SessionManager, LOCAL_IP
# TODO 优化logging模块的使用 https://juejin.im/post/5d3c82ab6fb9a07efb69cd02)
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(filename)s[:%(lineno)d] %(levelname)s %(message)s',
                    datefmt='%H:%M:%S')
BUFFER_SIZE = 4096
BIND_ADDRESS = '0.0.0.0', 53
LOGIN_MSG = b'LOGIN'    # 用户登录消息 USER_UUID.LOGIN.hostname.domain
DOWN_MSG = b'DOWN'      # 用户请求数据 SESSION_UUID.DOWN.hostname.domain
UP_MSG = b'UP'          # 用户上行数据 SESSION_UUID.UP.$BYTE_DATA.hostname.domain
SESSION_MANAGER = SessionManager()
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
        print('Server listen on %s:%s...' % BIND_ADDRESS)

    def __response_down_msg(self, data: list(bytes), addr)->bool:
        '''
        客户端请求接受数据包 KEEP_ALIVE 包\n
        接受服务端指令/回传数据\n
        用户请求数据 SESSION_UUID.QUERY.hostname.domain\n
        '''
        assert data[1] == DOWN_MSG
        session = SESSION_MANAGER.get_session_from_uuid(data[1].decode())
        if session is None:
            logging.error('Invalid Tun ID')
            return False
        packet = session.get_buffer_data()
        if packet is None or len(packet) <= 20:
            # TODO: reply sth to indicate no buffered data
            # TODO: check whether is IP packet
            packet = b''
        reply = dns_handler.make_txt_response(data, packet.hex())
        logging.debug('REPLY:')
        logging.debug(reply)
        self.__socket.sendto(reply, addr)
        logging.debug('SEND BACK')
        return True

    def __response_login_msg(self, data: list(bytes), addr)->bool:
        '''
        用户登录行为\n
        用户登录消息 USER_UUID.LOGIN.hostname.domain\n
        @data: 解析后的请求域名 [b'USER_UUID', b'LOGIN', b'hostname', b'domain']
        若成功登录，则
        - 添加tun_fd至可读取端口集合
        - 回应用户应答
        @return:
        - True: 登录成功
        - False: 登录失败
        '''
        assert data[1] == LOGIN_MSG
        session = SESSION_MANAGER.create_session(data[0].decode())
        if session is None:
            logging.info('Invalid User Login Detected')
            return False
        logging.info('Clinet <%s> connect successful', session.uuid)
        try:
            txt_record = '%s;%s;%s'%(session.uuid, session.tun_addr, LOCAL_IP)
            reply = dns_handler.make_txt_response(data, txt_record)
            self.__socket.sendto(reply, addr)
            self.readables.append(session.tun_fd)
        except DNSError:
            logging.info('Fail To Set Up Tunnel')
            logging.debug('Login DNS Message Parsing error')
        return True

    @staticmethod
    def __response_up_msg(data: list(bytes), _addr):
        '''
        相应用户上行数据\n
        @return
            - True: 成功转发上行数据
            - False: 异常
        '''
        assert data[1] == UP_MSG
        session = SESSION_MANAGER.get_session_from_uuid(data[0].decode())
        if session is None:
            # TODO: 向用户回传消息，通知session uuid不合法
            logging.info('Invalid Session <%s>', data[0].decode())
            return False
        tun_fd = session.tun_fd
        # TODO: 将-3参数化
        message = b''.join(data[2:-3])
        # TODO: check valid IP Packet
        if len(message) < 20:
            logging.debug('Not a IP Packet <%s>', message)
            return False
        try:
            logging.debug('Try to send DATA(%d) to TUN', (len(message)))
            print(IPPacket.str_info(message))
            print(type(message))
            os.write(tun_fd, message)
        except OSError:
            logging.error('Fail to write DATA to TUN')
            return False
        return True

    def __handle_dns_request(self, request: bytes, addr):
        '''
        处理绑定53接口的UDP服务器数据
        - DNS 请求检测
        - 新会话创建
        '''
        name_data = self.decode_dns_question(request)
        uuid = name_data[0].decode()
        logging.info('UUID: %s => \n%s', uuid, name_data[1].decode())
        # 相关预定义指令
        if name_data[1] == LOGIN_MSG:   # b'LOGIN':
            self.__response_login_msg(name_data, addr)
            return
        if name_data[1] == DOWN_MSG:    # b'DOWN':
            self.__response_down_msg(name_data, uuid)
            return
        if name_data[1] == UP_MSG:      # b'UP'
            self.__response_up_msg(name_data, addr)
            return
        logging.error('Invalid DNS Query or Not a Fake DNS')

    @staticmethod
    def decode_dns_question(data: bytes)->list(bytes):
        '''
        解析dns请求
        '''
        _idx = 12
        _len = data[_idx]
        _name = []
        while _len != 0:
            _idx += 1
            _name.append(data[_idx:_idx+_len])
            _idx += _len
            _len = data[_idx]
        return _name

    def run_forever(self):
        '''
        运行接收端
        '''
        while True:
            readab = select(self.readables, [], [], 1)[0]
            for tun_id in readab:
                if tun_id == self.__socket:
                    # DNS packet
                    data, addr = self.__socket.recvfrom(BUFFER_SIZE)
                    self.__handle_dns_request(data, addr)
                    continue
                # inbound data from tun
                data = os.read(tun_id, BUFFER_SIZE)
                logging.debug('GET DATA from Tun, sending to buffer')
                session = SESSION_MANAGER.get_session_from_tun_id(tun_id)
                if session is None:
                    logging.error('Invalid Tun ID')
                    continue
                session.put_buffer_data(data)
                logging.debug('To %s', session.tun_name)

if __name__ == '__main__':
    SERVER = Server()
    try:
        SERVER.run_forever()
    except KeyboardInterrupt:
        print('Closing vpn server ...')