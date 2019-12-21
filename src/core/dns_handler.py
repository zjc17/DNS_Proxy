# -*- coding: utf-8 -*-
'''
DNS 相关操作
'''
import re
import struct
from dnslib import (DNSRecord, DNSHeader, DNSQuestion,
                    QTYPE, RR, A, MX, TXT, CNAME)
from dnslib.dns import DNSError



def make_response(data):
    '''
    回应DNS请求
    '''
    request = DNSRecord.parse(data)
    qname = request.q.qname
    qtype = request.q.qtype
    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
    if qtype == QTYPE.A:
        reply.add_answer(RR(qname, qtype, rdata=A('1.2.3.4')))
    elif qtype == QTYPE.TXT:
        reply.add_answer(RR(qname, qtype, rdata=TXT('TXT RECORE1')))
    elif qtype == QTYPE.MX:
        reply.add_answer(RR(qname, qtype, rdata=MX('1.2.3.4')))
    else:
        reply.add_answer(RR(qname, QTYPE.CNAME, rdata=CNAME('CNAME RECORE')))
    return reply.pack()

def decode_dns_question(data: bytes)->list:
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

def make_txt_response(data, txt_record):
    '''
    返回TXT记录，用于登录
    '''
    request = DNSRecord.parse(data)
    # print('REQUEST:\n', request)
    qname = request.q.qname
    qtype = request.q.qtype
    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
    reply.add_answer(RR(qname, qtype, rdata=TXT(txt_record)))
    return reply.pack()

def put_bytes_into_txtrecord(data, bytes_record):
    '''
    将字节流记录到TXT记录
    '''
    request = DNSRecord.parse(data)
    # print('REQUEST:\n', request)
    qname = request.q.qname
    qtype = request.q.qtype
    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
    reply.add_answer(RR(qname, qtype, rdata=TXT(bytes_record)))
    return reply.pack()

def txt_from_dns_response(response):
    '''
    从DNS响应获取TXT记录
    TODO:
    - 支持多条记录
    - 不使用第三方库
    '''
    try:
        response = str(DNSRecord().parse(response))
        txt_records = re.findall(r'.*TXT.*\"(.*)\".*', response)
        return txt_records
    except DNSError:
        print('DNSError while parsing TXT record')
    return ''

# DNSQuestion:https://juejin.im/post/5ab719c151882577b45ef9d9

class Encapsulator:
    '''
    将数据封装至DNS包中
    '''
    @staticmethod
    def response_str_in_txt(request, data: str):
        '''
        将字符串包装在TXT记录里作为结果返回
        return: bytes
        '''
        print('\n======================================\n')
        request = DNSRecord.parse(request)
        print('REQUEST:\n', request)
        qname = request.q.qname
        qtype = request.q.qtype
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
        reply.add_answer(RR(qname, qtype, rdata=TXT(data)))
        print('RESPONSE:\n', reply)
        return reply.pack()

    @staticmethod
    def response_bytes_in_txt(request, data: bytes):
        '''
        将字节流包装在TXT记录里作为结果返回
        return: bytes
        '''
        assert len(data) < 256
        request = DNSRecord.parse(request)
        qname = request.q.qname
        qtype = request.q.qtype
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
        reply.add_answer(RR(qname, qtype, rdata=TXT('')))
        reply = reply.pack()
        reply[-3:-1] = struct.pack('>H', len(data) + 1)
        reply[-1] = len(data)
        reply += data
        return reply

    @staticmethod
    def __split_with_length(data: bytes, length: int = 63):
        data_segments = []
        _idx = 0
        _len = len(data)
        while True:
            if _idx + length >= _len:
                data_segments.append(data[_idx: _len])
                break
            data_segments.append(data[_idx: _idx+length])
            _idx += length
        return data_segments

    @staticmethod
    def make_fake_request(_uuid: str, data, host_name):
        '''
        进行伪装查询
        0        12     49
        | header | UUID |
        '''
        assert len(data) <= 63*3
        data_segments = Encapsulator.__split_with_length(data, 63)
        request_msg = DNSRecord()
        request_msg.add_question(DNSQuestion(_uuid+'.'+host_name, QTYPE.TXT))
        request_data = request_msg.pack()
        _idx = 13 + len(_uuid)
        modified_data = request_data[:_idx]
        for data_seg in data_segments:
            data_len = struct.pack('>B', len(data_seg))
            modified_data += data_len + data_seg
        modified_data += request_data[_idx:]
        return modified_data

class Decapsulator:
    '''
    解析DNS数据包
    '''
    TXT = 16
    IN = 1
    @staticmethod
    def get_host_name(packet: bytes)->list:
        '''
        传入DNS数据包，解析主机名
        '''
        # Header 12 byte
        _header = packet[:12]
        # Question Qname + Qtype(2 byte) + Qclass (2byte)
        packet = packet[12:]
        q_name = []
        _idx = 0
        while packet[_idx] > 0:
            _idx += 1
            print(_idx, packet[_idx: packet[_idx-1]+_idx])
            q_name.append(packet[_idx: packet[_idx-1]+_idx])
            _idx += packet[_idx-1]
        return q_name

    @staticmethod
    def get_txt_record(packet: bytes)->bytes:
        '''
        传入DNS数据包，解析TXT记录
        Header 12 byte
        Question Qname + Qtype(2 byte) + Qclass (2 byte)
        '''
        assert isinstance(packet, bytes)
        q_name = []
        _idx = 12
        while packet[_idx] > 0:
            _idx += 1
            q_name.append(packet[_idx: packet[_idx-1]+_idx])
            _idx += packet[_idx-1]
        _q_type, _q_class = struct.unpack('>HH', packet[_idx+1: _idx+5])
        answer = packet[_idx+5:]
        _r_name = packet[:2]
        if len(packet) < 10:
            # TODO: 基于包结构验证
            return b''
        _r_type, _r_class, _r_ttl, _r_dlength = struct.unpack('>HHIH', answer[2: 12])
        rdata = answer[12:]
        # print(r_type, r_class, r_ttl, r_dlength)
        return rdata[1:rdata[0]+1]

if __name__ == '__main__':
    # Client
    DATA = b'\xe2\x80\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00$779ea091-ad7d-43bf-8afc-8b94fdb576bf\x05LOGIN\x03www\x04ibbb\x03top\x00\x00\x10\x00\x01\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x00\x00762752af9e-2306-11ea-9320-00163e0cae2e;10.0.0.2;10.0.0.1'
    print(len('2752af9e-2306-11ea-9320-00163e0cae2e;10.0.0.2;10.0.0.1'))
    print(Decapsulator.get_txt_record(DATA))
    # Server
    from socket import socket, AF_INET, SOCK_DGRAM
    import os
    # os.popen('systemctl stop systemd-resolved').read()
    DATA = b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    DATA = b'\x00\x00\x08\x00E\x00\x00T\xab\xa9\x00\x00@\x01\xba\xfd\n\x00\x00\x01\n\x00\x00\x02\x00\x00\x01\x1a^K\x01\xb3rx\xfc]\x00\x00\x00\x00g>\n\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567'
    import uuid
    DATA = str(uuid.uuid1()).encode()
    print(DATA)
    print(len(DATA))
    try:
        while True:
            SOCKET = socket(AF_INET, SOCK_DGRAM)
            SOCKET.bind(('0.0.0.0', 53))
            REQUEST, ADDR = SOCKET.recvfrom(1024)
            RESPONSE = Encapsulator.response_bytes_in_txt(REQUEST, DATA)
            # RESPONSE = Encapsulator.response_str_in_txt(REQUEST, b'TXT_RECORD')
            print(RESPONSE)
            # Decapsulator.get_host_name(RESPONSE)
            SOCKET.sendto(RESPONSE, ADDR)
    except (KeyboardInterrupt):
        # os.popen('systemctl start systemd-resolved').read()
        pass

