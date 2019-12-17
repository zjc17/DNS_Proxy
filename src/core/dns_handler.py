# -*- coding: utf-8 -*-
'''
DNS 相关操作
'''
from dnslib import (DNSRecord, DNSHeader, DNSQuestion,
                    QTYPE, RR, A, MX, TXT, CNAME)
import logging
import struct


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
    logging.debug(reply)
    return reply.pack()

def make_txt_response(data, txt_record):
    '''
    返回TXT记录，用于登录
    '''
    request = DNSRecord.parse(data)
    qname = request.q.qname
    qtype = request.q.qtype
    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
    reply.add_answer(RR(qname, qtype, rdata=TXT(txt_record)))
    return reply.pack()

def __split_with_length(DATA:bytes, length:int=63):
    DATA_SEGMENTS = []
    _idx = 0
    _LEN = len(DATA)
    while True:
        if _idx + length >= _LEN:
            DATA_SEGMENTS.append(DATA[_idx: _LEN])
            break
        else:
            DATA_SEGMENTS.append(DATA[_idx: _idx+length])
            _idx += length
    return DATA_SEGMENTS



def make_fake_request(HOST_NAME, UUID, DATA):
    '''
    进行伪装查询
     0        12     49 
    | header | UUID |
    '''
    DATA_SEGMENTS = __split_with_length(DATA, 63)
    if len(DATA_SEGMENTS) > 3:
        # TODO: check the lenth of DATA
        print('len(DATA_SEGMENTS) =', len(DATA_SEGMENTS))
        raise IndexError
    request = DNSRecord()
    request.add_question(DNSQuestion(UUID+'.'+HOST_NAME, QTYPE.TXT))
    request_data = request.pack()
    data = request_data[:49]
    for DATA_SEG in DATA_SEGMENTS:
        DATA_LEN = struct.pack('>B', len(DATA_SEG))
        data += DATA_LEN + DATA_SEG
    data += request_data[49:]
    return data




if __name__ == '__main__':
    HOST_NAME = 'group11.cs305.fun'
    DOMAIN_NS_ADDR = ('120.78.166.34', 53)
    UUID = '779ea091-ad7d-43bf-8afc-8b94fdb576bf'
    DATA = b'\x00\x00\x86\xdd`\x00\x00\x00\x00\x08:\xff\xfe\x80\x00\x00\x00\x00\x00\x00h-V\xf0\xae+5\x14\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x85\x00\xda\xd9\x00\x00\x00\x00'
    request = make_fake_request(HOST_NAME, UUID, DATA)
    import socket
    _socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _socket.sendto(request, DOMAIN_NS_ADDR)
    data, _addr = _socket.recvfrom(2048)
    print('From', _addr)
    print(data)
    parser = DNSRecord.parse(data)
    print(parser)
    s:str = ""
    s.s

# DNSQuestion:https://juejin.im/post/5ab719c151882577b45ef9d9
