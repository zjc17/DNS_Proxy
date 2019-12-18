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
    if qtype == QTYPE.TXT:
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
        reply.add_answer(RR(qname, qtype, rdata=TXT(txt_record)))
        # reply.add_answer(RR(qname, qtype, rdata=TXT('TEST MSG')))
    elif qtype == QTYPE.CNAME:
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
        reply.add_answer(RR(qname, qtype, rdata=CNAME('CNAME RECORD HERE')))
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



def make_fake_request(host_name, uuid, data):
    '''
    进行伪装查询
     0        12     49
    | header | UUID |
    '''
    assert len(data) <= 63*3
    data_segments = __split_with_length(data, 63)
    request_msg = DNSRecord()
    request_msg.add_question(DNSQuestion(uuid+'.'+host_name, QTYPE.TXT))
    request_data = request_msg.pack()
    _idx = 13 + len(uuid)
    modified_data = request_data[:_idx]
    for data_seg in data_segments:
        data_len = struct.pack('>B', len(data_seg))
        modified_data += data_len + data_seg
    modified_data += request_data[_idx:]
    return modified_data

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
        assert len(txt_records) == 1
        txt_record = txt_records[0]
        return txt_record
    except DNSError:
        print('DNSError while parsing TXT record')
    return ''

# DNSQuestion:https://juejin.im/post/5ab719c151882577b45ef9d9
