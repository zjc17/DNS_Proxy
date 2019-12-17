'''
DNS 相关操作
'''
from dnslib import (DNSRecord, DNSHeader, QTYPE, RR,
                    A, MX, TXT, CNAME)
import logging


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
    # print(reply)
    return reply.pack()