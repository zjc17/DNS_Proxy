# -*- coding: utf-8 -*-
from core.tun import TUN
# from socket import socket


def test_placeholder():
    pass


def test_create_tun_interface():
    tun = TUN(nic_type="Tun", nic_name="tun0")
    assert(tun is not None)
    tun.close()


def test_write_into_tun_interface():
    pass
