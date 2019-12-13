#!/usr/bin/python3
# -*- coding: utf-8 -*-
import test.__init__


from core.Proxy_TUN import TUN


def test_placeholder():
    assert(True)
    pass


def test_createTUNInterface():
    tun = TUN(nic_type="Tun", nic_name="tun0")
    assert(tun is not None)
