#!python3
# -*- coding: utf-8 -*-
import pytest
import os
print(os.getcwd())
import sys 
sys.path.append("..")
print(os.getcwd())
from src.core.Proxy_TUN import TUN 
# from Proxy_TUN import TUN

def test_placeholder():
    pass

def test_createTUNInterface():
    tun = tun = TUN(nic_type="Tun",nic_name="tun0")