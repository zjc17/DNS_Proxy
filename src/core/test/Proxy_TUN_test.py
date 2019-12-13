import pytest

import sys 
sys.path.append("..") 
from src.core.Proxy_TUN import TUN

def test_placeholder():
    pass

def test_createTUNInterface():
    tun = tun = TUN(nic_type="Tun",nic_name="tun0")