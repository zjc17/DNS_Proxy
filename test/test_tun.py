'''
测试对Tun资源的管理
'''
from src.core.sys_manage import TunManager

def test_create_tun():
    '''
    测试创建Tun (未启动)
    '''
    tun_name = 'tun2'
    _tun_fn, name = TunManager.create_tunnel('tun2')
    assert name == tun_name

def test_close_tun():
    '''
    测试关闭Tun
    '''
    TunManager.del_tunnel(2)
