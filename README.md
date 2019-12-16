# DNS_Proxy

## 如何使用

克隆本仓库后

1. 创建虚拟环境 `python3 -m venv venv`

2. 进入虚拟环境 `source venv/bin/activate`

2. 安装依赖 `pip install -r requirements.txt` 

3. 添加环境变量 `python setup.py`

其他说明

1. 由于 TUN 接口需要管理员权限，因此建议在开发前（进入虚拟环境前），使用 `sudo -s` 提升权限。

2. 测试: 虚拟环境中使用 `pytest` 或 `sudo $(which pytest)`（无管理员权限）

3. 代码规范：使用 `pylint`

4. 关于 TUN 接口创建后为关闭导致的异常，直接执行相关 `linux` 命令：

    - 查看 `Tun`: `ifconfig`

    - 相关操作（需要 `sudo` 权限）：

        - `ip tuntap add dev tun0 mode tun`
        
        - `ip tuntap add dev tap0 mode tap`

        - `ip tuntap del dev tun0 mode tun`

        - `ip tuntap help`

5. 关于服务端 `53` 端口占用:
    
    - 查看: `sudo lsof -i:53`

    - 关闭: `sudo systemctl stop systemd-resolved`

    - 启动: `sudo systemctl start systemd-resolved`

6. 配置网卡转发:

    1. 查看NAT转发: `sudo iptables -L -n -t nat`

    2. 添加NAT转发:

        - TODO: ...

    3. 删除转发: 
        
        - `sudo iptables -t nat -D PREROUTING 1`

        - `sudo iptables -t nat -D POSTROUTING 1`

        - `sudo iptables -D FORWARD 1`

工具

1. 网络抓包: `tshark`: [Reference](https://kaimingwan.com/post/ji-chu-zhi-shi/wang-luo/shi-yong-tsharkzai-ming-ling-xing-jin-xing-wang-luo-zhua-bao)

2. DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION: [RFC1035](https://tools.ietf.org/html/rfc1035)

3. INTERNET PROTOCOL: [RFC791](https://tools.ietf.org/html/rfc791)

4. User Datagram Protocol: [RF768](https://tools.ietf.org/html/rfc768)

5. SOCKS Protocol Version 5: [RCF1928](https://tools.ietf.org/html/rfc1928)
