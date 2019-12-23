[![codebeat badge](https://codebeat.co/badges/a9ee193b-5436-450e-94e2-5646e1041684)](https://codebeat.co/a/jiachen/projects/github-com-jiachen-zhang-dns_proxy-master)

# DNS_Proxy

EN|[CN](./READNE.md)

## 简介

DNS_Proxy 是一个帮助构建私有计算机网络的网络工具。提供基于DNS的流量伪装，并结合基于ssh的sosck5代理能够对流量进行加密，保护隐私。

![Upstreaming packet flow](./pic/packet_flow.png)

## 如何使用

1. 克隆本仓库: `git clone https://github.com/Jiachen-Zhang/DNS_Proxy.git`

2. 安装依赖: `pip3 install dnslib`

3. 配置并解析域名（略）

4. 检测域名配置: `python3 test/test_dns_config.py` (update later)

4. 启动服务: 
    
    - 客户端: `sudo python3 src/client.py`

    - 服务端: `sudo python3 src/server.py`

5. 可选: 

    - 配置自定义用户认证：

        - 将 `src/client.py` 的 `UUID` 加入 `src/core/session.py` 的 `USER_UUID` 中即可

    - 自定义日志(release later)

6. 配置代理

    - `socks5`:
        
        - 启动服务端与客户端

        - 客户端: `ssh -D 127.0.0.1:8080 <username>@10.0.0.1`

        - 登录成功后即在本地开启地址为 `127.0.0.1:8080` 的 `socks5` 服务器
    
    - `NAT` (需要`sudo`权限，部分机型可能不支持并有可能造成服务器网络故障)
        
        > 这部分内容将在未来的发布中集成在 `config` 文件中，不需要手动设置

        - 客户端：

            - 查找默认网关：`route -n`

            - 添加服务器地址为网关: `route add -host 120.78.166.34 gw *.*.*.*` (120.78.166.34: NS IP)

            - 添加默认网关: `route add default gw 10.0.0.1`
    
        - 服务端:

            - 开启转发: `sysctl net.ipv4.ip_forward=1`

            - 设置`NAT`: `iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -j SNAT --to 18.162.51.192` (18.162.51.192: Server IP)

## 如何开发

克隆本仓库后

1. 创建虚拟环境: `python3 -m venv venv`

2. 进入虚拟环境: `source venv/bin/activate`

2. 安装依赖: `pip install -r requirements.txt` 

3. 添加环境变量: `python setup.py`

4. 检测域名解析: `dig @120.78.166.34 group11.cs305.fun`

## 其他说明

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


## 工具

1. 网络抓包: `tshark`: [Reference](https://kaimingwan.com/post/ji-chu-zhi-shi/wang-luo/shi-yong-tsharkzai-ming-ling-xing-jin-xing-wang-luo-zhua-bao)

2. DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION:

    - [RFC1035](https://tools.ietf.org/html/rfc1035)

    - [DNS Message](http://www-inf.int-evry.fr/~hennequi/CoursDNS/NOTES-COURS_eng/msg.html)
3. INTERNET PROTOCOL: [RFC791](https://tools.ietf.org/html/rfc791)

4. User Datagram Protocol: [RF768](https://tools.ietf.org/html/rfc768)

5. SOCKS Protocol Version 5: [RCF1928](https://tools.ietf.org/html/rfc1928)

## License

[The MIT License (MIT)](./LICENSE)

## Credits

本项目目前使用以下第三方库

- 生产

    - `pytest`

- 发布

    - `dnslib`
