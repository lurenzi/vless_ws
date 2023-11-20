#!/bin/bash
# json-vvhello
# xray installation script
# ubuntu 20.04
# bash xray_installation_vless.sh "你的域名" [vless]

if [ "$1" == "" ];then
  echo "请输入需要申请证书的域名：(bash acme_domain.sh 域名)"
  exit
fi
ip=$(curl -s4m8 ip.sb -k) || ip=$(curl -s6m8 ip.sb -k)
domainIP=$(curl -sm8 ipget.net/?ip="${1}")

if [[ $domainIP == $ip ]]; then
  echo $domainIP
  echo $1
else
  echo "当前域名解析的IP与当前VPS使用的真实IP不匹配"
  exit
fi

# 使用ubuntu官方源安装nginx和依赖包并设置开机启动
apt update -y
apt install nginx curl pwgen openssl netcat cron uuid-runtime socat -y
systemctl enable nginx
systemctl start nginx

# 配置系统时区为东八区
rm -f /etc/localtime
cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

#1.设置你的解析好的域名
domainName="$1"
#域名解析正确不会输出任何内容，如果不正确会退出当前终端
local_ip="$(curl ifconfig.me 2>/dev/null;echo)"
resolve_ip="$(host "$domainName" | awk '{print $NF}')"
if [ "$local_ip" != "$resolve_ip" ];then echo "域名解析不正确";exit 9;fi

#2.随机生成xray需要用到的服务端口
#3.随机生成一个uuid
#4.随机生成一个websocket需要使用的path

port="`shuf -i 20000-65000 -n 1`"
uuid="`uuidgen`"
path="/`pwgen -A0 6 8 | xargs |sed 's/ /\//g'`"

#安装xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)"
#5.以时间为基准随机创建一个存放ssl证书的目录
ssl_dir="$(mkdir -pv "/usr/local/etc/xray/ssl/`date +"%F-%H-%M-%S"`" |awk -F"'" END'{print $2}')"
#申请证书
source ~/.bashrc
if nc -z localhost 443;then /etc/init.d/nginx stop;fi
if nc -z localhost 443;then lsof -i :443 | awk 'NR==2{print $1}' | xargs -i killall {};sleep 1;fi
if ! [ -d /root/.acme.sh ];then curl https://get.acme.sh | sh;fi
~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
~/.acme.sh/acme.sh --issue -d "$domainName" -k ec-256 --alpn
~/.acme.sh/acme.sh --installcert -d "$domainName" --fullchainpath $ssl_dir/xray.crt --keypath $ssl_dir/xray.key --ecc
chown www-data.www-data $ssl_dir/xray.*

#6.定义nginx和xray配置文件路径
nginxConfig=/etc/nginx/conf.d/xray.conf
xrayConfig=/usr/local/etc/xray/config.json
#续签证书
echo -n '#!/bin/bash
/etc/init.d/nginx stop
"/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" &> /root/renew_ssl.log
/etc/init.d/nginx start
' > /usr/local/bin/ssl_renew.sh
chmod +x /usr/local/bin/ssl_renew.sh
(crontab -l;echo "0 00 15 * * /usr/local/bin/ssl_renew.sh") | crontab

mkdir -pv /usr/local/etc/xray

# 配置nginx
echo "
server {
  listen 80;
  listen [::]:80;
  server_name "$domainName";
  return 301 https://"'$host'""'$request_uri'";
}

server {
  listen 443 ssl http2 default_server;
  listen [::]:443 ssl http2 default_server;
  server_name "$domainName";
  charset utf-8;

  ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
  ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
  ssl_ecdh_curve secp384r1;
  ssl_prefer_server_ciphers on;
  ssl_session_cache shared:SSL:10m;
  ssl_session_timeout 10m;
  ssl_session_tickets off;
  ssl_certificate $ssl_dir/xray.crt;
  ssl_certificate_key $ssl_dir/xray.key;

  location / {
      proxy_pass https://www.aliexpress.com;
  }

  location "$path" {
    proxy_redirect off;
    proxy_pass http://127.0.0.1:"$port";
    proxy_http_version 1.1;
    proxy_set_header Upgrade "'"$http_upgrade"'";
    proxy_set_header Connection '"'upgrade'"';
    proxy_set_header Host "'"$host"'";
    proxy_set_header X-Real-IP "'"$remote_addr"'";
    proxy_set_header X-Forwarded-For "'"$proxy_add_x_forwarded_for"'";
	}
}
" > $nginxConfig


# 配置xray
echo '
{
  "log" : {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbound": {
    "port": '$port',
    "listen": "127.0.0.1",
    "protocol": "vless",
    "settings": {
      "decryption":"none",
      "clients": [
        {
          "id": '"\"$uuid\""',
          "level": 1
        }
      ]
    },
   "streamSettings":{
      "network": "ws",
      "wsSettings": {
           "path": '"\"$path\""'
      }
   }
  },
  "outbound": {
    "protocol": "freedom",
    "settings": {
      "decryption":"none"
    }
  },
  "outboundDetour": [
    {
      "protocol": "blackhole",
      "settings": {
        "decryption":"none"
      },
      "tag": "blocked"
    }
  ], 
  "routing": {
    "strategy": "rules",
    "settings": {
      "decryption":"none",
      "rules": [
        {
          "domain": [ "geosite:cn" ],
          "outboundTag": "blocked",
          "type": "field"
        },       
        {
          "type": "field",
          "ip": [ "geoip:cn" ],
          "outboundTag": "blocked"
        }
      ]
    }
  }
}
' > $xrayConfig


# 重启xray和nginx
systemctl restart xray
systemctl status -l xray
/usr/sbin/nginx -t && systemctl restart nginx

# 输出配置信息
echo
echo "域名: $domainName"
echo "端口: 443"
echo "UUID: $uuid"
echo "安全: tls"
echo "传输: websocket"
echo "路径: $path"
