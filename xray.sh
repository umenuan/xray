#!/bin/bash

# 定义颜色
re="\033[0m"
red="\033[1;91m"
green="\e[1;32m"
yellow="\e[1;33m"
purple="\e[1;35m"
skybule="\e[1;36m"
red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }
skyblue() { echo -e "\e[1;36m$1\033[0m"; }
reading() { read -p "$(red "$1")" "$2"; }

# 定义常量
server_name="xray"
work_dir="/etc/xray"
config_dir="${work_dir}/config.json"
client_dir="${work_dir}/url.txt"
# 定义环境变量
export UUID=${UUID:-$(cat /proc/sys/kernel/random/uuid)}
export PORT=${PORT:-$(shuf -i 1000-60000 -n 1)}
export ARGO_PORT=${ARGO_PORT:-'8080'}
export CFIP=${CFIP:-'ip.sb'} 
export CFPORT=${CFPORT:-'443'}   

# 检查是否为root下运行
[[ $EUID -ne 0 ]] && red "请在root用户下运行脚本" && exit 1

# 检查 xray 是否已安装
check_xray() {
if [ -f "${work_dir}/${server_name}" ]; then
    [ "$(systemctl is-active xray)" = "active" ] && green "running" && return 0 || yellow "not running" && return 1
else
    red "not installed"
    return 2
fi
}

# 检查 argo 是否已安装
check_argo() {
if [ -f "${work_dir}/argo" ]; then
    [ "$(systemctl is-active tunnel)" = "active" ] && green "running" && return 0 || yellow "not running" && return 1
else
    red "not installed"
    return 2
fi
}

#安装依赖
apt update && apt upgrade -y && apt autoremove -y  && apt install -y jq unzip iptables openssl coreutils
clear

# 获取ip
get_realip() {
  ip=$(curl -s --max-time 2 ipv4.ip.sb)
  if [ -z "$ip" ]; then
      ipv6=$(curl -s --max-time 2 ipv6.ip.sb)
      echo "[$ipv6]"
  else
      if echo "$(curl -s http://ipinfo.io/org)" | grep -qE 'Cloudflare|UnReal|AEZA|Andrei'; then
          ipv6=$(curl -s --max-time 2 ipv6.ip.sb)
          echo "[$ipv6]"
      else
          echo "$ip"
      fi
  fi
}

# 下载并安装 xray,cloudflared
install_xray() {
    clear
    purple "正在安装Xray-Argo中..."

    [ ! -d "${work_dir}" ] && mkdir -p "${work_dir}" && chmod 777 "${work_dir}"
    curl -sLo "${work_dir}/${server_name}.zip" "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
    curl -sLo "${work_dir}/argo" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
    unzip "${work_dir}/${server_name}.zip" -d "${work_dir}/" > /dev/null 2>&1 && chmod +x ${work_dir}/${server_name} ${work_dir}/argo
    rm -rf "${work_dir}/${server_name}.zip" "${work_dir}/geosite.dat" "${work_dir}/geoip.dat" "${work_dir}/README.md" "${work_dir}/LICENSE" 

    # 关闭防火墙
    iptables -F > /dev/null 2>&1 && iptables -P INPUT ACCEPT > /dev/null 2>&1 && iptables -P FORWARD ACCEPT > /dev/null 2>&1 && iptables -P OUTPUT ACCEPT > /dev/null 2>&1
    command -v ip6tables &> /dev/null && ip6tables -F > /dev/null 2>&1 && ip6tables -P INPUT ACCEPT > /dev/null 2>&1 && ip6tables -P FORWARD ACCEPT > /dev/null 2>&1 && ip6tables -P OUTPUT ACCEPT > /dev/null 2>&1

   # 生成配置文件
cat > "${config_dir}" << EOF
{
  "log": { "access": "/dev/null", "error": "/dev/null", "loglevel": "none" },
  "inbounds": [
      {
      "port": $ARGO_PORT,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "$UUID", "flow": "xtls-rprx-vision" }],
        "decryption": "none",
        "fallbacks": [
          { "dest": 3001 }, { "path": "/vless-argo", "dest": 3002 },
          { "path": "/vmess-argo", "dest": 3003 }, { "path": "", "dest": 3004 }
        ]
      },
      "streamSettings": { "network": "tcp" }
    },
    {
      "port": 3001, "listen": "127.0.0.1", "protocol": "vless",
      "settings": { "clients": [{ "id": "$UUID" }], "decryption": "none" },
      "streamSettings": { "network": "tcp", "security": "none" }
    },
    {
      "port": 3002, "listen": "127.0.0.1", "protocol": "vless",
      "settings": { "clients": [{ "id": "$UUID", "level": 0 }], "decryption": "none" },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vless-argo" } },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"], "metadataOnly": false }
    },
    {
      "port": 3003, "listen": "127.0.0.1", "protocol": "vmess",
      "settings": { "clients": [{ "id": "$UUID", "alterId": 0 }] },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "/vmess-argo" } },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"], "metadataOnly": false }
    }
  ],
  "dns": { "servers": ["https+local://8.8.8.8/dns-query"] },
   "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "block"
        }
    ]
}
EOF
}

# debian/ubuntu 守护进程
main_systemd_services() {
    cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/XTLS/Xray-core
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
NoNewPrivileges=yes
ExecStart=$work_dir/xray run -c $config_dir
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/tunnel.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target

[Service]
Type=simple
NoNewPrivileges=yes
TimeoutStartSec=0
ExecStart=/etc/xray/argo tunnel --url http://localhost:$ARGO_PORT --no-autoupdate --edge-ip-version auto --protocol http2
StandardOutput=append:/etc/xray/argo.log
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    bash -c 'echo "0 0" > /proc/sys/net/ipv4/ping_group_range'
    systemctl daemon-reload
    systemctl enable xray
    systemctl start xray
    systemctl enable tunnel
    systemctl start tunnel
}

get_info() {  
  clear
  IP=$(get_realip)

  isp=$(curl -s --max-time 2 https://speed.cloudflare.com/meta | awk -F\" '{print $26"-"$18}' | sed -e 's/ /_/g' || echo "vps")

  if [ -f "${work_dir}/argo.log" ]; then
      for i in {1..5}; do
          purple "第 $i 次尝试获取ArgoDoamin中..."
          argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${work_dir}/argo.log")
          [ -n "$argodomain" ] && break
          sleep 2
      done
  else
      restart_argo
      sleep 6
      argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${work_dir}/argo.log")
  fi

  green "\nArgoDomain：${purple}$argodomain${re}\n"

  cat > ${work_dir}/url.txt <<EOF
vless://${UUID}@${CFIP}:${CFPORT}?encryption=none&security=tls&sni=${argodomain}&type=ws&host=${argodomain}&path=%2Fvless-argo%3Fed%3D2048#${isp}
vmess://$(echo "{ \"v\": \"2\", \"ps\": \"${isp}\", \"add\": \"${CFIP}\", \"port\": \"${CFPORT}\", \"id\": \"${UUID}\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"${argodomain}\", \"path\": \"/vmess-argo?ed=2048\", \"tls\": \"tls\", \"sni\": \"${argodomain}\", \"alpn\": \"\" }" | base64 -w0)

EOF
echo ""
while IFS= read -r line; do echo -e "${purple}$line"; done < ${work_dir}/url.txt
base64 -w0 ${work_dir}/url.txt > ${work_dir}/sub.txt
}

# 启动 xray
start_xray() {
if [ ${check_xray} -eq 1 ]; then
    yellow "\n正在启动 ${server_name} 服务\n" 
    systemctl daemon-reload
    systemctl start "${server_name}"
    if [ $? -eq 0 ]; then
        green "${server_name} 服务已成功启动\n"
    else
        red "${server_name} 服务启动失败\n"
    fi
elif [ ${check_xray} -eq 0 ]; then
    yellow "xray 正在运行\n"
    sleep 1
    menu
else
    yellow "xray 尚未安装!\n"
    sleep 1
    menu
fi
}

# 停止 xray
stop_xray() {
if [ ${check_xray} -eq 0 ]; then
    yellow "\n正在停止 ${server_name} 服务\n"
    systemctl stop "${server_name}"
    if [ $? -eq 0 ]; then
        green "${server_name} 服务已成功停止\n"
    else
        red "${server_name} 服务停止失败\n"
    fi
elif [ ${check_xray} -eq 1 ]; then
    yellow "xray 未运行\n"
    sleep 1
    menu
else
    yellow "xray 尚未安装！\n"
    sleep 1
    menu
fi
}

# 重启 xray
restart_xray() {
if [ ${check_xray} -eq 0 ]; then
    yellow "\n正在重启 ${server_name} 服务\n"
    systemctl daemon-reload
    systemctl restart "${server_name}"
    if [ $? -eq 0 ]; then
        green "${server_name} 服务已成功重启\n"
    else
        red "${server_name} 服务重启失败\n"
    fi
elif [ ${check_xray} -eq 1 ]; then
    yellow "xray 未运行\n"
    sleep 1
    menu
else
    yellow "xray 尚未安装！\n"
    sleep 1
    menu
fi
}

# 更新 xray
update_xray() {
    yellow "\n检查 Xray 更新..."
    # 获取当前版本号
    current_version=$(/etc/xray/xray version | awk '/Xray/' | awk '{print $2}')
    # 获取最新版本号
    latest_version=$(curl -sL "https://api.github.com/repos/XTLS/Xray-core/releases/latest" | jq -r '.tag_name | sub("^v"; "")')
    
    if [ "$current_version" = "$latest_version" ]; then
        green "\n当前 Xray 已经是最新版本: ${current_version}\n"
        return 0
    fi
    
    yellow "\n当前版本: ${current_version}"
    yellow "最新版本: ${latest_version}"
    yellow "\n正在下载最新版本...\n"
    
    curl -sLo "${work_dir}/${server_name}.zip" "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
    unzip -o "${work_dir}/${server_name}.zip" -d "${work_dir}/" > /dev/null 2>&1 && chmod +x ${work_dir}/${server_name}
    rm -rf "${work_dir}/${server_name}.zip" "${work_dir}/geosite.dat" "${work_dir}/geoip.dat" "${work_dir}/README.md" "${work_dir}/LICENSE"
    
    restart_xray
    if [ $? -eq 0 ]; then
        green "\nXray 更新成功! 当前版本: ${latest_version}\n"
    else
        red "\nXray 更新失败\n"
    fi
}

# xray 管理
manage_xray() {
    green "1. 启动xray服务"
    skyblue "-------------------"
    green "2. 停止xray服务"
    skyblue "-------------------"
    green "3. 重启xray服务" 
    skyblue "-------------------"
    green "4. 更新xray服务"
    skyblue "-------------------"
    purple "5. 返回主菜单"
    skyblue "------------"
    reading "\n请输入选择: " choice
    case "${choice}" in
        1) start_xray ;;  
        2) stop_xray ;;
        3) restart_xray ;;
        4) update_xray ;;
        5) menu ;;
        *) red "无效的选项！" ;;
    esac
}

# 启动 argo
start_argo() {
if [ ${check_argo} -eq 1 ]; then
    yellow "\n正在启动 Argo 服务\n"
    systemctl daemon-reload
    systemctl start tunnel
    if [ $? -eq 0 ]; then
        green "Argo 服务已成功重启\n"
    else
        red "Argo 服务重启失败\n"
    fi
elif [ ${check_argo} -eq 0 ]; then
    green "Argo 服务正在运行\n"
    sleep 1
    menu
else
    yellow "Argo 尚未安装！\n"
    sleep 1
    menu
fi
}

# 停止 argo
stop_argo() {
if [ ${check_argo} -eq 0 ]; then
    yellow "\n正在停止 Argo 服务\n"
    systemctl daemon-reload
    systemctl stop tunnel
    if [ $? -eq 0 ]; then
        green "Argo 服务已成功停止\n"
    else
        red "Argo 服务停止失败\n"
    fi
elif [ ${check_argo} -eq 1 ]; then
    yellow "Argo 服务未运行\n"
    sleep 1
    menu
else
    yellow "Argo 尚未安装！\n"
    sleep 1
    menu
fi
}

# 重启 argo
restart_argo() {
if [ ${check_argo} -eq 0 ]; then
    yellow "\n正在重启 Argo 服务\n"
    rm /etc/xray/argo.log 2>/dev/null
    systemctl daemon-reload
    systemctl restart tunnel
    if [ $? -eq 0 ]; then
        green "Argo 服务已成功重启\n"
    else
        red "Argo 服务重启失败\n"
    fi
elif [ ${check_argo} -eq 1 ]; then
    yellow "Argo 服务未运行\n"
    sleep 1
    menu
else
    yellow "Argo 尚未安装！\n"
    sleep 1
    menu
fi
}

# 更新 argo
update_argo() {
    stop_argo
    yellow "\n正在更新 Argo...\n"
    curl -sLo "${work_dir}/argo" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
    chmod +x ${work_dir}/argo
    restart_argo
    if [ $? -eq 0 ]; then
        green "Argo 更新成功!\n"
    else
        red "Argo 更新失败\n"
    fi
}

# 卸载 xray
uninstall_xray() {
   reading "确定要卸载 Xray-Argo 吗? (y/n): " choice
   case "${choice}" in
       y|Y)
           yellow "正在卸载 xray"
           systemctl stop "${server_name}"
           systemctl stop tunnel
           # 禁用 xray 服务
           systemctl disable "${server_name}"
           systemctl disable tunnel

           # 重新加载 systemd
           systemctl daemon-reload || true
           # 删除配置文件和日志
           rm -rf "${work_dir}" || true
           rm -rf /etc/systemd/system/xray.service /etc/systemd/system/tunnel.service 2>/dev/null   
           
           green "\nXray-Argo 卸载成功\n"
           ;;
       *)
           purple "已取消卸载操作\n"
           ;;
   esac
}


# 变更配置
change_config() {
clear
echo ""
green "1. 修改UUID"
skyblue "------------"
purple "${purple}2. 返回主菜单"
skyblue "------------"
reading "请输入选择: " choice
case "${choice}" in
    1)
        reading "\n请输入新的UUID: " new_uuid
        [ -z "$new_uuid" ] && new_uuid=$(cat /proc/sys/kernel/random/uuid) && green "\n生成的UUID为：$new_uuid"
        sed -i "s/[a-fA-F0-9]\{8\}-[a-fA-F0-9]\{4\}-[a-fA-F0-9]\{4\}-[a-fA-F0-9]\{4\}-[a-fA-F0-9]\{12\}/$new_uuid/g" $config_dir
        restart_xray
        sed -i "s/[a-fA-F0-9]\{8\}-[a-fA-F0-9]\{4\}-[a-fA-F0-9]\{4\}-[a-fA-F0-9]\{4\}-[a-fA-F0-9]\{12\}/$new_uuid/g" $client_dir
        content=$(cat "$client_dir")
        vmess_urls=$(grep -o 'vmess://[^ ]*' "$client_dir")
        vmess_prefix="vmess://"
        for vmess_url in $vmess_urls; do
            encoded_vmess="${vmess_url#"$vmess_prefix"}"
            decoded_vmess=$(echo "$encoded_vmess" | base64 --decode)
            updated_vmess=$(echo "$decoded_vmess" | jq --arg new_uuid "$new_uuid" '.id = $new_uuid')
            encoded_updated_vmess=$(echo "$updated_vmess" | base64 | tr -d '\n')
            new_vmess_url="$vmess_prefix$encoded_updated_vmess"
            content=$(echo "$content" | sed "s|$vmess_url|$new_vmess_url|")
        done
        echo "$content" > "$client_dir"
        base64 -w0 $client_dir > /etc/xray/sub.txt
        while IFS= read -r line; do yellow "$line"; done < $client_dir
        green "\nUUID已修改为：${purple}${new_uuid}${re} ${green}请更新订阅或手动更改所有节点的UUID${re}\n"
        ;;
    2)  menu ;;
    *)  red "无效的选项！" ;;
esac
}

# xray 管理
manage_xray() {
    green "1. 启动xray服务"
    skyblue "-------------------"
    green "2. 停止xray服务"
    skyblue "-------------------"
    green "3. 重启xray服务" 
    skyblue "-------------------"
    green "4. 更新xray服务"
    skyblue "-------------------"
    purple "5. 返回主菜单"
    skyblue "------------"
    reading "\n请输入选择: " choice
    case "${choice}" in
        1) start_xray ;;  
        2) stop_xray ;;
        3) restart_xray ;;
        4) update_xray ;;
        5) menu ;;
        *) red "无效的选项！" ;;
    esac
}

# Argo 管理
manage_argo() {
if [ ${check_argo} -eq 2 ]; then
    yellow "Argo 尚未安装！"
    sleep 1
    menu
else
    clear
    echo ""
    green "1. 启动Argo服务"
    skyblue "------------"
    green "2. 停止Argo服务"
    skyblue "------------"
    green "3. 添加Argo固定隧道"
    skyblue "----------------"
    green "4. 切换回Argo临时隧道"
    skyblue "------------------"
    green "5. 重新获取Argo临时域名"
    skyblue "-------------------"
    green "6. 更新Argo服务"
    skyblue "-------------"
    purple "7. 返回主菜单"
    skyblue "-----------"
    reading "\n请输入选择: " choice
    case "${choice}" in
        1)  start_argo ;;
        2)  stop_argo ;; 
        3)
            clear
            yellow "\n固定隧道可为json或token，固定隧道端口为8080，自行在cf后台设置\n\njson在f佬维护的站点里获取，获取地址：${purple}https://fscarmen.cloudflare.now.cc${re}\n"
            reading "\n请输入你的argo域名: " argo_domain
            green "你的Argo域名为：$argo_domain"
            ArgoDomain=$argo_domain
            reading "\n请输入你的argo密钥(token或json): " argo_auth
            if [[ $argo_auth =~ TunnelSecret ]]; then
                echo $argo_auth > ${work_dir}/tunnel.json
                cat > ${work_dir}/tunnel.yml << EOF
tunnel: $(cut -d\" -f12 <<< "$argo_auth")
credentials-file: ${work_dir}/tunnel.json
protocol: http2
                                           
ingress:
  - hostname: $ArgoDomain
    service: http://localhost:8080
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF
                sed -i '/^ExecStart=/c ExecStart=/bin/sh -c "/etc/xray/argo tunnel --edge-ip-version auto --config /etc/xray/tunnel.yml run 2>&1"' /etc/systemd/system/tunnel.service
                restart_argo
                change_argo_domain
            elif [[ $argo_auth =~ ^[A-Z0-9a-z=]{120,250}$ ]]; then
                sed -i '/^ExecStart=/c ExecStart=/bin/sh -c "/etc/xray/argo tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token '$argo_auth' 2>&1"' /etc/systemd/system/tunnel.service
                restart_argo
                change_argo_domain
            else
                yellow "你输入的argo域名或token不匹配，请重新输入"
                manage_argo            
            fi
            ;; 
        4)
            clear
            main_systemd_services
            get_quick_tunnel
            change_argo_domain 
            ;; 

        5)  
            if grep -q 'ExecStart=.*--url http://localhost:8080' /etc/systemd/system/tunnel.service; then
                get_quick_tunnel
                change_argo_domain 
            else
                yellow "当前使用固定隧道，无法获取临时隧道"
                sleep 2
                menu
            fi 
            ;; 
        6)  update_argo ;;
        7)  menu ;; 
        *)  red "无效的选项！" ;;
    esac
fi
}

# 获取argo临时隧道
get_quick_tunnel() {
restart_argo
yellow "获取临时argo域名中，请稍等...\n"
sleep 3
if [ -f /etc/xray/argo.log ]; then
  for i in {1..5}; do
      get_argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' /etc/xray/argo.log)
      [ -n "$get_argodomain" ] && break
      sleep 2
  done
else
  restart_argo
  sleep 6
  get_argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' /etc/xray/argo.log)
fi
green "ArgoDomain：${purple}$get_argodomain${re}\n"
ArgoDomain=$get_argodomain
}

# 更新Argo域名到订阅
change_argo_domain() {
    sed -i "3s/sni=[^&]*/sni=$ArgoDomain/; 3s/host=[^&]*/host=$ArgoDomain/" /etc/xray/url.txt
    content=$(cat "$client_dir")
    vmess_urls=$(grep -o 'vmess://[^ ]*' "$client_dir")
    vmess_prefix="vmess://"
    for vmess_url in $vmess_urls; do
        encoded_vmess="${vmess_url#"$vmess_prefix"}"
        decoded_vmess=$(echo "$encoded_vmess" | base64 --decode)
        updated_vmess=$(echo "$decoded_vmess" | jq --arg new_domain "$ArgoDomain" '.host = $new_domain | .sni = $new_domain')
        encoded_updated_vmess=$(echo "$updated_vmess" | base64 | tr -d '\n')
        new_vmess_url="$vmess_prefix$encoded_updated_vmess"
        content=$(echo "$content" | sed "s|$vmess_url|$new_vmess_url|")
    done
    echo "$content" > "$client_dir"
    base64 -w0 ${work_dir}/url.txt > ${work_dir}/sub.txt

    while IFS= read -r line; do echo -e "${purple}$line"; done < "$client_dir"
    
    green "\n节点已更新,更新订阅或手动复制以上节点\n"
}

# 查看节点信息
check_nodes() {
if [ ${check_xray} -eq 0 ]; then
    while IFS= read -r line; do purple "${purple}$line"; done < ${work_dir}/url.txt
    server_ip=$(get_realip)
else 
    yellow "Xray-Argo 尚未安装或未运行,请先安装或启动Xray-Argo"
    sleep 1
    menu
fi
}

# 捕获 Ctrl+C 信号
trap 'red "已取消操作"; exit' INT

# 主菜单
menu() {
while true; do
   check_xray &>/dev/null; check_xray=$?
   check_argo &>/dev/null; check_argo=$?
   check_xray_status=$(check_xray) > /dev/null 2>&1
   check_argo_status=$(check_argo) > /dev/null 2>&1
   clear
   echo ""
   purple "Xray-Argo安装脚本\n"
   purple "Xray 状态: ${check_xray_status}\n"
   purple "Argo 状态: ${check_argo_status}\n"   
   green "1. 安装Xray"
   red "2. 卸载Xray"
   echo "============="
   green "3. Xray管理"
   green "4. Argo管理"
   echo  "============="
   green  "5. 查看节点"
   green  "6. 修改UUID"
   echo  "============="
   red "0. 退出脚本"
   echo "============="
   reading "请输入选择(0-6): " choice
   echo ""
   case "${choice}" in
        1)  
            if [ ${check_xray} -eq 0 ]; then
                yellow "Xray-Argo 已经安装！"
            else
                install_xray
                main_systemd_services
                sleep 3
                get_info
            fi
           ;;
        2) uninstall_xray ;;
        3) manage_xray ;;
        4) manage_argo ;;
        5) check_nodes ;;
        6) change_config ;;
        0) exit 0 ;;
        *) red "无效的选项，请输入 0 到 6" ;; 
   esac
   read -n 1 -s -r -p $'\033[1;91m按任意键继续...\033[0m'
done
}
menu
