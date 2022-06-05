#!/bin/bash
#
# ==================================================
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
#########################

BURIQ () {
    curl -sS https://raw.githubusercontent.com/irwan-aidan/tetbot/main/skkkk > /root/tmp
    data=( `cat /root/tmp | grep -E "^### " | awk '{print $2}'` )
    for user in "${data[@]}"
    do
    exp=( `grep -E "^### $user" "/root/tmp" | awk '{print $3}'` )
    d1=(`date -d "$exp" +%s`)
    d2=(`date -d "$biji" +%s`)
    exp2=$(( (d1 - d2) / 86400 ))
    if [[ "$exp2" -le "0" ]]; then
    echo $user > /etc/.$user.ini
    else
    rm -f /etc/.$user.ini > /dev/null 2>&1
    fi
    done
    rm -f /root/tmp
}

MYIP=$(curl -sS ipv4.icanhazip.com)
Name=$(curl -sS https://raw.githubusercontent.com/irwan-aidan/tetbot/main/skkkk | grep $MYIP | awk '{print $2}')
echo $Name > /usr/local/etc/.$Name.ini
CekOne=$(cat /usr/local/etc/.$Name.ini)

Bloman () {
if [ -f "/etc/.$Name.ini" ]; then
CekTwo=$(cat /etc/.$Name.ini)
    if [ "$CekOne" = "$CekTwo" ]; then
        res="Expired"
    fi
else
res="Permission Accepted..."
fi
}

PERMISSION () {
    MYIP=$(curl -sS ipv4.icanhazip.com)
    IZIN=$(curl -sS https://raw.githubusercontent.com/irwan-aidan/tetbot/main/skkkk | awk '{print $4}' | grep $MYIP)
    if [ "$MYIP" = "$IZIN" ]; then
    Bloman
    else
    res="Permission Denied!"
    fi
    BURIQ
}
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }
PERMISSION
if [ -f /home/needupdate ]; then
red "Your script need to update first !"
exit 0
elif [ "$res" = "Permission Accepted..." ]; then
echo -ne
else
red "Permission Denied!"
exit 0
fi

#############################
# INSTALL # OPENVPN PACKAGE #
#############################
echo -n "Pasang pakej openvpn... ";
apt-get -y -qq install openvpn
cd /usr/share/easy-rsa
./easyrsa --batch init-pki
./easyrsa --batch build-ca nopass
./easyrsa --batch gen-dh
./easyrsa --batch build-server-full server nopass
./easyrsa --batch build-client-full client nopass
openvpn --genkey --secret /usr/share/easy-rsa/pki/ta.key
cp -R /usr/share/easy-rsa/pki /etc/openvpn/ && cd

[[ -d /etc/openvpn/server ]] && rm -d /etc/openvpn/server
[[ -d /etc/openvpn/client ]] && rm -d /etc/openvpn/client
systemctl stop openvpn &>/dev/null
systemctl disable openvpn &>/dev/null

echo "# OVPN SERVER-TCP CONFIG
# ----------------------------
port 1194
proto tcp
dev tun

ca /etc/openvpn/pki/ca.crt
cert /etc/openvpn/pki/issued/server.crt
key /etc/openvpn/pki/private/server.key
dh /etc/openvpn/pki/dh.pem
tls-auth /etc/openvpn/pki/ta.key

server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push \"redirect-gateway def1 bypass-dhcp\"
push \"dhcp-option DNS 1.1.1.1\"
push \"dhcp-option DNS 1.0.0.1\"
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn/status.log
log /var/log/openvpn/access.log
verb 3
mute 10
plugin /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so login
username-as-common-name" > /etc/openvpn/server-tcp.conf

echo "# OVPN SERVER-UDP CONFIG
# ----------------------------
port 994
proto udp
dev tun
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450

ca /etc/openvpn/pki/ca.crt
cert /etc/openvpn/pki/issued/server.crt
key /etc/openvpn/pki/private/server.key
dh /etc/openvpn/pki/dh.pem
tls-auth /etc/openvpn/pki/ta.key

server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push \"redirect-gateway def1 bypass-dhcp\"
push \"dhcp-option DNS 1.1.1.1\"
push \"dhcp-option DNS 1.0.0.1\"
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn/status.log
log /var/log/openvpn/access.log
verb 3
mute 10
plugin /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so login
username-as-common-name" > /etc/openvpn/server-udp.conf

echo "# OVPN SERVER-TLS CONFIG
# ----------------------------
port 587
proto tcp
dev tun

ca /etc/openvpn/pki/ca.crt
cert /etc/openvpn/pki/issued/server.crt
key /etc/openvpn/pki/private/server.key
dh /etc/openvpn/pki/dh.pem
tls-auth /etc/openvpn/pki/ta.key

server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push \"redirect-gateway def1 bypass-dhcp\"
push \"route ${GETIP} 255.255.255.255 net_gateway\"
push \"dhcp-option DNS 1.1.1.1\"
push \"dhcp-option DNS 1.0.0.1\"
keepalive 5 30
reneg-sec 0
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn/status.log
log /var/log/openvpn/access.log
verb 3
mute 10
plugin /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so login
username-as-common-name" > /etc/openvpn/server-tls.conf

echo "# OVPN CLIENT-TCP CONFIG
# ----------------------------
setenv FRIENDLY_NAME jokervpn
client
dev tun
proto tcp
remote $GETIP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
auth none
verb 3
auth-user-pass

;http-proxy-retry
;http-proxy $GETIP 8080
;http-proxy-option CUSTOM-HEADER Protocol HTTP/1.1
;http-proxy-option CUSTOM-HEADER Host HOSTNAME" > /etc/openvpn/client-tcp.conf

echo "" >> /etc/openvpn/client-tcp.conf
echo "<ca>" >> /etc/openvpn/client-tcp.conf
cat /etc/openvpn/pki/ca.crt >> /etc/openvpn/client-tcp.conf
echo "</ca>" >> /etc/openvpn/client-tcp.conf

echo "<cert>" >> /etc/openvpn/client-tcp.conf
cat /etc/openvpn/pki/issued/client.crt >> /etc/openvpn/client-tcp.conf
echo "</cert>" >> /etc/openvpn/client-tcp.conf

echo "<key>" >> /etc/openvpn/client-tcp.conf
cat /etc/openvpn/pki/private/client.key >> /etc/openvpn/client-tcp.conf
echo "</key>" >> /etc/openvpn/client-tcp.conf

echo "<tls-auth>" >> /etc/openvpn/client-tcp.conf
cat /etc/openvpn/pki/ta.key >> /etc/openvpn/client-tcp.conf
echo "</tls-auth>" >> /etc/openvpn/client-tcp.conf

echo "# OVPN CLIENT-UDP CONFIG
# ----------------------------
setenv FRIENDLY_NAME jokervpn
client
dev tun
proto udp
remote $GETIP 994
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
auth none
verb 3
auth-user-pass" > /etc/openvpn/client-udp.conf

echo "" >> /etc/openvpn/client-udp.conf
echo "<ca>" >> /etc/openvpn/client-udp.conf
cat /etc/openvpn/pki/ca.crt >> /etc/openvpn/client-udp.conf
echo "</ca>" >> /etc/openvpn/client-udp.conf

echo "<cert>" >> /etc/openvpn/client-udp.conf
cat /etc/openvpn/pki/issued/client.crt >> /etc/openvpn/client-udp.conf
echo "</cert>" >> /etc/openvpn/client-udp.conf

echo "<key>" >> /etc/openvpn/client-udp.conf
cat /etc/openvpn/pki/private/client.key >> /etc/openvpn/client-udp.conf
echo "</key>" >> /etc/openvpn/client-udp.conf

echo "<tls-auth>" >> /etc/openvpn/client-udp.conf
cat /etc/openvpn/pki/ta.key >> /etc/openvpn/client-udp.conf
echo "</tls-auth>" >> /etc/openvpn/client-udp.conf

echo "# OVPN CLIENT-TLS CONFIG
# ----------------------------
setenv FRIENDLY_NAME jokervpn
client
dev tun
proto tcp
remote $GETIP 587
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
tls-client
tls-version-min 1.2
tls-chiper TLS-ECDHE-ECDSA-WITH-128-GCM-SHA256
auth none
verb 3
auth-user-pass" > /etc/openvpn/client-tls.conf

echo "" >> /etc/openvpn/client-tls.conf
echo "<ca>" >> /etc/openvpn/client-tls.conf
cat /etc/openvpn/pki/ca.crt >> /etc/openvpn/client-tls.conf
echo "</ca>" >> /etc/openvpn/client-tls.conf

echo "<cert>" >> /etc/openvpn/client-tls.conf
cat /etc/openvpn/pki/issued/client.crt >> /etc/openvpn/client-tls.conf
echo "</cert>" >> /etc/openvpn/client-tls.conf

echo "<key>" >> /etc/openvpn/client-tls.conf
cat /etc/openvpn/pki/private/client.key >> /etc/openvpn/client-tls.conf
echo "</key>" >> /etc/openvpn/client-tls.conf

echo "<tls-auth>" >> /etc/openvpn/client-tls.conf
cat /etc/openvpn/pki/ta.key >> /etc/openvpn/client-tls.conf
echo "</tls-auth>" >> /etc/openvpn/client-tls.conf

sed -i 's/#AUTOSTART="all"/AUTOSTART="all"/g' /etc/default/openvpn
systemctl start openvpn &>/dev/null
systemctl enable openvpn &>/dev/null
systemctl disable systemd-ask-password-wall.service
echo -e "${GREEN}[ Selesai ]${PLAIN}"; cd

# Delete script
 
cd /home/vps/public_html/
zip cfg.zip Tcp.ovpn Udp.ovpn SSL.ovpn > /dev/null 2>&1
cd
cat <<'mySiteOvpn' > /home/vps/public_html/index.html
<!DOCTYPE html>
<html lang="en">

<!-- Simple OVPN Download site -->

<head><meta charset="utf-8" /><title>OVPN Config Download</title><meta name="description" content="Server" /><meta content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" name="viewport" /><meta name="theme-color" content="#000000" /><link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.2/css/all.css"><link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdnjs.cloudflare.com/ajax/libs/mdbootstrap/4.8.3/css/mdb.min.css" rel="stylesheet"></head><body><div class="container justify-content-center" style="margin-top:9em;margin-bottom:5em;"><div class="col-md"><div class="view"><img src="https://openvpn.net/wp-content/uploads/openvpn.jpg" class="card-img-top"><div class="mask rgba-white-slight"></div></div><div class="card"><div class="card-body"><h5 class="card-title">Config List</h5><br /><ul class="list-group">

<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>TCP <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small></small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESSS:81/Tcp.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li>

<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>UDP <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small></small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESSS:81/Udp.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li>

<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>SSL <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small></small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESSS:81/SSL.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li>

<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p> ALL.zip <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small></small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESSS:81/cfg.zip" style="float:right;"><i class="fa fa-download"></i> Download</a></li>

</ul></div></div></div></div></body></html>
mySiteOvpn

sed -i "s|IP-ADDRESSS|$(curl -sS ifconfig.me)|g" /home/vps/public_html/index.html

history -c
rm -f /root/vpn.sh
