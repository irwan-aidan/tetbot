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

# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";
ANU=$(ip -o $ANU -4 route show to default | awk '{print $5}');
MySentev="$(cat /etc/hostname)";

# Checking if openvpn folder is accidentally deleted or purged
 if [[ ! -e /etc/openvpn ]]; then
  mkdir -p /etc/openvpn
 fi

 # Removing all existing openvpn server files
 rm -rf /etc/openvpn/*

# Install OpenVPN dan Easy-RSA
apt-get install -y openvpn dnsutils easy-rsa unzip 
apt install -y openvpn dnsutils easy-rsa unzip 
apt-get install -y  openssl iptables iptables-persistent 
apt install -y  openssl iptables iptables-persistent 

# Installing OpenVPN by pulling its repository inside sources.list file 
rm -rf /etc/apt/sources.list.d/openvpn*
echo "deb http://build.openvpn.net/debian/openvpn/stable $(lsb_release -sc) main" > /etc/apt/sources.list.d/openvpn.list
wget -qO - http://build.openvpn.net/debian/openvpn/stable/pubkey.gpg|apt-key add -
apt-get update
apt-get install openvpn

# Install the latest version of easy-rsa from source, if not already installed.
        easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.0/EasyRSA-3.1.0.tgz'
        mkdir -p /etc/openvpn/easy-rsa/
        { wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/easy-rsa/ --strip-components 1
        chown -R root:root /etc/openvpn/easy-rsa/
        cd /etc/openvpn/easy-rsa/

cat > /etc/openvpn/easy-rsa/vars << EOF
set_var EASYRSA_REQ_COUNTRY    "MY"
set_var EASYRSA_REQ_PROVINCE   "Selangor"
set_var EASYRSA_REQ_CITY       "Gombak"
set_var EASYRSA_REQ_ORG        "Copyleft Certificate vpnku"
set_var EASYRSA_REQ_EMAIL      "irwanmohi@gmail.com"
set_var EASYRSA_REQ_OU         "VPNKU Script"
set_var EASYRSA_ALGO           "ec"
set_var EASYRSA_DIGEST         "sha512"
set_var EASYRSA_REQ_CN         "VPNKU-Script"
EOF
cd

# Create the PKI, set up the CA and the server and client certificates
cd /etc/openvpn/easy-rsa/
./easyrsa --batch init-pki
./easyrsa --batch build-ca nopass
openssl dhparam -out /etc/openvpn/dh2048.pem 2048
EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-server-full server nopass
EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-client-full client nopass
EASYRSA_CRL_DAYS=3650 ./easyrsa --batch gen-crl
openvpn --genkey --secret /etc/openvpn/ta.key 
[[ -d /etc/openvpn/server ]] && rm -d /etc/openvpn/server
[[ -d /etc/openvpn/client ]] && rm -d /etc/openvpn/client
systemctl stop openvpn
systemctl disable openvpn

# Move the stuff we need
cd /etc/openvpn/easy-rsa
cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/
/etc/openvpn/

# CRL is read with each client connection, while OpenVPN is dropped to nobody
chown nobody:"$group_name" /etc/openvpn/crl.pem

# Without +x in the directory, OpenVPN can't run a stat() on the CRL file
chmod o+x /etc/openvpn/
	
# Generate key for tls-crypt
openvpn --genkey --secret /etc/openvpn/tc.key
sudo openvpn --genkey --secret /etc/openvpn/ta.key


cd
mkdir -p /usr/lib/openvpn/
cp /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /usr/lib/openvpn/openvpn-plugin-auth-pam.so

# nano /etc/default/openvpn
sed -i 's/#AUTOSTART="all"/AUTOSTART="all"/g' /etc/default/openvpn

# aktifkan ip4 forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf

# Remove default Create New
cd
rm /etc/openvpn/*.conf

# Buat config server TCP 1194
cd /etc/openvpn
cat > /etc/openvpn/server-tcp-1194.conf <<-EOF
port 1194
proto tcp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login
verify-client-cert none
username-as-common-name
server 10.6.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
keepalive 5 30
comp-lzo
persist-key
persist-tun
status /var/log/openvpn/server-tcp-1194.log
verb 3
EOF

# Buat config server UDP 2200
cat > /etc/openvpn/server-udp-2200.conf <<-EOF3
port 2200
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login
verify-client-cert none
username-as-common-name
server 10.7.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
keepalive 5 30
comp-lzo
persist-key
persist-tun
status /var/log/openvpn/server-udp-2200.log
verb 3
EOF3

# restart openvpn dan cek status openvpn
systemctl enable --now openvpn-server@server-tcp-1194
systemctl enable --now openvpn-server@server-udp-2200
/etc/init.d/openvpn restart
/etc/init.d/openvpn status

# Buat config client TCP 1194
cat > /etc/openvpn/client-tcp-1194.ovpn <<-END
# OVPN CLIENT-TCP CONFIG
# ----------------------------
setenv FRIENDLY_NAME $MySentev
setenv CLIENT_CERT 0
client
dev tun
proto tcp
remote xxxxxxxxx 1194
# back-quary or back inject method
# remote "IP:PORT@bughost.yourdomain.com/
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3

## [1] ##
# http-proxy-option CUSTOM-HEADER Protocol HTTP/1.1
# http-proxy-option CUSTOM-HEADER Host bughost.yourdomain.com
## [2] ##
# "http-proxy-option CUSTOM-HEADER HTTP/1.1" or "http-proxy-option VERSION 1.1"
# http-proxy-option CUSTOM-HEADER Host bughost.yourdomain.com
# http-proxy-option CUSTOM-HEADER X-Forward-Host bughost.yourdomain.com
# http-proxy-option CUSTOM-HEADER X-Forwarded-For bughost.yourdomain.com
# http-proxy-option CUSTOM-HEADER Referrer bughost.yourdomain.com
## 3 ##
# http-proxy-option CUSTOM-HEADER Host bughost.yourdomain.com
# http-proxy-option CUSTOM-HEADER X-Forwarded-For bughost.yourdomain.com
# http-proxy-option CUSTOM-HEADER Referrer bughost.yourdomain.com
#
## [3] [NEW proxy-option] ##
# http-proxy-option CUSTOM-HEADER CONNECT HTTP/1.1
# http-proxy-option CUSTOM-HEADER Host bughost.yourdomain.com
# http-proxy-option CUSTOM-HEADER X-Online-Host bughost.yourdomain.com
# http-proxy-option CUSTOM-HEADER ""
# http-proxy-option CUSTOM-HEADER "PUT http://bughost.yourdomain.com/ HTTP/1.1"
# http-proxy-option CUSTOM-HEADER X-Forward-Host bughost.yourdomain.com
# http-proxy-option CUSTOM-HEADER Connection:Keep-Alive

END

sed -i $MYIP2 /etc/openvpn/client-tcp-1194.ovpn;

# Buat config client UDP 2200
cat > /etc/openvpn/client-udp-2200.ovpn <<-END2
# OVPN CLIENT-TCP CONFIG
# ----------------------------
setenv FRIENDLY_NAME $MySentev
setenv CLIENT_CERT 0
client
dev tun
proto udp
remote xxxxxxxxx 2200
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3

END2

sed -i $MYIP2 /etc/openvpn/client-udp-2200.ovpn;

# Buat config client SSL
cat > /etc/openvpn/client-tcp-ssl.ovpn <<-END3
# OVPN CLIENT-TCP-SSL CONFIG
# ----------------------------
setenv FRIENDLY_NAME $MySentev
setenv CLIENT_CERT 0
client
dev tun
proto tcp
remote xxxxxxxxx 442
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3

## [1] ##
# http-proxy-option CUSTOM-HEADER Protocol HTTP/1.1
# http-proxy-option CUSTOM-HEADER Host bughost.yourdomain.com
## [2] ##
# "http-proxy-option CUSTOM-HEADER HTTP/1.1" or "http-proxy-option VERSION 1.1"
# http-proxy-option CUSTOM-HEADER Host bughost.yourdomain.com
# http-proxy-option CUSTOM-HEADER X-Forward-Host bughost.yourdomain.com
# http-proxy-option CUSTOM-HEADER X-Forwarded-For bughost.yourdomain.com
# http-proxy-option CUSTOM-HEADER Referrer bughost.yourdomain.com
## 3 ##
# http-proxy-option CUSTOM-HEADER Host bughost.yourdomain.com
# http-proxy-option CUSTOM-HEADER X-Forwarded-For bughost.yourdomain.com
# http-proxy-option CUSTOM-HEADER Referrer bughost.yourdomain.com
#
## [3] [NEW proxy-option] ##
# http-proxy-option CUSTOM-HEADER CONNECT HTTP/1.1
# http-proxy-option CUSTOM-HEADER Host bughost.yourdomain.com
# http-proxy-option CUSTOM-HEADER X-Online-Host bughost.yourdomain.com
# http-proxy-option CUSTOM-HEADER ""
# http-proxy-option CUSTOM-HEADER "PUT http://bughost.yourdomain.com/ HTTP/1.1"
# http-proxy-option CUSTOM-HEADER X-Forward-Host bughost.yourdomain.com
# http-proxy-option CUSTOM-HEADER Connection:Keep-Alive

END3

sed -i $MYIP2 /etc/openvpn/client-tcp-ssl.ovpn;

cd
# pada tulisan xxx ganti dengan alamat ip address VPS anda 
/etc/init.d/openvpn restart

# Enter the certificate into the TCP 1194 client .
echo '<ca>' >> /etc/openvpn/client-tcp-1194.ovpn
cat '/etc/openvpn/server/ca.crt' >> /etc/openvpn/client-tcp-1194.ovpn
echo '</ca>' >> /etc/openvpn/client-tcp-1194.ovpn

# Copy config OpenVPN client ke home directory root agar mudah didownload ( TCP 1194 )
cp /etc/openvpn/client-tcp-1194.ovpn /home/vps/public_html/TCP.ovpn

# 2200
# Enter the certificate into the UDP 2200 client config
cho '<ca>' >> /etc/openvpn/client-udp-2200.ovpn
cat '/etc/openvpn/ca.crt' >> /etc/openvpn/client-udp-2200.ovpn
echo '</ca>' >> /etc/openvpn/client-udp-2200.ovpn

# Copy config OpenVPN client ke home directory root agar mudah didownload ( UDP 2200 )
cp /etc/openvpn/client-udp-2200.ovpn /home/vps/public_html/UDP.ovpn

# Enter the certificate into the config SSL client .
echo '<ca>' >> /etc/openvpn/client-tcp-ssl.ovpn
cat '/etc/openvpn/server/ca.crt' >> /etc/openvpn/client-tcp-ssl.ovpn
echo '</ca>' >> /etc/openvpn/client-tcp-ssl.ovpn

# Copy config OpenVPN client ke home directory root agar mudah didownload ( SSL )
cp /etc/openvpn/client-tcp-ssl.ovpn /home/vps/public_html/SSL.ovpn

# allow ufw 
apt-get install ufw
ufw allow ssh
ufw allow 1194/tcp
ufw allow 81/tcp
ufw allow 2200/udp


#firewall untuk memperbolehkan akses UDP dan akses jalur TCP
iptables -t nat -I POSTROUTING -s 10.6.0.0/24 -o $ANU -j MASQUERADE
iptables -t nat -I POSTROUTING -s 10.7.0.0/24 -o $ANU -j MASQUERADE
iptables-save > /etc/iptables.up.rules
chmod +x /etc/iptables.up.rules

iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

# Restart service openvpn
systemctl enable openvpn
systemctl start openvpn
/etc/init.d/openvpn restart

#create web
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

# Delete script
history -c
sleep 1
rm -f /root/vpn.sh
