#!/bin/bash
#
# By Rpj Wonosobo
# ==================================================

# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- ifconfig.me/ip);
MYIP2="s/xxxxxxxxx/$MYIP/g";
ANU=$(ip -o $ANU -4 route show to default | awk '{print $5}');

# Install OpenVPN dan Easy-RSA
apt install openvpn easy-rsa unzip -y
apt install openssl iptables iptables-persistent -y
mkdir -p /etc/openvpn/server/easy-rsa/
cd /etc/openvpn/
wget https://raw.githubusercontent.com/4hidessh/baru/main/vpn.zip

unzip vpn.zip
rm -f vpn.zip
chown -R root:root /etc/openvpn/server/easy-rsa/

cd
mkdir -p /usr/lib/openvpn/
cp /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /usr/lib/openvpn/openvpn-plugin-auth-pam.so

# nano /etc/default/openvpn
sed -i 's/#AUTOSTART="all"/AUTOSTART="all"/g' /etc/default/openvpn

# restart openvpn dan cek status openvpn
systemctl enable --now openvpn-server@server-tcp-1194
systemctl enable --now openvpn-server@server-udp-2200
/etc/init.d/openvpn restart
/etc/init.d/openvpn status

# aktifkan ip4 forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf

# Buat config client TCP 1194
cat > /etc/openvpn/client-tcp-1194.ovpn <<-END
############## WELCOME TO Regsub.com ###############
########## Config Bye Regsub ###########
####### DONT FORGET TO SUPPORT US #######
client
dev tun
proto tcp
remote xxxxxxxxx 1194
##### Modification VPN with BUG and Squid Proxy #####
#http-proxy-retry
#http-proxy xxxxxxxxx 3128
#http-proxy-option CUSTOM-HEADER Host google.com
##### if used, you can delete the code below ###
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
client-cert-not-required


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
cat > /etc/openvpn/client-udp-2200.ovpn <<-END
############## WELCOME TO Regsub.com ###############
########## Config Bye Regsub ###########
####### DONT FORGET TO SUPPORT US #######
client
dev tun
proto udp
remote xxxxxxxxx 2200
##### Modification VPN with BUG and Squid Proxy #####
#http-proxy-retry
#http-proxy xxxxxxxxx 3128
#http-proxy-option CUSTOM-HEADER Host google.com
##### if used, you can delete the code below ###
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
client-cert-not-required
END

sed -i $MYIP2 /etc/openvpn/client-udp-2200.ovpn;

# Buat config client SSL
cat > /etc/openvpn/client-tcp-ssl.ovpn <<-END
############## WELCOME TO Regsub.com ###############
########## Config Bye Regsub ###########
####### DONT FORGET TO SUPPORT US #######
client
dev tun
proto tcp
remote xxxxxxxxx 442
##### Modification VPN with BUG and Squid Proxy #####
#http-proxy-retry
#http-proxy xxxxxxxxx 3128
#http-proxy-option CUSTOM-HEADER Host google.com
##### if used, you can delete the code below ###
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
client-cert-not-required
END

sed -i $MYIP2 /etc/openvpn/client-tcp-ssl.ovpn;

# Buat config client stunnel
cat > /etc/openvpn/client-stunnel.ovpn <<-END
############## WELCOME TO Regsub ###############
########## Config Bye Regsub ###########
####### DONT FORGET TO SUPPORT US #######
client
dev tun
proto tcp
remote xxxxxxxxx 1194
##### Modification VPN with BUG and Squid Proxy #####
#http-proxy-retry
#http-proxy xxxxxxxxx 3128
#http-proxy-option CUSTOM-HEADER Host google.com
##### if used, you can delete the code below ###
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
client-cert-not-required
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

sed -i $MYIP2 /etc/openvpn/client-stunnel.ovpn;



cd
# pada tulisan xxx ganti dengan alamat ip address VPS anda 
/etc/init.d/openvpn restart

# masukkan certificatenya ke dalam config client TCP 1194
echo '<ca>' >> /etc/openvpn/client-tcp-1194.ovpn
cat /etc/openvpn/server/ca.crt >> /etc/openvpn/client-tcp-1194.ovpn
echo '</ca>' >> /etc/openvpn/client-tcp-1194.ovpn

# Copy config OpenVPN client ke home directory root agar mudah didownload ( TCP 1194 )
cp /etc/openvpn/client-tcp-1194.ovpn /home/vps/public_html/client-tcp-1194.ovpn

# masukkan certificatenya ke dalam config client UDP 2200
echo '<ca>' >> /etc/openvpn/client-udp-2200.ovpn
cat /etc/openvpn/server/ca.crt >> /etc/openvpn/client-udp-2200.ovpn
echo '</ca>' >> /etc/openvpn/client-udp-2200.ovpn

# Copy config OpenVPN client ke home directory root agar mudah didownload ( UDP 2200 )
cp /etc/openvpn/client-udp-2200.ovpn /home/vps/public_html/client-udp-2200.ovpn

# masukkan certificatenya ke dalam config client SSL
echo '<ca>' >> /etc/openvpn/client-tcp-ssl.ovpn
cat /etc/openvpn/server/ca.crt >> /etc/openvpn/client-tcp-ssl.ovpn
echo '</ca>' >> /etc/openvpn/client-tcp-ssl.ovpn

# Copy config OpenVPN client ke home directory root agar mudah didownload ( SSL )
cp /etc/openvpn/client-tcp-ssl.ovpn /home/vps/public_html/client-tcp-ssl.ovpn

# masukkan certificatenya ke dalam config client stunnel
echo '<ca>' >> /etc/openvpn/client-stunnel.ovpn
cat /etc/openvpn/server/ca.crt >> /etc/openvpn/client-stunnel.ovpn
echo '</ca>' >> /etc/openvpn/client-stunnel.ovpn

# Copy config OpenVPN client ke home directory root agar mudah didownload ( SSL )
cp /etc/openvpn/client-tcp-ssl.ovpn /home/vps/public_html/client-stunnel.ovpn



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

#buat web

# Delete script
 
cd /home/vps/public_html/
cat <<'mySiteOvpn' > /home/vps/public_html/index.html
<!DOCTYPE html>
<html lang="en">

<!-- Simple OVPN Download site -->

<head><meta charset="utf-8" /><title>OVPN Config Download</title><meta name="description" content="Server" /><meta content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" name="viewport" /><meta name="theme-color" content="#000000" /><link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.2/css/all.css"><link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdnjs.cloudflare.com/ajax/libs/mdbootstrap/4.8.3/css/mdb.min.css" rel="stylesheet"></head><body><div class="container justify-content-center" style="margin-top:9em;margin-bottom:5em;"><div class="col-md"><div class="view"><img src="https://openvpn.net/wp-content/uploads/openvpn.jpg" class="card-img-top"><div class="mask rgba-white-slight"></div></div><div class="card"><div class="card-body"><h5 class="card-title">Config List</h5><br /><ul class="list-group">

<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>TCP <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small></small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESSS:81/client-tcp-1194.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li>

<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>UDP <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small></small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESSS:81/client-udp-2200.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li>

<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>SSL <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small></small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESSS:81/client-tcp-ssl.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li>

<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p> ALL.zip <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small></small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESSS:81/cfg.zip" style="float:right;"><i class="fa fa-download"></i> Download</a></li>

</ul></div></div></div></div></body></html>
mySiteOvpn

sed -i "s|IP-ADDRESSS|$(curl -sS ifconfig.me)|g" /home/vps/public_html/index.html



# Delete script
history -c
rm -f /root/vpn.sh
cd /home/vps/public_html
zip config.zip client-udp-2200.ovpn client-tcp-1194.ovpn client-tcp-ssl.ovpn
