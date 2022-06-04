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
MYIP=$(curl -sS ifconfig.me);
MYIP2="s/xxxxxxxxx/$MYIP/g";
ANU=$(ip -o $ANU -4 route show to default | awk '{print $5}');

# Checking if openvpn folder is accidentally deleted or purged
 if [[ ! -e /etc/openvpn ]]; then
  mkdir -p /etc/openvpn
 fi

 # Removing all existing openvpn server files
 rm -rf /etc/openvpn/*

 # Creating server.conf, ca.crt, server.crt and server.key
 cat <<'myOpenVPNconf' > /etc/openvpn/server_tcp.conf
# OpenVPN TCP
port 1720
proto tcp
dev tun
sndbuf 0 
rcvbuf 0 
push "sndbuf 393216" 
push "rcvbuf 393216"
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh2048.pem
verify-client-cert none
username-as-common-name
key-direction 0
plugin /etc/openvpn/plugins/openvpn-plugin-auth-pam.so login
server 10.200.0.0 255.255.0.0
ifconfig-pool-persist ipp.txt
push "route IP-ADDRESS 255.255.255.255 vpn_gateway"
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
push "route-method exe"
push "route-delay 2"
socket-flags TCP_NODELAY
push "socket-flags TCP_NODELAY"
keepalive 10 120
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log tcp.log
management 127.0.0.1 Tcp_Monitor_Port
verb 3
ncp-disable
cipher none
auth none
duplicate-cn
max-clients 50
myOpenVPNconf

cat <<'myOpenVPNconf2' > /etc/openvpn/server_udp.conf
# OpenVPN UDP
port 3900
proto udp
dev tun
sndbuf 0 
rcvbuf 0 
push "sndbuf 393216" 
push "rcvbuf 393216"
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh2048.pem
verify-client-cert none
username-as-common-name
key-direction 0
plugin /etc/openvpn/plugins/openvpn-plugin-auth-pam.so login
server 10.201.0.0 255.255.0.0
ifconfig-pool-persist ipp.txt
push "route IP-ADDRESS 255.255.255.255 vpn_gateway"
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
push "route-method exe"
push "route-delay 2"
socket-flags TCP_NODELAY
push "socket-flags TCP_NODELAY"
keepalive 10 120
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log udp.log
management 127.0.0.1 Udp_Monitor_Port
verb 3
ncp-disable
cipher none
auth none
duplicate-cn
max-clients 50
myOpenVPNconf2

 cat <<'EOF7'> /etc/openvpn/ca.crt
-----BEGIN CERTIFICATE-----
MIIE9DCCA9ygAwIBAgIJAICa83Bjin6VMA0GCSqGSIb3DQEBCwUAMIGsMQswCQYD
VQQGEwJQSDERMA8GA1UECBMIQkFUQU5HQVMxEDAOBgNVBAcTB1RBTkFVQU4xFDAS
BgNVBAoTC0tPUk4tR0FNSU5HMQ0wCwYDVQQLEwRrb3JuMRcwFQYDVQQDEw5LT1JO
LUdBTUlORyBDQTERMA8GA1UEKRMIS29ybi1WUE4xJzAlBgkqhkiG9w0BCQEWGEdX
QVBPTkcuTEFOREVSQGdtYWlsLmNvbTAeFw0yMDEyMjkxMjUwNTVaFw0zMDEyMjcx
MjUwNTVaMIGsMQswCQYDVQQGEwJQSDERMA8GA1UECBMIQkFUQU5HQVMxEDAOBgNV
BAcTB1RBTkFVQU4xFDASBgNVBAoTC0tPUk4tR0FNSU5HMQ0wCwYDVQQLEwRrb3Ju
MRcwFQYDVQQDEw5LT1JOLUdBTUlORyBDQTERMA8GA1UEKRMIS29ybi1WUE4xJzAl
BgkqhkiG9w0BCQEWGEdXQVBPTkcuTEFOREVSQGdtYWlsLmNvbTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMxAtgmScsiqqBtk5/AwmC+iyAT+jbgcSTo0
NhpmboGNKEV7CCinAwZsYmm172Nx7s08mljxmZl988n5aq338unanEdZKxnJ/nd3
3r3TyTFvb5gQ1ZjRKYHroiTb2LlZdPIXc6hjavVaL/wSX6rWIl/OLNp+jC1xyzgz
PsUw8PmL3DcJGuaeqZmigT7ihIufo8328Lnhpjyak2JzYbeq+Ecp6KTLyX8Vcwei
r+sfcG2aZsRHaELT1lDL89VCvsvTKX51V5vcYgyA7WWXIFIxEA7Xb09iDfHEIacD
UOR5C63AlFd7P236Ya1MkD0dm1BE8A2/ncNAK6imtuDPEc5MFVECAwEAAaOCARUw
ggERMB0GA1UdDgQWBBRxLGapu/LRv3i2e/tnO4MitQvIdDCB4QYDVR0jBIHZMIHW
gBRxLGapu/LRv3i2e/tnO4MitQvIdKGBsqSBrzCBrDELMAkGA1UEBhMCUEgxETAP
BgNVBAgTCEJBVEFOR0FTMRAwDgYDVQQHEwdUQU5BVUFOMRQwEgYDVQQKEwtLT1JO
LUdBTUlORzENMAsGA1UECxMEa29ybjEXMBUGA1UEAxMOS09STi1HQU1JTkcgQ0Ex
ETAPBgNVBCkTCEtvcm4tVlBOMScwJQYJKoZIhvcNAQkBFhhHV0FQT05HLkxBTkRF
UkBnbWFpbC5jb22CCQCAmvNwY4p+lTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEB
CwUAA4IBAQBx/i8n74O0XRn2qTHPcDMQgVewNkBoMau50VH/E1cY8R5Zzy7L/ty7
2uu5BOT5GnVTwKpMSz+AalEptTpZ1dFDuYMz1E3190kHD4xNQjRTKP+BhgBi+rGL
CB5FK7YseZGLcHqmYuYx9caEDAqKg/zzDSLYs4Gfy55IG1V1XtAs0BLsKm+t8mvy
Cq5rWD5VoC8UbPbjo2Zl3l+ceJTTgkU4+7YHCBkyBsu1SOTqXJn3mTafIkCb+Kk9
+GtTpmAIms8xnHkzl0kCG/WA4t8vWWA21Ja/Bac0ZjqjR5xEm7bBLhAOdPg8r3iO
aUkO7wClIE6dNtSc2jKJhYRO3UhOFxqd
-----END CERTIFICATE-----
EOF7

 cat <<'EOF9'> /etc/openvpn/server.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=PH, ST=BATANGAS, L=TANAUAN, O=KORN-GAMING, OU=korn, CN=KORN-GAMING CA/name=Korn-VPN/emailAddress=GWAPONG.LANDER@gmail.com
        Validity
            Not Before: Dec 29 12:50:55 2020 GMT
            Not After : Dec 27 12:50:55 2030 GMT
        Subject: C=PH, ST=BATANGAS, L=TANAUAN, O=KORN-GAMING, OU=korn, CN=server/name=Korn-VPN/emailAddress=GWAPONG.LANDER@gmail.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:a5:7d:4f:e2:14:14:23:9b:a6:6e:09:9f:c2:6e:
                    ee:83:67:1a:4f:b1:ee:32:16:09:d2:0e:9c:fb:29:
                    cc:b9:45:e1:fd:21:e2:e4:2f:7d:70:83:42:dc:75:
                    b5:6a:a7:94:da:36:e4:26:e9:d3:86:08:b8:2f:24:
                    9a:ca:61:31:d9:36:03:ec:e3:01:30:24:30:c2:7d:
                    94:e0:07:ac:ea:c8:81:c6:14:3d:6d:b5:0c:90:e4:
                    1f:e7:f4:bd:04:ca:84:a8:f2:43:78:93:f7:d2:80:
                    69:9f:00:82:b0:35:21:51:d2:57:7e:10:e6:85:50:
                    aa:80:a1:ed:bc:0b:99:f9:70:e3:f7:c2:5b:2b:4c:
                    6e:f5:a1:61:b3:aa:77:3d:33:fa:f0:d3:00:02:bb:
                    13:b5:eb:a2:60:f8:96:1c:22:cb:a4:94:01:ef:66:
                    60:a2:15:98:35:d4:66:b2:c8:02:2c:fa:2c:f2:e9:
                    6a:4d:7d:47:69:ab:2d:41:63:6a:d1:ac:e2:0e:93:
                    7f:29:a6:5c:b2:af:d8:11:e3:ab:a7:45:b8:8e:a8:
                    fb:e2:04:de:86:79:2c:cc:2c:1f:58:4f:8c:29:24:
                    55:f1:6e:1a:df:5b:fb:3a:11:b4:24:63:d8:c7:bb:
                    95:ca:3e:ef:6c:84:67:30:98:58:9f:95:da:52:09:
                    2e:47
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Cert Type: 
                SSL Server
            Netscape Comment: 
                Easy-RSA Generated Server Certificate
            X509v3 Subject Key Identifier: 
                20:89:52:D3:B8:CC:BE:ED:89:04:FA:64:EB:3C:4C:29:27:36:09:C4
            X509v3 Authority Key Identifier: 
                keyid:71:2C:66:A9:BB:F2:D1:BF:78:B6:7B:FB:67:3B:83:22:B5:0B:C8:74
                DirName:/C=PH/ST=BATANGAS/L=TANAUAN/O=KORN-GAMING/OU=korn/CN=KORN-GAMING CA/name=Korn-VPN/emailAddress=GWAPONG.LANDER@gmail.com
                serial:80:9A:F3:70:63:8A:7E:95

            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:server
    Signature Algorithm: sha256WithRSAEncryption
         12:18:dd:33:b6:52:49:e9:2d:69:75:3b:ac:4d:e2:bf:85:48:
         07:4f:14:bd:fb:e2:37:fb:86:3b:78:69:01:43:29:4d:62:a3:
         5f:85:98:9a:82:fc:21:72:50:5e:dd:a6:a5:3e:94:b7:f9:a3:
         eb:ee:76:94:b3:27:5a:fa:f0:0d:b8:8c:9b:0e:ed:21:c2:79:
         3e:4f:bf:e7:50:7b:42:06:2b:d9:79:ab:0e:d9:79:12:2a:8e:
         d6:55:f8:a4:fc:1c:48:13:d7:b3:81:0b:ab:ad:90:3d:9a:7e:
         07:be:e8:64:8d:cf:7a:29:01:df:da:31:0e:4b:22:2d:c0:3a:
         f9:ff:0e:e8:f0:07:dd:13:8b:94:95:6d:70:52:af:49:52:58:
         11:61:35:d2:83:a0:04:49:d0:17:0c:68:dd:70:24:d5:33:a9:
         6e:28:7f:16:48:e6:d7:1c:3d:88:2a:32:5e:0d:61:2b:56:bc:
         cf:23:e2:7e:20:f7:2a:72:2e:f4:5c:a8:cd:d7:7d:07:72:cd:
         68:57:bf:0b:d0:bf:c0:36:5b:66:e8:2a:5b:76:5b:5a:af:cd:
         04:16:d2:e3:19:6f:34:9c:93:36:c9:fb:b4:45:6b:1a:20:02:
         93:81:a4:b5:12:c2:f3:29:33:e8:8d:dd:69:6b:7f:db:35:ca:
         f6:07:d5:60
-----BEGIN CERTIFICATE-----
MIIFXzCCBEegAwIBAgIBATANBgkqhkiG9w0BAQsFADCBrDELMAkGA1UEBhMCUEgx
ETAPBgNVBAgTCEJBVEFOR0FTMRAwDgYDVQQHEwdUQU5BVUFOMRQwEgYDVQQKEwtL
T1JOLUdBTUlORzENMAsGA1UECxMEa29ybjEXMBUGA1UEAxMOS09STi1HQU1JTkcg
Q0ExETAPBgNVBCkTCEtvcm4tVlBOMScwJQYJKoZIhvcNAQkBFhhHV0FQT05HLkxB
TkRFUkBnbWFpbC5jb20wHhcNMjAxMjI5MTI1MDU1WhcNMzAxMjI3MTI1MDU1WjCB
pDELMAkGA1UEBhMCUEgxETAPBgNVBAgTCEJBVEFOR0FTMRAwDgYDVQQHEwdUQU5B
VUFOMRQwEgYDVQQKEwtLT1JOLUdBTUlORzENMAsGA1UECxMEa29ybjEPMA0GA1UE
AxMGc2VydmVyMREwDwYDVQQpEwhLb3JuLVZQTjEnMCUGCSqGSIb3DQEJARYYR1dB
UE9ORy5MQU5ERVJAZ21haWwuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEApX1P4hQUI5umbgmfwm7ug2caT7HuMhYJ0g6c+ynMuUXh/SHi5C99cINC
3HW1aqeU2jbkJunThgi4LySaymEx2TYD7OMBMCQwwn2U4Aes6siBxhQ9bbUMkOQf
5/S9BMqEqPJDeJP30oBpnwCCsDUhUdJXfhDmhVCqgKHtvAuZ+XDj98JbK0xu9aFh
s6p3PTP68NMAArsTteuiYPiWHCLLpJQB72ZgohWYNdRmssgCLPos8ulqTX1Haast
QWNq0aziDpN/KaZcsq/YEeOrp0W4jqj74gTehnkszCwfWE+MKSRV8W4a31v7OhG0
JGPYx7uVyj7vbIRnMJhYn5XaUgkuRwIDAQABo4IBkDCCAYwwCQYDVR0TBAIwADAR
BglghkgBhvhCAQEEBAMCBkAwNAYJYIZIAYb4QgENBCcWJUVhc3ktUlNBIEdlbmVy
YXRlZCBTZXJ2ZXIgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFCCJUtO4zL7tiQT6ZOs8
TCknNgnEMIHhBgNVHSMEgdkwgdaAFHEsZqm78tG/eLZ7+2c7gyK1C8h0oYGypIGv
MIGsMQswCQYDVQQGEwJQSDERMA8GA1UECBMIQkFUQU5HQVMxEDAOBgNVBAcTB1RB
TkFVQU4xFDASBgNVBAoTC0tPUk4tR0FNSU5HMQ0wCwYDVQQLEwRrb3JuMRcwFQYD
VQQDEw5LT1JOLUdBTUlORyBDQTERMA8GA1UEKRMIS29ybi1WUE4xJzAlBgkqhkiG
9w0BCQEWGEdXQVBPTkcuTEFOREVSQGdtYWlsLmNvbYIJAICa83Bjin6VMBMGA1Ud
JQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIFoDARBgNVHREECjAIggZzZXJ2ZXIw
DQYJKoZIhvcNAQELBQADggEBABIY3TO2UknpLWl1O6xN4r+FSAdPFL374jf7hjt4
aQFDKU1io1+FmJqC/CFyUF7dpqU+lLf5o+vudpSzJ1r68A24jJsO7SHCeT5Pv+dQ
e0IGK9l5qw7ZeRIqjtZV+KT8HEgT17OBC6utkD2afge+6GSNz3opAd/aMQ5LIi3A
Ovn/DujwB90Ti5SVbXBSr0lSWBFhNdKDoARJ0BcMaN1wJNUzqW4ofxZI5tccPYgq
Ml4NYStWvM8j4n4g9ypyLvRcqM3XfQdyzWhXvwvQv8A2W2boKlt2W1qvzQQW0uMZ
bzSckzbJ+7RFaxogApOBpLUSwvMpM+iN3Wlrf9s1yvYH1WA=
-----END CERTIFICATE-----
EOF9

 cat <<'EOF10'> /etc/openvpn/server.key
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQClfU/iFBQjm6Zu
CZ/Cbu6DZxpPse4yFgnSDpz7Kcy5ReH9IeLkL31wg0LcdbVqp5TaNuQm6dOGCLgv
JJrKYTHZNgPs4wEwJDDCfZTgB6zqyIHGFD1ttQyQ5B/n9L0EyoSo8kN4k/fSgGmf
AIKwNSFR0ld+EOaFUKqAoe28C5n5cOP3wlsrTG71oWGzqnc9M/rw0wACuxO166Jg
+JYcIsuklAHvZmCiFZg11GayyAIs+izy6WpNfUdpqy1BY2rRrOIOk38pplyyr9gR
46unRbiOqPviBN6GeSzMLB9YT4wpJFXxbhrfW/s6EbQkY9jHu5XKPu9shGcwmFif
ldpSCS5HAgMBAAECggEBAKLueZPQyPM17+out4gqx9G/1PvZ5vaRFCIoGQ5/3Pwc
fZ9HmaenygzYbx+3FGJpk/g0SvS1CnjQZOalV3EhuH5u2/aCmUzYlNkn40eexvRx
bLOkgcZdln2g3Hj3UJJDAdGElEFHDZvGqjbNvd3WsXNpcJLB+PQQs43p37Jgibw3
gBWIS1/kJfVzeTnzk5qgrMogNIW4RAXUzI3tEbhYEVXCi/ZP/iBzalb2eAl/DOC9
iKyZ+rEwPCfWL+JFq5Qe6T0R/USOZAdC1irr6XQ0rNQwWbce/RWAmb45d3QYHbb6
Qjhx0ScuheRdutqaJUkqDHk26V13Z4KjLbKzUQZIg0ECgYEA0l+vajfWtTMnW1CR
Qp+gpxvgQnN+V3tX30KiXOtM2BtGLXFIDdvbQxaMRzd+hW0naVVhu0KIQo07OEOz
4OH/xNHqVZ47gQgKHkUZub72JXaJAk1F40NdRbLvn5jfMz3I+MtTIXT7f1mBHvM7
xLnBpwhs+JUKAAFTrw+TzOTd2skCgYEAyWGTHsBUEuEt9wj8LEp2fm6M9Iqp3eWS
6V7TiOqWduK3aCDhyw1BkvVZjWHFiL927y+imik9z0SBAKdUnKPSxLrMkzKH0ZER
v2UmKhZHKMsKERIh8kcaAFYuNZSvxdbWRdMzM5dam5L6P67LvysZutE7gXsorynE
OX8eRUBAOI8CgYEAznUjVM26BBhQrpgSBt1br8R2wSBRRI+C/FOLvj8aKhgSNjSv
bxJuS5fMUXQP0ef+vqwRftJboVyzWpNu6+s/tKwCGsZwRUBblbtg9N6I+NksurqV
NOT+m5FxAyLnIYWoPypjyjjhPOjdBD/XT0ix2Tg2oXq61qh2tR5HgdS2OakCgYEA
s8FANGvS4ANWJzNC/Tn+aT6+3S3FEMfyihNV2NolMruOoQjw43HSvZ35sMS8MSNO
w5QOnXMAtDleuTmjwipNYcOoBiBNsde/MsvT9C9sl1Idiz1XRc8Hu5Mxriwpdfwd
ybgK9Rs+Cq54aE3bmqmbTvGjHyHTH/+1IumAGKqQaKsCgYAMacI1eSUDTNa0I4Us
29bKpvZrbDn/oDBaLGxBLrLMf450HJvpz0PGvNh0mY2G3a3dd6JRf5ZZ8me1rHXZ
cwB6fMAtJdp6x/2QTDZ2va5avhRB/4lRNyJifl6lhad0XPKhEOByd7wg+VeCBJ6P
xXEZw5bUG9re12VX9nWNBLhJCw==
-----END PRIVATE KEY-----
EOF10

 cat <<'EOF13'> /etc/openvpn/dh2048.pem
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA6LG2I1lCezcnn9QXIT4pVFqB1mlww4YUywZ0lZV9OL6FyT+hlhix
LKulx5Wt6JhbSMjq7bJOhXiXaKh4Ve3UYTF0M+9t+7PeWyzgYu7ouyUWJDdubb/f
KqObXujveTPUs8BxtmOYNZQwVmh/hXPVeC62PyrL3uX8t2oziZcn52RN+nUxzAWS
wbZ7VXkKCfAC/QzJu+SEooS18I8R02waN5Pem0lj7Dg8IvT1Y4u8ZpLdr7uBg6mX
dN49yNN5IfrmebxWqTH71JkyvIr9eX4HUSBH16bKfjjBr2XD0L0/jd0xxkQ4at38
Baz0CzH2Sn+GXV44+gfR6/9WBSSmsnZ4cwIBAg==
-----END DH PARAMETERS-----
EOF13

 # Creating a New update message in server.conf
 cat <<'NUovpn' > /etc/openvpn/server.conf
 # New Update are now released, OpenVPN Server
 # are now running both TCP and UDP Protocol. (Both are only running on IPv4)
 # But our native server.conf are now removed and divided
 # Into two different configs base on their Protocols:
 #  * OpenVPN TCP (located at /etc/openvpn/server_tcp.conf
 #  * OpenVPN UDP (located at /etc/openvpn/server_udp.conf
 # 
 # Also other logging files like
 # status logs and server logs
 # are moved into new different file names:
 #  * OpenVPN TCP Server logs (/etc/openvpn/tcp.log)
 #  * OpenVPN UDP Server logs (/etc/openvpn/udp.log)
 #  * OpenVPN TCP Status logs (/etc/openvpn/tcp_stats.log)
 #  * OpenVPN UDP Status logs (/etc/openvpn/udp_stats.log)
 #
 # Server ports are configured base on env vars
 # executed/raised from this script (OpenVPN_TCP_Port/OpenVPN_UDP_Port)
 #
NUovpn

 # setting openvpn server port
 sed -i "s|OVPNTCP|$OpenVPN_TCP_Port|g" /etc/openvpn/server_tcp.conf
 sed -i "s|OVPNUDP|$OpenVPN_UDP_Port|g" /etc/openvpn/server_udp.conf
 sed -i "s|IP-ADDRESS|$IPADDR|g" /etc/openvpn/server_tcp.conf
 sed -i "s|IP-ADDRESS|$IPADDR|g" /etc/openvpn/server_udp.conf
 sed -i "s|Tcp_Monitor_Port|$Tcp_Monitor_Port|g" /etc/openvpn/server_tcp.conf
 sed -i "s|Udp_Monitor_Port|$Udp_Monitor_Port|g" /etc/openvpn/server_udp.conf

 # Getting some OpenVPN plugins for unix authentication
 cd
 wget https://github.com/korn-sudo/Project-Fog/raw/main/files/plugins/plugin.tgz
 tar -xzvf /root/plugin.tgz -C /etc/openvpn/
 rm -f plugin.tgz
 
 # Some workaround for OpenVZ machines for "Startup error" openvpn service
 if [[ "$(hostnamectl | grep -i Virtualization | awk '{print $2}' | head -n1)" == 'openvz' ]]; then
 sed -i 's|LimitNPROC|#LimitNPROC|g' /lib/systemd/system/openvpn*
 systemctl daemon-reload
fi

 # Allow IPv4 Forwarding
 sed -i '/net.ipv4.ip_forward.*/d' /etc/sysctl.conf
 sed -i '/net.ipv4.ip_forward.*/d' /etc/sysctl.d/*.conf
 echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/20-openvpn.conf
 sysctl --system &> /dev/null

 # Iptables Rule for OpenVPN server
 cat <<'EOFipt' > /etc/openvpn/openvpn.bash
#!/bin/bash
PUBLIC_INET="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
IPCIDR='10.200.0.0/16'
IPCIDR2='10.201.0.0/16'
iptables -I FORWARD -s $IPCIDR -j ACCEPT
iptables -I FORWARD -s $IPCIDR2 -j ACCEPT
iptables -t nat -A POSTROUTING -o $PUBLIC_INET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $IPCIDR -o $PUBLIC_INET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $IPCIDR2 -o $PUBLIC_INET -j MASQUERADE
EOFipt
 chmod +x /etc/openvpn/openvpn.bash
 bash /etc/openvpn/openvpn.bash

 # Enabling IPv4 Forwarding
 echo 1 > /proc/sys/net/ipv4/ip_forward
 
 # Starting OpenVPN server
 systemctl start openvpn@server_tcp
 systemctl enable openvpn@server_tcp
 systemctl start openvpn@server_udp
 systemctl enable openvpn@server_udp

# Now creating all of our OpenVPN Configs 
mkdir -p /home/vps/public_html
find . -type d -exec chmod 755 {} \;
find . -type f -exec chmod 644 {} \;
chown -R www-data:www-data .

# Smart Giga Games Promo TCP
cat <<Config1> /home/vps/public_html/SSL.ovpn
# ----------------------------
# OPENVPN BY $DOMAIN
# ----------------------------
client
dev tun
proto tcp
remote xxxxxxxxx 445
;remote $DOMAIN 445
resolv-retry infinite
nobind
persist-key
persist-tun
comp-lzo
keepalive 10 120
tls-client
remote-cert-tls server
verb 2
auth-user-pass
cipher none
auth none
auth-nocache
auth-retry interact
connect-retry 0 1
nice -20
reneg-sec 0
redirect-gateway def1
setenv CLIENT_CERT 0

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
Config1


# Default TCP
cat <<Config3> /home/vps/public_html/TCP.ovpn
# ----------------------------
# OPENVPN BY $DOMAIN
# ----------------------------
client
dev tun
proto tcp
remote xxxxxxxxx 1720
;remote $DOMAIN 1720
nobind
persist-key
persist-tun
comp-lzo
keepalive 10 120
tls-client
remote-cert-tls server
verb 2
auth-user-pass
cipher none
auth none
auth-nocache
auth-retry interact
connect-retry 0 1
nice -20
reneg-sec 0
redirect-gateway def1
setenv CLIENT_CERT 0

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
Config3

# Default UDP
cat <<Config4> /home/vps/public_html/UDP.ovpn
# ----------------------------
# OPENVPN BY $DOMAIN
# ----------------------------
client
dev tun
proto udp
remote xxxxxxxxx 3900
;remote $DOMAIN 3900
nobind
persist-key
persist-tun
comp-lzo
keepalive 10 120
tls-client
remote-cert-tls server
verb 2
auth-user-pass
cipher none
auth none
auth-nocache
auth-retry interact
connect-retry 0 1
nice -20
reneg-sec 0
redirect-gateway def1
setenv CLIENT_CERT 0

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
Config4

# Smart Giga Stories Promo TCP
cat <<Config5> /home/vps/public_html/Smart.Giga.Stories.ovpn
# ----------------------------
# OPENVPN BY $DOMAIN
# ----------------------------
client
dev tun
proto tcp
remote xxxxxxxxx 1720
;remote $DOMAIN 1720
nobind
persist-key
persist-tun
comp-lzo
keepalive 10 120
tls-client
remote-cert-tls server
verb 2
auth-user-pass
cipher none
auth none
auth-nocache
auth-retry interact
connect-retry 0 1
nice -20
reneg-sec 0
redirect-gateway def1
setenv CLIENT_CERT 0

http-proxy xxxxxxxxx 3128
http-proxy-option VERSION 1.1
http-proxy-option CUSTOM-HEADER Host static.muscdn.com
http-proxy-option CUSTOM-HEADER X-Forward-Host static.muscdn.com
http-proxy-option CUSTOM-HEADER X-Forwarded-For static.muscdn.com
http-proxy-option CUSTOM-HEADER Referrer static.muscdn.com

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
Config5

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
