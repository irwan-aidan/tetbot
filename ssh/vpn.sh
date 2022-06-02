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

# Install OpenVPN dan Easy-RSA
apt install openssl iptables iptables-persistent -y >/dev/null 2>&1
mkdir -p /etc/openvpn/server/easy-rsa/
cd /etc/openvpn/
wget -q https://notabug.org/irwan-aidan/vps/raw/master/vpn.zip
unzip -o -P scvps07 vpn.zip >/dev/null 2>&1
rm -f vpn.zip
chown -R root:root /etc/openvpn/server/easy-rsa/

cd
mkdir -p /usr/lib/openvpn/
cp /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /usr/lib/openvpn/openvpn-plugin-auth-pam.so >/dev/null 2>&1

# nano /etc/default/openvpn
sed -i 's/#AUTOSTART="all"/AUTOSTART="all"/g' /etc/default/openvpn

# restart openvpn dan cek status openvpn
systemctl enable --now openvpn-server@server-tcp-1194 >/dev/null 2>&1
systemctl enable --now openvpn-server@server-udp-2200 >/dev/null 2>&1
/etc/init.d/openvpn restart >/dev/null 2>&1
/etc/init.d/openvpn status >/dev/null 2>&1

# aktifkan ip4 forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf

# cert

cat <<'EOF7'> /etc/openvpn/ca.crt
-----BEGIN CERTIFICATE-----
MIIFDDCCA/SgAwIBAgIJAIxbDcvh6vPEMA0GCSqGSIb3DQEBCwUAMIG0MQswCQYD
VQQGEwJQSDEPMA0GA1UECBMGVGFybGFjMRMwEQYDVQQHEwpDb25jZXBjaW9uMRMw
EQYDVQQKEwpKb2huRm9yZFRWMRMwEQYDVQQLEwpKb2huRm9yZFRWMRIwEAYDVQQD
EwlEZWJpYW5WUE4xHTAbBgNVBCkTFEpvaG4gRm9yZCBNYW5naWxpbWFuMSIwIAYJ
KoZIhvcNAQkBFhNhZG1pbkBqb2huZm9yZHR2Lm1lMB4XDTE5MTEyNTA4MDUzMFoX
DTI5MTEyMjA4MDUzMFowgbQxCzAJBgNVBAYTAlBIMQ8wDQYDVQQIEwZUYXJsYWMx
EzARBgNVBAcTCkNvbmNlcGNpb24xEzARBgNVBAoTCkpvaG5Gb3JkVFYxEzARBgNV
BAsTCkpvaG5Gb3JkVFYxEjAQBgNVBAMTCURlYmlhblZQTjEdMBsGA1UEKRMUSm9o
biBGb3JkIE1hbmdpbGltYW4xIjAgBgkqhkiG9w0BCQEWE2FkbWluQGpvaG5mb3Jk
dHYubWUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCf+WkN868YMiCl
d3z1Tq2OeRNb6ljiRGzEi1qrIvj/gXq6o0QD0SD+Nf3QWJrrJYFi1GECq72PNFhy
2jLFgZH0RRLOVZfG+jwZ9itxofweiwALvgMdz2e+mpQItMxKh1ZYkzNw+4zJ7zJV
u0Tq7YGPaMFPkLNU3V454rDYCdI8GG/wPDoW5FMc3FogI8fwylQvTWyE0yxHMxH6
FkISA5hOuSo6MO1FgAfDdNNwxa/MAbpHwJ+W6RBHv4lhE6bQePMCj/90pgt3NpxF
i++qwpSRfOR6OuuyDr1c++z6qhjLB7YzDLzj+HXCyfsPWPj+gJ0+3ckhW4gf/nhR
uB+BTd8fAgMBAAGjggEdMIIBGTAdBgNVHQ4EFgQULXGeDQBLXCPId0F3r/58FDCm
jC4wgekGA1UdIwSB4TCB3oAULXGeDQBLXCPId0F3r/58FDCmjC6hgbqkgbcwgbQx
CzAJBgNVBAYTAlBIMQ8wDQYDVQQIEwZUYXJsYWMxEzARBgNVBAcTCkNvbmNlcGNp
b24xEzARBgNVBAoTCkpvaG5Gb3JkVFYxEzARBgNVBAsTCkpvaG5Gb3JkVFYxEjAQ
BgNVBAMTCURlYmlhblZQTjEdMBsGA1UEKRMUSm9obiBGb3JkIE1hbmdpbGltYW4x
IjAgBgkqhkiG9w0BCQEWE2FkbWluQGpvaG5mb3JkdHYubWWCCQCMWw3L4erzxDAM
BgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBZUpwZ+LQWAQI8VW3hdZVN
WV+P12yYQ1UzyagtB3MqBR4aZhjk42NFBrwPZwpvWUXB0GB4DhBuvbVPtqnt5p4V
sDtQ6vKYeDlE/KDGDc0oJDsgxo2wwIXy+y/14EDqidAVjtf1rk5MDAAEVvonHxkP
861kzoIOZ0+D7sJDo3aZ8uNy8UznrRSzLDT63o28DkL3iLASyt1GHWu05wYmgzsg
m+w+AWvN5rL65mzyn/Bipf0I9snVB4saCgfy7TCI/4slOcMCNc2e6oOwOLvFA+s8
dZMt2qg62PEOj/LblYGD+qLn0xLRwqK0UWSmWobz5LXoxyssZLK2KiMkS41PHkfh
-----END CERTIFICATE-----
EOF7
 cat <<'EOF9'> /etc/openvpn/server.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            53:9b:68:c4:0e:e6:31:cb:14:ea:fc:91:ec:f5:b0:b8
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=Aidan VPN
        Validity
            Not Before: Mar 13 13:26:48 2022 GMT
            Not After : Mar 10 13:26:48 2032 GMT
        Subject: CN=server
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:bf:27:07:c2:a9:b3:04:41:98:c3:0e:17:c5:7c:
                    78:c0:d5:c1:33:2f:6b:07:1b:da:49:86:a6:a1:1f:
                    10:de:bb:f6:98:08:88:49:21:fd:19:f7:87:d2:5f:
                    5e:23:54:2b:02:fd:8b:8c:bc:88:f5:6f:53:2b:da:
                    9f:93:0d:f3:6c:3f:6f:3e:e0:40:32:56:96:4a:a4:
                    11:1d:29:bd:78:b1:16:71:fb:c5:8f:1a:c5:cf:68:
                    73:49:a2:13:39:9f:06:92:62:38:dc:ee:32:43:7e:
                    0e:19:98:a1:50:4a:1f:1d:5b:b8:cd:b6:a3:b7:aa:
                    85:35:f4:2e:15:7d:de:16:a2:f6:45:64:99:67:c3:
                    c5:0f:a9:8d:50:c6:e7:25:08:18:fd:75:c0:a1:0d:
                    93:db:c7:77:44:54:ae:43:7f:3e:ee:94:11:09:fb:
                    c4:5a:33:ab:1f:40:35:2a:9a:1b:46:f4:49:4d:9d:
                    33:6c:67:0b:d0:41:4b:4d:a1:17:47:05:4d:9b:88:
                    99:9a:64:93:3b:25:80:06:22:d9:f1:fc:69:fc:3c:
                    05:61:b6:31:7f:f8:42:3f:ff:8c:84:d2:60:17:8c:
                    bd:ba:49:cc:83:6c:b2:a5:8e:d9:b7:57:b1:9b:e7:
                    7f:e4:f9:c8:01:06:98:ea:63:19:e3:37:7d:af:c8:
                    f1:5b
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                F2:16:9F:93:AB:FD:DB:F2:B4:68:FD:B9:E8:B1:35:4E:C3:CA:25:CF
            X509v3 Authority Key Identifier: 
                keyid:24:84:8C:FD:34:DA:30:CD:54:24:4A:21:A2:D0:BC:4B:4C:C1:1C:41
                DirName:/CN=Aidan VPN
                serial:12:7D:57:E2:8E:64:E5:AA:EC:C7:B3:8E:31:EC:06:19:C9:CF:A7:B6

            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:server
    Signature Algorithm: sha256WithRSAEncryption
         c4:55:3b:7f:d5:d1:55:bc:74:31:d0:c8:8d:74:8a:d5:0e:0f:
         37:82:3b:59:ad:32:f5:89:e8:03:e5:8d:dc:c0:3b:4e:36:a9:
         61:85:22:72:66:c3:d6:fc:18:a5:5c:b5:8f:ee:a9:10:0f:de:
         78:82:0e:41:87:94:3f:29:fb:e8:32:23:31:c6:c4:48:1e:68:
         b4:15:b7:a1:99:60:e1:93:01:b2:fa:72:84:85:23:fe:ab:79:
         bb:3e:d3:07:10:a5:60:e2:4f:35:f5:98:45:34:43:f3:99:14:
         33:1c:f3:4c:65:59:0d:a0:6c:97:88:cb:6d:b2:73:80:27:0d:
         f3:96:8a:7b:18:a3:7d:9a:c7:29:17:c3:e5:7a:95:18:a5:b4:
         5b:cf:7d:d6:b4:0a:5f:7f:ac:b1:2c:23:2a:7a:82:bc:c3:28:
         f4:db:15:15:00:49:76:3c:d7:d5:ed:35:b2:ee:94:f3:ce:ad:
         ab:16:c6:e9:0f:f4:f4:81:13:23:a7:00:dd:1e:26:48:4b:0f:
         22:1d:1f:b1:25:82:e9:5f:33:ae:59:70:b0:79:a4:d4:bd:08:
         d5:0d:a2:2a:a1:a8:ce:e5:10:40:02:9f:19:22:97:30:64:cb:
         23:5e:06:e5:fd:d8:de:99:28:34:24:05:10:c7:d0:27:63:51:
         df:ca:f2:f2
-----BEGIN CERTIFICATE-----
MIIDYzCCAkugAwIBAgIQU5toxA7mMcsU6vyR7PWwuDANBgkqhkiG9w0BAQsFADAU
MRIwEAYDVQQDDAlBaWRhbiBWUE4wHhcNMjIwMzEzMTMyNjQ4WhcNMzIwMzEwMTMy
NjQ4WjARMQ8wDQYDVQQDDAZzZXJ2ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQC/JwfCqbMEQZjDDhfFfHjA1cEzL2sHG9pJhqahHxDeu/aYCIhJIf0Z
94fSX14jVCsC/YuMvIj1b1Mr2p+TDfNsP28+4EAyVpZKpBEdKb14sRZx+8WPGsXP
aHNJohM5nwaSYjjc7jJDfg4ZmKFQSh8dW7jNtqO3qoU19C4Vfd4WovZFZJlnw8UP
qY1QxuclCBj9dcChDZPbx3dEVK5Dfz7ulBEJ+8RaM6sfQDUqmhtG9ElNnTNsZwvQ
QUtNoRdHBU2biJmaZJM7JYAGItnx/Gn8PAVhtjF/+EI//4yE0mAXjL26ScyDbLKl
jtm3V7Gb53/k+cgBBpjqYxnjN32vyPFbAgMBAAGjgbMwgbAwCQYDVR0TBAIwADAd
BgNVHQ4EFgQU8hafk6v92/K0aP256LE1TsPKJc8wTwYDVR0jBEgwRoAUJISM/TTa
MM1UJEohotC8S0zBHEGhGKQWMBQxEjAQBgNVBAMMCUFpZGFuIFZQToIUEn1X4o5k
5arsx7OOMewGGcnPp7YwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCwYDVR0PBAQDAgWg
MBEGA1UdEQQKMAiCBnNlcnZlcjANBgkqhkiG9w0BAQsFAAOCAQEAxFU7f9XRVbx0
MdDIjXSK1Q4PN4I7Wa0y9YnoA+WN3MA7TjapYYUicmbD1vwYpVy1j+6pEA/eeIIO
QYeUPyn76DIjMcbESB5otBW3oZlg4ZMBsvpyhIUj/qt5uz7TBxClYOJPNfWYRTRD
85kUMxzzTGVZDaBsl4jLbbJzgCcN85aKexijfZrHKRfD5XqVGKW0W8991rQKX3+s
sSwjKnqCvMMo9NsVFQBJdjzX1e01su6U886tqxbG6Q/09IETI6cA3R4mSEsPIh0f
sSWC6V8zrllwsHmk1L0I1Q2iKqGozuUQQAKfGSKXMGTLI14G5f3Y3pkoNCQFEMfQ
J2NR38ry8g==
-----END CERTIFICATE-----
EOF9
 cat <<'EOF10'> /etc/openvpn/server.key
-----BEGIN PRIVATE KEY-----
MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQC/JwfCqbMEQZjD
DhfFfHjA1cEzL2sHG9pJhqahHxDeu/aYCIhJIf0Z94fSX14jVCsC/YuMvIj1b1Mr
2p+TDfNsP28+4EAyVpZKpBEdKb14sRZx+8WPGsXPaHNJohM5nwaSYjjc7jJDfg4Z
mKFQSh8dW7jNtqO3qoU19C4Vfd4WovZFZJlnw8UPqY1QxuclCBj9dcChDZPbx3dE
VK5Dfz7ulBEJ+8RaM6sfQDUqmhtG9ElNnTNsZwvQQUtNoRdHBU2biJmaZJM7JYAG
Itnx/Gn8PAVhtjF/+EI//4yE0mAXjL26ScyDbLKljtm3V7Gb53/k+cgBBpjqYxnj
N32vyPFbAgMBAAECggEBAL77uRY2RQUgoQdpojiPR3qrVu/UFaQxoORLY1qh1lIk
DJoUFE61ZdM27H41CLJVmu/O8Um46UIHa1rqgPsFOkvSCU0R8zIYLur+h5bSqFrY
3CsgOV/kiPTUUDOmenzctU02U8fxOUkTvfS2+Z1loTbM+JSYQXT1K0kf4ZdZfbaw
ePR6muQSXameianZLF6dqNmOHqy50eX5Cn2bDrUFZQZcC4QKajcNPSb8GbcIsMgg
MAhukCWg0/++7HJYg5iSsXScAArBrBV6iNkMxoCKFztzdlE1CLfzKAZFRDH4Zsrt
zBtF87LTvOniXdxd5ZYq7VpPvtvEcMwUeRYjoOvhzXECgYEA9Pf2zbvobXFXRMI+
9XjLLuGcLOGUOTFCb6hgFvfNhM8iC/LAlcmz3YLKgWAbi3CCm+7YGgiQ3ImMDdcv
NV6A/71n1vT3dpqfaoCpfZrl4vorYmhuY0RLNFDy1kGXnGJl96Ppy4KKdnocqKje
8NSpbRdnJ4nJ0+HIUkq4VIng7IkCgYEAx8KqVsgnYtDUVDq+c5dgPYI0Zb1iZO4D
HjhX3RYntFhnoecPhpahtvUxNNcX9i1qEoSr8TWy780AN/bziNWYzWc41FqcvWQr
BuujfCrcFjlpQ/BzfQicz1evuBdmaKmMmbltP/sghEviIjxwOu1gDNkCExxANjxK
BHJu+HuPXcMCgYEA1QdN+VuPpJ0L5x+E4LNK/ln0FpOU8qeDvtYNueuFLhly4jEY
iSn+4IL818VcLsaIzlHGW91XHHIA+YhH5YFpbPypcKVXDi0otNVuj2xEvj4PvGRU
mr6pJ7W9d9VSowxu4AwLJI9BGgbXJVS1i3lkXRoc+qU4fqm6KtYPtnSwxQECgYEA
g3mOHzvxIEqN1Tosq2uQPit6TRQOtJsqljNDMRIp47rjyl2HjG+L1B0g28RN0wsk
6zdC66kKMmZcpHj25LKgtWAguTNCQiyxXQauPUUAQehbbgnOGRcYDieKUcGk93HQ
RkUSsK+aQTiohxv8Sex98TbK9MT9RjT8Cl0+yHCadX0CgYEAqzh7y7JaQV5SpIS9
Iu1s0TFsUyhhTVLUb9nABWVX0sfi9gf9ij/3p/V+r5P30iaRUx8d72R9tFclBKSm
RhorWKhxk1ppbCRqHGuqRnCXGU0mmm9hJmllek1DSFi8NAfxuupKRvlYJJN0AG5F
pyGoVzXfwFEAbFORAo9Y1cZyFNU=
-----END PRIVATE KEY-----
EOF10
 cat <<'EOF13'> /etc/openvpn/dh2048.pem
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEArmQMu1nrBaN7jtF4UDK9xk0T5J44pNrl4mlNHKkOjoOuAC1Jo2wF
p997VJNUY99ttEEi/dZbVKFH9S007ny1xJny//bkYdJznPiTvYXdwbu/nBZPlzho
n8YcbuwL54LHN+iJ6lRaaYTJumUJQhfmcfbg5CbNsnnWnMwmgtlhlF7yXPs95al6
rNlUT15+80XXCR3jSPR/et7jebxNJnOxc3FcZCwRkgqxrtcYlGXMOwTJLO+AyYjQ
BPpTD8iMAXYLPgahpq11/ZCVlHxi7i3Oed2YPd2TrET4Lm8Sbh33eKhxBSThooox
00Gn4IhcAamTry+6tmz4I69Q5yo1Ze1QqwIBAg==
-----END DH PARAMETERS-----
EOF13

# Buat config client TCP 1194
cat > /etc/openvpn/Tcp.ovpn <<-END
client
dev tun
proto tcp
remote xxxxxxxxx 1194
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
END

sed -i $MYIP2 /etc/openvpn/Tcp.ovpn

# Buat config client UDP 2200
cat > /etc/openvpn/Udp.ovpn <<-END
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
END

sed -i $MYIP2 /etc/openvpn/Udp.ovpn

# Buat config client SSL
cat > /etc/openvpn/SSL.ovpn <<-END
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
END

sed -i $MYIP2 /etc/openvpn/SSL.ovpn

cd
# pada tulisan xxx ganti dengan alamat ip address VPS anda 
/etc/init.d/openvpn restart >/dev/null 2>&1

# masukkan certificatenya ke dalam config client TCP 1194
echo '<ca>' >> /etc/openvpn/Tcp.ovpn
cat /etc/openvpn/ca.crt >> /etc/openvpn/Tcp.ovpn
echo '</ca>' >> /etc/openvpn/Tcp.ovpn

# Copy config OpenVPN client ke home directory root agar mudah didownload ( TCP 1194 )
cp /etc/openvpn/Tcp.ovpn /home/vps/public_html/Tcp.ovpn

# masukkan certificatenya ke dalam config client UDP 2200
echo '<ca>' >> /etc/openvpn/Udp.ovpn
cat /etc/openvpn/ca.crt >> /etc/openvpn/Udp.ovpn
echo '</ca>' >> /etc/openvpn/Udp.ovpn

# Copy config OpenVPN client ke home directory root agar mudah didownload ( UDP 2200 )
cp /etc/openvpn/Udp.ovpn /home/vps/public_html/Udp.ovpn

# masukkan certificatenya ke dalam config client SSL
echo '<ca>' >> /etc/openvpn/SSL.ovpn
cat /etc/openvpn/ca.crt >> /etc/openvpn/SSL.ovpn
echo '</ca>' >> /etc/openvpn/SSL.ovpn

# Copy config OpenVPN client ke home directory root agar mudah didownload ( SSL )
cp /etc/openvpn/SSL.ovpn /home/vps/public_html/SSL.ovpn

#firewall untuk memperbolehkan akses UDP dan akses jalur TCP

sudo iptables -t nat -I POSTROUTING -s 10.6.0.0/24 -o $ANU -j MASQUERADE
sudo iptables -t nat -I POSTROUTING -s 10.7.0.0/24 -o $ANU -j MASQUERADE
sudo iptables-save > /etc/iptables.up.rules
chmod +x /etc/iptables.up.rules

sudo iptables-restore -t < /etc/iptables.up.rules
sudo netfilter-persistent save >/dev/null 2>&1
sudo netfilter-persistent reload >/dev/null 2>&1

# Restart service openvpn
systemctl enable openvpn >/dev/null 2>&1
systemctl start openvpn >/dev/null 2>&1
/etc/init.d/openvpn restart >/dev/null 2>&1

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

