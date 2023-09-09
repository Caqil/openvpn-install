#!/bin/bash
#
# https://github.com/Nyr/openvpn-install
#
# Copyright (c) 2013 Nyr. Released under the MIT License.


# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'This installer needs to be run with "bash", not "sh".'
	exit
fi

# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OpenVZ 6
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
	echo "The system is running an old kernel, which is incompatible with this installer."
	exit
fi

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
	group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
	group_name="nogroup"
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
	os="centos"
	os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
	group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
	os="fedora"
	os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
	group_name="nobody"
else
	echo "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS and Fedora."
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
	echo "Ubuntu 18.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
	exit
fi

if [[ "$os" == "debian" && "$os_version" -lt 9 ]]; then
	echo "Debian 9 or higher is required to use this installer.
This version of Debian is too old and unsupported."
	exit
fi

if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
	echo "CentOS 7 or higher is required to use this installer.
This version of CentOS is too old and unsupported."
	exit
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH does not include sbin. Try using "su -" instead of "su".'
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "This installer needs to be run with superuser privileges."
	exit
fi

if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
	echo "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
	exit
fi

new_client () {
	# Generates the custom client.ovpn
	{
	cat /etc/openvpn/server/client-common.txt
	echo "<ca>"
	-----BEGIN CERTIFICATE-----
MIIDNjCCAh6gAwIBAgIUA3IjX2RWinwaHCMW3DW7Iz4FkU0wDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEb3ZwbjAeFw0yMzAyMDgyMTUyNDBaFw0zMzAyMDUyMTUy
NDBaMA8xDTALBgNVBAMMBG92cG4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCudg2wUSyWt4Pi+2OAZyPFT5RHh42gP0WYGfPA8/BDhLWmYqvWNxwQ4oAV
CDa5Olx4zYUM1AgCDnu7m5NmQThNPrSd/5dWm9aAtZVKXMGviHMVtbHKTQgkEpeK
PS5HOBP7oa7VVveZnMQAf79U1jd5W8ZQN+0mC4857W6tCv3MejMEQxmPAUa701KN
0VIUyKrfXR9q4mAyE/1DGmz/Ds54YH7v6i1Y3KQeUKacIeg9SGe2yCtouH0e7/YJ
f1v6vLxvQ1FRaiAycWvd/ZuRm2lTSCUzOyedaGpOM5o2y/AfMfoXjvXe0232Ovt9
j+/KtgN+pGSmY7u/Ht9Twbu8OWrNAgMBAAGjgYkwgYYwDAYDVR0TBAUwAwEB/zAd
BgNVHQ4EFgQUml7/8spmdRwHPaUAHD3T4Bj2LkQwSgYDVR0jBEMwQYAUml7/8spm
dRwHPaUAHD3T4Bj2LkShE6QRMA8xDTALBgNVBAMMBG92cG6CFANyI19kVop8Ghwj
Ftw1uyM+BZFNMAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAFziG+aZi
99jYoScc9Fr07wKvStkqukP4k3iTF1pK7tLB8GND9VVBIjeUiVEvk4aea7S3a1RT
TE97sQZvDNTZX2WBAzd0DbFZ63GGgAy8NxnoC8sdDwfLcMnkZefsYsNmolachVpe
yakAMJZDyGslti/XTrQTD6+oGNNlY6Xx9N+XdlxfNFu3SjU28nbo0CNTPtwZDPw8
R7+/gBjX7tzSIYX18S4+aeoxcwOt/rhB30dFp0wRhdf/DCr8qV/mnh1l2Xmdp5HZ
2zaVLFYQMrkYt7vzWqW98qnYAZjJnTBAhJxnBpHkR3HruNljHaWqPuznHXmqJdJb
wqebDDB+t/W9Fg==
-----END CERTIFICATE-----
	echo "</ca>"
	echo "<cert>"
	Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            bf:4b:a5:00:f0:e1:a9:eb:cd:9a:34:b9:d8:cf:60:35
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=ovpn
        Validity
            Not Before: Feb  8 21:52:40 2023 GMT
            Not After : May 13 21:52:40 2025 GMT
        Subject: CN=ovpn
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:bc:22:cb:c9:67:39:3b:a6:0d:d2:13:7f:1e:40:
                    02:3d:c7:97:bb:4e:e7:03:2c:1b:a8:7b:5f:12:46:
                    96:bc:dc:c6:15:03:fa:41:59:7b:61:55:b6:04:be:
                    6a:a8:74:f0:1a:19:d6:84:fc:35:d4:29:44:10:2f:
                    a3:09:60:90:e8:5d:bc:57:a5:d9:11:25:80:f9:c3:
                    13:a7:5a:53:bc:d0:39:f6:fc:08:98:0d:9c:d0:e0:
                    a1:95:42:53:d8:8e:e3:9a:9c:57:d6:dc:23:2a:0a:
                    f5:3d:0c:b3:9d:2d:4f:6d:1d:cb:b5:1e:61:a8:12:
                    f8:32:41:45:fe:5c:6d:e1:d8:cb:c4:04:6b:2a:56:
                    02:24:48:c0:df:65:de:17:2c:3b:8c:22:4a:35:9b:
                    0c:b0:65:8e:25:6f:81:2e:cf:0d:ac:28:1c:cc:44:
                    51:72:20:f0:42:75:e1:2f:fe:b4:d1:d2:30:36:86:
                    8b:cf:3d:ee:6d:ab:a1:e5:ae:39:12:aa:1f:ce:cf:
                    cd:32:da:f3:53:e2:46:57:93:99:6d:2e:8c:ca:53:
                    0c:db:e1:84:e5:b3:27:49:19:0d:07:ee:28:fe:49:
                    83:b3:cd:77:94:66:43:f3:24:89:0b:bd:b9:90:b4:
                    4a:dd:cc:f5:f7:fb:9c:88:3c:b9:5f:93:a4:9c:51:
                    d1:f1
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                B6:EE:DE:78:E6:51:A3:3E:43:05:A8:33:E2:CE:7D:F8:3B:9A:EF:E7
            X509v3 Authority Key Identifier: 
                keyid:9A:5E:FF:F2:CA:66:75:1C:07:3D:A5:00:1C:3D:D3:E0:18:F6:2E:44
                DirName:/CN=ovpn
                serial:03:72:23:5F:64:56:8A:7C:1A:1C:23:16:DC:35:BB:23:3E:05:91:4D

            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Key Usage: 
                Digital Signature
    Signature Algorithm: sha256WithRSAEncryption
         10:39:42:e1:b1:6d:2d:e1:da:4c:48:67:6a:e1:18:8f:a7:17:
         59:c3:6f:32:08:f9:ea:f6:1e:0b:00:a7:b2:3b:00:d5:4f:79:
         bd:78:a0:52:d4:8e:6b:3f:d6:ea:9e:e0:3e:63:74:57:df:9b:
         71:79:4b:27:52:44:f6:c2:2e:eb:dc:6f:c2:76:94:e9:64:f6:
         64:dd:11:d3:32:3d:94:bc:42:a7:b5:79:47:ff:5b:c6:b2:13:
         b0:fd:2d:1e:50:2e:51:fb:8a:ea:ba:30:61:b8:e8:c1:71:cb:
         69:b0:cc:ca:3d:14:7a:66:8d:6a:c4:1c:77:e7:a7:0c:74:03:
         48:ce:db:25:69:36:42:2c:ed:fb:49:95:b5:0c:07:c9:5d:ee:
         47:98:cd:55:0c:62:5a:8b:8f:ba:2c:0b:1f:cf:69:67:d6:7a:
         a2:b7:35:03:8e:95:67:ee:48:f7:d5:65:15:c1:19:99:e9:a1:
         63:92:fc:6c:ac:f2:23:a2:dd:67:d4:16:b5:13:92:a0:da:83:
         a8:9b:c3:34:8c:be:3c:b7:32:69:50:5c:88:27:c1:49:95:b5:
         bd:e5:1b:bc:11:52:e1:de:81:c5:5f:cc:7e:31:71:be:10:5d:
         cb:ef:30:4b:21:aa:f1:24:be:93:bf:9c:fb:e9:81:f3:2b:84:
         1e:92:9f:e0
-----BEGIN CERTIFICATE-----
MIIDRTCCAi2gAwIBAgIRAL9LpQDw4anrzZo0udjPYDUwDQYJKoZIhvcNAQELBQAw
DzENMAsGA1UEAwwEb3ZwbjAeFw0yMzAyMDgyMTUyNDBaFw0yNTA1MTMyMTUyNDBa
MA8xDTALBgNVBAMMBG92cG4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQC8IsvJZzk7pg3SE38eQAI9x5e7TucDLBuoe18SRpa83MYVA/pBWXthVbYEvmqo
dPAaGdaE/DXUKUQQL6MJYJDoXbxXpdkRJYD5wxOnWlO80Dn2/AiYDZzQ4KGVQlPY
juOanFfW3CMqCvU9DLOdLU9tHcu1HmGoEvgyQUX+XG3h2MvEBGsqVgIkSMDfZd4X
LDuMIko1mwywZY4lb4Euzw2sKBzMRFFyIPBCdeEv/rTR0jA2hovPPe5tq6HlrjkS
qh/Oz80y2vNT4kZXk5ltLozKUwzb4YTlsydJGQ0H7ij+SYOzzXeUZkPzJIkLvbmQ
tErdzPX3+5yIPLlfk6ScUdHxAgMBAAGjgZswgZgwCQYDVR0TBAIwADAdBgNVHQ4E
FgQUtu7eeOZRoz5DBagz4s59+Dua7+cwSgYDVR0jBEMwQYAUml7/8spmdRwHPaUA
HD3T4Bj2LkShE6QRMA8xDTALBgNVBAMMBG92cG6CFANyI19kVop8GhwjFtw1uyM+
BZFNMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAsGA1UdDwQEAwIHgDANBgkqhkiG9w0B
AQsFAAOCAQEAEDlC4bFtLeHaTEhnauEYj6cXWcNvMgj56vYeCwCnsjsA1U95vXig
UtSOaz/W6p7gPmN0V9+bcXlLJ1JE9sIu69xvwnaU6WT2ZN0R0zI9lLxCp7V5R/9b
xrITsP0tHlAuUfuK6rowYbjowXHLabDMyj0UemaNasQcd+enDHQDSM7bJWk2Qizt
+0mVtQwHyV3uR5jNVQxiWouPuiwLH89pZ9Z6orc1A46VZ+5I99VlFcEZmemhY5L8
bKzyI6LdZ9QWtROSoNqDqJvDNIy+PLcyaVBciCfBSZW1veUbvBFS4d6BxV/MfjFx
vhBdy+8wSyGq8SS+k7+c++mB8yuEHpKf4A==
-----END CERTIFICATE-----
	echo "</cert>"
	echo "<key>"
	-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC8IsvJZzk7pg3S
E38eQAI9x5e7TucDLBuoe18SRpa83MYVA/pBWXthVbYEvmqodPAaGdaE/DXUKUQQ
L6MJYJDoXbxXpdkRJYD5wxOnWlO80Dn2/AiYDZzQ4KGVQlPYjuOanFfW3CMqCvU9
DLOdLU9tHcu1HmGoEvgyQUX+XG3h2MvEBGsqVgIkSMDfZd4XLDuMIko1mwywZY4l
b4Euzw2sKBzMRFFyIPBCdeEv/rTR0jA2hovPPe5tq6HlrjkSqh/Oz80y2vNT4kZX
k5ltLozKUwzb4YTlsydJGQ0H7ij+SYOzzXeUZkPzJIkLvbmQtErdzPX3+5yIPLlf
k6ScUdHxAgMBAAECggEADoOgtSkBgViOOGbIp8zIX3vGeOzdZaFBgP4Dl6Vae7eM
kJJ9/AyrOBcks7j9AYIEA/96TUgn3vZQCe+i5FZO155jqV9iH7CFAr/KBF8zlp15
21QWVaS3NGYgESPM1Cgx5vuoyyqwi83MnakdMkMMnZ5u2Mo/Png4LahbfgQjdgjh
qFjYMFv7ksAEHX+6JhDYsNGdBd2cNtA3Ufrro0FqDxkT/0FB2SqQjU1g318DxnSv
odCQT9xXtoDjQ2u8T0Jr/vcouJ4zfA0ibrs0pKs+PVhQV+ujELfgJ2VpL3RJF9f/
6dXSqRqV53acjSzDqcoSxS/PjoBZ3p8sV+aydQ/EAQKBgQDySMTfxgmXcqkPzWgL
dYAqyWPl0ZB/t1EGAbtI8Yb9hb/MbSMv1E/CDtEHjKdHqZNkTv9yxigBa0GzDs+/
D9XDrHv/NZyOBL+qZqxoS/h8aHB7lie0fLPFM6XfAfr+HeyyxgC4XLy037mVEKIp
63+Ca+pTvsMJKkqveXR6yYmmBQKBgQDGyUx6uSaL+SNlC1Dg66WlvVx54rFU2ap/
7U/idVRZ2Hn64un8ogyjRZJPRV9eTEXHhk14m+NQgsnX8Aid6Pg+5jffA1/O6qXt
KbtGMworfeha+2XQmD23/nwPzV57RmIYIIwdPxfJTRz6RSrpPNCAYY1UiW2ewsDg
OWkrqIrz/QKBgQDCn6vuaeHok4W1GPacRd4YAMDLqyUdQv/GCHwOo14hp2Aj8gOS
90S+iTJmkxkJGvI4YLEY3I7kXOlg0eQWAb1guty8bK9+8deZJXMXMPfB0A+TZ1Ir
zQSHw+5Zjvi1SwqJrT6E2pIH5bPpR3xMmk1KUi/g59s6MIvgG3ty6xQ0lQKBgQCp
jWshRildvIv3FJbQsc4hNwnYoIX2xI3L/cNkegUPeThZyRAhPqse3Cl2WcqFaPMf
wyrzE6vosRWujHsdDWgoZj8DhiJDIBuU1UJ6FvC2tfbpG4L1T9VcycBRzi6nYRos
UB6Sl40XUyHDShnWxNtmlU5x66JHhv/ygKV26pRSlQKBgChdUMySzzohKqyBRjDk
HbXnCN4xCkLIx7L6bfOlL0NTVpK00lX2M7qRABZFiKZHQvWCoAyedjRp93g92AbZ
n4p+zX6UPrQwhsqRwj19SQM9aRhYao189vp2iOhbdS/ZXNMMNoFKYfmDUbYOPis6
NiRw3D85Vfp/2CwS9Y5p9K/D
-----END PRIVATE KEY-----
	echo "</key>"
	echo "<tls-crypt>"
	#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
f783bbffb7842aaef57c1804691e6682
aeebca61555db03aa398db5993c10254
32976641ef2ed5c5e3e97a49dca29440
f583f95034dd28ca1b0de2975493971a
c9eb447e58f737abc8ab1f575f3cc094
c06c55e0840d811b610014998145460c
cb76588cec6fbf5f53c616a5ab0a7265
8014d1d6f487e1b92e3cd621a318041d
8280558b0c6f203cc29e9d7050be040b
5a33347144fe840a73b895f967108895
69119137bc6d320ef50a1d472a245ea2
fc507f926fbacd932cbfc74c13136ddc
48a644cce0c0ad17670e2020e58ede30
7b8dbfcade3efbad75c2af3977a57de8
a031644718d76de9cc7f9a5169deed3f
63484a84cc4a62f513444a997f9f0242
-----END OpenVPN Static key V1-----

	echo "</tls-crypt>"
	} > ~/"$client".ovpn
}

if [[ ! -e /etc/openvpn/server/server.conf ]]; then
	# Detect some Debian minimal setups where neither wget nor curl are installed
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		echo "Wget is required to use this installer."
		read -n1 -r -p "Press any key to install Wget and continue..."
		apt-get update
		apt-get install -y wget
	fi
	clear
	echo 'Welcome to this OpenVPN road warrior installer!'
	# If system has a single IPv4, it is selected automatically. Else, ask the user
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
		echo
		echo "Which IPv4 address should be used?"
		ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
		read -p "IPv4 address [1]: " ip_number
		until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
			echo "$ip_number: invalid selection."
			read -p "IPv4 address [1]: " ip_number
		done
		[[ -z "$ip_number" ]] && ip_number="1"
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
	fi
	# If $ip is a private IP address, the server must be behind NAT
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "This server is behind NAT. What is the public IPv4 address or hostname?"
		# Get public IP and sanitize with grep
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
		# If the checkip service is unavailable and user didn't provide input, ask again
		until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
			echo "Invalid input."
			read -p "Public IPv4 address / hostname: " public_ip
		done
		[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
	fi
	# If system has a single IPv6, it is selected automatically
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
	fi
	# If system has multiple IPv6, ask the user to select one
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
		number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
		echo
		echo "Which IPv6 address should be used?"
		ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
		read -p "IPv6 address [1]: " ip6_number
		until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
			echo "$ip6_number: invalid selection."
			read -p "IPv6 address [1]: " ip6_number
		done
		[[ -z "$ip6_number" ]] && ip6_number="1"
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
	fi
	echo
	echo "Which protocol should OpenVPN use?"
	echo "   1) UDP (recommended)"
	echo "   2) TCP"
	read -p "Protocol [1]: " protocol
	until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
		echo "$protocol: invalid selection."
		read -p "Protocol [1]: " protocol
	done
	case "$protocol" in
		1|"") 
		protocol=udp
		;;
		2) 
		protocol=tcp
		;;
	esac
	echo
	echo "What port should OpenVPN listen to?"
	read -p "Port [1194]: " port
	until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
		echo "$port: invalid port."
		read -p "Port [1194]: " port
	done
	[[ -z "$port" ]] && port="1194"
	echo
	echo "Select a DNS server for the clients:"
	echo "   1) Current system resolvers"
	echo "   2) Google"
	echo "   3) 1.1.1.1"
	echo "   4) OpenDNS"
	echo "   5) Quad9"
	echo "   6) AdGuard"
	read -p "DNS server [1]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
		echo "$dns: invalid selection."
		read -p "DNS server [1]: " dns
	done
	echo
	echo "Enter a name for the first client:"
	read -p "Name [client]: " unsanitized_client
	# Allow a limited set of characters to avoid conflicts
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	[[ -z "$client" ]] && client="client"
	echo
	echo "OpenVPN installation is ready to begin."
	# Install a firewall if firewalld or iptables are not already available
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
			# We don't want to silently enable firewalld, so we give a subtle warning
			# If the user continues, firewalld will be installed and enabled during setup
			echo "firewalld, which is required to manage routing tables, will also be installed."
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			# iptables is way less invasive than firewalld so no warning is given
			firewall="iptables"
		fi
	fi
	read -n1 -r -p "Press any key to continue..."
	# If running inside a container, disable LimitNPROC to prevent conflicts
	if systemd-detect-virt -cq; then
		mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
		echo "[Service]
LimitNPROC=infinity" > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	fi
	if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
		apt-get update
		apt-get install -y --no-install-recommends openvpn openssl ca-certificates $firewall
	elif [[ "$os" = "centos" ]]; then
		yum install -y epel-release
		yum install -y openvpn openssl ca-certificates tar $firewall
	else
		# Else, OS must be Fedora
		dnf install -y openvpn openssl ca-certificates tar $firewall
	fi
	# If firewalld was just installed, enable it
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi
	# Get easy-rsa
	easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.2/EasyRSA-3.1.2.tgz'
	mkdir -p /etc/openvpn/server/easy-rsa/
	{ wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1
	chown -R root:root /etc/openvpn/server/easy-rsa/
	cd /etc/openvpn/server/easy-rsa/
	# Create the PKI, set up the CA and the server and client certificates
	./easyrsa --batch init-pki
	./easyrsa --batch build-ca nopass
	./easyrsa --batch --days=3650 build-server-full server nopass
	./easyrsa --batch --days=3650 build-client-full "$client" nopass
	./easyrsa --batch --days=3650 gen-crl
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
	# CRL is read with each client connection, while OpenVPN is dropped to nobody
	chown nobody:"$group_name" /etc/openvpn/server/crl.pem
	# Without +x in the directory, OpenVPN can't run a stat() on the CRL file
	chmod o+x /etc/openvpn/server/
	# Generate key for tls-crypt
	openvpn --genkey --secret /etc/openvpn/server/tc.key
	# Create the DH parameters file using the predefined ffdhe2048 group
	echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
	# Generate server.conf
	echo "local $ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server 10.8.0.0 255.255.255.0" > /etc/openvpn/server/server.conf
	# IPv6
	if [[ -z "$ip6" ]]; then
		echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	else
		echo 'server-ipv6 fddd:1194:1194:1194::/64' >> /etc/openvpn/server/server.conf
		echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	fi
	echo 'ifconfig-pool-persist ipp.txt' >> /etc/openvpn/server/server.conf
	# DNS
	case "$dns" in
		1|"")
			# Locate the proper resolv.conf
			# Needed for systems running systemd-resolved
			if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
				resolv_conf="/etc/resolv.conf"
			else
				resolv_conf="/run/systemd/resolve/resolv.conf"
			fi
			# Obtain the resolvers from resolv.conf and use them for OpenVPN
			grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
				echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
			done
		;;
		2)
			echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
		;;
		3)
			echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf
		;;
		4)
			echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf
		;;
		5)
			echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server/server.conf
		;;
		6)
			echo 'push "dhcp-option DNS 94.140.14.14"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 94.140.15.15"' >> /etc/openvpn/server/server.conf
		;;
	esac
	echo 'push "block-outside-dns"' >> /etc/openvpn/server/server.conf
	echo "keepalive 10 120
cipher AES-256-CBC
user nobody
group $group_name
persist-key
persist-tun
verb 3
duplicate-cn
management $ip 17562
crl-verify crl.pem" >> /etc/openvpn/server/server.conf
	if [[ "$protocol" = "udp" ]]; then
		echo "explicit-exit-notify" >> /etc/openvpn/server/server.conf
	fi
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
	# Enable without waiting for a reboot or service restart
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-openvpn-forward.conf
		# Enable without waiting for a reboot or service restart
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
	if systemctl is-active --quiet firewalld.service; then
		# Using both permanent and not permanent rules to avoid a firewalld
		# reload.
		# We don't use --add-service=openvpn because that would only work with
		# the default port and protocol.
		firewall-cmd --add-port="$port"/"$protocol"
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --add-port="$port"/"$protocol"
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
		fi
	else
		# Create a service to set up persistent iptables rules
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		# nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
		# if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/openvpn-iptables.service
		if [[ -n "$ip6" ]]; then
			echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/openvpn-iptables.service
		fi
		echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service
		systemctl enable --now openvpn-iptables.service
	fi
	# If SELinux is enabled and a custom port was selected, we need this
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		# Install semanage if not already present
		if ! hash semanage 2>/dev/null; then
			if [[ "$os_version" -eq 7 ]]; then
				# Centos 7
				yum install -y policycoreutils-python
			else
				# CentOS 8 or Fedora
				dnf install -y policycoreutils-python-utils
			fi
		fi
		semanage port -a -t openvpn_port_t -p "$protocol" "$port"
	fi
	# If the server is behind NAT, use the correct IP address
	[[ -n "$public_ip" ]] && ip="$public_ip"
	# client-common.txt is created so we have a template to add further users later
	echo "client
dev tun
proto $protocol
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
ignore-unknown-option block-outside-dns
verb 3" > /etc/openvpn/server/client-common.txt
	# Enable and start the OpenVPN service
	systemctl enable --now openvpn-server@server.service
	# Generates the custom client.ovpn
	new_client
	echo
	echo "Finished!"
	echo
	echo "The client configuration is available in:" ~/"$client.ovpn"
	echo "New clients can be added by running this script again."
else
	clear
	echo "OpenVPN is already installed."
	echo
	echo "Select an option:"
	echo "   1) Add a new client"
	echo "   2) Revoke an existing client"
	echo "   3) Remove OpenVPN"
	echo "   4) Exit"
	read -p "Option: " option
	until [[ "$option" =~ ^[1-4]$ ]]; do
		echo "$option: invalid selection."
		read -p "Option: " option
	done
	case "$option" in
		1)
			echo
			echo "Provide a name for the client:"
			read -p "Name: " unsanitized_client
			client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
				echo "$client: invalid name."
				read -p "Name: " unsanitized_client
				client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			done
			cd /etc/openvpn/server/easy-rsa/
			./easyrsa --batch --days=3650 build-client-full "$client" nopass
			# Generates the custom client.ovpn
			new_client
			echo
			echo "$client added. Configuration available in:" ~/"$client.ovpn"
			exit
		;;
		2)
			# This option could be documented a bit better and maybe even be simplified
			# ...but what can I say, I want some sleep too
			number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "There are no existing clients!"
				exit
			fi
			echo
			echo "Select the client to revoke:"
			tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			read -p "Client: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: invalid selection."
				read -p "Client: " client_number
			done
			client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
			echo
			read -p "Confirm $client revocation? [y/N]: " revoke
			until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
				echo "$revoke: invalid selection."
				read -p "Confirm $client revocation? [y/N]: " revoke
			done
			if [[ "$revoke" =~ ^[yY]$ ]]; then
				cd /etc/openvpn/server/easy-rsa/
				./easyrsa --batch revoke "$client"
				./easyrsa --batch --days=3650 gen-crl
				rm -f /etc/openvpn/server/crl.pem
				cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
				# CRL is read with each client connection, when OpenVPN is dropped to nobody
				chown nobody:"$group_name" /etc/openvpn/server/crl.pem
				echo
				echo "$client revoked!"
			else
				echo
				echo "$client revocation aborted!"
			fi
			exit
		;;
		3)
			echo
			read -p "Confirm OpenVPN removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -p "Confirm OpenVPN removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				if systemctl is-active --quiet firewalld.service; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24' | grep -oE '[^ ]+$')
					# Using both permanent and not permanent rules to avoid a firewalld reload.
					firewall-cmd --remove-port="$port"/"$protocol"
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --remove-port="$port"/"$protocol"
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					if grep -qs "server-ipv6" /etc/openvpn/server/server.conf; then
						ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 '"'"'!'"'"' -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
						firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
						firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
					fi
				else
					systemctl disable --now openvpn-iptables.service
					rm -f /etc/systemd/system/openvpn-iptables.service
				fi
				if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
					semanage port -d -t openvpn_port_t -p "$protocol" "$port"
				fi
				systemctl disable --now openvpn-server@server.service
				rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
				rm -f /etc/sysctl.d/99-openvpn-forward.conf
				if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
					rm -rf /etc/openvpn/server
					apt-get remove --purge -y openvpn
				else
					# Else, OS must be CentOS or Fedora
					yum remove -y openvpn
					rm -rf /etc/openvpn/server
				fi
				echo
				echo "OpenVPN removed!"
			else
				echo
				echo "OpenVPN removal aborted!"
			fi
			exit
		;;
		4)
			exit
		;;
	esac
fi
