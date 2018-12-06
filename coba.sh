#!/bin/bash
#
# 
# 
# ==================================================
# 

# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- ipv4.icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";

# go to root
cd

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# install wget and curl
apt-get update;apt-get -y install wget curl;

# set time GMT +7
#ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
ln -fs /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart

# set repo
#wget -O /etc/apt/sources.list "https://raw.githubusercontent.com/rizal180499/Auto-Installer-VPS/master/conf/sources.list.debian7"
#wget "http://www.dotdeb.org/dotdeb.gpg"
#cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
#wget -O /etc/apt/sources.list "https://raw.githubusercontent.com/ForNesiaFreak/FNS_Debian7/fornesia.com/null/sources.list.debian7"
#wget "http://www.dotdeb.org/dotdeb.gpg"
#wget "http://www.webmin.com/jcameron-key.asc"
#cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
cat jcameron-key.asc | apt-key add -;rm jcameron-key.asc

# set repo
cat > /etc/apt/sources.list <<END2
deb http://security.debian.org/ jessie/updates main contrib non-free
deb-src http://security.debian.org/ jessie/updates main contrib non-free
deb http://http.us.debian.org/debian jessie main contrib non-free
deb http://packages.dotdeb.org jessie all
deb-src http://packages.dotdeb.org jessie all
END2
wget "http://www.dotdeb.org/dotdeb.gpg"
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg

# remove unused
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove bind9*;

# update
apt-get update; apt-get -y upgrade;

# install webserver
#apt-get -y install nginx

# install essential package
apt-get -y install bmon iftop htop nmap axel nano iptables traceroute sysv-rc-conf dnsutils bc nethogs openvpn vnstat less screen psmisc apt-file whois ptunnel ngrep mtr git zsh mrtg snmp snmpd snmp-mibs-downloader unzip unrar rsyslog debsums rkhunter
apt-get -y install build-essential

# disable exim
service exim4 stop
sysv-rc-conf exim4 off

# update apt-file
apt-file update

# setting vnstat
vnstat -u -i venet0
service vnstat restart

# install screenfetch
cd

#touch screenfetch-dev
cd
wget 'https://raw.githubusercontent.com/ForNesiaFreak/FNS_Debian7/fornesia.com/null/screenfetch-dev'
mv screenfetch-dev /usr/bin/screenfetch-dev
chmod +x /usr/bin/screenfetch-dev
echo "clear" >> .profile
echo "screenfetch-dev" >> .profile

# install webserver
#cd
#rm /etc/nginx/sites-enabled/default
#rm /etc/nginx/sites-available/default
#wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/rizal180499/Auto-Installer-VPS/master/conf/nginx.conf"
#mkdir -p /home/vps/public_html
#echo "<pre>Setup by Yonatan Kanu | 085707136028</pre>" > /home/vps/public_html/index.html
#wget -O /etc/nginx/conf.d/vps.conf "https://raw.githubusercontent.com/nifira123/debian7_32bit/master/vps.conf"
#service nginx restart

# install openvpn
#wget -O /etc/openvpn/openvpn.tar "https://raw.github.com/arieonline/autoscript/master/conf/openvpn-debian.tar"
#cd /etc/openvpn/
#tar xf openvpn.tar
#wget -O /etc/openvpn/1194.conf "https://raw.githubusercontent.com/rizal180499/Auto-Installer-VPS/master/conf/1194.conf"
#service openvpn restart
#sysctl -w net.ipv4.ip_forward=1
#sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
#iptables -t nat -I POSTROUTING -s 192.168.100.0/24 -o eth0 -j MASQUERADE
#iptables-save > /etc/iptables_yg_baru_dibikin.conf
#wget -O /etc/network/if-up.d/iptables "https://raw.githubusercontent.com/nifira123/debian7_32bit/master/iptables"
#chmod +x /etc/network/if-up.d/iptables
#service openvpn restart

#konfigurasi openvpn
#cd /etc/openvpn/
#wget -O /etc/openvpn/client.ovpn "https://raw.githubusercontent.com/nifira123/debian7_32bit/master/client-1194.conf"
#sed -i $MYIP2 /etc/openvpn/client.ovpn;
#cp client.ovpn /home/vps/public_html/

cd
# install badvpn
wget -O /usr/bin/badvpn-udpgw "https://github.com/ForNesiaFreak/FNS/raw/master/sett/badvpn-udpgw"
if [ "$OS" == "x86_64" ]; then
  wget -O /usr/bin/badvpn-udpgw "https://github.com/ForNesiaFreak/FNS/raw/master/sett/badvpn-udpgw64"
fi
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300

# install mrtg
#wget -O /etc/snmp/snmpd.conf "https://raw.githubusercontent.com/rizal180499/Auto-Installer-VPS/master/conf/snmpd.conf"
#wget -O /root/mrtg-mem.sh "https://raw.githubusercontent.com/rizal180499/Auto-Installer-VPS/master/conf/mrtg-mem.sh"
#chmod +x /root/mrtg-mem.sh
#cd /etc/snmp/
#sed -i 's/TRAPDRUN=no/TRAPDRUN=yes/g' /etc/default/snmpd
#service snmpd restart
#snmpwalk -v 1 -c public localhost 1.3.6.1.4.1.2021.10.1.3.1
#mkdir -p /home/vps/public_html/mrtg
#cfgmaker --zero-speed 100000000 --global 'WorkDir: /home/vps/public_html/mrtg' --output /etc/mrtg.cfg public@localhost
#curl "https://raw.githubusercontent.com/rizal180499/Auto-Installer-VPS/master/conf/mrtg.conf" >> /etc/mrtg.cfg
#sed -i 's/WorkDir: \/var\/www\/mrtg/# WorkDir: \/var\/www\/mrtg/g' /etc/mrtg.cfg
#sed -i 's/# Options\[_\]: growright, bits/Options\[_\]: growright/g' /etc/mrtg.cfg
#indexmaker --output=/home/vps/public_html/mrtg/index.html /etc/mrtg.cfg
#if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
#if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
#if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
cd

# setting port ssh
#sed -i '/Port 22/a Port 2147' /etc/ssh/sshd_config
#sed -i '/Port 22/a Port 143' /etc/ssh/sshd_config
sed -i 's/Port 22/Port  22/g' /etc/ssh/sshd_config
service ssh restart

# install dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=442/g' /etc/default/dropbear
#sed -i 's/OPTIONS="-p 443 -K 3"/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 442 -p 444 -p 90 -p 993 -p 995 -p 777 -p 143 -p 109 -p 110 -p 192 -p 427 -p 625 -p 1220 -K 3"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
sed -i 's/DROPBEAR_BANNER=""/DROPBEAR_BANNER="bannerssh"/g' /etc/default/dropbear
service ssh restart
service dropbear restart

# upgrade dropbear 2014
apt-get install zlib1g-dev
#wget https://github.com/ForNesiaFreak/FNS/raw/master/go/dropbear-2014.63.tar.bz2
#bzip2 -cd dropbear-2014.63.tar.bz2  | tar xvf -
#cd dropbear-2014.63
wget https://matt.ucc.asn.au/dropbear/releases/dropbear-2018.76.tar.bz2
bzip2 -cd dropbear-2018.76.tar.bz2  | tar xvf -
cd dropbear-2018.76
./configure
make && make install
mv /usr/sbin/dropbear /usr/sbin/dropbear1
ln /usr/local/sbin/dropbear /usr/sbin/dropbear
service dropbear restart

# install vnstat gui
#cd /home/vps/public_html/
#wget https://github.com/ForNesiaFreak/FNS/raw/master/go/vnstat_php_frontend-1.5.1.tar.gz
#tar xf vnstat_php_frontend-1.5.1.tar.gz
#rm vnstat_php_frontend-1.5.1.tar.gz
#mv vnstat_php_frontend-1.5.1 vnstat
#cd vnstat
#sed -i 's/eth0/venet0/g' config.php
#sed -i "s/\$iface_list = array('venet0', 'sixxs');/\$iface_list = array('venet0');/g" config.php
#sed -i "s/\$language = 'nl';/\$language = 'en';/g" config.php
#sed -i 's/Internal/Internet/g' config.php
#sed -i '/SixXS IPv6/d' config.php
cd

# install fail2ban
#apt-get -y install fail2ban;service fail2ban restart
#cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
#service fail2ban restart

# Instal DDOS Flate
if [ -d '/usr/local/ddos' ]; then
	echo; echo; echo "Please un-install the previous version first"
	exit 0
else
	mkdir /usr/local/ddos
fi
clear
echo; echo 'Installing DOS-Deflate 0.6'; echo
echo; echo -n 'Downloading source files...'
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
echo -n '.'
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
echo -n '.'
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
echo -n '.'
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
echo '...done'
echo; echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
echo '.....done'
echo; echo 'Installation has completed.'
echo 'Config file is at /usr/local/ddos/ddos.conf'
echo 'Please send in your comments and/or suggestions to zaf@vsnl.com'

# install squid3
apt-get -y install squid3
cat > /etc/squid3/squid.conf <<-END
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
acl SSH dst xxxxxxxxx-xxxxxxxxx/32
http_access allow SSH
http_access allow manager localhost
http_access deny manager
http_access allow localhost
http_access deny all
http_port 8080
http_port 3130
http_port 3000
http_port 1080
http_port 8000
http_port 8888
http_port 3128
coredump_dir /var/spool/squid3
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname boostvpn
END
sed -i $MYIP2 /etc/squid3/squid.conf;
service squid3 restart

#update repository
apt-get install stunnel4 -y
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
[dropbear]
connect = 127.0.0.1:995
accept = 443
[dropbear]
connect = 127.0.0.1:993
accept = 445
END

#membuat sertifikat
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
service stunnel4 restart

# bannerssh
wget https://raw.githubusercontent.com/nexne/32n64/master/bannerssh
mv ./bannerssh /bannerssh
chmod 0644 /bannerssh
service dropbear restart
service ssh restart
# install webmin
#cd
#wget -O webmin-current.deb "http://www.webmin.com/download/deb/webmin-current.deb"
#dpkg -i --force-all webmin-current.deb;
#apt-get -y -f install;
#rm /root/webmin-current.deb
#service webmin restart

# download script
cd /usr/bin
wget -O menu "https://raw.githubusercontent.com/nexne/32n64/master/menu.sh"
wget -O usernew "https://raw.githubusercontent.com/nexne/32n64/master/usernew.sh"
wget -O trial "https://raw.githubusercontent.com/nexne/32n64/master/trial.sh"
wget -O hapus "https://raw.githubusercontent.com/nexne/32n64/master/hapus.sh"
wget -O login "https://raw.githubusercontent.com/nexne/32n64/master/user-login.sh"
wget -O dropmon "https://raw.githubusercontent.com/nexne/32n64/master/dropmon.sh"
#wget -O user-expired.sh "https://raw.githubusercontent.com/ForNesiaFreak/FNS_Debian7/fornesia.com/freak/user-expired.sh"
#wget -O userlimit.sh "https://raw.githubusercontent.com/suryadewa/fornesiavps/fns/limit.sh"
wget -O member "https://raw.githubusercontent.com/nexne/32n64/master/user-list.sh"
wget -O restart "https://raw.githubusercontent.com/nexne/32n64/master/resvis.sh"
wget -O speedtest "https://raw.githubusercontent.com/ForNesiaFreak/FNS_Debian7/fornesia.com/null/speedtest_cli.py"
wget -O bench-network "https://raw.githubusercontent.com/ForNesiaFreak/FNS_Debian7/fornesia.com/null/bench-network.sh"
wget -O ps-mem "https://raw.githubusercontent.com/ForNesiaFreak/FNS_Debian7/fornesia.com/null/ps_mem.py"
wget -O about "https://raw.githubusercontent.com/nexne/32n64/master/about.sh"
wget -O delete "https://raw.githubusercontent.com/nexne/32n64/master/delete.sh"
wget -O renew "https://raw.githubusercontent.com/nexne/32n64/master/renew.sh"
wget -O kill "https://raw.githubusercontent.com/nexne/32n64/master/kill.sh"
wget -O ban "https://raw.githubusercontent.com/nexne/32n64/master/ban.sh"
wget -O unban "https://raw.githubusercontent.com/nexne/32n64/master/unban.sh"
wget -O log "https://raw.githubusercontent.com/nexne/32n64/master/log.sh"
wget -O rasakan "https://raw.githubusercontent.com/nexne/32n64/master/rasakan.sh"
wget -O log1 "https://raw.githubusercontent.com/nexne/32n64/master/log1.sh"
echo "0 0 * * * root /root/user-expired.sh" > /etc/cron.d/user-expired
#echo "0 0 * * * root /usr/bin/expired" > /etc/cron.d/expired
echo "0 0 * * * root /usr/bin/reboot" > /etc/cron.d/reboot
echo "#* * * * * service dropbear restart" > /etc/cron.d/dropbear
chmod +x menu
chmod +x usernew
chmod +x trial
chmod +x hapus
chmod +x login
chmod +x dropmon
#chmod +x user-expired
#chmod +x userlimit.sh
chmod +x member
chmod +x restart
chmod +x speedtest
chmod +x bench-network
chmod +x ps-mem
chmod +x about
chmod +x delete
chmod +x renew
#chmod +x user-expired.sh
chmod +x kill
chmod +x ban
chmod +x unban
chmod +x log
chmod +x rasakan
chmod +x log1
cd
echo "0 */12 * * * root /usr/bin/delete" >> /etc/crontab
echo "#* * * * * root service dropbear restart" >> /etc/crontab
echo "#0 */6 * * * root /usr/bin/restart" >> /etc/crontab
#echo "#*/10 * * * * root service squid3 restart" >> /etc/crontab
echo "#* * * * * root /usr/bin/kill" >> /etc/crontab
#echo "#* * * * * root sleep 10; /usr/bin/kill" >> /etc/crontab
echo "#0 */6 * * * root /usr/bin/ban" >> /etc/crontab
echo "#* * * * * root /usr/bin/rasakan 2" >> /etc/crontab
echo "0 3 * * * root /sbin/reboot" > /etc/cron.d/reboot
service cron restart

#Blockir Torrent
iptables -A OUTPUT -p tcp --dport 6881:6889 -j DROP
iptables -A OUTPUT -p udp --dport 1024:65534 -j DROP
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
#BrutoFurse
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -m recent --update --seconds 600 --hitcount 3 --rttl --name SSH -j LOG --log-prefix "SSH_Brute_Force"
iptables -A INPUT -p tcp --dport 22 -m recent --update --seconds 600 --hitcount 3 --rttl --name SSH -j DROP

# finishing
cd
#chown -R www-data:www-data /home/vps/public_html
#service nginx start
#service php-fpm start
#service vnstat restart
#service openvpn restart
#service snmpd restart
service cron restart
service ssh restart
service dropbear restart
#service fail2ban restart
service squid3 restart
#service webmin restart
rm -rf ~/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile

# info
clear
echo "Autoscript Include:" | tee log-install.txt
echo "===========================================" | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Service"  | tee -a log-install.txt
echo "-------"  | tee -a log-install.txt
echo "OpenSSH  : 22, 143"  | tee -a log-install.txt
echo "Dropbear : 443, 80"  | tee -a log-install.txt
echo "Squid3   : 8080, 3128 (limit to IP SSH)"  | tee -a log-install.txt
#echo "OpenVPN  : TCP 1194 (client config : http://$MYIP:81/client.ovpn)"  | tee -a log-install.txt
echo "badvpn   : badvpn-udpgw port 7300"  | tee -a log-install.txt
echo "nginx    : 81"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Script"  | tee -a log-install.txt
echo "------"  | tee -a log-install.txt
echo "menu (Menampilkan daftar perintah yang tersedia)"  | tee -a log-install.txt
echo "usernew (Membuat Akun SSH)"  | tee -a log-install.txt
echo "trial (Membuat Akun Trial)"  | tee -a log-install.txt
echo "hapus (Menghapus Akun SSH)"  | tee -a log-install.txt
echo "login (Cek User Login)"  | tee -a log-install.txt
echo "dropmon (Cek Dropbear Login)"  | tee -a log-install.txt
echo "user-expired (Auto Lock User Expire tiap jam 00:00)"  | tee -a log-install.txt
echo "member (Cek Member SSH)"  | tee -a log-install.txt
echo "restart (Restart Service dropbear, webmin, squid3, openvpn dan ssh)"  | tee -a log-install.txt
echo "reboot (Reboot VPS)"  | tee -a log-install.txt
echo "speedtest (Speedtest VPS)"  | tee -a log-install.txt
echo "bench-network (Cek Kualitas VPS)"  | tee -a log-install.txt
echo "ps-mem (Cek RAM)"  | tee -a log-install.txt
echo "about (Informasi tentang script auto install)"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Account Default (utk SSH dan VPN)"  | tee -a log-install.txt
echo "---------------"  | tee -a log-install.txt
echo "User     : thornssh"  | tee -a log-install.txt
echo "Password : yonatankanu"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Fitur lain"  | tee -a log-install.txt
echo "----------"  | tee -a log-install.txt
echo "Webmin   : http://$MYIP:10000/"  | tee -a log-install.txt
echo "vnstat   : http://$MYIP/vnstat/"  | tee -a log-install.txt
echo "MRTG     : http://$MYIP/mrtg/"  | tee -a log-install.txt
echo "Timezone : Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo "Fail2Ban : [on]"  | tee -a log-install.txt
echo "IPv6     : [off]"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "http://"  | tee -a log-install.txt
echo "Modified"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Log Instalasi --> /root/log-install.txt"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "VPS AUTO REBOOT TIAP 12 JAM"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "==========================================="  | tee -a log-install.txt
cd
rm -f /root/coba.sh
