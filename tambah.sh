#!/bin/sh
# Created by https://www.hostingtermurah.net
# Modified by 0123456

# go to root
cd

# disable ipv6
#echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
#sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

#Add DNS Server ipv4
#echo "nameserver 8.8.8.8" > /etc/resolv.conf
#echo "nameserver 8.8.4.4" >> /etc/resolv.conf
#sed -i '$ i\echo "nameserver 8.8.8.8" > /etc/resolv.conf' /etc/rc.local
#sed -i '$ i\echo "nameserver 8.8.4.4" >> /etc/resolv.conf' /etc/rc.local

# install wget and curl
#apt-get update;apt-get -y install wget curl;

# set time GMT +8
ln -fs /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime

cd
wget -O /usr/bin/screenfetch "https://raw.githubusercontent.com/nexne/centos/master/screenfetch"
chmod +x /usr/bin/screenfetch
echo "clear" >> .profile
echo "screenfetch" >> .profile

cd

# setting banner
rm /etc/issue.net
wget -O /etc/issue.net "https://raw.githubusercontent.com/nexne/centos/master/issue.net"
sed -i 's@#Banner@Banner@g' /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear
service ssh restart
service dropbear restart

# download script
cd
wget https://raw.githubusercontent.com/nexne/centos/master/install-premiumscript.sh -O - -o /dev/null|sh

# Download script
cd /usr/bin
#wget -O restart "https://raw.githubusercontent.com/nexne/32n64/master/resvis.sh"
#wget -O usernew "https://raw.githubusercontent.com/nexne/32n64/master/usernew.sh"
#wget -O trial "https://raw.githubusercontent.com/nexne/32n64/master/trial.sh"
#wget -O hapus "https://raw.githubusercontent.com/nexne/32n64/master/hapus.sh"
#wget -O login "https://raw.githubusercontent.com/nexne/32n64/master/user-login.sh"
#wget -O member "https://raw.githubusercontent.com/nexne/32n64/master/user-list.sh"
#wget -O speedtest "https://raw.githubusercontent.com/ForNesiaFreak/FNS_Debian7/fornesia.com/null/speedtest_cli.py"
#wget -O bench-network "https://raw.githubusercontent.com/ForNesiaFreak/FNS_Debian7/fornesia.com/null/bench-network.sh"
#wget -O ps-mem "https://raw.githubusercontent.com/ForNesiaFreak/FNS_Debian7/fornesia.com/null/ps_mem.py"
#wget -O about "https://raw.githubusercontent.com/nexne/32n64/master/about.sh"
wget -O delete "https://raw.githubusercontent.com/nexne/32n64/master/delete.sh"
#wget -O renew "https://raw.githubusercontent.com/nexne/32n64/master/renew.sh"
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
#chmod +x menu
#chmod +x usernew
#chmod +x trial
chmod +x hapus
#chmod +x login
#chmod +x user-expired
#chmod +x userlimit.sh
#chmod +x member
#chmod +x restart
#chmod +x speedtest
#chmod +x bench-network
#chmod +x ps-mem
#chmod +x about
chmod +x delete
#chmod +x renew
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
#echo "0 3 * * * root /sbin/reboot" > /etc/cron.d/reboot
echo "0 */12 * * * root /sbin/reboot" > /etc/cron.d/reboot
service cron restart


#clearing history
history -c

