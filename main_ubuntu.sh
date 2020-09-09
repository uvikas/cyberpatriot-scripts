echo " "
echo "------------------------------------------------------"
echo "Prelim Checks"
echo "------------------------------------------------------"
echo " "


if [ "$(id -u)" != "0" ]; then

echo "Please logon to root"

exit

fi

# FORENSICS

echo "Forensics completed? (Y/N)"

read contyn

if [ "$contyn" = "N" ] || [ "$contyn" = "n" ];

then

	echo "The script has been terminated"

	exit

fi

echo " "
echo "------------------------------------------------------"
echo "Check Host Files"
echo "------------------------------------------------------"
echo " "

echo "Printing /etc/hosts file. Please make sure it is correct."
echo " "
cat /etc/hosts
echo " "
echo "Edit Hosts? [Y/N]"
read hosts_case;
if [[ $hosts_case =~ ^[Yy]$ ]]; then
	nano /etc/hosts
fi
echo ""
echo "Printing /etc/resolv.conf file. Please make sure it is correct."
echo " "
cat /etc/resolv.conf
echo " "
echo "Edit Resolv? [Y/N]"
read resolv_case;
if [[ $hosts_case =~ ^[Yy]$ ]]; then
	nano /etc/resolv.conf
fi

echo " "
echo "------------------------------------------------------"
echo "User Accounts"
echo "------------------------------------------------------"
echo " "

# USER ACCOUNTS

apt-get -V -y install members

members sudo > admin.txt
members users > users.txt
touch realadmin.txt
touch realusers.txt

getent passwd | awk -F: '$3 > 1000 {print $1}'


echo "Admins:"

members sudo

echo "Members:"

members users

python3 script.py

# ADD USERS

echo "Type user account names of users you want to ADD"

read -a addstuff

usersAdd=${#addstuff[@]}

for ((i=0;i<$usersAdd;i++))

do

echo "Creating ${addstuff[${i}]}"

useradd ${addstuff[${i}]}

done

# DELETE USERS

echo "Type user account names of users you want to DELETE"

read -a deletestuff

usersDel=${#deletestuff[@]}

for ((i=0;i<$usersDel;i++))

do

echo "Deleting ${deletestuff[${i}]}"

userdel ${deletestuff[${i}]}

done



# REMOVE ADMIN rights

echo "Type user account names of users you want to REMOVE ADMIN"

read -a remAdmin



usersnoAdmin=${#remAdmin[@]}



for ((i=0;i<$usersnoAdmin;i++))

do

echo "Removing admin rights for ${remAdmin[${i}]}"

userdel ${remAdmin[${i}]} sudo

done



# Add ADMIN rights

echo "Type user account names of users you want to ADD ADMIN"

read -a addAdmin



usersAdmin=${#addAdmin[@]}



for ((i=0;i<$usersAdmin;i++))

do

echo "Removing admin rights for ${addAdmin[${i}]}"

usermod -aG sudo ${addAdmin[${i}]}

done



echo " "
echo "------------------------------------------------------"
echo "Changing Passwords"
echo "------------------------------------------------------"
echo " "

echo "Type user account names of users you want to change the password to"

read -a changePass

passwords=${#changePass[@]}

for ((i=0;i<$passwords;i++))

do

echo "Changing password for ${changePass[${i}]}"

echo -e "Cyb3rP@triot!\nCyb3rP@triot!" | passwd ${changePass[${i}]}

done


echo " "
echo "------------------------------------------------------"
echo "Disabling Guest User"
echo "------------------------------------------------------"
echo " "

echo "Editing /etc/lightdm/lightdm.conf"
echo "allow-guest=false" >> /etc/lightdm/lightdm.conf


echo " "
echo "------------------------------------------------------"
echo "Password Security Policies"
echo "------------------------------------------------------"
echo " "

echo "Editing /etc/login.defs"
echo " "
echo "PASS_MAX_DAYS set to 90"
sudo sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS   90' /etc/login.defs
echo "PASS_MIN_DAYS set to 10"
sudo sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS   10'  /etc/login.defs
echo "PASS_WARN_AGE set to 7"
sudo sed -i '/^PASS_WARN_AGE/ c\PASS_WARN_AGE   7' /etc/login.defs

echo " "


sudo apt-get -y install libpam-cracklib

echo " "

echo "libpam-cracklib installed"

echo "Editing /etc/pam.d/common-password"
echo "Add minlen=8 remember=5 to the end of line that has pam_unix.so"
echo "Add ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 to the end of pam_cracklib.so"
nano /etc/pam.d/common-password
echo " "
echo "Editing /etc/pam.d/common-auth"
echo "Add deny=5 unlock_time=1800 onerr=fail audit even_deny_root_account silent to end of line with pam_tally.so"
nano /etc/pam.d/common-auth
echo " "

echo " "
echo "------------------------------------------------------"
echo "Denying Root Login"
echo "------------------------------------------------------"
echo " "

echo "PermitRootLogin set to no"
sudo sed -i '/^PermitRootLogin/ c\PermitRootLogin no' /etc/ssh/sshd_config

echo " "
echo "------------------------------------------------------"
echo "Configuring Cron to allow Root"
echo "------------------------------------------------------"
echo " "

echo "Reseting crontab"
crontab -r
cd /etc/
/bin/rm -f cron.deny at.deny
echo root >cron.allow
echo root >at.allow
/bin/chown root:root cron.allow at.allow
/bin/chmod 644 cron.allow at.allow

echo " "
echo "------------------------------------------------------"
echo "File Inspection"
echo "------------------------------------------------------"
echo " "

echo "Emptying /etc/rc.local"
echo 'exit 0' > /etc/rc.local

echo " "
echo "------------------------------------------------------"
echo "Removing Prohibited Media Files"
echo "------------------------------------------------------"
echo " "

find / -name '*.mp3' -type f -delete

find / -name '*.mov' -type f -delete

find / -name '*.mp4' -type f -delete

find / -name '*.avi' -type f -delete

find / -name '*.mpg' -type f -delete

find / -name '*.mpeg' -type f -delete

find / -name '*.flac' -type f -delete

find / -name '*.m4a' -type f -delete

find / -name '*.flv' -type f -delete

find / -name '*.ogg' -type f -delete

find /home -name '*.gif' -type f -delete

find /home -name '*.png' -type f -delete

find /home -name '*.jpg' -type f -delete

find /home -name '*.jpeg' -type f -delete

echo " "
echo "------------------------------------------------------"
echo "Removing Malware/Prohibited Software"
echo "------------------------------------------------------"
echo " "

echo "Removing hydra"
sudo apt-get -y purge hydra*
echo " "
echo "Removing john"
sudo apt-get -y purge john*
echo " "
echo "Removing nikto"
sudo apt-get -y purge nikto*
echo " "
echo "Removing netcat"
sudo apt-get -y purge netcat*
echo " "
echo "Removing freeciv"
sudo apt-get -y purge freeciv*
echo " "
echo "Removing ophcrack"
sudo apt-get -y purge ophcrack*
echo " "
echo "Removing kismet"
sudo apt-get -y purge kismet*
echo " "


echo " "
echo "------------------------------------------------------"
echo "Updating and Upgrading Bash"
echo "------------------------------------------------------"
echo " "

echo "Starting Update"

apt-get -y update
echo " "
echo "Starting Upgrade"
apt-get -y upgrade
echo " "
echo "Starting dist-upgrade"
apt-get -y dist-upgrade
echo " "
echo "Starting autoremove"
apt-get autoremove -y
echo " "
echo "Starting autoclean"
apt-get autoclean -y
echo " "
echo "Starting check"
apt-get check
echo " "

echo " "
echo "------------------------------------------------------"
echo "Installing/updating packages"
echo "------------------------------------------------------"
echo " "

echo "Installing firefox hardinfo chkrootkit iptables portsentry lynis ufw gufw sysv-rc-conf nessus clamav lynis hardinfo rkhunter"

apt-get -V -y install firefox hardinfo chkrootkit iptables portsentry lynis ufw gufw sysv-rc-conf nessus clamav lynis hardinfo

apt-get -V -y install --reinstall coreutils



echo " "
echo "------------------------------------------------------"
echo "Configuring Critical Services"
echo "------------------------------------------------------"
echo " "


echo "Critical Service: VSFTP"
echo " "
echo -n "VSFTP [Y/n] "
read option
if [[ $option =~ ^[Yy]$ ]];
then
  sudo apt-get -y install vsftpd
  # Disable anonymous uploads
  sudo sed -i '/^anon_upload_enable/ c\anon_upload_enable no' /etc/vsftpd.conf
  sudo sed -i '/^anonymous_enable/ c\anonymous_enable=NO' /etc/vsftpd.conf
  # FTP user directories use chroot
  sudo sed -i '/^chroot_local_user/ c\chroot_local_user=YES' /etc/vsftpd.conf
  sudo service vsftpd restart
else
  sudo apt-get -y purge vsftpd*
fi
echo " "

echo "Critical Service: OpenSSH"
echo " "
echo -n "OpenSSH Server [Y/n] "
read option1

if [[ $option1 =~ ^[Yy]$ ]];

then

sudo apt-get -y install ssh

sudo apt-get -y install openssh-server

else

sudo apt-get -y purge openssh-server

fi
echo " "

echo "Critical Service: MySQL"
echo " "
echo -n "MySQL [Y/n] "
read option2
if [[ $option2 =~ ^[Yy]$ ]];
then
  sudo apt-get -y install mysql-server
  # Disable remote access
  sudo sed -i '/bind-address/ c\bind-address = 127.0.0.1' /etc/mysql/my.cnf
  sudo service mysql restart
else
  sudo apt-get -y purge mysql*
fi
echo " "



echo "Critical Service: Apache"
echo " "
echo -n "Apache [Y/n] "
read option2
if [[ $option2 =~ ^[Yy]$ ]];
then
  sudo apt-get -y install apache apache2
	chown -R root:root /etc/apache2
	chown -R root:root /etc/apache
	if [ -e /etc/apache2/apache2.conf ]; then
		echo "<Directory />" >> /etc/apache2/apache2.conf
		echo "        AllowOverride None" >> /etc/apache2/apache2.conf
		echo "        Order Deny,Allow" >> /etc/apache2/apache2.conf
		echo "        Deny from all" >> /etc/apache2/apache2.conf
		echo "</Directory>" >> /etc/apache2/apache2.conf
		echo "UserDir disabled root" >> /etc/apache2/apache2.conf
	fi
	systemctl restart apache2.service
else
  sudo apt-get -y purge apache*
	sudo apt-get -y purge apache2*
fi
echo " "


echo " "
echo "------------------------------------------------------"
echo "Secure networking"
echo "------------------------------------------------------"
echo " "


echo "Blocking unsecure ports with IPTABLES"
echo "Blocking Telnet"
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 23 -j DROP         #Block Telnet
echo "Blocking NFS"
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 2049 -j DROP       #Block NFS
iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 2049 -j DROP       #Block NFS
echo "Blocking X-Windows"
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 6000:6009 -j DROP  #Block X-Windows
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 7100 -j DROP       #Block X-Windows font server
echo "Blocking printer ports"
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 515 -j DROP        #Block printer port
iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 515 -j DROP        #Block printer port
echo "Blocking Sun rpc/NFS"
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 111 -j DROP        #Block Sun rpc/NFS
iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 111 -j DROP        #Block Sun rpc/NFS
echo "Denying ouside packets from internet which claim to be from loopback interface"
iptables -A INPUT -p all -s localhost  -i eth0 -j DROP            #Deny outside packets from internet which claim to be from your loopback interface.
echo " "

echo "Enabling firewall"
ufw enable
echo " "

echo "Denying firewall ports"
echo "Blocking telnet"
ufw deny 23
echo "Blocking open ports 2049, 515, 111"
ufw deny 2049
ufw deny 515
ufw deny 111


echo "Enable syn cookie protection"
sysctl -n net.ipv4.tcp_syncookies
echo "Disable IPv6"
sudo echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "Disable IP Forwarding"
sudo echo 0 > /proc/sys/net/ipv4/ip_forward
echo "Prevent IP Spoofing"
sudo echo "nospoof on" >> /etc/host.conf
echo "Making Sysctl Secure"
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -p

echo " "

echo " "
echo "------------------------------------------------------"
echo "Security Scans"
echo "------------------------------------------------------"
echo " "

echo "Running chkrootkit"
chkrootkit
echo " "

echo "Running lynis"
lynis -c
echo " "

echo "Running freshclam"
freshclam
clamscan -r
echo " "

echo "Running rkhunter"
rkhunter --update
rkhunter --propupd
rkhunter -c --enable-all
echo " "


echo "Running HardInfo"
hardinfo -r -f html
echo " "

echo " "
echo "------------------------------------------------------"
echo "Closing Remarks"
echo "------------------------------------------------------"
echo " "

echo "Remember to "
echo "		- set automatic updates in GUI"
echo "		- look at all the /etc/cron.*/ files"
echo "		- look at all the /etc/rc?.d/ files"
echo "		- check for hidden home directories"
echo "		- check for wierd file permissions"
echo "		- check services"
echo " 		- harden the kernel with sysctl"
echo "		- lock the root user"
echo "		- check process at startup"
echo "		- compare installed packages to Vanilla's installed packages"
echo " 		- look at the Linux Bible for service configurations"
echo " 		- look at CIS Benchmarks Security checklists"
echo "		- restart configured services"
echo "		- improve file inspections of conf files (lightdm.conf, sources.list, sshd_config)"
echo " 		- check sources.list for malicious sources"
echo "NOTE: You should probably reboot soon"
