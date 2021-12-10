echo "Saving manually installed packages to 'manuallyinstalledpackages'"
comm -23 <(apt-mark showmanual | sort -u) <(gzip -dc /var/log/installer/initial-status.gz | sed -n 's/^Package: //p' | sort -u) > manuallyinstalledpackages

maxpwage=30
minpwage=10
warningdays=7
echo "Setting maximum password age to $maxpwage, minimum password age to $minpwage, and the warning days to $warningdays"
chage -M $maxpwage -m $minpwage -W $warningdays

echo "checking for rsh-server..."
if [ -z $( dpkg -l | grep rsh-server ) ]
then
  echo "rsh-server is not installed"
else
  echo "rsh-server is installed. uninstalling..."
  sudo apt-get remove rsh-server
fi

echo "checking for nis..."
if [ -z $( dpkg -l | grep nis ) ]
then
  echo "nis is not installed"
else
  echo "nis is installed. uninstalling..."
  sudo apt-get remove nis
fi

echo "checking for libpam-pkcs11..."
if [ -z $( dpkg -l | grep libpam-pkcs11 ) ]
then
  echo "libpam-pkcs11 is not installed. installing..."
  sudo apt install libpam-pkcs11 -y
  if [ -f /etc/etc/pam_pkcs11/pam_pkcs11.conf ]
  then
    echo use_mappers=pwent >> /etc/etc/pam_pkcs11/pam_pkcs11.conf
  else
    echo 'YOURE GOING TO NEED TO DO SOME MORE CONFIGURATION OF PKCS11'
else
  echo "libpam-pkcs11 is installed"
fi

echo "disabling automatic and unattended ssh logins"
grep -v "PermitEmptyPasswords" /etc/ssh/sshd_config >> /etc/ssh/sshd_config
grep -v "PermitUserEnvironment" /etc/ssh/sshd_config >> /etc/ssh/sshd_config
printf "PermitEmptyPasswords no\nPermitUserEnvironment no" >> /etc/ssh/sshd_config
systemctl restart sshd.service

echo "Finding all accounts with no password (ADD A PASSWORD) and logging to 'pwlessaccs'"
awk -F: '($2 == "") {print}' /etc/shadow | tee -a "pwlessaccs"

echo "Listing all accounts with UID 0 (should only be root, so remove all other accounts that show up) and logging to 'uid0accs'"
awk -F: '($3 == "0") {print}' /etc/passwd | tee -a "uid0accs"

echo "Listing all services registered in systemd and logging to 'systemdservices'"
systemctl list-unit-files --type=service | tee -a "systemdservices"
