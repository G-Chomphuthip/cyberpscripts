echo "Saving manually installed packages to 'manuallyinstalledpackages'"
comm -23 <(apt-mark showmanual | sort -u) <(gzip -dc /var/log/installer/initial-status.gz | sed -n 's/^Package: //p' | sort -u) > manuallyinstalledpackages

maxpwage=30
minpwage=10
warningdays=7
echo "Setting maximum password age to $maxpwage, minimum password age to $minpwage, and the warning days to $warningdays"
chage -M $maxpwage -m $minpwage -W $warningdays

echo "Finding all accounts with no password (ADD A PASSWORD) and logging to 'pwlessaccs'"
awk -F: '($2 == "") {print}' /etc/shadow | tee -a "pwlessaccs"

echo "Listing all accounts with UID 0 (should only be root, so remove all other accounts that show up) and logging to 'uid0accs'"
awk -F: '($3 == "0") {print}' /etc/passwd | tee -a "uid0accs"

echo "Listing all services registered in systemd and logging to 'systemdservices'"
systemctl list-unit-files --type=service | tee -a "systemdservices"
