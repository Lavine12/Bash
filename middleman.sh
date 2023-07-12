#!/bin/bash

# Read the last set of data from form_data.txt
last_set=$(awk '/^Server ID:/ {rec="";}{rec=rec"\n"$0;}END{print rec;}' form_data.txt)

# Extract values from the last set
server_id=$(echo "$last_set" | awk -F ': ' '/^Server ID:/ {print $2}')
#os=$(echo "$last_set" | awk -F ': ' '/^Operating System:/ {print $2}')
ip_address=$(echo "$last_set" | awk -F ': ' '/IP Address:/ {print $2}')
netmask=$(echo "$last_set" | awk -F ': ' '/Netmask:/ {print $2}')
gateway=$(echo "$last_set" | awk -F ': ' '/Gateway:/ {print $2}')
root_password=$(echo "$last_set" | awk -F ': ' '/^Root Password:/ {print $2}')
ssh_port=$(echo "$last_set" | awk -F ': ' '/^SSH \/ RDP Port:/ {print $2}')
boot_size=$(echo "$last_set" | awk -F ': ' '/^\/boot Size:/ {print $2}')
swap_size=$(echo "$last_set" | awk -F ': ' '/^Swap Size:/ {print $2}')
root_size=$(echo "$last_set" | awk -F ': ' '/^Root Size:/ {print $2}')

# Update ks.cfg with the extracted values
sed -i "s/^network --hostname=.*/network --hostname=$server_id/" ks.cfg
sed -i "s/^rootpw --plaintext .*/rootpw --plaintext $root_password/" ks.cfg
sed -i "s/^ssh_port=.*/ssh_port=$ssh_port/" ks.cfg
sed -i "s/^part \/boot --fstype=xfs --size=.*/part \/boot --fstype=xfs --size=$boot_size/" ks.cfg
sed -i "s/^part swap --size=.*/part swap --size=$swap_size/" ks.cfg

# Update IP address in network configuration
sed -E -i "s/^network --bootproto=static --ip=[^[:space:]]+ --netmask=[^[:space:]]+ --gateway=[^[:space:]]+/network --bootproto=static --ip=$ip_address --netmask=$netmask --gateway=$gateway/" ks.cfg

# Copy ks.cfg to the isolinux folder in cus_centos
cp ks.cfg /mnt/newpartition/cus_iso/isolinux/

xorriso -as mkisofs -o new_centos.iso -isohybrid-mbr /usr/share/syslinux/isohdpfx.bin   -c isolinux/boot.cat -b isolinux/isolinux.bin   -no-emul-boot -boot-load-size 4 -boot-info-table   -eltorito-alt-boot -e images/efiboot.img   -no-emul-boot -isohybrid-gpt-basdat   -V "CentOS 7 x86_64" /mnt/newpartition/cus_iso

sshpass -p "root" scp -P 45888 new_centos.iso root@124.217.224.119:/var/lib/kvmd/msd
