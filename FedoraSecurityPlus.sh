#!/usr/bin/env bash

HEIGHT=22
WIDTH=90
CHOICE_HEIGHT=4
BACKTITLE="My Mini Script for Fedora Linux by topminipie"
TITLE="FedoraSecurityPlus"
MENU="Please Choose one of the following options:"

# Git repo project: https://github.com/topminipie/FedoraSecurityPlus
# Credits: https://github.com/topminipie/FedoraSecurityPlus#credits

# TODO:
            ### umask
            #echo "Set umask to 077 for all users instead of 022"
            #sudo bash -c 'echo "umask 077" > /etc/profile.d/set-umask077-for-all-users.sh'

            ### Make home directory private
            #chmod 700 /home/*

            ### Firewall
            #echo "Set firewall to drop zone"
            #sudo firewall-cmd --set-dTODO:efault-zone=drop
            #sudo firewall-cmd --add-protocol=ipv6-icmp --permanent
            #sudo firewall-cmd --add-service=dhcpv6-client --permanent

# Check to see if Dialog is installed, if not install it - Thanks Kinkz_nl
if [ $(rpm -q dialog 2>/dev/null | grep -c "dialog is not installed") -eq 1 ]; then
sudo dnf install -y dialog
fi

rm -rf /home/$USER/.tmp_FedoraSecurityPlus  # Delete old temp dir
mkdir /home/$USER/.tmp_FedoraSecurityPlus   # Make temp dir

OPTIONS=(1 "Speed up DNF"
         2 "Enable AutoUpdates"
         3 "Update System And Reboot Now! (Offline-Upgrade)"
         4 "Update Firmware - If your system supports fw update delivery"
         5 "Install Basic Software - Check basic-dnf.txt"
         6 "Install Extras Software - Check extras-dnf.txt"
         7 "Enable FlatHub repo"
         8 "Update Flatpak Apps And Delete Unused RunTime"
         9 "Install some flatpak software - Check flatpak-packages.txt"
         10 "Install Videos packages - Video codec and stuff as per the official doc"
         11 "Harden your Fedora"
         12 "Install hardened_malloc"
         13 "Clear system (journald) logs files"
         14 "Clear Bash, Python history"
         99 "Quit")

while [ "$CHOICE -ne 4" ]; do
    CHOICE=$(dialog --clear \
                --backtitle "$BACKTITLE" \
                --title "$TITLE" \
                --nocancel \
                --menu "$MENU" \
                $HEIGHT $WIDTH $CHOICE_HEIGHT \
                "${OPTIONS[@]}" \
                2>&1 >/dev/tty)

    clear
    case $CHOICE in
        1)
            echo "Speeding Up DNF"
            grep -q "# FedoraSecurityPlus" /etc/dnf/dnf.conf || sudo echo "# FedoraSecurityPlus" >> /etc/dnf/dnf.conf
            grep -q "fastestmirror=1" /etc/dnf/dnf.conf || sudo echo "fastestmirror=1" >> /etc/dnf/dnf.conf
            grep -q "max_parallel_downloads=10" /etc/dnf/dnf.conf || sudo echo "max_parallel_downloads=10" >> /etc/dnf/dnf.conf
            grep -q "deltarpm=true" /etc/dnf/dnf.conf || sudo echo "deltarpm=true" >> /etc/dnf/dnf.conf
            grep -q "countme=false" /etc/dnf/dnf.conf || sudo echo "countme=false" >> /etc/dnf/dnf.conf
            notify-send "Your DNF config has now been amended" --expire-time=1000
            ;;
        2)
            echo "Enable AutoUpdates"
            sudo dnf install -y dnf-automatic
            sudo systemctl enable --now dnf-automatic-install.timer
            notify-send "System updated - Reboot now" --expire-time=1000
            ;;
        3)
            echo "Update System And Reboot Now (Offline-Upgrade)"
            dnf offline-upgrade download -y
            dnf offline-upgrade reboot
            notify-send "Reboot..." --expire-time=1000
            ;;
        4)
            echo "Updating Firmware"
            sudo fwupdmgr get-devices
            sudo fwupdmgr refresh --force
            sudo fwupdmgr get-updates -y
            sudo fwupdmgr update -y
            notify-send "Firmware updated" --expire-time=1000
            ;;
        5)
            echo "Install Basic Software"
            sudo dnf install -y $(cat basic-dnf.txt)
            notify-send "Basic Software have been installed" --expire-time=1000
            ;;
        6)
            echo "Installing Extras Software"
            sudo dnf install -y $(cat extras-dnf.txt)
            notify-send "Extras Software have been installed" --expire-time=1000
            ;;
        7)
            echo "Enabling FlatHub"
            flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
            flatpak update --noninteractive
            notify-send "FlatHub has now been enabled" --expire-time=1000
            ;;
        8)
            echo "Update Flatpak Apps And Delete Unused RunTime"
            flatpak uninstall --unused --noninteractive
            flatpak update --noninteractive
            flatpak uninstall --unused --noninteractive
            notify-send "Flatpak Apps Updated, Unused RunTime Deleted" --expire-time=1000
            ;;
        9)
            echo "Install some flatpak software"
            source 'flatpak-install.sh'
            ;;
        10)
            echo "Installing Videos packages"
            sudo dnf install -y gstreamer1-plugins-{bad-\*,good-\*,base} gstreamer1-plugin-openh264 gstreamer1-libav --exclude=gstreamer1-plugins-bad-free-devel
            sudo dnf install lame\* --exclude=lame-devel
            sudo dnf group upgrade -y --with-optional Multimedia
            sudo dnf update -y
            notify-send "All done" --expire-time=1000
            ;;
        11)
            echo "Hardening Fedora"
            echo "Downloading sysctl files from Kicksecure"
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/usr/lib/sysctl.d/990-security-misc.conf > /home/$USER/.tmp_FedoraSecurityPlus/30_security-misc.conf
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/30_security-misc.conf /etc/sysctl.d/30_security-misc.conf
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/usr/lib/sysctl.d/30_silent-kernel-printk.conf > /home/$USER/.tmp_FedoraSecurityPlus/30_silent-kernel-printk.conf
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/30_silent-kernel-printk.conf /etc/sysctl.d/30_silent-kernel-printk.conf
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/usr/lib/sysctl.d/30_security-misc_kexec-disable.conf > /home/$USER/.tmp_FedoraSecurityPlus/30_security-misc_kexec-disable.conf
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/30_security-misc_kexec-disable.conf /etc/sysctl.d/30_security-misc_kexec-disable.conf

            echo "Enable mac address randomization"
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/usr/lib/NetworkManager/conf.d/80_ipv6-privacy.conf > /home/$USER/.tmp_FedoraSecurityPlus/80_ipv6-privacy.conf
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/80_ipv6-privacy.conf /etc/NetworkManager/conf.d/80_ipv6-privacy.conf
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/usr/lib/NetworkManager/conf.d/80_randomize-mac.conf > /home/$USER/.tmp_FedoraSecurityPlus/80_randomize-mac.conf
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/80_randomize-mac.conf /etc/NetworkManager/conf.d/80_randomize-mac.conf
            # enable ipv6 privacy
            sudo rm -rf /etc/systemd/networkd.conf.d/
            sudo mkdir /etc/systemd/networkd.conf.d/
            #sudo echo -n > /etc/systemd/networkd.conf.d/80_ipv6-privacy-extensions.conf
            sudo echo "[Network]" >> /etc/systemd/networkd.conf.d/80_ipv6-privacy-extensions.conf
            sudo echo "IPv6PrivacyExtensions=kernel" >> /etc/systemd/networkd.conf.d/80_ipv6-privacy-extensions.conf

            echo "Disable CoreDump"
            #
            sudo rm -rf /lib/systemd/coredump.conf.d/
            sudo mkdir /lib/systemd/coredump.conf.d/
            #sudo echo -n > /lib/systemd/coredump.conf.d/30_security-misc.conf
            sudo echo "[Coredump]" >> /lib/systemd/coredump.conf.d/30_security-misc.conf
            sudo echo "Storage=none" >> /lib/systemd/coredump.conf.d/30_security-misc.conf
            #
            sudo rm -rf /etc/security/limits.d/
            sudo mkdir /etc/security/limits.d/
            #sudo echo -n > /etc/security/limits.d/30_security-misc.conf
            sudo echo "## Disable coredumps." >> /etc/security/limits.d/30_security-misc.conf
            sudo echo "* hard core 0" >> /etc/security/limits.d/30_security-misc.conf

            echo "Clear system crash and CoreDump files"    # Credits: https://privacy.sexy
            sudo rm -rfv /var/crash/*
            sudo rm -rfv /var/lib/systemd/coredump/

            echo "Set hostname 'localhost'"     # TODO: look
            sudo hostnamectl hostname "localhost"

            echo "Enable DNSSEC"
            grep -q "# FedoraSecurityPlus" /etc/systemd/resolved.conf || sudo echo "# FedoraSecurityPlus" >> /etc/systemd/resolved.conf
            grep -q "DNSSEC=yes" /etc/systemd/resolved.conf || sudo echo "DNSSEC=yes" >> /etc/systemd/resolved.conf

            echo "Set generic machine id (https://github.com/Whonix/dist-base-files/blob/master/etc/machine-id)"
            sudo echo "b08dfa6083e7567a1921a715000001fb" > /var/lib/dbus/machine-id

            echo "Add more entropy sources (jitterentropy)"     # https://github.com/Kicksecure/security-misc/blob/master/usr/lib/modules-load.d/30_security-misc.conf
            sudo echo "jitterentropy_rng" > /usr/lib/modules-load.d/30_security-misc.conf

            echo "Apply hardened bluetooth config"
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/etc/bluetooth/30_security-misc.conf > /home/$USER/.tmp_FedoraSecurityPlus/30_security-misc.conf
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/30_security-misc.conf /etc/bluetooth/30_security-misc.conf

            ### Hardening linux kernel parameters
            #echo "Hardening linux kernel parameters"
            #sudo mkdir /etc/default/grub.d/
            #sudo curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/etc/default/grub.d/40_cpu_mitigations.cfg > /etc/grub.d/40_cpu_mitigations.cfg
            #sudo curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/etc/default/grub.d/40_distrust_bootloader.cfg > /etc/grub.d/40_distrust_bootloader.cfg
            #sudo curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/etc/default/grub.d/40_distrust_cpu.cfg > /etc/grub.d/40_distrust_cpu.cfg
            #sudo curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/etc/default/grub.d/40_enable_iommu.cfg > /etc/grub.d/40_enable_iommu.cfg
            #sudo curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/etc/default/grub.d/40_kernel_hardening.cfg > /etc/grub.d/40_kernel_hardening.cfg
            #sudo curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/etc/default/grub.d/41_quiet.cfg > /etc/grub.d/41_quiet.cfg
            #sudo grub2-mkconfig -o /boot/grub2/grub.cfg
            # TODO: check NoVidia, unroot curl

            # sudo bash -c 'sed -i '6iGRUB_CMDLINE_LINUX_DEFAULT="slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on vsyscall=none debugfs=off oops=panic lockdown=confidentiality mce=0 quiet loglevel=0 spectre_v2=on spec_store_bypass_disable=on tsx=off tsx_async_abort=full,nosmt mds=full,nosmt l1tf=full,force nosmt=force kvm.nx_huge_pages=force randomize_kstack_offset=on"''
            # sudo grub2-mkconfig -o /boot/grub2/grub.cfg
            # echo "You can add "module.sig_enforce=1" if you signed your Nvidia drivers"

            echo "Add miscellaneous modules to blacklist (modprobe)"
            echo "Warning!!! Thunderbolt is DISABLE by default."
            echo "Config: /etc/modprobe.d/30_security-misc.conf"
            curl -fsSL https://raw.githubusercontent.com/Kicksecure/security-misc/master/etc/modprobe.d/30_security-misc.conf > /home/$USER/.tmp_FedoraSecurityPlus/30_security-misc.conf
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/30_security-misc.conf /etc/modprobe.d/30_security-misc.conf
            # Delete conflicting Fedora blacklist config
            echo "Delete conflicting Fedora blacklist config"
            sudo rm -f /etc/modprobe.d/appletalk-blacklist.conf
            sudo rm -f /etc/modprobe.d/atm-blacklist.conf
            sudo rm -f /etc/modprobe.d/ax25-blacklist.conf
            sudo rm -f /etc/modprobe.d/netrom-blacklist.conf
            sudo rm -f /etc/modprobe.d/rds-blacklist.conf
            sudo rm -f /etc/modprobe.d/rose-blacklist.conf
            sudo rm -f /etc/modprobe.d/sctp-blacklist.conf
            # ???
            sudo rm -f /etc/modprobe.d/firewalld-sysctls.conf
            # Install "disabled-by-security-misc" echo script
            echo 'Install "disabled-by-security-misc" echo script'
            #curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/bin/disabled-bluetooth-by-security-misc > /home/$USER/.tmp_FedoraSecurityPlus/disabled-bluetooth-by-security-misc    # Not used
            #sudo cp /home/$USER/.tmp_FedoraSecurityPlus/disabled-bluetooth-by-security-misc /bin/disabled-bluetooth-by-security-misc
            #curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/bin/disabled-cdrom-by-security-misc > /home/$USER/.tmp_FedoraSecurityPlus/disabled-cdrom-by-security-misc            # Not used
            #sudo cp /home/$USER/.tmp_FedoraSecurityPlus/disabled-cdrom-by-security-misc /bin/disabled-cdrom-by-security-misc
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/bin/disabled-filesys-by-security-misc > /home/$USER/.tmp_FedoraSecurityPlus/disabled-filesys-by-security-misc
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/disabled-filesys-by-security-misc /bin/disabled-filesys-by-security-misc
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/bin/disabled-firewire-by-security-misc > /home/$USER/.tmp_FedoraSecurityPlus/disabled-firewire-by-security-misc
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/disabled-firewire-by-security-misc /bin/disabled-firewire-by-security-misc
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/bin/disabled-intelme-by-security-misc > /home/$USER/.tmp_FedoraSecurityPlus/disabled-intelme-by-security-misc
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/disabled-intelme-by-security-misc /bin/disabled-intelme-by-security-misc
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/bin/disabled-msr-by-security-misc > /home/$USER/.tmp_FedoraSecurityPlus/disabled-msr-by-security-misc
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/disabled-msr-by-security-misc /bin/disabled-msr-by-security-misc
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/bin/disabled-netfilesys-by-security-misc > /home/$USER/.tmp_FedoraSecurityPlus/disabled-netfilesys-by-security-misc
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/disabled-netfilesys-by-security-misc /bin/disabled-netfilesys-by-security-misc
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/bin/disabled-network-by-security-misc > /home/$USER/.tmp_FedoraSecurityPlus/disabled-network-by-security-misc
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/disabled-network-by-security-misc /bin/disabled-network-by-security-misc
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/bin/disabled-thunderbolt-by-security-misc > /home/$USER/.tmp_FedoraSecurityPlus/disabled-thunderbolt-by-security-misc
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/disabled-thunderbolt-by-security-misc /bin/disabled-thunderbolt-by-security-misc
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/bin/disabled-vivid-by-security-misc > /home/$USER/.tmp_FedoraSecurityPlus/disabled-vivid-by-security-misc
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/disabled-vivid-by-security-misc /bin/disabled-vivid-by-security-misc

            ### NTS (Time synchronization)
            echo "Replicate chrony.conf from GrapheneOS and hardening chrony demon"
            curl -fsSL https://raw.githubusercontent.com/GrapheneOS/infrastructure/main/chrony.conf > /home/$USER/.tmp_FedoraSecurityPlus/chrony.conf
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/chrony.conf /etc/chrony.conf
            sudo echo -n > /etc/sysconfig/chronyd
            sudo echo 'OPTIONS="-F 1"' >> /etc/sysconfig/chronyd          # Enable seccomp for chronyd
            sudo systemctl restart chronyd

            ### More isolate
            echo "Isolate NetworkManager, irqbalance, ModemManager"
            # NetworkManager
            sudo rm -rf /etc/systemd/system/NetworkManager.service.d
            sudo mkdir -p /etc/systemd/system/NetworkManager.service.d
            curl -fsSL https://github.com/divestedcg/Brace/raw/master/brace/usr/lib/systemd/system/NetworkManager.service.d/99-brace.conf > /home/$USER/.tmp_FedoraSecurityPlus/99-brace.conf
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/99-brace.conf /etc/systemd/system/NetworkManager.service.d/99-brace.conf
            # irqbalance
            sudo rm -rf /etc/systemd/system/irqbalance.service.d
            sudo mkdir -p /etc/systemd/system/irqbalance.service.d
            curl -fsSL https://github.com/divestedcg/Brace/raw/master/brace/usr/lib/systemd/system/irqbalance.service.d/99-brace.conf > /home/$USER/.tmp_FedoraSecurityPlus/99-brace.conf
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/99-brace.conf /etc/systemd/system/irqbalance.service.d/99-brace.conf
            # ModemManager
            sudo rm -rf /etc/systemd/system/ModemManager.service.d
            sudo mkdir -p /etc/systemd/system/ModemManager.service.d
            curl -fsSL https://github.com/divestedcg/Brace/raw/master/brace/usr/lib/systemd/system/ModemManager.service.d/99-brace.conf > /home/$USER/.tmp_FedoraSecurityPlus/99-brace.conf
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/99-brace.conf /etc/systemd/system/ModemManager.service.d/99-brace.conf
            notify-send "Fedora is hardened (you must reboot to make it effective)" --expire-time=1000
            ;;
        12)
            echo "Installing Divested repo"
            # Install rpm repo package
            sudo dnf install -y https://gitlab.com/divested/divested-release/-/jobs/4361602859/artifacts/file/build/noarch/divested-release-20230406-2.noarch.rpm
            dnf makecache
            echo "Installing hardened_malloc"
            sudo dnf install hardened_malloc
            notify-send "hardened_malloc installed (you must reboot to make it effective)" --expire-time=1000
            ;;
        13)
            echo 'Clear system (journald) logs'         # Credits: https://privacy.sexy
            sudo journalctl --vacuum-time=1s
            sudo rm -rfv /run/log/journal/*
            sudo rm -rfv /var/log/journal/*
            notify-send "Done" --expire-time=1000
            ;;
        14)
            echo 'Clear Bash, Python history'
            rm -f /home/$USER/.bash_history
            rm -f /home/$USER/.python_history
            notify-send "Done" --expire-time=1000
            ;;
        99)
            rm -rf /home/$USER/.tmp_FedoraSecurityPlus  # Delete temp dir
            exit 0
            ;;
    esac
done
