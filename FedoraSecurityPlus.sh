#!/bin/sh

HEIGHT=24
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
echo "Need install dialog utility"
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
         8 "Update Flatpak Apps And Delete Unused Runtime"
         9 "Install some flatpak software - Check flatpak-packages.txt"
         10 "Install Videos packages - Video codec and stuff as per the official doc"
         11 "Harden your Fedora"
         12 "Install hardened_malloc"
         13 "Clear system (journald) logs files"
         14 "Clear Bash, Python history"
         15 "Set DNS Server"
         16 "Enable more entropy sources (jitterentropy_rngd)"
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
            grep -q "# FedoraSecurityPlus" /etc/dnf/dnf.conf || sudo sh -c 'echo "# FedoraSecurityPlus" >> /etc/dnf/dnf.conf'
            grep -q "fastestmirror=1" /etc/dnf/dnf.conf || sudo sh -c 'echo "fastestmirror=1" >> /etc/dnf/dnf.conf'
            grep -q "max_parallel_downloads=10" /etc/dnf/dnf.conf || sudo sh -c 'echo "max_parallel_downloads=10" >> /etc/dnf/dnf.conf'
            grep -q "countme=false" /etc/dnf/dnf.conf || sudo sh -c 'echo "countme=false" >> /etc/dnf/dnf.conf'

            # Credit https://github.com/divestedcg/Brace/blob/master/brace/usr/bin/brace-supplemental-changes#L35
            sudo sed -i 's/countme=1/countme=0/' /etc/yum.repos.d/*.repo
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
            sudo dnf offline-upgrade download -y
            sudo dnf offline-upgrade reboot
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
            echo "Installing Multimedia libraries & H264 Codec"      
            sudo dnf install -y gstreamer1-plugins-{bad-\*,good-\*,base} gstreamer1-plugin-openh264 gstreamer1-plugin-libav --exclude=gstreamer1-plugins-bad-free-devel
            sudo dnf install -y lame\* --exclude=lame-devel
            sudo dnf group upgrade -y --with-optional Multimedia
            #
            sudo dnf install -y gstreamer1-plugin-openh264 mozilla-openh264
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
            sudo mkdir -p /etc/NetworkManager/conf.d/
            
            # 80_ipv6-privacy.conf
            sudo sh -c 'echo -n > /etc/NetworkManager/conf.d/80_ipv6-privacy.conf'
            sudo sh -c 'echo "[connection]" >> /etc/NetworkManager/conf.d/80_ipv6-privacy.conf'
            sudo sh -c 'echo "ipv6.ip6-privacy=2" >> /etc/NetworkManager/conf.d/80_ipv6-privacy.conf'

            # 80_randomize-mac.conf
            sudo sh -c 'echo -n > /etc/NetworkManager/conf.d/80_randomize-mac.conf'
            sudo sh -c 'echo "[device-mac-randomization]" >> /etc/NetworkManager/conf.d/80_randomize-mac.conf'
            sudo sh -c 'echo "wifi.scan-rand-mac-address=yes" >> /etc/NetworkManager/conf.d/80_randomize-mac.conf'
            sudo sh -c 'echo "" >> /etc/NetworkManager/conf.d/80_randomize-mac.conf'
            sudo sh -c 'echo "[connection-mac-randomization]" >> /etc/NetworkManager/conf.d/80_randomize-mac.conf'
            sudo sh -c 'echo "ethernet.cloned-mac-address=random" >> /etc/NetworkManager/conf.d/80_randomize-mac.conf'
            sudo sh -c 'echo "wifi.cloned-mac-address=random" >> /etc/NetworkManager/conf.d/80_randomize-mac.conf'

            # 80_ipv6-privacy-extensions.conf
            sudo mkdir -p /etc/systemd/networkd.conf.d/
            sudo sh -c 'echo -n > /etc/systemd/networkd.conf.d/80_ipv6-privacy-extensions.conf'
            sudo sh -c 'echo "[Network]" >> /etc/systemd/networkd.conf.d/80_ipv6-privacy-extensions.conf'
            sudo sh -c 'echo "IPv6PrivacyExtensions=kernel" >> /etc/systemd/networkd.conf.d/80_ipv6-privacy-extensions.conf'

            # Disabled https://github.com/Kicksecure/security-misc/issues/184
            #curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/usr/lib/NetworkManager/conf.d/80_ipv6-privacy.conf > /home/$USER/.tmp_FedoraSecurityPlus/80_ipv6-privacy.conf
            #sudo cp /home/$USER/.tmp_FedoraSecurityPlus/80_ipv6-privacy.conf /etc/NetworkManager/conf.d/80_ipv6-privacy.conf
            #curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/usr/lib/NetworkManager/conf.d/80_randomize-mac.conf > /home/$USER/.tmp_FedoraSecurityPlus/80_randomize-mac.conf
            #sudo cp /home/$USER/.tmp_FedoraSecurityPlus/80_randomize-mac.conf /etc/NetworkManager/conf.d/80_randomize-mac.conf
            # enable ipv6 privacy
            #curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/usr/lib/systemd/networkd.conf.d/80_ipv6-privacy-extensions.conf > /home/$USER/.tmp_FedoraSecurityPlus/80_ipv6-privacy-extensions.conf
            #sudo cp /home/$USER/.tmp_FedoraSecurityPlus/80_ipv6-privacy-extensions.conf /etc/systemd/networkd.conf.d/80_ipv6-privacy-extensions.conf

            echo "Disable CoreDump"
            #
            sudo mkdir -p /lib/systemd/coredump.conf.d/
            sudo sh -c 'echo -n > /lib/systemd/coredump.conf.d/30_security-misc.conf'
            sudo sh -c 'echo "[Coredump]" >> /lib/systemd/coredump.conf.d/30_security-misc.conf'
            sudo sh -c 'echo "Storage=none" >> /lib/systemd/coredump.conf.d/30_security-misc.conf'
            #
            sudo sh -c 'echo -n > /etc/security/limits.d/30_security-misc.conf'
            sudo sh -c 'echo "## Disable coredumps." >> /etc/security/limits.d/30_security-misc.conf'
            sudo sh -c 'echo "* hard core 0" >> /etc/security/limits.d/30_security-misc.conf'

            echo "Clear system crash and CoreDump files"    # Credit: https://privacy.sexy
            sudo rm -rfv /var/crash/*
            sudo rm -rfv /var/lib/systemd/coredump/

            echo "Set hostname 'localhost'"
            sudo hostnamectl hostname "localhost"

            echo "Set generic machine id (https://github.com/Kicksecure/dist-base-files/blob/master/etc/machine-id)"
            sudo sh -c 'echo "b08dfa6083e7567a1921a715000001fb" > /var/lib/dbus/machine-id'

            echo "Apply hardened bluetooth config"
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/etc/bluetooth/30_security-misc.conf > /home/$USER/.tmp_FedoraSecurityPlus/30_security-misc.conf
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/30_security-misc.conf /etc/bluetooth/30_security-misc.conf

            ### Hardening linux kernel parameters
            #echo "Hardening linux kernel parameters"
            #sudo mkdir -p /etc/default/grub.d/
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
            echo 'Install "disabled-by-security-misc" echo script'
            #curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/usr/bin/disabled-bluetooth-by-security-misc > /home/$USER/.tmp_FedoraSecurityPlus/disabled-bluetooth-by-security-misc    # Not used
            #sudo cp /home/$USER/.tmp_FedoraSecurityPlus/disabled-bluetooth-by-security-misc /usr/bin/disabled-bluetooth-by-security-misc
            #curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/usr/bin/disabled-cdrom-by-security-misc > /home/$USER/.tmp_FedoraSecurityPlus/disabled-cdrom-by-security-misc            # Not used
            #sudo cp /home/$USER/.tmp_FedoraSecurityPlus/disabled-cdrom-by-security-misc /usr/bin/disabled-cdrom-by-security-misc
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/usr/bin/disabled-filesys-by-security-misc > /home/$USER/.tmp_FedoraSecurityPlus/disabled-filesys-by-security-misc
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/disabled-filesys-by-security-misc /usr/bin/disabled-filesys-by-security-misc
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/usr/bin/disabled-firewire-by-security-misc > /home/$USER/.tmp_FedoraSecurityPlus/disabled-firewire-by-security-misc
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/disabled-firewire-by-security-misc /usr/bin/disabled-firewire-by-security-misc
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/usr/bin/disabled-intelme-by-security-misc > /home/$USER/.tmp_FedoraSecurityPlus/disabled-intelme-by-security-misc
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/disabled-intelme-by-security-misc /usr/bin/disabled-intelme-by-security-misc
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/usr/bin/disabled-msr-by-security-misc > /home/$USER/.tmp_FedoraSecurityPlus/disabled-msr-by-security-misc
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/disabled-msr-by-security-misc /usr/bin/disabled-msr-by-security-misc
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/usr/bin/disabled-netfilesys-by-security-misc > /home/$USER/.tmp_FedoraSecurityPlus/disabled-netfilesys-by-security-misc
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/disabled-netfilesys-by-security-misc /usr/bin/disabled-netfilesys-by-security-misc
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/usr/bin/disabled-network-by-security-misc > /home/$USER/.tmp_FedoraSecurityPlus/disabled-network-by-security-misc
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/disabled-network-by-security-misc /usr/bin/disabled-network-by-security-misc
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/usr/bin/disabled-thunderbolt-by-security-misc > /home/$USER/.tmp_FedoraSecurityPlus/disabled-thunderbolt-by-security-misc
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/disabled-thunderbolt-by-security-misc /usr/bin/disabled-thunderbolt-by-security-misc
            curl -fsSL https://github.com/Kicksecure/security-misc/raw/master/usr/bin/disabled-vivid-by-security-misc > /home/$USER/.tmp_FedoraSecurityPlus/disabled-vivid-by-security-misc
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/disabled-vivid-by-security-misc /usr/bin/disabled-vivid-by-security-misc

            ### NTS (Time synchronization)
            echo "Replicate chrony.conf from GrapheneOS and hardening chrony demon"
            curl -fsSL https://raw.githubusercontent.com/GrapheneOS/infrastructure/main/chrony.conf > /home/$USER/.tmp_FedoraSecurityPlus/chrony.conf
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/chrony.conf /etc/chrony.conf
            sudo sh -c 'echo 'OPTIONS="-F 1"' > /etc/sysconfig/chronyd'          # Enable seccomp for chronyd
            sudo systemctl restart chronyd

            ### More isolate
            echo "Isolate NetworkManager, irqbalance, ModemManager"
            # NetworkManager
            sudo mkdir -p /etc/systemd/system/NetworkManager.service.d
            curl -fsSL https://github.com/divestedcg/Brace/raw/master/brace/usr/lib/systemd/system/NetworkManager.service.d/99-brace.conf > /home/$USER/.tmp_FedoraSecurityPlus/99-brace.conf
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/99-brace.conf /etc/systemd/system/NetworkManager.service.d/99-brace.conf
            # irqbalance
            sudo mkdir -p /etc/systemd/system/irqbalance.service.d
            curl -fsSL https://github.com/divestedcg/Brace/raw/master/brace/usr/lib/systemd/system/irqbalance.service.d/99-brace.conf > /home/$USER/.tmp_FedoraSecurityPlus/99-brace.conf
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/99-brace.conf /etc/systemd/system/irqbalance.service.d/99-brace.conf
            # ModemManager
            sudo mkdir -p /etc/systemd/system/ModemManager.service.d
            curl -fsSL https://github.com/divestedcg/Brace/raw/master/brace/usr/lib/systemd/system/ModemManager.service.d/99-brace.conf > /home/$USER/.tmp_FedoraSecurityPlus/99-brace.conf
            sudo cp /home/$USER/.tmp_FedoraSecurityPlus/99-brace.conf /etc/systemd/system/ModemManager.service.d/99-brace.conf
            notify-send "Fedora is hardened (you must reboot to make it effective)" --expire-time=1000
            ;;
        12)
            echo "Warning!!!"
            echo
            echo "Some software is incompatible with hardened_malloc!!!"
            echo "Read this before you use it:"
            echo "https://github.com/divestedcg/rpm-hardened_malloc#known-issues"
            echo
            read -p "Install hardened_malloc? [y/N]: " hardened_malloc_select

            if [ $hardened_malloc_select == y ]; then
                sudo dnf install -y 'https://divested.dev/rpm/fedora/divested-release-20231210-2.noarch.rpm'
                sudo dnf config-manager --save --setopt=divested.includepkgs=divested-release,hardened_malloc
                sudo dnf -y install hardened_malloc
                notify-send "hardened_malloc installed (you must reboot to make it effective)" --expire-time=1000
                
            else
                echo "Exit"

            fi
            ;;
        13)
            echo 'Clear system (journald) logs'         # Credit: https://privacy.sexy
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
        15)
            function start_resolv_conf {
                sudo mkdir -p /etc/systemd/resolved.conf.d
                sudo sh -c "echo -n > /etc/systemd/resolved.conf.d/custom_dns.conf"
                sudo sh -c 'echo "[Resolve]" > /etc/systemd/resolved.conf.d/custom_dns.conf'
            }

            function put_resolv_conf {
                sudo sh -c 'echo "DNS='$1'" >> /etc/systemd/resolved.conf.d/custom_dns.conf'
            }

            function complete_resolv_conf {
                sudo sh -c 'echo "DNSOverTLS=yes" >> /etc/systemd/resolved.conf.d/custom_dns.conf'
                sudo sh -c 'echo "DNSSEC=yes" >> /etc/systemd/resolved.conf.d/custom_dns.conf'
            }

            function restart_network_services {
                sudo systemctl restart systemd-resolved
                sudo systemctl restart NetworkManager
            }

            function invalid_input {
                clear
                echo "Invalid Input"
                echo
            }

            function main_memu {
                clear
                echo "Please read this before choosing a DNS provider:"
                echo "https://www.privacyguides.org/en/advanced/dns-overview"
                echo "https://www.privacyguides.org/en/dns"
                echo ""
                echo "You can check the installed DNS server with this command - resolvectl status"
                echo ""
                echo "Please Choose one of the following options:"
                echo "1 - Set Quad9 DNS         (Some Logs, No ECS)"
                echo "2 - Set Mullvad DNS       (No Logs,   No ECS)"
                echo "3 - Set ControlD DNS      (No Logs,   No ECS)"
                echo "4 - Set CloudFlare DNS    (Some Logs, No ECS)"
                echo "5 - Set AdGuard DNS       (Some Logs, Always ECS)"
                echo "6 - Delete custom_dns.conf"
                echo "7 - Exit"
                read -p "Enter Number: " main_memu_select
                
                if [ $main_memu_select == 1 ]; then
                    clear
                    dns_quad9_memu

                elif [ $main_memu_select == 2 ]; then
                    clear
                    dns_mullvad_menu

                elif [ $main_memu_select == 3 ]; then
                    clear
                    dns_controld_menu

                elif [ $main_memu_select == 4 ]; then
                    clear
                    dns_cloudflare_menu

                elif [ $main_memu_select == 5 ]; then
                    clear
                    dns_adguard_menu

                elif [ $main_memu_select == 6 ]; then
                    sudo rm -rf /etc/systemd/resolved.conf.d/custom_dns.conf
                    restart_network_services

                elif [ $main_memu_select == 7 ]; then
                    clear

                else
                    main_memu

                fi
            }

            function dns_quad9_memu {
                echo "Quad9 DNS"
                echo "1 - Set, filtered only malware."
                echo "2 - Exit"
                read -p "Enter Number: " dns_quad9_select

                if [ $dns_quad9_select == 1 ]; then
                    start_resolv_conf
                    put_resolv_conf 9.9.9.9#dns.quad9.net
                    put_resolv_conf 149.112.112.112#dns.quad9.net
                    put_resolv_conf 2620:fe::fe#dns.quad9.net
                    put_resolv_conf 2620:fe::9#dns.quad9.net
                    complete_resolv_conf
                    restart_network_services
                    notify-send "Quad9 DNS Installed" --expire-time=1000
                    main_memu

                elif [ $dns_quad9_select == 2 ]; then
                    main_memu

                else
                    invalid_input
                    dns_quad9_memu

                fi
            }

            function dns_mullvad_menu {
                echo "Mullvad DNS"
                echo "1 - Set, unfiltered."
                echo "2 - Set, filtered ads, tracker, malware. (with Mullvad blocklist)"
                echo "3 - Exit"
                read -p "Enter Number: " dns_mullvad_select

                if [ $dns_mullvad_select == 1 ]; then
                    start_resolv_conf
                    put_resolv_conf 194.242.2.2#dns.mullvad.net
                    put_resolv_conf 2a07:e340::2#dns.mullvad.net
                    complete_resolv_conf
                    restart_network_services
                    notify-send "Mullvad DNS (unfiltered) Installed" --expire-time=1000
                    main_memu

                elif [ $dns_mullvad_select == 2 ]; then
                    start_resolv_conf
                    put_resolv_conf 194.242.2.4#base.dns.mullvad.net
                    put_resolv_conf 2a07:e340::4#base.dns.mullvad.net
                    complete_resolv_conf
                    restart_network_services
                    notify-send "Mullvad DNS (filtered) Installed" --expire-time=1000
                    main_memu

                elif [ $dns_mullvad_select == 3 ]; then
                    main_memu

                else
                    invalid_input
                    dns_mullvad_menu

                fi
            }

            function dns_controld_menu {
                echo "ControlD DNS"
                echo "1 - Set, unfiltered."
                echo "2 - Set, filtered ads, tracker, malware. (With ControlD blocklist)"
                echo "3 - Set, filtered ads, tracker, malware. (With Hagezi-Pro blocklist - https://github.com/hagezi/dns-blocklists)"
                echo "4 - Set, filtered ads, tracker, malware. (With Hagezi-Ultimate blocklist - https://github.com/hagezi/dns-blocklists)"
                echo "5 - Exit"
                read -p "Enter Number: " dns_controld_select

                if [ $dns_controld_select == 1 ]; then
                    start_resolv_conf
                    put_resolv_conf 76.76.2.0#p0.freedns.controld.com
                    put_resolv_conf 76.76.10.0#p0.freedns.controld.com
                    put_resolv_conf 2606:1a40::#p0.freedns.controld.com
                    put_resolv_conf 2606:1a40:1::#p0.freedns.controld.com
                    complete_resolv_conf
                    restart_network_services
                    notify-send "ControlD DNS (unfiltered) Installed" --expire-time=1000
                    main_memu

                elif [ $dns_controld_select == 2 ]; then
                    start_resolv_conf
                    put_resolv_conf 76.76.2.2#p2.freedns.controld.com
                    put_resolv_conf 76.76.10.2#p2.freedns.controld.com
                    put_resolv_conf 2606:1a40::2#p2.freedns.controld.com
                    put_resolv_conf 2606:1a40:1::2#p2.freedns.controld.com
                    complete_resolv_conf
                    restart_network_services
                    notify-send "ControlD DNS (filtered ControlD) Installed" --expire-time=1000
                    main_memu

                elif [ $dns_controld_select == 3 ]; then
                    start_resolv_conf
                    put_resolv_conf 76.76.2.41#x-hagezi-pro.freedns.controld.com
                    put_resolv_conf 76.76.10.41#x-hagezi-pro.freedns.controld.com
                    put_resolv_conf 2606:1a40::41#x-hagezi-pro.freedns.controld.com
                    put_resolv_conf 2606:1a40:1::41#x-hagezi-pro.freedns.controld.com
                    complete_resolv_conf
                    restart_network_services
                    notify-send "ControlD DNS (filtered Hagezi-Pro) Installed" --expire-time=1000
                    main_memu

                elif [ $dns_controld_select == 4 ]; then
                    start_resolv_conf
                    put_resolv_conf 76.76.2.45#x-hagezi-ultimate.freedns.controld.com
                    put_resolv_conf 76.76.10.45#x-hagezi-ultimate.freedns.controld.com
                    put_resolv_conf 2606:1a40::45#x-hagezi-ultimate.freedns.controld.com
                    put_resolv_conf 2606:1a40:1::45#x-hagezi-ultimate.freedns.controld.com
                    complete_resolv_conf
                    restart_network_services
                    notify-send "ControlD DNS (filtered Hagezi-Ultimate) Installed" --expire-time=1000
                    main_memu

                elif [ $dns_controld_select == 5 ]; then
                    main_memu

                else
                    invalid_input
                    dns_controld_menu


                fi
            }

            function dns_cloudflare_menu {
                echo "CloudFlare DNS"
                echo "1 - Set, unfiltered."
                echo "2 - Set, filtered only malware."
                echo "3 - Set, family filter."
                echo "4 - Exit"
                read -p "Enter Number: " dns_cloudflare_select

                if [ $dns_cloudflare_select == 1 ]; then
                    start_resolv_conf
                    put_resolv_conf 1.1.1.1#cloudflare-dns.com
                    put_resolv_conf 1.0.0.1#cloudflare-dns.com
                    put_resolv_conf 2606:4700:4700::1111#cloudflare-dns.com
                    put_resolv_conf 2606:4700:4700::1001#cloudflare-dns.com
                    complete_resolv_conf
                    restart_network_services
                    notify-send "CloudFlare DNS (unfiltered) Installed" --expire-time=1000
                    main_memu

                elif [ $dns_cloudflare_select == 2 ]; then
                    start_resolv_conf
                    put_resolv_conf 1.1.1.2#security.cloudflare-dns.com
                    put_resolv_conf 1.0.0.2#security.cloudflare-dns.com
                    put_resolv_conf 2606:4700:4700::1112#security.cloudflare-dns.com
                    put_resolv_conf 2606:4700:4700::1002#security.cloudflare-dns.com
                    complete_resolv_conf
                    restart_network_services
                    notify-send "CloudFlare DNS (filtered only malware) Installed" --expire-time=1000
                    main_memu

                elif [ $dns_cloudflare_select == 3 ]; then
                    start_resolv_conf
                    put_resolv_conf 1.1.1.3#family.cloudflare-dns.com
                    put_resolv_conf 1.0.0.3#family.cloudflare-dns.com
                    put_resolv_conf 2606:4700:4700::1113#family.cloudflare-dns.com
                    put_resolv_conf 2606:4700:4700::1003#family.cloudflare-dns.com
                    complete_resolv_conf
                    restart_network_services
                    notify-send "CloudFlare DNS (family filter) Installed" --expire-time=1000
                    main_memu

                elif [ $dns_cloudflare_select == 4 ]; then
                    main_memu

                else
                    invalid_input
                    dns_cloudflare_menu

                fi
            }

            function dns_adguard_menu {
                echo "AdGuard DNS"
                echo "1 - Set, unfiltered."
                echo "2 - Set, filtered ads, tracker, malware. (With AdGuard blocklist)"
                echo "3 - Set, family filter."
                echo "4 - Exit"
                read -p "Enter Number: " dns_adguard_select

                if [ $dns_adguard_select == 1 ]; then
                    start_resolv_conf
                    put_resolv_conf 94.140.14.140#unfiltered.adguard-dns.com
                    put_resolv_conf 94.140.14.141#unfiltered.adguard-dns.com
                    put_resolv_conf 2a10:50c0::1:ff#unfiltered.adguard-dns.com
                    put_resolv_conf 2a10:50c0::2:ff#unfiltered.adguard-dns.com
                    complete_resolv_conf
                    restart_network_services
                    notify-send "AdGuard DNS (unfiltered) Installed" --expire-time=1000
                    main_memu

                elif [ $dns_adguard_select == 2 ]; then
                    start_resolv_conf
                    put_resolv_conf 94.140.14.14#dns.adguard-dns.com
                    put_resolv_conf 94.140.14.141#dns.adguard-dns.com
                    put_resolv_conf 2a10:50c0::ad1:ff#dns.adguard-dns.com
                    put_resolv_conf 2a10:50c0::ad2:ff#dns.adguard-dns.com
                    complete_resolv_conf
                    restart_network_services
                    notify-send "AdGuard DNS (filtered AdGuard) Installed" --expire-time=1000
                    main_memu

                elif [ $dns_adguard_select == 3 ]; then
                    start_resolv_conf
                    put_resolv_conf 94.140.14.15#family.adguard-dns.com
                    put_resolv_conf 94.140.15.16#family.adguard-dns.com
                    put_resolv_conf 2a10:50c0::bad1:ff#family.adguard-dns.com
                    put_resolv_conf 2a10:50c0::bad2:ff#family.adguard-dns.com
                    complete_resolv_conf
                    restart_network_services
                    notify-send "AdGuard DNS (family filter) Installed" --expire-time=1000
                    main_memu

                elif [ $dns_adguard_select == 4 ]; then
                    main_memu

                else
                    invalid_input
                    dns_adguard_menu

                fi
            }

            main_memu   # Start main menu
            ;;
         16)
            function build_jitterentropy_rngd {
                echo 'Install GCC'
                sudo dnf install -y gcc

                echo 'Download source jitterentropy-rngd'
                git clone https://github.com/smuellerDD/jitterentropy-rngd.git

                cd ./jitterentropy-rngd

                echo 'Build jitterentropy-rngd'
                make

                echo 'Install jitterentropy-rngd'
                sudo make install

                echo 'Enable jitterentropy'
                sudo systemctl enable --now jitterentropy

                cd ..

                echo 'Remove source and binary'
                rm -rf ./jitterentropy-rngd

                echo
                echo
                read -p "Remove GCC? [Y/n]: " gcc_select

                if [ $gcc_select == n ]; then
                    echo
                    echo "Done"

                else
                    sudo dnf remove -y gcc
                    echo
                    echo "Done"

                fi
            }
            
            function jitterentropy_rngd_install {
                echo "jitterentropy_rngd not found"
                echo
                echo "Build and install jitterentropy_rngd?"
                echo "1 - Yes"
                echo "2 - No"
                read -p "Enter Number: " jitterentropy_rngd_install_select
                    
                if [ $jitterentropy_rngd_install_select == 1 ]; then
                    build_jitterentropy_rngd

                elif [ $jitterentropy_rngd_install_select == 2 ]; then
                    echo "Exit"

                else
                    echo "Invalid Input"

                fi
            }
            
            function verify_jitterentropy_rngd {
                if [ -f "/usr/local/sbin/jitterentropy-rngd" ]; then
                    echo "jitterentropy_rngd already installed"
                    sudo systemctl enable --now jitterentropy

                else
                    jitterentropy_rngd_install

                fi
            }
            
            echo "Enable more entropy sources (jitterentropy_rngd)?"
            echo "1 - Yes"
            echo "2 - No"
            read -p "Enter Number: " jitterentropy_rngd_select
            
            if [ $jitterentropy_rngd_select == 1 ]; then
                verify_jitterentropy_rngd

            elif [ $jitterentropy_rngd_select == 2 ]; then
                echo "Exit"

            else
                echo "Invalid Input"

            fi
            ;;
        99)
            rm -rf /home/$USER/.tmp_FedoraSecurityPlus  # Delete temp dir
            exit 0
            ;;
    esac
done
