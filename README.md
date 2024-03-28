# FedoraSecurityPlus

[![GPLv3 license](https://img.shields.io/badge/License-GPLv3-blue.svg)](./LICENSE)

FedoraSecurityPlus is a script for enhancing Fedora security.

This script has been tested for: Fedora 39, Fedora 38.



## Install

Clone this repo
```sh
git clone https://github.com/topminipie/FedoraSecurityPlus
```

Switch directory
```sh
cd ~/FedoraSecurityPlus
```

Make it executable
```sh
chmod +x FedoraSecurityPlus.sh
```

Execute it (read [Usage](#usage) before executing)
```sh
./FedoraSecurityPlus.sh
```

## Usage

`basic-dnf.txt` > Really basic software, and needed for the script anyway. You probably don't want to edit it (but you **CAN**).

`extras-dns.txt` > Bunch of software that you probably need, you **MUST** edit it to fit your needs.

`flatpak-packages.txt` > Bunch of most used flatpak softwares, you **MUST** edit it to fit your needs. Check [Flathub](https://flathub.org/home) and search your software to find the flatpak ID.

## Known Issues

#### ptrace

(0) - Full allow ptrace for all processes
```sh
  sudo sed -i 's/kernel.yama.ptrace_scope=3/kernel.yama.ptrace_scope=0/g' /etc/sysctl.d/990-security-misc.conf
```
(1) - [Kernel Doc](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
```sh
  sudo sed -i 's/kernel.yama.ptrace_scope=3/kernel.yama.ptrace_scope=1/g' /etc/sysctl.d/990-security-misc.conf
```
(2) - Only processes with CAP_SYS_PTRACE (or root) may use ptrace
```sh
  sudo sed -i 's/kernel.yama.ptrace_scope=3/kernel.yama.ptrace_scope=2/g' /etc/sysctl.d/990-security-misc.conf
```
A workaround for WINE would be to give the wineserver and wine-preloader ptrace capabilities.
Fix:
```sh
  sudo dnf install libcap
  sudo setcap cap_sys_ptrace=eip /usr/bin/wineserver
  sudo setcap cap_sys_ptrace=eip /usr/bin/wine-preloader
```
(3) - Full disable ptrace (default in FedoraSecurityPlus)
```sh
  sudo sed -i 's/kernel.yama.ptrace_scope=3/kernel.yama.ptrace_scope=3/g' /etc/sysctl.d/990-security-misc.conf
```

#

#### MAC randomization and IPv6 Privacy...

Read more about the problems [here](https://github.com/Kicksecure/security-misc/issues/184)

Delete configs:
```sh
  sudo rm -f /etc/NetworkManager/conf.d/80_ipv6-privacy.conf
  sudo rm -f /etc/NetworkManager/conf.d/80_randomize-mac.conf
  sudo rm -f /etc/systemd/networkd.conf.d/80_ipv6-privacy-extensions.conf
```

## Credits

[PYFO](https://github.com/d4rklynk/PYFO) ([GPL-3.0](https://github.com/d4rklynk/PYFO/blob/main/LICENSE))

[fedora-setup](https://github.com/smittix/fedora-setup) ([GPL-3.0](https://github.com/smittix/fedora-setup/blob/main/LICENSE))

[Brace](https://github.com/divestedcg/Brace) ([GPL-3.0](https://github.com/divestedcg/Brace/blob/master/LICENSE))

[Privacy.sexy](https://privacy.sexy) ([AGPL-3.0](https://github.com/undergroundwires/privacy.sexy/blob/master/LICENSE))

[GrapheneOS Configs](https://github.com/GrapheneOS/infrastructure) ([MIT](https://github.com/GrapheneOS/infrastructure/blob/main/LICENSE))

[Kicksecure Configs](https://github.com/Kicksecure/security-misc) ([AGPL-3.0](https://github.com/Kicksecure/security-misc/blob/master/debian/copyright))

[Privsec Linux Hardening](https://privsec.dev/posts/linux/desktop-linux-hardening) ([CC BY-SA 4.0](https://github.com/PrivSec-dev/privsec.dev/blob/main/LICENSE.md))

[Madaidans Linux Hardening](https://madaidans-insecurities.github.io/guides/linux-hardening.html) (*¯\ _ (ツ)_/¯*)

[PrivacyGuides.org](https://www.privacyguides.org/) ([CC-BY-ND-4.0](https://github.com/privacyguides/privacyguides.org/blob/main/LICENSE))
