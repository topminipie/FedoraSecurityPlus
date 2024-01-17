# FedoraSecurityPlus

[![GPLv3 license](https://img.shields.io/badge/License-GPLv3-blue.svg)](./LICENSE)

FedoraSecurityPlus is a post-install script for upstream version of Fedora. It also focuses on security.

This script has been tested for: Fedora 39, Fedora 38.

It is meant to use right after you installed Fedora. This script will just install needed software that most people probably use.
So you will not have a bunch of sketchy software that you don't need.

## Install

Clone this repo

`git clone https://github.com/topminipie/FedoraSecurityPlus`

Switch directory

`cd ~/FedoraSecurityPlus`

Make it executable

`chmod +x FedoraSecurityPlus.sh`

Execute it (read [Usage](#usage) before executing)

`./FedoraSecurityPlus.sh`

## Usage

`basic-dnf.txt` > Really basic software, and needed for the script anyway. You probably don't want to edit it (but you **CAN**).

`extras-dns.txt` > Bunch of software that you probably need, you **MUST** edit it to fit your needs.

`flatpak-packages.txt` > Bunch of most used flatpak softwares, you **MUST** edit it to fit your needs. Check [Flathub](https://flathub.org/home) and search your software to find the flatpak ID.

## Known Issues

Restricts the use of ptrace to root. This might break some programs running under WINE.
A workaround for WINE would be to give the wineserver and wine-preloader ptrace capabilities.
Fix:
```
  sudo dnf install libcap
  sudo setcap cap_sys_ptrace=eip /usr/bin/wineserver
  sudo setcap cap_sys_ptrace=eip /usr/bin/wine-preloader
```
or globally enable for all processes
```
  sed -i 's/kernel.yama.ptrace_scope=2/kernel.yama.ptrace_scope=3/g' /etc/sysctl.d/30_security-misc.conf
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

[PrivacyGuides.org](https://www.privacyguides.org/) ([LICENSE](https://github.com/privacyguides/privacyguides.org/blob/main/LICENSE))
