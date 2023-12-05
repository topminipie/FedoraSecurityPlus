# FedoraSecurityPlus
FedoraSecurityPlus is a post-install script for upstream version of Fedora. It also focuses on security.

This script has been tested for: none (Coming soon)

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

## Credits

[PYFO](https://github.com/d4rklynk/PYFO) ([GPL-3.0](https://github.com/d4rklynk/PYFO/blob/main/LICENSE))

[fedora-setup](https://github.com/smittix/fedora-setup) ([GPL-3.0](https://github.com/smittix/fedora-setup/blob/main/LICENSE))

[Brace](https://github.com/divestedcg/Brace) ([GPL-3.0](https://github.com/divestedcg/Brace/blob/master/LICENSE))

[Privacy.sexy](https://privacy.sexy) ([AGPL-3.0](https://github.com/undergroundwires/privacy.sexy/blob/master/LICENSE))

[GrapheneOS Configs](https://github.com/GrapheneOS/infrastructure) ([MIT](https://github.com/GrapheneOS/infrastructure/blob/main/LICENSE))

[Kicksecure Configs](https://github.com/Kicksecure/security-misc) (AGPL-3.0)

[Privsec Linux Hardening](https://privsec.dev/posts/linux/desktop-linux-hardening) (CC BY-SA 4.0)

[Madaidans Linux Hardening](https://madaidans-insecurities.github.io/guides/linux-hardening.html) (¯\_ (ツ)_/¯)

[PrivacyGuides.org](https://www.privacyguides.org/) ([LICENSE](https://github.com/privacyguides/privacyguides.org/blob/main/LICENSE))
