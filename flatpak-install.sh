#!/usr/bin/env bash

# Check if flatpak is enabled
if ! flatpak --version > /dev/null 2>&1; then
  echo "Error: flatpak is not enabled on this system"
  exit 1
fi

# Install the packages using flatpak
for PACKAGE in $(cat flatpak-packages.txt); do
  flatpak install -y $PACKAGE
done
