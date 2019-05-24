#!/bin/bash

set -e

. /etc/os-release

if [ "$ID" = "fedora" ]; then
    sudo dnf -y install make clang llvm gcc-c++ elfutils-devel
elif [ "$ID" = "ubuntu" ]; then
    sudo apt install --yes clang g++ linux-libc-dev libelf-dev
else
    echo "Warning: '$ID' is not a supported OS."
fi
