#!/bin/bash
cd "$(dirname "$BASH_SOURCE")"

if command -v apt-get &> /dev/null; then
    sudo apt-get update && sudo apt-get install -y git cmake build-essential libssl-dev libcurl4-openssl-dev
elif command -v dnf &> /dev/null; then
    sudo dnf check-update && sudo dnf install -y git cmake @c-development openssl-devel libcurl-devel
elif command -v pacman &> /dev/null; then
    sudo pacman -Syu --noconfirm git cmake base-devel openssl curl
elif command -v zypper &> /dev/null; then
    sudo zypper install -y git cmake libopenssl-devel libcurl-devel -t pattern devel_basis
elif command -v apk &> /dev/null; then
    apk add --no-cache git cmake build-base openssl-dev curl-dev
elif command -v brew &> /dev/null; then
    brew update && brew install git cmake openssl curl
else
    echo "No supported package manager found."
    exit 1
fi
