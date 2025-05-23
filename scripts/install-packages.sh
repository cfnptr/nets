#!/bin/bash
cd "$(dirname "$BASH_SOURCE")"

if [[ "$OSTYPE" == "darwin"* ]]; then
    brew --version > /dev/null
    status=$?

    if [ $status -ne 0 ]; then
        echo "Failed to get Homebrew version, please check if it's installed."
        exit $status
    fi

    brew update && brew install git cmake zlib openssl
    status=$?

    if [ $status -ne 0 ]; then
        echo "Homebrew failed to install required packages."
        exit $status
    fi
else
    apt-get --version > /dev/null
    status=$?

    if [ $status -ne 0 ]; then
        echo "Failed to get apt-get version, please check if it's installed."
        exit $status
    fi

    sudo apt-get update && sudo apt-get install git cmake gcc g++ zlib1g-dev libssl-dev
    status=$?

    if [ $status -ne 0 ]; then
        echo "apt-get failed to install required packages."
        exit $status
    fi
fi

exit 0