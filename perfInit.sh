#!/bin/bash

sudo apt update

sudo apt-get install linux-tools-common -y
sudo apt-get install linux-tools-"$(uname -r)" -y
sudo apt-get install linux-cloud-tools-"$(uname -r)" -y
sudo apt-get install linux-tools-generic -y
sudo apt-get install linux-cloud-tools-generic -y

sudo apt-get install -y cargo python2 cmake g++ git bison libz3-dev  ninja-build python3-pip zlib1g-dev
sudo apt-get install libtool-bin libgtk2.0-dev -y

pip3 install matplotlib
pip3 install lit
pip3 install angr

# 安装angr-utils
pip3 install angr-utils