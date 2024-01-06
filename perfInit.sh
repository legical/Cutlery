#!/bin/bash

sudo apt-get install linux-tools-common -y
sudo apt-get install linux-tools-"$(uname -r)" -y
sudo apt-get install linux-cloud-tools-"$(uname -r)" -y
sudo apt-get install linux-tools-generic -y
sudo apt-get install linux-cloud-tools-generic -y
