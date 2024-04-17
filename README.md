# PTATM-AFL

This repository contains code developed under:
- Ubuntu 22.04 LTS
- kernel version 5.19.0-x

If your kernel version does not match or you want to downgrade to 5.19.0-x kernel, please refer to [this link](https://www.haoyep.com/posts/ptatm-1/).

## Environment

- Python 3.10.12

## Installation Instructions

Before running the project, ensure that you have the necessary dependencies installed. Follow the steps below:

1. **Update package lists**:

```bash
sudo apt update
```

2. **Install Linux Tools**:

Install Linux tools corresponding to the current kernel version:

```bash
sudo apt-get install linux-tools-common -y
sudo apt-get install linux-tools-$(uname -r) -y
sudo apt-get install linux-cloud-tools-$(uname -r) -y
sudo apt-get install linux-tools-generic -y
sudo apt-get install linux-cloud-tools-generic -y
```

3. **Install Development Tools**:

Install various development tools and libraries:

```bash
sudo apt-get install -y cargo python2 cmake g++ git bison libz3-dev ninja-build python3-pip zlib1g-dev
sudo apt-get install libtool-bin libgtk2.0-dev -y
```

4. **Install Additional Packages**:

Install additional packages such as jq and Python libraries:

```bash
sudo apt install jq -y
sudo apt install -y python3-pip
```

5. **Install Python Libraries**:

Install required Python libraries using pip3:

```bash
pip3 install matplotlib
pip3 install lit
pip3 install angr
pip3 install angr-utils
pip3 install gcovr
```

6. **Install AFL (American Fuzzy Lop)**:

Ensure you have AFL (American Fuzzy Lop) installed by following these steps:
- Change directory to the "AFL" directory within your project directory.
- Execute the following command with administrator privileges to install AFL:

```bash
cd path/to/your/project/AFL
sudo make install
```

These commands do the following:

- `sudo apt update`: Updates package lists to ensure you have the latest versions.
- Linux Tools installation: Installs Linux tools for the current kernel version and generic Linux tools.
- Development Tools installation: Installs various development tools and libraries required for building and compiling.
- Additional Packages installation: Installs jq, a command-line JSON processor, and Python3-pip.
- Python Libraries installation: Installs Matplotlib, Lit, Angr, Angr Utils, and gcovr using pip3 for Python dependencies.
- AFL Installation: Installs AFL by compiling and installing it from source. Ensure to change directory to the AFL directory within your project and execute `make install` with administrator privileges.

Ensure all dependencies are correctly installed before running the project.