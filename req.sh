#!/bin/bash

if [ "$(id -u)" != "0" ]; then
  echo "This script must be run as root. Please use sudo." 1>&2
  exit 1
fi
install_nmap() {
  echo "Installing nmap..."

  if [ -f /etc/debian_version ]; then
    apt-get update
    apt-get install -y nmap
  elif [ -f /etc/redhat-release ]; then
    yum install -y nmap
  elif [ "$(uname)" == "Darwin" ]; then
    brew install nmap
  else
    echo "Unsupported operating system. Please install nmap manually."
    exit 1
  fi
}

install_python_nmap() {
  echo "Installing python-nmap..."

  pip install python-nmap
}

if ! command -v nmap &> /dev/null; then
  install_nmap
else
  echo "nmap is already installed."
fi
if ! command -v pip &> /dev/null; then
  echo "pip is not installed. Installing pip..."
  
  if [ -f /etc/debian_version ]; then
    apt-get update
    apt-get install -y python3-pip
  elif [ -f /etc/redhat-release ]; then
    yum install -y python3-pip
  elif [ "$(uname)" == "Darwin" ]; then
    easy_install pip
  else
    echo "Unsupported operating system. Please install pip manually."
    exit 1
  fi
fi

install_python_nmap

echo "Installation complete. You can now run your Python script."
