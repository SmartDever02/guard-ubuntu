#!/usr/bin/env bash

set -e

echo "========================================"
echo "Updating system..."
echo "========================================"

sudo apt update
sudo apt upgrade -y


echo "========================================"
echo "Installing base dependencies..."
echo "========================================"

sudo apt install -y \
    curl \
    wget \
    git \
    build-essential \
    ca-certificates \
    gnupg \
    software-properties-common \
    unzip \
    jq


echo "========================================"
echo "Installing Python..."
echo "========================================"

sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev

python3 --version


echo "========================================"
echo "Installing NVM..."
echo "========================================"

export NVM_DIR="$HOME/.nvm"

if [ ! -d "$NVM_DIR" ]; then
    curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
fi

# Load nvm immediately
source "$NVM_DIR/nvm.sh"


echo "========================================"
echo "Installing Node.js LTS..."
echo "========================================"

nvm install --lts
nvm use --lts
nvm alias default node

node -v
npm -v


echo "========================================"
echo "Installing PM2..."
echo "========================================"

npm install -g pm2

pm2 -v


echo "========================================"
echo "Configuring PM2 startup..."
echo "========================================"

pm2 startup systemd -u $USER --hp $HOME
pm2 save


echo "========================================"
echo "Creating default Python virtual env folder..."
echo "========================================"

mkdir -p $HOME/venvs


echo "========================================"
echo "Installation Complete"
echo "========================================"

echo ""
echo "Node version: $(node -v)"
echo "NPM version:  $(npm -v)"
echo "PM2 version:  $(pm2 -v)"
echo "Python version: $(python3 --version)"
echo ""
echo "Python virtual envs folder: $HOME/venvs"
echo ""
echo "To create venv:"
echo "python3 -m venv ~/venvs/myenv"
echo "source ~/venvs/myenv/bin/activate"
