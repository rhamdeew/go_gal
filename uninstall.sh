#!/bin/bash

# Uninstallation script for Go Crypto Gallery service
set -e

SERVICE_NAME="go_gal"
INSTALL_DIR="/opt/go_gal"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --dir=*)
      INSTALL_DIR="${1#*=}"
      shift
      ;;
    --help)
      echo "Usage: $0 [OPTIONS]"
      echo "Options:"
      echo "  --dir=DIR      Installation directory to remove (default: /opt/go_gal)"
      echo "  --help         Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or using sudo"
  exit 1
fi

echo "Uninstalling Go Crypto Gallery from $INSTALL_DIR..."

# Stop and disable the service if it exists
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
  echo "Stopping $SERVICE_NAME service..."
  systemctl stop "$SERVICE_NAME"
fi

if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
  echo "Disabling $SERVICE_NAME service..."
  systemctl disable "$SERVICE_NAME"
fi

# Remove the service file
if [ -f "/etc/systemd/system/$SERVICE_NAME.service" ]; then
  echo "Removing service file..."
  rm "/etc/systemd/system/$SERVICE_NAME.service"
  systemctl daemon-reload
fi

# Ask for confirmation before removing installation directory
read -p "Do you want to remove the installation directory $INSTALL_DIR? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  echo "Removing installation directory..."
  rm -rf "$INSTALL_DIR"
  echo "Installation directory removed."
else
  echo "Installation directory has been kept."
fi

echo "Uninstallation completed successfully!"