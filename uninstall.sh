#!/bin/bash

# Uninstallation script for Go Crypto Gallery service
set -e

SERVICE_NAME="go_gal"
INSTALL_DIR="/opt/go_gal"
SYS_USER="gogal"
SYS_GROUP="gogal"
REMOVE_GROUP=false
REMOVE_USER=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --dir=*)
      INSTALL_DIR="${1#*=}"
      shift
      ;;
    --remove-group)
      REMOVE_GROUP=true
      shift
      ;;
    --remove-user)
      REMOVE_USER=true
      shift
      ;;
    --remove-all)
      REMOVE_GROUP=true
      REMOVE_USER=true
      shift
      ;;
    --help)
      echo "Usage: $0 [OPTIONS]"
      echo "Options:"
      echo "  --dir=DIR      Installation directory to remove (default: /opt/go_gal)"
      echo "  --remove-group Remove the gogal system group"
      echo "  --remove-user  Remove the gogal system user"
      echo "  --remove-all   Remove both the user and group"
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
read -p "Do you want to remove the installation directory $INSTALL_DIR? This will delete all gallery data and thumbnails. (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  echo "Removing installation directory..."
  rm -rf "$INSTALL_DIR"
  echo "Installation directory removed."
else
  echo "Installation directory has been kept."
fi

# Remove system user if requested
if [ "$REMOVE_USER" = true ]; then
  if getent passwd "$SYS_USER" > /dev/null; then
    echo "Removing $SYS_USER system user..."
    userdel "$SYS_USER"
    echo "System user removed."
  else
    echo "System user $SYS_USER does not exist."
  fi
else
  echo "System user $SYS_USER has been kept. Use --remove-user to remove it."
fi

# Remove system group if requested
if [ "$REMOVE_GROUP" = true ]; then
  if getent group "$SYS_GROUP" > /dev/null; then
    echo "Removing $SYS_GROUP system group..."
    groupdel "$SYS_GROUP"
    echo "System group removed."
  else
    echo "System group $SYS_GROUP does not exist."
  fi
else
  echo "System group $SYS_GROUP has been kept. Use --remove-group to remove it."
fi

echo "Uninstallation completed successfully!"