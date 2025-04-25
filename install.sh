#!/bin/bash

# Installation script for Go Crypto Gallery service
set -e

# Default installation directory
INSTALL_DIR="/opt/go_gal"
SERVICE_NAME="go_gal"
SERVICE_FILE="$SERVICE_NAME.service"
BINARY_NAME="go_gal"
BINARY_PATTERN="go_gal*"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --dir=*)
      INSTALL_DIR="${1#*=}"
      shift
      ;;
    --port=*)
      PORT="${1#*=}"
      shift
      ;;
    --host=*)
      HOST="${1#*=}"
      shift
      ;;
    --enable-ssl)
      ENABLE_SSL=true
      shift
      ;;
    --cert=*)
      CERT_FILE="${1#*=}"
      shift
      ;;
    --key=*)
      KEY_FILE="${1#*=}"
      shift
      ;;
    --help)
      echo "Usage: $0 [OPTIONS]"
      echo "Options:"
      echo "  --dir=DIR          Installation directory (default: /opt/go_gal)"
      echo "  --port=PORT        Port to listen on (default: 8080)"
      echo "  --host=HOST        Host to bind to (default: 0.0.0.0)"
      echo "  --enable-ssl       Enable SSL/TLS"
      echo "  --cert=FILE        Path to SSL certificate (default: cert.pem)"
      echo "  --key=FILE         Path to SSL key (default: key.pem)"
      echo "  --help             Show this help message"
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

# Set default values if not specified
PORT=${PORT:-8080}
HOST=${HOST:-0.0.0.0}
CERT_FILE=${CERT_FILE:-cert.pem}
KEY_FILE=${KEY_FILE:-key.pem}

echo "Installing Go Crypto Gallery to $INSTALL_DIR..."

# Create installation directory
mkdir -p "$INSTALL_DIR"

# Find appropriate binary (handles naming like go_gal_linux_amd64)
FOUND_BINARY=""
for f in $BINARY_PATTERN; do
  if [ -e "$f" ] && [ -x "$f" ]; then
    FOUND_BINARY="$f"
    break
  fi
done

if [ -z "$FOUND_BINARY" ]; then
  # Check for exact binary name as fallback
  if [ -e "$BINARY_NAME" ]; then
    FOUND_BINARY="$BINARY_NAME"
  else
    echo "Error: No binary matching $BINARY_PATTERN or $BINARY_NAME found. Please build the application first."
    exit 1
  fi
fi

echo "Using binary: $FOUND_BINARY"
cp "$FOUND_BINARY" "$INSTALL_DIR/$BINARY_NAME"
chmod +x "$INSTALL_DIR/$BINARY_NAME"

# Copy templates, static directory, and other required files
cp -r templates "$INSTALL_DIR/" 2>/dev/null || echo "Warning: templates directory not found"
cp -r static "$INSTALL_DIR/" 2>/dev/null || echo "Warning: static directory not found"

# Create gallery directory
mkdir -p "$INSTALL_DIR/gallery"

# Configure SSL options if enabled
SSL_OPTS=""
if [ "$ENABLE_SSL" = true ]; then
  SSL_OPTS="--ssl --cert=$CERT_FILE --key=$KEY_FILE"
  # Copy certificate files if they exist
  if [ -f "$CERT_FILE" ]; then
    cp "$CERT_FILE" "$INSTALL_DIR/"
  fi
  if [ -f "$KEY_FILE" ]; then
    cp "$KEY_FILE" "$INSTALL_DIR/"
  fi
fi

# Copy service file
cp "$SERVICE_FILE" "/etc/systemd/system/"

# Configure the service environment
sed -i "s|WorkingDirectory=.*|WorkingDirectory=$INSTALL_DIR|" "/etc/systemd/system/$SERVICE_FILE"
sed -i "s|ExecStart=.*|ExecStart=$INSTALL_DIR/$BINARY_NAME --port=\${PORT} --host=\${HOST} \$SSL_OPTS|" "/etc/systemd/system/$SERVICE_FILE"
sed -i "s|Environment=\"PORT=.*\"|Environment=\"PORT=$PORT\"|" "/etc/systemd/system/$SERVICE_FILE"
sed -i "s|Environment=\"HOST=.*\"|Environment=\"HOST=$HOST\"|" "/etc/systemd/system/$SERVICE_FILE"
sed -i "s|Environment=\"SSL_OPTS=.*\"|Environment=\"SSL_OPTS=$SSL_OPTS\"|" "/etc/systemd/system/$SERVICE_FILE"

# Set proper permissions - use a system user that always exists
chown -R root:root "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"

# Reload systemd configuration
systemctl daemon-reload

echo "Installation completed successfully!"
echo "You can start the service with: systemctl start $SERVICE_NAME"
echo "To enable automatic start at boot: systemctl enable $SERVICE_NAME"