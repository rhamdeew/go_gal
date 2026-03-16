#!/bin/bash

# Installation script for Go Crypto Gallery service
set -e

# Default installation directory
INSTALL_DIR="/opt/go_gal"
SERVICE_NAME="go_gal"
SERVICE_FILE="$SERVICE_NAME.service"
BINARY_NAME="go_gal"
BINARY_PATTERN="go_gal*"
SYS_USER="gogal"
SYS_GROUP="gogal"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or using sudo"
  exit 1
fi

echo "=== Go Crypto Gallery Installation ==="
echo ""

# --- Security Configuration ---
echo "--- Security Configuration ---"
echo ""
read -rp "Session key (press Enter to generate randomly): " SESSION_KEY
if [ -z "$SESSION_KEY" ]; then
  SESSION_KEY=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)
  echo "  Generated random session key."
fi

read -rp "Password salt (press Enter to generate randomly): " SALT
if [ -z "$SALT" ]; then
  SALT=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)
  echo "  Generated random salt."
fi

echo ""

# --- Network Configuration ---
echo "--- Network Configuration ---"
echo ""
read -rp "Host to bind to [0.0.0.0]: " HOST
HOST=${HOST:-0.0.0.0}

read -rp "Port [8080]: " PORT
PORT=${PORT:-8080}

echo ""

# --- SSL/TLS Configuration ---
echo "--- SSL/TLS Mode ---"
echo ""
echo "  1) None (HTTP only)"
echo "  2) Manual (provide certificate and key files)"
echo "  3) Automated (Let's Encrypt / ACME)"
echo ""
read -rp "SSL mode [1]: " SSL_CHOICE
SSL_CHOICE=${SSL_CHOICE:-1}

SSL_OPTS=""
ENABLE_SSL=false
ENABLE_ACME=false

case "$SSL_CHOICE" in
  2)
    ENABLE_SSL=true
    echo ""
    read -rp "Path to certificate file [cert.pem]: " CERT_FILE
    CERT_FILE=${CERT_FILE:-cert.pem}
    read -rp "Path to key file [key.pem]: " KEY_FILE
    KEY_FILE=${KEY_FILE:-key.pem}
    ;;
  3)
    ENABLE_ACME=true
    echo ""
    read -rp "Domain name (e.g. example.com): " ACME_DOMAIN
    if [ -z "$ACME_DOMAIN" ]; then
      echo "Error: domain name is required for Let's Encrypt"
      exit 1
    fi
    read -rp "Email for Let's Encrypt notifications: " ACME_EMAIL
    ;;
esac

echo ""
echo "Installing Go Crypto Gallery to $INSTALL_DIR..."
echo ""

# Create system group if it doesn't exist
if ! getent group "$SYS_GROUP" > /dev/null; then
  echo "Creating system group $SYS_GROUP..."
  groupadd --system "$SYS_GROUP"
fi

# Create system user if it doesn't exist
if ! getent passwd "$SYS_USER" > /dev/null; then
  echo "Creating system user $SYS_USER..."
  useradd --system --gid "$SYS_GROUP" --no-create-home --shell /usr/sbin/nologin "$SYS_USER"
fi

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

if [ ! -f "$INSTALL_DIR/static/images/favicon.ico" ]; then
  echo "Warning: favicon.ico not found - browsers may show default icon"
fi

# Create data directories
mkdir -p "$INSTALL_DIR/gallery"
mkdir -p "$INSTALL_DIR/thumbnails"

# Configure SSL options
if [ "$ENABLE_ACME" = true ]; then
  ACME_CACHE_DIR="$INSTALL_DIR/acme-cache"
  mkdir -p "$ACME_CACHE_DIR"
  SSL_OPTS="--acme --acme-domain=$ACME_DOMAIN --acme-cache=$ACME_CACHE_DIR"
  if [ -n "$ACME_EMAIL" ]; then
    SSL_OPTS="$SSL_OPTS --acme-email=$ACME_EMAIL"
  fi
elif [ "$ENABLE_SSL" = true ]; then
  INSTALL_CERT="$INSTALL_DIR/$(basename "$CERT_FILE")"
  INSTALL_KEY="$INSTALL_DIR/$(basename "$KEY_FILE")"
  SSL_OPTS="--ssl --cert=$INSTALL_CERT --key=$INSTALL_KEY"
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

# Add environment variables for security
if grep -q "^Environment=\"GO_GAL_SESSION_KEY=" "/etc/systemd/system/$SERVICE_FILE"; then
  sed -i "s|^Environment=\"GO_GAL_SESSION_KEY=.*\"|Environment=\"GO_GAL_SESSION_KEY=$SESSION_KEY\"|" "/etc/systemd/system/$SERVICE_FILE"
else
  sed -i "/^Environment=\"SSL_OPTS=/ a Environment=\"GO_GAL_SESSION_KEY=$SESSION_KEY\"" "/etc/systemd/system/$SERVICE_FILE"
fi

if grep -q "^Environment=\"GO_GAL_SALT=" "/etc/systemd/system/$SERVICE_FILE"; then
  sed -i "s|^Environment=\"GO_GAL_SALT=.*\"|Environment=\"GO_GAL_SALT=$SALT\"|" "/etc/systemd/system/$SERVICE_FILE"
else
  sed -i "/^Environment=\"GO_GAL_SESSION_KEY=/ a Environment=\"GO_GAL_SALT=$SALT\"" "/etc/systemd/system/$SERVICE_FILE"
fi

if [ "$ENABLE_SSL" = true ] || [ "$ENABLE_ACME" = true ]; then
  if grep -q "^Environment=\"GO_GAL_SSL_ENABLED=" "/etc/systemd/system/$SERVICE_FILE"; then
    sed -i "s|^Environment=\"GO_GAL_SSL_ENABLED=.*\"|Environment=\"GO_GAL_SSL_ENABLED=true\"|" "/etc/systemd/system/$SERVICE_FILE"
  else
    sed -i "/^Environment=\"GO_GAL_SALT=/ a Environment=\"GO_GAL_SSL_ENABLED=true\"" "/etc/systemd/system/$SERVICE_FILE"
  fi
fi

# For ACME mode: allow binding to ports 80 and 443
if [ "$ENABLE_ACME" = true ]; then
  if ! grep -q "AmbientCapabilities" "/etc/systemd/system/$SERVICE_FILE"; then
    sed -i "/^NoNewPrivileges=/ a AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE" "/etc/systemd/system/$SERVICE_FILE"
  fi
fi

# Add or update Group directive in service file
if grep -q "^Group=" "/etc/systemd/system/$SERVICE_FILE"; then
  sed -i "s|^Group=.*|Group=$SYS_GROUP|" "/etc/systemd/system/$SERVICE_FILE"
else
  sed -i "/^User=/ a Group=$SYS_GROUP" "/etc/systemd/system/$SERVICE_FILE"
fi

# Add or update User directive in service file
if grep -q "^User=" "/etc/systemd/system/$SERVICE_FILE"; then
  sed -i "s|^User=.*|User=$SYS_USER|" "/etc/systemd/system/$SERVICE_FILE"
else
  sed -i "/^Group=/ i User=$SYS_USER" "/etc/systemd/system/$SERVICE_FILE"
fi

# Set proper permissions
chown -R $SYS_USER:$SYS_GROUP "$INSTALL_DIR"
chmod -R 750 "$INSTALL_DIR"
chmod 770 "$INSTALL_DIR/gallery"
chmod 770 "$INSTALL_DIR/thumbnails"
if [ "$ENABLE_ACME" = true ]; then
  chmod 700 "$INSTALL_DIR/acme-cache"
fi

# Reload systemd configuration
systemctl daemon-reload

echo ""
echo "Installation completed successfully!"
echo "You can start the service with: systemctl start $SERVICE_NAME"
echo "To enable automatic start at boot: systemctl enable $SERVICE_NAME"
