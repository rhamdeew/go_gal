#!/bin/bash

set -e

SERVICE_NAME="go_gal"
INSTALL_DIR="/opt/go_gal"
BACKUP_DIR="/opt/go_gal_backup_$(date +%Y%m%d_%H%M%S)"
REPO="rhamdeew/go_gal"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    case "$ARCH" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    
    echo "${OS}_${ARCH}"
}

get_current_version() {
    if [ -f "$INSTALL_DIR/go_gal" ]; then
        "$INSTALL_DIR/go_gal" --version 2>/dev/null || echo "unknown"
    else
        echo "not installed"
    fi
}

get_latest_release() {
    local api_url="https://api.github.com/repos/${REPO}/releases/latest"
    curl -s "$api_url" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/'
}

get_installed_keys() {
    if [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]; then
        SESSION_KEY=$(grep -oP 'Environment="GO_GAL_SESSION_KEY=\K[^"]+' "/etc/systemd/system/${SERVICE_NAME}.service" 2>/dev/null || echo "")
        SALT=$(grep -oP 'Environment="GO_GAL_SALT=\K[^"]+' "/etc/systemd/system/${SERVICE_NAME}.service" 2>/dev/null || echo "")
        HOST=$(grep -oP 'Environment="HOST=\K[^"]+' "/etc/systemd/system/${SERVICE_NAME}.service" 2>/dev/null || echo "0.0.0.0")
        PORT=$(grep -oP 'Environment="PORT=\K[^"]+' "/etc/systemd/system/${SERVICE_NAME}.service" 2>/dev/null || echo "8080")
        SSL_OPTS=$(grep -oP 'Environment="SSL_OPTS=\K[^"]+' "/etc/systemd/system/${SERVICE_NAME}.service" 2>/dev/null || echo "")
    fi
}

backup_installation() {
    log_info "Creating backup at $BACKUP_DIR..."
    mkdir -p "$BACKUP_DIR"
    cp -r "$INSTALL_DIR"/* "$BACKUP_DIR/" 2>/dev/null || true
    log_info "Backup created successfully"
}

restore_backup() {
    log_error "Update failed, restoring from backup..."
    rm -rf "$INSTALL_DIR"/*
    cp -r "$BACKUP_DIR"/* "$INSTALL_DIR/" 2>/dev/null || true
    systemctl start "$SERVICE_NAME" 2>/dev/null || true
    log_info "Restored from backup"
}

cleanup_backup() {
    if [ -d "$BACKUP_DIR" ]; then
        log_info "Cleaning up backup..."
        rm -rf "$BACKUP_DIR"
    fi
}

download_release() {
    local version="$1"
    local platform="$2"
    local download_url="https://github.com/${REPO}/releases/download/${version}/go_gal_${platform}.tar.gz"
    local temp_dir=$(mktemp -d)
    local archive="${temp_dir}/go_gal.tar.gz"
    
    log_info "Downloading ${version} for ${platform}..."
    
    if ! curl -fsSL "$download_url" -o "$archive"; then
        log_error "Failed to download release"
        rm -rf "$temp_dir"
        exit 1
    fi
    
    log_info "Extracting archive..."
    tar -xzf "$archive" -C "$temp_dir"
    
    echo "$temp_dir"
}

stop_service() {
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        log_info "Stopping service..."
        systemctl stop "$SERVICE_NAME"
    fi
}

start_service() {
    log_info "Starting service..."
    systemctl start "$SERVICE_NAME" || true
    systemctl status "$SERVICE_NAME" --no-pager
    if ! systemctl is-active --quiet "$SERVICE_NAME"; then
        log_error "Service failed to start. Check logs with: journalctl -u $SERVICE_NAME"
        return 1
    fi
}

update_files() {
    local temp_dir="$1"
    
    log_info "Updating files..."
    
    [ -f "$INSTALL_DIR/go_gal" ] && mv "$INSTALL_DIR/go_gal" "$INSTALL_DIR/go_gal.old"
    
    cp "${temp_dir}/go_gal" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/go_gal"
    
    cp -r "${temp_dir}/templates" "$INSTALL_DIR/" 2>/dev/null || true
    cp -r "${temp_dir}/static" "$INSTALL_DIR/" 2>/dev/null || true
    
    if [ -f "${temp_dir}/install.sh" ]; then
        cp "${temp_dir}/install.sh" "$INSTALL_DIR/"
        chmod +x "$INSTALL_DIR/install.sh"
    fi
    
    if [ -f "${temp_dir}/uninstall.sh" ]; then
        cp "${temp_dir}/uninstall.sh" "$INSTALL_DIR/"
        chmod +x "$INSTALL_DIR/uninstall.sh"
    fi
    
    rm -rf "$temp_dir"
    
    chown -R gogal:gogal "$INSTALL_DIR"
}

check_version_flag() {
    if ! grep -q "version" <<< "$("$INSTALL_DIR/go_gal" --help 2>&1)" && \
       ! "$INSTALL_DIR/go_gal" --version 2>/dev/null; then
        log_info "Note: --version flag not available in current binary"
    fi
}

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --version=VERSION   Update to specific version (default: latest)"
    echo "  --no-backup         Skip backup creation (not recommended)"
    echo "  --dry-run           Check for updates without installing"
    echo "  --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                  # Update to latest version"
    echo "  $0 --version=v0.0.26"
    echo "  $0 --dry-run        # Check for updates"
}

main() {
    local target_version=""
    local no_backup=false
    local dry_run=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --version=*)
                target_version="${1#*=}"
                shift
                ;;
            --no-backup)
                no_backup=true
                shift
                ;;
            --dry-run)
                dry_run=true
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run as root or using sudo"
        exit 1
    fi
    
    if [ ! -d "$INSTALL_DIR" ]; then
        log_error "Installation not found at $INSTALL_DIR"
        log_info "Run install.sh first"
        exit 1
    fi
    
    echo ""
    echo "=== Go Gallery Updater ==="
    echo ""
    
    local current_version=$(get_current_version)
    log_info "Current version: $current_version"
    
    if [ -z "$target_version" ]; then
        target_version=$(get_latest_release)
        if [ -z "$target_version" ]; then
            log_error "Failed to get latest release"
            exit 1
        fi
    fi
    
    log_info "Target version: $target_version"
    
    if [ "$current_version" = "$target_version" ]; then
        log_info "Already up to date!"
        exit 0
    fi
    
    if [ "$dry_run" = true ]; then
        log_info "Dry run complete. Run without --dry-run to update."
        exit 0
    fi
    
    get_installed_keys
    
    if [ -z "$SESSION_KEY" ] || [ -z "$SALT" ]; then
        log_error "Could not find encryption keys in service file"
        log_error "Make sure GO_GAL_SESSION_KEY and GO_GAL_SALT are set"
        exit 1
    fi
    
    log_warn "Important: Keep your encryption keys safe!"
    log_info "Session key: ${SESSION_KEY:0:4}****"
    log_info "Salt: ${SALT:0:4}****"
    
    local platform=$(detect_platform)
    log_info "Platform: $platform"
    
    local temp_dir=$(download_release "$target_version" "$platform")
    
    if [ "$no_backup" = false ]; then
        backup_installation
    else
        log_warn "Skipping backup (--no-backup)"
    fi
    
    stop_service
    
    if ! update_files "$temp_dir"; then
        if [ "$no_backup" = false ]; then
            restore_backup
        fi
        exit 1
    fi
    
    rm -f "$INSTALL_DIR/go_gal.old"
    
    if ! start_service; then
        if [ "$no_backup" = false ]; then
            restore_backup
        fi
        exit 1
    fi
    
    if [ "$no_backup" = false ]; then
        cleanup_backup
    fi
    
    echo ""
    log_info "Update complete! Version: $target_version"
    if echo "$SSL_OPTS" | grep -q -- '--acme'; then
        log_info "Service is running at https://localhost:443"
    elif echo "$SSL_OPTS" | grep -q -- '--ssl'; then
        log_info "Service is running at https://localhost:${PORT:-8080}"
    else
        log_info "Service is running at http://localhost:${PORT:-8080}"
    fi
}

main "$@"