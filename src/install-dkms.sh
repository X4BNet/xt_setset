#!/bin/bash

# DKMS installation script for xt_setset module

PACKAGE_NAME="xt_setset"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_VERSION="$($SCRIPT_DIR/version.sh)"

error() {
    echo "Error: $*" >&2
    exit 1
}

info() {
    echo "Info: $*"
}

warning() {
    echo "Warning: $*" >&2
}

# Check if we're running as root for DKMS operations
check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "DKMS operations require root privileges. Please run as root or with sudo."
    fi
}

# Check if DKMS is installed
check_dkms() {
    if ! command -v dkms >/dev/null 2>&1; then
        error "DKMS is not installed. Please install dkms package first."
    fi
}

# Install the module via DKMS
dkms_install() {
    check_root
    check_dkms
    
    info "Installing $PACKAGE_NAME $MODULE_VERSION via DKMS..."
    
    # Remove any existing version first
    if dkms status "$PACKAGE_NAME" | grep -q "$MODULE_VERSION"; then
        info "Removing existing DKMS module $PACKAGE_NAME/$MODULE_VERSION"
        dkms remove "$PACKAGE_NAME/$MODULE_VERSION" --all 2>/dev/null || true
    fi
    
    # Copy source to DKMS tree
    DKMS_SRC_DIR="/usr/src/$PACKAGE_NAME-$MODULE_VERSION"
    if [ -d "$DKMS_SRC_DIR" ]; then
        info "Removing existing source directory $DKMS_SRC_DIR"
        rm -rf "$DKMS_SRC_DIR"
    fi
    
    info "Copying source to $DKMS_SRC_DIR"
    mkdir -p "$DKMS_SRC_DIR"
    cp -r "$SCRIPT_DIR"/* "$DKMS_SRC_DIR/"
    
    # Add, build and install the module
    info "Adding module to DKMS tree"
    dkms add "$PACKAGE_NAME/$MODULE_VERSION" || error "Failed to add module to DKMS"
    
    info "Building module with DKMS"
    dkms build "$PACKAGE_NAME/$MODULE_VERSION" || error "Failed to build module with DKMS"
    
    info "Installing module with DKMS"
    dkms install "$PACKAGE_NAME/$MODULE_VERSION" || error "Failed to install module with DKMS"
    
    info "DKMS installation completed successfully"
}

# Uninstall the module via DKMS
dkms_uninstall() {
    check_root
    check_dkms
    
    info "Uninstalling $PACKAGE_NAME via DKMS..."
    
    # Get all installed versions
    INSTALLED_VERSIONS=$(dkms status "$PACKAGE_NAME" 2>/dev/null | grep 'installed' | cut -d',' -f1 | cut -d'/' -f2 || true)
    
    if [ -z "$INSTALLED_VERSIONS" ]; then
        warning "No installed DKMS versions of $PACKAGE_NAME found"
        return 0
    fi
    
    for version in $INSTALLED_VERSIONS; do
        info "Removing DKMS module $PACKAGE_NAME/$version"
        dkms remove "$PACKAGE_NAME/$version" --all 2>/dev/null || true
        
        # Remove source directory
        DKMS_SRC_DIR="/usr/src/$PACKAGE_NAME-$version"
        if [ -d "$DKMS_SRC_DIR" ]; then
            info "Removing source directory $DKMS_SRC_DIR"
            rm -rf "$DKMS_SRC_DIR"
        fi
    done
    
    info "DKMS uninstallation completed"
}

# Show DKMS status
dkms_status() {
    check_dkms
    
    info "DKMS status for $PACKAGE_NAME:"
    if ! dkms status "$PACKAGE_NAME" 2>/dev/null; then
        info "No DKMS modules found for $PACKAGE_NAME"
    fi
}

# Show usage information
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
  --install     Install the module via DKMS
  --uninstall   Uninstall the module via DKMS
  --status      Show DKMS status for the module
  --help        Show this help message

Examples:
  $0 --install    # Install xt_setset module via DKMS
  $0 --uninstall  # Remove xt_setset module from DKMS
  $0 --status     # Show current DKMS status

EOF
}

# Main script logic
case "$1" in
    --install)
        dkms_install
        ;;
    --uninstall)
        dkms_uninstall
        ;;
    --status)
        dkms_status
        ;;
    --help|-h)
        show_usage
        ;;
    *)
        echo "Invalid option: $1" >&2
        show_usage
        exit 1
        ;;
esac