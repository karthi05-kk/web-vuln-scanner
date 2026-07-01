#!/bin/bash

################################################################################
# Web Vulnerability Scanner - Automated Setup Script
# 
# This script automates the entire setup process including:
# - Creating a virtual environment
# - Installing all dependencies
# - Verifying the installation
# - Creating necessary directories
#
# Usage: bash SETUP.sh
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "\n${BLUE}════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Main setup process
main() {
    print_header "Web Vulnerability Scanner - Setup"
    
    # Check Python version
    print_info "Checking Python version..."
    if ! command -v python3 &> /dev/null; then
        print_error "Python3 not found. Please install Python 3.8 or higher."
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    print_success "Python $PYTHON_VERSION found"
    
    # Check if virtual environment already exists
    if [ -d "venv" ]; then
        print_info "Virtual environment 'venv' already exists"
        read -p "Do you want to recreate it? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_info "Removing existing virtual environment..."
            rm -rf venv
        else
            print_info "Using existing virtual environment"
        fi
    fi
    
    # Create virtual environment
    if [ ! -d "venv" ]; then
        print_info "Creating virtual environment..."
        python3 -m venv venv
        print_success "Virtual environment created"
    fi
    
    # Activate virtual environment
    print_info "Activating virtual environment..."
    source venv/bin/activate
    print_success "Virtual environment activated"
    
    # Upgrade pip
    print_info "Upgrading pip..."
    pip install --upgrade pip > /dev/null 2>&1
    print_success "pip upgraded"
    
    # Install requirements
    print_info "Installing dependencies from requirements.txt..."
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
        print_success "Dependencies installed"
    else
        print_error "requirements.txt not found!"
        exit 1
    fi
    
    # Create reports directory
    print_info "Creating reports directory..."
    mkdir -p reports
    chmod 755 reports
    print_success "Reports directory ready"
    
    # Verify installation
    print_header "Verification"
    
    print_info "Verifying installed packages..."
    PACKAGES_OK=true
    
    # Check each package
    python3 -c "import requests" 2>/dev/null && print_success "requests installed" || { print_error "requests missing"; PACKAGES_OK=false; }
    python3 -c "import reportlab" 2>/dev/null && print_success "reportlab installed" || { print_error "reportlab missing"; PACKAGES_OK=false; }
    python3 -c "import urllib3" 2>/dev/null && print_success "urllib3 installed" || { print_error "urllib3 missing"; PACKAGES_OK=false; }
    
    # Verify main script
    if [ -f "simple_main.py" ]; then
        print_success "simple_main.py found"
    else
        print_error "simple_main.py not found!"
        PACKAGES_OK=false
    fi
    
    # Final status
    print_header "Setup Status"
    
    if [ "$PACKAGES_OK" = true ]; then
        print_success "✓ All checks passed!"
        echo -e "\n${GREEN}Setup Complete!${NC}\n"
        
        echo -e "${YELLOW}Next steps:${NC}"
        echo -e "1. Activate virtual environment (next time you open terminal):"
        echo -e "   ${BLUE}source venv/bin/activate${NC}"
        echo ""
        echo -e "2. Run a scan:"
        echo -e "   ${BLUE}python3 simple_main.py \"http://target.com/page?param=value\" --pdf${NC}"
        echo ""
        echo -e "3. Check results:"
        echo -e "   ${BLUE}ls -la reports/${NC}"
        echo ""
        echo -e "For help:"
        echo -e "   ${BLUE}python3 simple_main.py -h${NC}"
        echo ""
    else
        print_error "Setup completed with errors. Please check the output above."
        exit 1
    fi
}

# Run main function
main
