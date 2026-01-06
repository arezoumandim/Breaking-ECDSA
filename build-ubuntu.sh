#!/bin/bash
# Build script for Ubuntu/Linux

set -e  # stop on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Information
BINARY_NAME="real_transaction_example"
MAIN_FILE="examples/real_transaction_example.go"
OUTPUT_DIR="dist"
VERSION=$(date +%Y%m%d-%H%M%S)

echo -e "${GREEN}🔨 Starting build for Ubuntu/Linux...${NC}"

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "${RED}✗ Error: Go is not installed!${NC}"
    echo "Please install Go from https://golang.org/dl"
    exit 1
fi

# Display Go version
echo -e "${YELLOW}📋 Go version: $(go version)${NC}"

# Check if main file exists
if [ ! -f "$MAIN_FILE" ]; then
    echo -e "${RED}✗ Error: File $MAIN_FILE not found!${NC}"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Build for Linux amd64
echo -e "${GREEN}🔨 Building for Linux (amd64)...${NC}"
GOOS=linux GOARCH=amd64 go build -v -ldflags "-s -w" -o "$OUTPUT_DIR/${BINARY_NAME}-linux-amd64-${VERSION}" "$MAIN_FILE"

# Create symlink to latest version
ln -sf "${BINARY_NAME}-linux-amd64-${VERSION}" "$OUTPUT_DIR/${BINARY_NAME}-linux-amd64-latest"

# Build for Linux arm64 (for Raspberry Pi and ARM servers)
echo -e "${GREEN}🔨 Building for Linux (arm64)...${NC}"
GOOS=linux GOARCH=arm64 go build -v -ldflags "-s -w" -o "$OUTPUT_DIR/${BINARY_NAME}-linux-arm64-${VERSION}" "$MAIN_FILE"
ln -sf "${BINARY_NAME}-linux-arm64-${VERSION}" "$OUTPUT_DIR/${BINARY_NAME}-linux-arm64-latest"

# Display information about built files
echo -e "\n${GREEN}✓ Build completed successfully!${NC}"
echo -e "${YELLOW}📦 Built files:${NC}"
ls -lh "$OUTPUT_DIR"/${BINARY_NAME}-linux-* | awk '{print "  " $9 " (" $5 ")"}'

echo -e "\n${GREEN}📋 Commands to transfer to Ubuntu:${NC}"
echo -e "  ${YELLOW}scp $OUTPUT_DIR/${BINARY_NAME}-linux-amd64-latest user@ubuntu-server:/path/to/destination${NC}"
echo -e "  ${YELLOW}chmod +x /path/to/destination/${BINARY_NAME}-linux-amd64-latest${NC}"
echo -e "  ${YELLOW}/path/to/destination/${BINARY_NAME}-linux-amd64-latest --maxA 10 --maxB 10${NC}"


