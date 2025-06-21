#!/bin/bash
set -e

# This script builds all OS-specific packages for NSD

echo "Building all packages for NSD..."

# Get version
VERSION=$(git describe --tags --always --dirty | sed 's/^v//')
echo "Version: $VERSION"

# Clean previous builds
rm -rf dist
mkdir -p dist

# Build basic tar.gz packages for all platforms
echo "=== Building tar.gz packages ==="
./scripts/build-packages.sh

# Check for required tools and build additional packages
if command -v dpkg-deb >/dev/null 2>&1; then
    echo "=== Building DEB packages ==="
    ./scripts/build-deb.sh
else
    echo "Skipping DEB packages (dpkg-deb not found)"
fi

if command -v rpmbuild >/dev/null 2>&1; then
    echo "=== Building RPM packages ==="
    ./scripts/build-rpm.sh
else
    echo "Skipping RPM packages (rpmbuild not found)"
fi

# Update Homebrew formula with actual SHA256 checksums
if [ -f dist/SHA256SUMS ]; then
    echo "=== Updating Homebrew formula ==="
    
    # Extract SHA256 for each platform
    SHA_DARWIN_ARM64=$(grep "darwin-arm64.tar.gz" dist/SHA256SUMS | cut -d' ' -f1)
    SHA_DARWIN_AMD64=$(grep "darwin-amd64.tar.gz" dist/SHA256SUMS | cut -d' ' -f1)
    SHA_LINUX_ARM64=$(grep "linux-arm64.tar.gz" dist/SHA256SUMS | cut -d' ' -f1)
    SHA_LINUX_AMD64=$(grep "linux-amd64.tar.gz" dist/SHA256SUMS | cut -d' ' -f1)
    
    # Create updated formula
    cp scripts/nsd.rb dist/nsd.rb
    sed -i.bak "s/PLACEHOLDER_SHA256_DARWIN_ARM64/$SHA_DARWIN_ARM64/g" dist/nsd.rb
    sed -i.bak "s/PLACEHOLDER_SHA256_DARWIN_AMD64/$SHA_DARWIN_AMD64/g" dist/nsd.rb
    sed -i.bak "s/PLACEHOLDER_SHA256_LINUX_ARM64/$SHA_LINUX_ARM64/g" dist/nsd.rb
    sed -i.bak "s/PLACEHOLDER_SHA256_LINUX_AMD64/$SHA_LINUX_AMD64/g" dist/nsd.rb
    rm dist/nsd.rb.bak
fi

# Create release notes
cat > dist/RELEASE_NOTES.md << EOF
# NSD v${VERSION} - Release Packages

## Installation Instructions

### Linux

#### Using tar.gz archive:
\`\`\`bash
# Download the appropriate archive
wget https://github.com/perplext/nsd/releases/download/v${VERSION}/nsd-${VERSION}-linux-amd64.tar.gz

# Extract and install
tar -xzf nsd-${VERSION}-linux-amd64.tar.gz
cd nsd-${VERSION}-linux-amd64
sudo ./install.sh
\`\`\`

#### Using DEB package (Debian/Ubuntu):
\`\`\`bash
# Download and install
wget https://github.com/perplext/nsd/releases/download/v${VERSION}/nsd_${VERSION}_amd64.deb
sudo dpkg -i nsd_${VERSION}_amd64.deb
\`\`\`

#### Using RPM package (Fedora/RHEL/CentOS):
\`\`\`bash
# Download and install
wget https://github.com/perplext/nsd/releases/download/v${VERSION}/nsd-${VERSION}-1.x86_64.rpm
sudo rpm -i nsd-${VERSION}-1.x86_64.rpm
\`\`\`

### macOS

#### Using Homebrew:
\`\`\`bash
# Add tap and install
brew tap perplext/nsd
brew install nsd
\`\`\`

#### Using tar.gz archive:
\`\`\`bash
# Download the appropriate archive
curl -LO https://github.com/perplext/nsd/releases/download/v${VERSION}/nsd-${VERSION}-darwin-arm64.tar.gz

# Extract and install
tar -xzf nsd-${VERSION}-darwin-arm64.tar.gz
cd nsd-${VERSION}-darwin-arm64
sudo ./install.sh
\`\`\`

## Checksums

See \`SHA256SUMS\` file for verification.

## Usage

\`\`\`bash
# View available interfaces
ifconfig -a

# Start monitoring
sudo nsd -i eth0
\`\`\`
EOF

echo "=== Package Summary ==="
echo "Packages created in dist/:"
ls -lh dist/

echo ""
echo "Next steps:"
echo "1. Test the packages locally"
echo "2. Upload to GitHub release with: gh release upload v${VERSION} dist/*"
echo "3. Update Homebrew tap repository with the new formula"