#!/bin/bash
set -e

# Variables
BINARY_NAME="nsd"
VERSION=$(git describe --tags --always --dirty | sed 's/^v//')
RELEASE="1"
DESCRIPTION="Network Sniffing Dashboard - Real-time network traffic monitoring tool"
SUMMARY="Real-time network traffic monitoring tool with terminal UI"
LICENSE="MIT"
URL="https://github.com/perplext/nsd"
PACKAGER="NSD Team <nsd@example.com>"

# Create RPM build directories
BUILD_ROOT="$HOME/rpmbuild"
mkdir -p "$BUILD_ROOT"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Create tarball for sources
echo "Creating source tarball..."
git archive --format=tar.gz --prefix="${BINARY_NAME}-${VERSION}/" -o "$BUILD_ROOT/SOURCES/${BINARY_NAME}-${VERSION}.tar.gz" HEAD

# Create spec file
cat > "$BUILD_ROOT/SPECS/${BINARY_NAME}.spec" << EOF
Name:           $BINARY_NAME
Version:        $VERSION
Release:        $RELEASE%{?dist}
Summary:        $SUMMARY
License:        $LICENSE
URL:            $URL
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  golang >= 1.21
BuildRequires:  libpcap-devel
Requires:       libpcap

%description
$DESCRIPTION

NSD provides real-time network statistics, visual traffic graphs,
and connection details using libpcap for packet capture.
Features include multiple visualization modes, theme support,
internationalization, and a plugin system.

%prep
%setup -q

%build
export GOPATH=\$PWD/go
mkdir -p \$GOPATH

# Build for the target architecture
go build -ldflags="-s -w -X main.version=%{version} -X main.commit=%{_commit} -X main.date=%{_date}" \\
    -o %{name} ./cmd/nsd

%install
rm -rf \$RPM_BUILD_ROOT

# Install binary
install -D -m 0755 %{name} \$RPM_BUILD_ROOT%{_bindir}/%{name}

# Install man page
install -D -m 0644 /dev/stdin \$RPM_BUILD_ROOT%{_mandir}/man1/%{name}.1 << 'MANEOF'
.TH NSD 1 "%{_date}" "%{version}" "NSD Manual"
.SH NAME
nsd \\- Network Sniffing Dashboard
.SH SYNOPSIS
.B nsd
[\\fB\\-i\\fR \\fIinterface\\fR]
[\\fB\\-\\-theme\\fR \\fItheme\\fR]
[\\fB\\-\\-plugins\\fR \\fIplugins\\fR]
[\\fB\\-\\-help\\fR]
.SH DESCRIPTION
NSD is a real-time network traffic monitoring tool with a terminal UI similar to btop.
It provides visual traffic graphs, connection details, and network statistics using libpcap for packet capture.
.SH OPTIONS
.TP
.BR \\-i ", " \\-\\-interface " " \\fIinterface\\fR
Network interface to monitor (required)
.TP
.BR \\-\\-theme " " \\fItheme\\fR
Color theme to use (default, dark, light, monokai, solarized, nord, dracula)
.TP
.BR \\-\\-theme\\-file " " \\fIpath\\fR
Path to custom theme JSON/YAML file
.TP
.BR \\-\\-plugins " " \\fIplugins\\fR
Comma-separated list of plugin .so files to load
.TP
.BR \\-\\-i18n\\-file " " \\fIpath\\fR
Path to JSON translation file
.TP
.BR \\-h ", " \\-\\-help
Display help information
.SH EXAMPLES
Monitor eth0 interface:
.B sudo nsd -i eth0
.SH AUTHOR
NSD Team
.SH SEE ALSO
tcpdump(1), wireshark(1)
MANEOF

# Install documentation
install -D -m 0644 README.md \$RPM_BUILD_ROOT%{_docdir}/%{name}/README.md
install -D -m 0644 LICENSE \$RPM_BUILD_ROOT%{_docdir}/%{name}/LICENSE

# Install examples
mkdir -p \$RPM_BUILD_ROOT%{_datadir}/%{name}/examples
cp -r examples/* \$RPM_BUILD_ROOT%{_datadir}/%{name}/examples/

%clean
rm -rf \$RPM_BUILD_ROOT

%post
# Set capabilities for packet capture without full root
if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw,cap_net_admin+eip %{_bindir}/%{name} || :
fi

%files
%defattr(-,root,root,-)
%{_bindir}/%{name}
%{_mandir}/man1/%{name}.1*
%doc %{_docdir}/%{name}/README.md
%license %{_docdir}/%{name}/LICENSE
%{_datadir}/%{name}/examples

%changelog
* $(date +"%a %b %d %Y") $PACKAGER - $VERSION-$RELEASE
- Initial RPM release

%global _commit $(git rev-parse --short HEAD)
%global _date $(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

# Build RPMs for different architectures
for ARCH in x86_64 aarch64; do
    echo "Building RPM for $ARCH..."
    
    # Use mock or rpmbuild depending on availability
    if command -v mock >/dev/null 2>&1; then
        mock -r "fedora-39-$ARCH" --rebuild "$BUILD_ROOT/SRPMS/${BINARY_NAME}-${VERSION}-${RELEASE}.src.rpm" \
            --resultdir="dist/" --no-clean
    else
        rpmbuild -bb --target "$ARCH" "$BUILD_ROOT/SPECS/${BINARY_NAME}.spec"
        
        # Copy built RPMs to dist
        mkdir -p dist
        find "$BUILD_ROOT/RPMS" -name "*.rpm" -exec cp {} dist/ \;
    fi
done

echo "RPM packages created successfully!"