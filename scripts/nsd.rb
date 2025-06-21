# Homebrew formula for NSD (Network Sniffing Dashboard)
class Nsd < Formula
  desc "Real-time network traffic monitoring tool with terminal UI"
  homepage "https://github.com/perplext/nsd"
  version "0.7"
  license "MIT"

  # For now, we'll use the GitHub release URL
  # In production, this would point to the actual release artifacts
  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/perplext/nsd/releases/download/v0.7/nsd-0.7-darwin-arm64.tar.gz"
    sha256 "PLACEHOLDER_SHA256_DARWIN_ARM64"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/perplext/nsd/releases/download/v0.7/nsd-0.7-darwin-amd64.tar.gz"
    sha256 "PLACEHOLDER_SHA256_DARWIN_AMD64"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/perplext/nsd/releases/download/v0.7/nsd-0.7-linux-arm64.tar.gz"
    sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/perplext/nsd/releases/download/v0.7/nsd-0.7-linux-amd64.tar.gz"
    sha256 "PLACEHOLDER_SHA256_LINUX_AMD64"
  end

  depends_on "libpcap"

  def install
    bin.install "nsd"
    
    # Install examples
    (share/"nsd").install "examples"
    
    # Install documentation
    doc.install "README.md", "LICENSE"
    
    # Install man page if it exists
    if File.exist?("man/nsd.1")
      man1.install "man/nsd.1"
    end
  end

  def caveats
    <<~EOS
      NSD requires root privileges to capture network packets.
      Run with sudo:
        sudo nsd -i <interface>

      To allow running without sudo (on macOS), you can set capabilities:
        sudo chmod +s #{opt_bin}/nsd

      Example usage:
        sudo nsd -i en0                    # Monitor en0 interface
        sudo nsd -i en0 --theme dark      # Use dark theme
        sudo nsd -i en0 --plugins plugin.so  # Load plugins

      View available interfaces:
        ifconfig -a

      Example files are installed in:
        #{share}/nsd/examples/
    EOS
  end

  test do
    # Basic test to ensure binary runs
    assert_match "nsd", shell_output("#{bin}/nsd --help 2>&1", 0)
  end
end