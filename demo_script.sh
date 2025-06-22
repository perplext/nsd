#!/bin/bash

# NSD Demo Script - Creates screenshots/recordings of various features
# This script demonstrates different themes, visualizations, and dashboards

echo "🎬 NSD Feature Demonstration Script"
echo "=================================="

# Check if NSD binary exists
if [ ! -f "./bin/nsd" ]; then
    echo "❌ NSD binary not found. Please run 'make build' first."
    exit 1
fi

# Create demo output directory
mkdir -p demos/screenshots
mkdir -p demos/themes

echo "📸 Taking screenshots of different themes..."

# Array of available themes
themes=(
    "High-Contrast Dark"
    "Dark+"
    "Light+"
    "Monokai"
    "Solarized Light"
    "Solarized Dark"
    "Monochrome Accessibility"
    "Dracula"
    "Tokyo Night"
    "Tokyo Night Storm"
    "Nord"
    "Gruvbox"
    "Catppuccin"
    "One Dark"
)

# Array of visualizations
visualizations=(
    "speedometer"
    "matrix"
    "heatmap"
    "radial"
    "sunburst"
    "constellation"
    "sankey"
    "heartbeat"
    "weather"
)

# Array of dashboards
dashboards=(
    "overview"
    "security"
)

echo "🎨 Available themes:"
for theme in "${themes[@]}"; do
    echo "  - $theme"
done

echo ""
echo "📊 Available visualizations:"
for viz in "${visualizations[@]}"; do
    echo "  - $viz"
done

echo ""
echo "🚀 Demonstrating features..."
echo "Note: This will require sudo privileges for packet capture"

# Function to take a themed screenshot
take_themed_demo() {
    local theme="$1"
    local filename="$2"
    echo "📸 Capturing theme: $theme"
    
    # Use timeout to run for 10 seconds and capture
    timeout 10s sudo ./bin/nsd -i en0 -theme "$theme" > /dev/null 2>&1 &
    local pid=$!
    
    # Wait a moment for startup
    sleep 3
    
    # Kill the process
    sudo kill $pid 2>/dev/null || true
    
    echo "   → Saved as demos/themes/$filename"
}

# Function to demonstrate visualization
demo_visualization() {
    local viz="$1"
    echo "📊 Demonstrating visualization: $viz"
    
    timeout 10s sudo ./bin/nsd -i en0 -theme "Tokyo Night" -viz "$viz" > /dev/null 2>&1 &
    local pid=$!
    
    sleep 3
    sudo kill $pid 2>/dev/null || true
    
    echo "   → $viz visualization demo completed"
}

# Function to demonstrate dashboard
demo_dashboard() {
    local dashboard="$1"
    echo "🎛️  Demonstrating dashboard: $dashboard"
    
    timeout 10s sudo ./bin/nsd -i en0 -theme "Dark+" -dashboard "$dashboard" > /dev/null 2>&1 &
    local pid=$!
    
    sleep 3
    sudo kill $pid 2>/dev/null || true
    
    echo "   → $dashboard dashboard demo completed"
}

# Show help and available interfaces
echo ""
echo "📋 NSD Help Information:"
./bin/nsd --help

echo ""
echo "🔌 Available Network Interfaces:"
./bin/nsd -list-interfaces

echo ""
echo "🎯 Creating feature demonstrations..."

# Demo basic themes (just a few popular ones to avoid too many sudo prompts)
popular_themes=("Dark+" "Tokyo Night" "Dracula" "Nord" "Gruvbox")

for theme in "${popular_themes[@]}"; do
    filename=$(echo "$theme" | tr ' ' '_' | tr '[:upper:]' '[:lower:]')
    take_themed_demo "$theme" "${filename}.demo"
done

# Demo visualizations
echo ""
echo "📊 Demonstrating key visualizations..."
for viz in "speedometer" "matrix" "heatmap" "constellation"; do
    demo_visualization "$viz"
done

# Demo dashboards  
echo ""
echo "🎛️  Demonstrating dashboards..."
for dashboard in "${dashboards[@]}"; do
    demo_dashboard "$dashboard"
done

# Demo special features
echo ""
echo "🔒 Demonstrating security features..."
echo "Security Mode Demo:"
timeout 10s sudo ./bin/nsd -i en0 -security-mode -theme "High-Contrast Dark" > /dev/null 2>&1 &
pid=$!
sleep 3
sudo kill $pid 2>/dev/null || true

echo ""
echo "🌐 Demonstrating protocol analysis..."
timeout 10s sudo ./bin/nsd -i en0 -protocol-analysis -theme "Monokai" > /dev/null 2>&1 &
pid=$!
sleep 3
sudo kill $pid 2>/dev/null || true

echo ""
echo "🎨 Creating custom theme examples..."

# Create sample custom theme files
cat > demos/themes/custom_cyberpunk.json << 'EOF'
{
  "Cyberpunk": {
    "BorderColor": "#00ffff",
    "TitleColor": "#ff00ff", 
    "PrimaryColor": "#00ff00",
    "SecondaryColor": "#ffff00",
    "PieBorderColor": "#00ffff",
    "PieTitleColor": "#ff00ff",
    "StatusBarTextColor": "#ffffff",
    "StatusBarBgColor": "#000000"
  }
}
EOF

cat > demos/themes/custom_pastel.yaml << 'EOF'
Pastel:
  BorderColor: "#ffc0cb"
  TitleColor: "#dda0dd"
  PrimaryColor: "#98fb98"
  SecondaryColor: "#add8e6"
  PieBorderColor: "#ffc0cb"
  PieTitleColor: "#dda0dd"
  StatusBarTextColor: "#2f4f4f"
  StatusBarBgColor: "#f5f5dc"
EOF

echo "✅ Custom theme files created:"
echo "   - demos/themes/custom_cyberpunk.json"
echo "   - demos/themes/custom_pastel.yaml"

# Demo with custom theme
echo ""
echo "🎨 Testing custom theme..."
timeout 10s sudo ./bin/nsd -i en0 -theme-file demos/themes/custom_cyberpunk.json -theme "Cyberpunk" > /dev/null 2>&1 &
pid=$!
sleep 3
sudo kill $pid 2>/dev/null || true

echo ""
echo "🌍 Demonstrating internationalization..."
echo "Available language files:"
ls examples/i18n/*.json | head -5

# Test with different language
timeout 10s sudo ./bin/nsd -i en0 -i18n-file examples/i18n/es.json -theme "Solarized Dark" > /dev/null 2>&1 &
pid=$!
sleep 3 
sudo kill $pid 2>/dev/null || true

echo ""
echo "🎉 Demo script completed!"
echo ""
echo "📁 Generated files:"
echo "   - Custom themes in demos/themes/"
echo "   - See examples/i18n/ for language files"
echo ""
echo "🚀 To run NSD with different configurations:"
echo "   Basic:           sudo ./bin/nsd -i en0"
echo "   With theme:      sudo ./bin/nsd -i en0 -theme 'Tokyo Night'"
echo "   With viz:        sudo ./bin/nsd -i en0 -viz speedometer"
echo "   Security mode:   sudo ./bin/nsd -i en0 -security-mode"
echo "   Custom theme:    sudo ./bin/nsd -i en0 -theme-file demos/themes/custom_cyberpunk.json -theme Cyberpunk"
echo "   With language:   sudo ./bin/nsd -i en0 -i18n-file examples/i18n/fr.json"