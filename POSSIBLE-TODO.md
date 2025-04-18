# Possible TODOs for NetMon

This document lists potential new features, improvements, and style/theme ideas for NetMon.

## Themes & Styles
- **High-Contrast Dark Theme**  
  Deep blacks with bright accent colors (neon green, electric blue) for readability and accessibility.
- **Solarized Light/Dark**  
  Toggle between Solarized light and dark palettes.
- **Monochrome Accessibility Mode**  
  Pure black-and-white UI for users with color vision sensitivities.
- **Dynamic Gradient Styles**  
  Static or animated gradients for graph fills (e.g., blue→cyan, purple→magenta).
- **Custom User-Defined Themes**  
  Load JSON/YAML theme files at runtime for personalized palettes.

## UI & Layout Enhancements
- **Resizable Panels**  
  Keyboard-driven resizing of UI panels.
- **Customizable Layouts**  
  Preset grid layouts: single-focus, dual-split, quad-view.
- **Inline Help & Tooltips**  
  Contextual hover descriptions and keybinding hints.
- **Configurable Hotkeys**  
  Map or remap keys via a config file.
- **Auto Dark/Light Mode**  
  Detect terminal background to auto-switch themes.

## Graph & Visualization Features
- **Multiple Metric Overlays**  
  In/out traffic alongside CPU/memory usage on unified graphs.
- **Interactive Zoom & Pan**  
  Zoom into time windows and pan across history.
- **Logarithmic/Linear Scales**  
  Switch between log and linear scale rendering.
- **Export to SVG/PNG**  
  Save graph snapshots as image files.

## Packet View & Analysis
- **Protocol Color-Coding**  
  Color-code TCP/UDP/ICMP in tables and dumps.
- **Layered Packet Inspection**  
  Expand/collapse views for Ethernet, IP, TCP layers.
- **Search & Filter in Hex Dump**  
  Live search for hex or ASCII patterns.
- **ASCII Art Packet Trees**  
  Simple block-diagrams showing layer relationships.

## Performance & Testing
- **Comprehensive Unit & Integration Tests**  
  Cover formatting, shading, graph logic, and core capture functions.
- **Mockable Screen Interfaces**  
  Abstract tcell screen for headless UI testing.
- **CI/CD Pipeline**  
  Automated testing, linting, and builds (e.g., GitHub Actions).

## Architecture & Extensibility
- **Plugin System**  
  Loadable modules for custom analyzers or metrics.
- **RESTful API**  
  Expose real-time stats over HTTP.
- **Persisted Storage Backend**  
  Optional SQLite/PostgreSQL for historical data.

## Other Ideas
- **Theme Sharing**  
  Export/import theme definitions for sharing.
- **Responsive Layout**  
  Auto-adjust to terminal resizes.
- **Localization**  
  Multi-language support for UI text.

> Next steps: Prioritize features, open issues, and assign tickets.
