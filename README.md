# WireGuard to Xray Outbound Converter

A fast, lightweight, and minimal client-side web application to convert WireGuard (`.conf`) configurations into [Xray-core](https://github.com/XTLS/Xray-core) outbound JSON format (compatible with Xray-core 26.x / 26.6.1).

🌐 **Live Web Application**: [https://theneet0.github.io/wg-to-xray/](https://theneet0.github.io/wg-to-xray/)

---

## ✨ Features

- **Material Minimal Black Theme**: Deep OLED black palette (`#000000`), subtle borders, high contrast, and clean typography.
- **100% Client-Side & Private**: Runs entirely in your browser with zero external network requests or server logging.
- **Drag & Drop + File Picker**: Drop `.conf` or `.txt` files directly or browse from your device.
- **Configurable Outbound Options**:
  - `tag` (default: `wireguard`)
  - `domainStrategy` (`ForceIP`, `ForceIPv4`, `ForceIPv6`, `ForceIPv4v6`, `ForceIPv6v4`)
  - `mtu` (auto-detected from `[Interface]` with manual override support)
  - `noKernelTun` (enabled by default for Windows & client environments)
  - `wrapInOutbounds` (optionally wrap in `{"outbounds": [ ... ]}`)
- **WireGuard Reserved Bytes**: Automatically extracts `Reserved` bytes (e.g. `[1, 2, 3]`) from either `[Interface]` or `[Peer]` sections.
- **Multi-Peer Support**: Accurately parses and maps all peers with endpoints, allowed IPs, pre-shared keys, and persistent keepalive.
- **Syntax Highlighting & Export**: Instant formatted JSON preview with one-click **Copy to Clipboard** and **Download JSON**.

---

## 🚀 Usage

### Option 1: Live GitHub Pages
Open the web app directly in your browser:
👉 **[https://theneet0.github.io/wg-to-xray/](https://theneet0.github.io/wg-to-xray/)**

### Option 2: Local / Offline
Clone the repository and open `index.html` in any modern web browser:

```bash
git clone https://github.com/theneet0/wg-to-xray.git
cd wg-to-xray
# Open index.html directly
```

---

## 🧪 Testing

The conversion logic has been verified with 100% test parity against the Python reference parser across multiple configuration variants and edge cases:

```bash
node test_parity.js
node test_html_script.js
```

---

## 📄 License

MIT License
