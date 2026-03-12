# Caddy Header Verification

[![License: GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://opensource.org/licenses/GPL-3.0)

**Caddy Header Verification** is a Caddy addon designed to detect bots and potentially malicious clients by inspecting and validating incoming HTTP headers. It helps identify unusual, malformed, or manipulated headers commonly associated with automated or abusive traffic.

⚠️ This project is licensed under **GPL-3.0**.

---

## ✨ Features

- Detects malformed or suspicious HTTP headers
- Helps identify bot or automated traffic
- Integrates as a Caddy middleware
- Includes unit tests for header verification logic

---

## 🚀 Installation

This module must be compiled into a custom Caddy binary.

### Install `xcaddy`

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

## Build Caddy with this module

```bash
xcaddy build --with github.com/IgnifexLabs/CaddyHeaderVerification
```

This produces a custom Caddy binary that includes the header verification middleware.

## ⚙️ Usage

Enable the middleware in your Caddyfile for the sites or routes you want to protect
It is important to change the order in the caddy File. for chromium based applications the client hints are a valuable item and should be integrated. 
```config
{
    order headerchecker before respond
}

:8080 {
    header {
        Accept-CH "Sec-CH-Device-Memory, Sec-CH-DPR, Sec-CH-Prefers-Color-Scheme, Sec-CH-Prefers-Reduced-Motion, Sec-CH-Prefers-Reduced-Transparency, Sec-CH-UA, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Form-Factors, Sec-CH-UA-Full-Version, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Mobile, Sec-CH-UA-Model, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-WoW64, Sec-CH-Viewport-Height, Sec-CH-Viewport-Width, Sec-CH-Width"
        Critical-CH "Sec-CH-Device-Memory, Sec-CH-DPR,Sec-CH-UA, Sec-CH-UA-Arch,Sec-CH-UA-Bitness,Sec-CH-UA-Full-Version, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Mobile, Sec-CH-UA-Model, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-WoW64, Sec-CH-Viewport-Height, Sec-CH-Viewport-Width, Sec-CH-Width"    
    }
    headerchecker
    respond "OK"
}
```
## 🧪 Running Tests

Unit tests are included for validating header detection logic.

## 🤝 Contributing

Contributions are welcome!

Fork the repository

Create a feature or bugfix branch

Submit a pull request with a clear description

Please include tests for new functionality where possible.

## 📝 License

This project is licensed under the GNU General Public License v3.0.
See the LICENSE
