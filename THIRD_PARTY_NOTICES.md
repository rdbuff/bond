# Third-party software

Bond is built on the following projects. Their license texts are in each
module's source; the Wintun license ships next to `wintun.dll`.

| Component | Used for | License |
|---|---|---|
| [Wintun](https://www.wintun.net/) (`wintun.dll`, prebuilt) | Windows tunnel adapter driver | Wintun Prebuilt Binaries License (redistributed unmodified, used only via its API) |
| [wireguard-go](https://git.zx2c4.com/wireguard-go) `tun` package | TUN devices on Windows (Wintun) and Linux (GSO/GRO) | MIT |
| [wireguard-windows](https://git.zx2c4.com/wireguard-windows) `winipcfg`; `tunnel/firewall` (adapted copy in `internal/firewall`) | Windows routes/addresses; kill switch (WFP) | MIT |
| [go-webview2](https://github.com/jchv/go-webview2), [go-winloader](https://github.com/jchv/go-winloader) | App window (Microsoft Edge WebView2) | MIT, ISC |
| [fyne.io/systray](https://github.com/fyne-io/systray) | Notification-area icon | Apache-2.0 |
| [golang.org/x/crypto, net, sys](https://go.googlesource.com/) | HKDF, batched UDP, DNS messages, Windows/Linux syscalls | BSD-3-Clause |
| [StevenBlack/hosts](https://github.com/StevenBlack/hosts) (downloaded at runtime, not bundled) | Ad blocker list | MIT |
| Microsoft Edge WebView2 Runtime (downloaded by the installer if missing) | Renders the app window | Microsoft software license |
