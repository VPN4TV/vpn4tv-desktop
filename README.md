# VPN4TV Desktop

Desktop VPN client for **Windows, macOS and Linux**, built on the
[sing-box](https://sing-box.sagernet.org/) core with embedded protocol bridges
for xhttp, Outline SS and AmneziaWG. Fork of
[sing-box-for-desktop](https://github.com/SagerNet/sing-box-for-desktop); the
core comes from our fork [sing-box-xhttp](https://github.com/VPN4TV/sing-box-xhttp)
(branch `desktop-beta`) and the UI from
[vpn4tv-dashboard](https://github.com/VPN4TV/vpn4tv-dashboard).

## Download

| Platform | File |
| --- | --- |
| Windows 10/11 (x64) | [vpn4tv-windows-latest.exe](https://bell.a4e.ar/vpn4tv-windows-latest.exe) |
| macOS (Apple Silicon) | [vpn4tv-macos-latest.dmg](https://bell.a4e.ar/vpn4tv-macos-latest.dmg) |
| Debian/Ubuntu (x64) | [vpn4tv-linux-latest.deb](https://bell.a4e.ar/vpn4tv-linux-latest.deb) |
| Fedora/RHEL (x64) | [vpn4tv-linux-latest.rpm](https://bell.a4e.ar/vpn4tv-linux-latest.rpm) |

The tunnel is created by a privileged service. The app installs it on first
launch: Windows asks for UAC, macOS explains first and then asks for an
administrator password, and the Linux packages install a systemd unit.

The macOS build is signed with a Developer ID and notarised. The Windows build
carries a self-signed certificate — enough for the daemon's own integrity check,
but SmartScreen still warns on first run (*More info → Run anyway*).

## Features

- **Single-screen home** — subscription, expiry, one connect button, server
  picker with latency, session traffic
- **Telegram onboarding** — add a subscription by scanning a QR or sending a
  10-digit code to [@VPN4TV_Bot](https://t.me/VPN4TV_Bot), with an MTProto proxy
  fallback for when Telegram itself is blocked
- **Manual import** — subscription links, server links (vless/vmess/trojan/ss/
  hy2/tuic/wg), Xray JSON, sing-box JSON, AmneziaVPN `vpn://`
- **Server key links** — `vless://` and friends register as system link handlers
- **Embedded bridges** — the profile carries xray / outline / wireproxy configs
  under a private key and the core starts them in-process
- **Per-app split tunnelling** — exclude applications from the tunnel, or route
  only the selected ones through it (matched by executable name)
- **LAN bypass** — network drives, printers and the router's own page keep
  working while connected
- **DNS resilience** — known DoH endpoints are probed before every connection
  and the profile is rewritten to whichever one answers
- **Auto-refresh on expired** — a renewed subscription is fetched before
  connecting instead of handing the user a dead tunnel
- **Subscription info** — expiry date and traffic usage from provider headers
- **Updates** — checked against our own feed, not upstream releases
- **Crash reports** — sent to our receiver, switchable in settings

## Building

See [VPN4TV.md](VPN4TV.md) for the full loop: toolchains, running against a
local daemon, packaging for each platform, code signing and notarisation.

```bash
pnpm install
pnpm --dir dashboard install
pnpm generate && pnpm --dir dashboard generate
VPN4TV_GO="$HOME/go/bin/go1.26.4" pnpm dev
```

## Support

- Channel: [@VPN4TV](https://t.me/VPN4TV)
- Support: [@vpn4tv_support](https://t.me/vpn4tv_support)

## License

GPL-3.0-or-later, inherited from sing-box.

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
```
