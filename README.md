# Bond

**Use your WiFi and your Ethernet cable at the same time, for a faster
internet connection on Windows.** Just like Speedify, but you use your own VPS
instead of their proprietary paid servers.

Normally Windows uses only one connection at a time. Bond splits your traffic
across both and joins it back together on a small server you rent (a "VPS"),
so one download can use the speed of both. It also includes a system-wide **ad
blocker** on your PC.

Are you limited by your Ethernet port speed? Maybe cable speed? Using a CPL
(powerline) kit? Not getting what your internet provider gives you?
Then Bond is for you. Combine WiFi and Ethernet for faster bandwidth!
You can also use your phone hotspot along with your wifi/ethernet.

Tested on an Oracle free tier VPS running Ubuntu 24.04, with the
VM.Standard.A1.Flex shape: 2 cores, 12 GB RAM, 40 GB storage.

```
 Your PC ─ WiFi (250 Mbps) ─────┐
                                ├──▶  your VPS server (250+300 Mbps)  ──▶  internet (550 Mbps)
 Your PC ─ Ethernet (300 Mbps) ─┘
```

---

## Installation (about 15 minutes)

You need:

- A **Windows 10 or 11** PC with two internet connections (for example WiFi
  *and* an Ethernet cable).
- A **VPS**: a small rented Linux server. Oracle Cloud has a free tier;
  Hetzner, DigitalOcean, Vultr and others cost a few euros/dollars a month.

  > 💡 **Want it free?** Follow **[FREEVPSGUIDE.md](FREEVPSGUIDE.md)**: a
  > click-by-click guide to a free Oracle Cloud server, ready for Bond. It
  > replaces Steps 1 and 2 below.

### Step 1: Install the relay on your server

1. Open **PowerShell** on your PC (press the Windows key, type `PowerShell`,
   press Enter).

2. Connect to your server. Replace the address with your server's IP
   address, and `ubuntu` with your server's username (your provider shows
   both):

   ```
   ssh ubuntu@203.0.113.10
   ```

   Type `yes` if it asks whether to continue connecting. If your provider
   gave you a **key file** instead of a password (Oracle does), add it like
   this: `ssh -i C:\Users\you\Downloads\ssh-key.key ubuntu@203.0.113.10`

3. Copy this whole line, paste it into the window (right-click pastes) and
   press Enter:

   ```
   curl -fsSL -o bond.tar.gz https://github.com/rdbuff/bond/releases/latest/download/bond-server-linux.tar.gz && tar -xzf bond.tar.gz && sudo sh bond-server/install.sh
   ```

4. When it finishes, it shows something like this. **Keep this window open**,
   you need these two values in Step 3:

   ```
   In the Bond app, open Settings and enter:
     Relay server: 203.0.113.10
     Server key:   q5T0...long text...k8=
   ```

   Copy the **Relay server** and **Server key** and paste them into a new
   Notepad file, so you have them ready.

### Step 2: Open port 51820 on your provider's website

Your provider has a firewall in front of the server. Allow Bond through it:
in your provider's control panel, find **Firewall**, **Security group** or
**Security list** and add a rule:

| Setting | Value |
|---|---|
| Direction | Inbound / Ingress |
| Protocol | **UDP** |
| Port | **51820** |
| Source | `0.0.0.0/0` (anywhere) |

> **Oracle Cloud:** *Networking → Virtual Cloud Networks →* your network →
> *Subnets →* the **public** subnet → its **Default Security List** →
> **Add Ingress Rules**. Source CIDR `0.0.0.0/0`, IP Protocol **UDP**,
> Destination Port **51820**.

Some providers (e.g. Hetzner, DigitalOcean) have no firewall unless you
created one; then there's nothing to do here.

### Step 3: Install the app on your PC

1. Download **[installer.exe](https://github.com/rdbuff/bond/raw/main/installer.exe)**
   and double-click it.
2. Click **Yes** when Windows asks for permission, then **Next**. When it's
   done, leave **Launch Bond** ticked and click **Finish**.
3. Bond opens its **Settings**. Paste the **Relay server** and **Server key**
   from Step 1 and click **Save**.
4. Click the big switch. When it says **Connected**, you're done. 🎉

To check it works, search "what is my IP" in your browser: it should now show
your server's address.

---

## Something's not working?

| Problem | What to do |
|---|---|
| Stuck on **Connecting…** | Usually the firewall in Step 2. Check the rule is **UDP**, port **51820**, **inbound**, and on the right server/network. Also check the server address and key in Settings. |
| I lost the server key | Connect to the server (Step 1, points 1–2) and run `sudo cat /etc/bond/key` |
| Only one connection is used | Open Settings and tick both connections under **Connections to bond**. Both must be connected to the internet. |
| A website doesn't load with the ad blocker on | Settings → **Ad blocker: always allow** → add the site, e.g. `example.com`. Or switch the ad blocker off. |
| The internet is gone while Bond is on | If you enabled the **kill switch** in Settings, the internet is blocked until Bond connects. Switch Bond off to get it back. |
| Not faster than before | Bond can't be faster than your two connections combined, or than the server's own internet speed. Choose a server close to you. |

To uninstall: Windows Settings → Apps → **Bond** → Uninstall. To remove the
relay from the server, run
`sudo systemctl disable --now bond-server && sudo rm /usr/local/bin/bond-server`.

---

## For advanced users

Bond also has a command-line client (`bond-client.exe -server HOST:51820`, run
as administrator) and a portable mode: if `bond.json` / `bond.key` sit next to
`Bond.exe`, it uses them instead of `%APPDATA%\Bond`.

## Security

- **Encryption**: each session runs an ephemeral X25519 key exchange
  authenticated with the pre-shared key (HMAC-SHA256). Session keys come from
  HKDF over both, and every packet is AES-256-GCM with a replay window.
  Because the ephemeral keys are discarded, recorded traffic stays unreadable
  even if `bond.key` leaks later (forward secrecy).
- **Your relay sees your traffic**: it decrypts traffic and sends it on to the
  internet, like any VPN server. HTTPS still protects page contents beyond
  it. Your ISP sees only encrypted UDP to your relay.
- **The key is the password**: anyone with `bond.key` can use your relay.
  Keep it private.
- **IPv4 only**: IPv6 traffic is not tunnelled yet.
- **Kill switch scope**: with the kill switch on, local-network devices are
  blocked too while Bond is on.
- **Not audited**: Bond uses standard primitives from Go's crypto library, but
  the protocol has not had an independent security review.

## How it works

| Part | Where |
|---|---|
| Wire format, handshake, crypto | `internal/proto` |
| Scheduler (earliest-delivery across paths, per-path feedback for RTT, rate and inflight), reorder buffer (per-path FIFO loss detection plus an adaptive 100–500 ms timeout) | `internal/bond` |
| Windows client: Wintun adapter, sockets pinned per interface with `IP_UNICAST_IF`, routes, session handling | `internal/client` |
| Kill switch (Windows Filtering Platform, adapted from wireguard-windows) | `internal/firewall` |
| Ad blocker: filtering DNS forwarder; the app points Windows at it with an NRPT rule | `internal/adblock` |
| Relay: Linux TUN with GSO/GRO, `recvmmsg`, UDP GSO sends | `cmd/bond-server` |
| App: WebView2 window, tray, startup task | `cmd/bond-gui` |

## Building from source

Requires Go (version in `go.mod`) and, for the installer,
[Inno Setup 6](https://jrsoftware.org/isinfo.php)
(`winget install JRSoftware.InnoSetup`).

```powershell
.\build.ps1 -Version 1.0.0          # tests, app, relay, installer -> .\dist
.\build.ps1 -SkipInstaller          # without Inno Setup
```

The build downloads `wintun.dll` from wintun.net and verifies its SHA-256. The
app's icon and admin manifest are compiled in from `cmd/bond-gui/winres`;
after changing them, regenerate with
`go run github.com/tc-hib/go-winres@v0.3.3 make --in winres/winres.json`
inside `cmd/bond-gui`.

Pushing a tag like `v1.0.0` builds the installer and relay package on GitHub
Actions and attaches them to a release.

## License

MIT, see [LICENSE](LICENSE). Bundled and used third-party components are
listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
