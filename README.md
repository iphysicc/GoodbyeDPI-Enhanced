# GoodbyeDPI Enhanced

**Cross-platform** Deep Packet Inspection circumvention utility.

This is an enhanced fork of [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) by @ValdikSS, extended with **Linux** and **macOS** support while maintaining full Windows compatibility.

> **Original project**: [https://github.com/ValdikSS/GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)  
> **This fork**: [https://github.com/iphysicc/GoodbyeDPI-Enhanced](https://github.com/iphysicc/GoodbyeDPI-Enhanced)

---

## What is this?

GoodbyeDPI Enhanced bypasses Deep Packet Inspection (DPI) systems used by Internet Service Providers to block access to websites. It works against both:

- **Passive DPI** — connected via optical splitter or port mirroring, sends fake responses faster than the real server
- **Active DPI** — connected inline, actively modifies or drops packets

## Supported Platforms

| Platform | Packet Engine | Privileges | Status |
|----------|--------------|------------|--------|
| Windows 7/8/10/11 | WinDivert | Administrator | ✅ Stable |
| Linux (kernel 3.13+) | NFQUEUE (netfilter) | root / sudo | ✅ Working |
| macOS 10.12+ | Divert sockets (pf) | root / sudo | ⚠️ Experimental |

---

## Quick Start

### Windows

1. Download the latest release from the [Releases page](https://github.com/iphysicc/GoodbyeDPI-Enhanced/releases)
2. Extract the archive
3. Run `goodbyedpi.exe` as Administrator (right-click → Run as administrator)

The program runs in mode `-9` by default (recommended for most users).

### Linux

1. Download the latest release or [build from source](#building-from-source)
2. Install dependencies:
   ```bash
   # Debian/Ubuntu
   sudo apt install libnetfilter-queue1 iptables

   # Fedora/RHEL
   sudo dnf install libnetfilter_queue iptables

   # Arch
   sudo pacman -S libnetfilter_queue iptables
   ```
3. Set up iptables rules and run:
   ```bash
   sudo ./scripts/linux/setup-iptables.sh start
   sudo ./goodbyedpi
   ```
4. To stop:
   ```bash
   # Press Ctrl+C to stop goodbyedpi, then:
   sudo ./scripts/linux/setup-iptables.sh stop
   ```

### macOS

1. Download the latest release or [build from source](#building-from-source)
2. Set up pf rules and run:
   ```bash
   sudo ./scripts/macos/setup-pf.sh start
   sudo ./goodbyedpi
   ```
3. To stop:
   ```bash
   # Press Ctrl+C to stop goodbyedpi, then:
   sudo ./scripts/macos/setup-pf.sh stop
   ```

> **Note**: On macOS, you may need to adjust the network interface name in `setup-pf.sh` (default is `en0`). Use `ifconfig` to find yours.

---

## Command-Line Options

```
Usage: goodbyedpi [OPTION...]
 -p          block passive DPI
 -q          block QUIC/HTTP3
 -r          replace Host with hoSt
 -s          remove space between host header and its value
 -m          mix Host header case (test.com -> tEsT.cOm)
 -f <value>  set HTTP fragmentation to value
 -k <value>  enable HTTP persistent (keep-alive) fragmentation and set it to value
 -n          do not wait for first segment ACK when -k is enabled
 -e <value>  set HTTPS fragmentation to value
 -a          additional space between Method and Request-URI (enables -s, may break sites)
 -w          try to find and parse HTTP traffic on all processed ports (not only on port 80)
 --port        <value>    additional TCP port to perform fragmentation on
 --dns-addr    <value>    redirect UDP DNS requests to the supplied IP address
 --dns-port    <value>    redirect UDP DNS requests to the supplied port (53 by default)
 --dnsv6-addr  <value>    redirect UDPv6 DNS requests to the supplied IPv6 address
 --dnsv6-port  <value>    redirect UDPv6 DNS requests to the supplied port (53 by default)
 --dns-verb               print verbose DNS redirection messages
 --blacklist   <txtfile>  perform tricks only to hosts from supplied text file
 --allow-no-sni           perform circumvention if TLS SNI can't be detected
 --frag-by-sni            fragment the packet right before SNI value
 --set-ttl     <value>    activate Fake Request Mode with supplied TTL value
 --auto-ttl    [a1-a2-m]  automatically detect TTL and decrease it based on distance
 --min-ttl     <value>    minimum TTL distance for Fake Request
 --wrong-chksum           send fake request with incorrect TCP checksum
 --wrong-seq              send fake request with TCP SEQ/ACK in the past
 --native-frag            split packets without shrinking Window Size
 --reverse-frag           send fragments in reversed order
 --fake-from-hex <value>  load fake packets from HEX values
 --fake-with-sni <value>  generate fake packets with given SNI domain name
 --fake-gen <value>       generate random-filled fake packets (up to 30)
 --fake-resend <value>    send each fake packet N times (default: 1)
 --max-payload [value]    skip packets with payload > value (default: 1200)
 --daemon / -D            run as background daemon (Linux/macOS only)
```

## Presets

| Preset | Description |
|--------|-------------|
| `-1` | `-p -r -s -f 2 -k 2 -n -e 2` — most compatible (legacy) |
| `-2` | `-p -r -s -f 2 -k 2 -n -e 40` — better HTTPS speed (legacy) |
| `-3` | `-p -r -s -e 40` — better speed for both (legacy) |
| `-4` | `-p -r -s` — best speed (legacy) |
| `-5` | `-f 2 -e 2 --auto-ttl --reverse-frag --max-payload` |
| `-6` | `-f 2 -e 2 --wrong-seq --reverse-frag --max-payload` |
| `-7` | `-f 2 -e 2 --wrong-chksum --reverse-frag --max-payload` |
| `-8` | `-f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload` |
| `-9` | Same as `-8` plus `-q` (block QUIC) — **this is the default** |

---

## How It Works

### Passive DPI Blocking
Passive DPI sends HTTP 302 Redirect or TCP Reset faster than the real server. These packets typically have IP ID `0x0000` or `0x0001`. GoodbyeDPI detects and drops them.

### Active DPI Circumvention
Active DPI is harder to fool. GoodbyeDPI uses these techniques:

1. **TCP fragmentation** — splits the first data packet into smaller pieces
2. **Host header manipulation** — replaces `Host:` with `hoSt:`, removes spaces, mixes case
3. **Fake packets** — sends decoy HTTP/HTTPS packets with low TTL, wrong checksum, or wrong sequence numbers that expire before reaching the destination but fool the DPI
4. **Native fragmentation** — sends packet data in smaller TCP segments without modifying window size
5. **Reverse fragmentation** — sends fragments in reverse order

These methods are fully compatible with TCP/HTTP standards and should not break any website.

---

## Building from Source

### Prerequisites

| Platform | Requirements |
|----------|-------------|
| Windows | MinGW-w64, CMake 3.16+, [WinDivert](https://github.com/basil00/Divert) |
| Linux | GCC/Clang, CMake 3.16+, libnetfilter-queue-dev |
| macOS | Xcode CLI Tools, CMake 3.16+ |

### Build Commands

**All platforms (CMake):**
```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

**Windows with WinDivert path:**
```bash
mkdir build && cd build
cmake .. -DWINDIVERT_PATH=C:/path/to/windivert -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

**Windows (legacy Makefile, x86_64):**
```bash
cd src
make CPREFIX=x86_64-w64-mingw32- BIT64=1 \
     WINDIVERTHEADERS=/path/to/windivert/include \
     WINDIVERTLIBS=/path/to/windivert/x64
```

**Linux:**
```bash
sudo apt install cmake libnetfilter-queue-dev   # install deps
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

**macOS:**
```bash
brew install cmake
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(sysctl -n hw.ncpu)
```

### Debug Build
```bash
cmake .. -DCMAKE_BUILD_TYPE=Debug -DENABLE_DEBUG=ON
```

---

## Installation as a Service

### Windows Service

```cmd
sc create "GoodbyeDPI" binPath= "C:\path\to\goodbyedpi.exe -9" start= auto
sc start GoodbyeDPI
```

To remove:
```cmd
sc stop GoodbyeDPI
sc delete GoodbyeDPI
```

### Linux (systemd)

```bash
sudo cp build/goodbyedpi /usr/local/bin/
sudo cp scripts/linux/setup-iptables.sh /usr/local/share/goodbyedpi/
sudo chmod +x /usr/local/share/goodbyedpi/setup-iptables.sh
sudo cp scripts/linux/goodbyedpi.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now goodbyedpi
```

Check status:
```bash
sudo systemctl status goodbyedpi
```

### macOS (launchd)

```bash
sudo cp build/goodbyedpi /usr/local/bin/
sudo cp scripts/macos/com.goodbyedpi.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.goodbyedpi.plist
```

To unload:
```bash
sudo launchctl unload /Library/LaunchDaemons/com.goodbyedpi.plist
```

---

## Platform-Specific Notes

### Windows
- Requires Administrator privileges
- WinDivert driver (`WinDivert64.sys` / `WinDivert32.sys`) must be in the same directory as the executable
- Works out of the box — no additional configuration needed
- Can be installed as a Windows Service for auto-start

### Linux
- Requires root privileges (for NFQUEUE access)
- **iptables rules must be configured before running** — use `scripts/linux/setup-iptables.sh`
- Works with both iptables and nftables (via iptables compatibility layer)
- Passive DPI blocking (`-p`) and QUIC blocking (`-q`) are handled by iptables DROP rules
- Supports running as a systemd service
- Use `--daemon` flag to run in background without systemd

### macOS
- Requires root privileges (for divert sockets)
- **pf rules must be configured before running** — use `scripts/macos/setup-pf.sh`
- Adjust the network interface name in the script (default: `en0`)
- Divert sockets may require SIP (System Integrity Protection) to be partially disabled on newer macOS versions
- Supports running as a launchd daemon
- Use `--daemon` flag to run in background without launchd

---

## Troubleshooting

### Windows
| Error | Solution |
|-------|----------|
| "WinDivert32.sys not found" | Place WinDivert DLL/SYS files next to the executable |
| Error 577 (invalid signature) | Update Windows or disable Secure Boot |
| Error 1275 (blocked by security) | Whitelist WinDivert in your antivirus |

### Linux
| Error | Solution |
|-------|----------|
| "nfq_open() failed" | Run with `sudo` |
| "nfq_create_queue() failed" | Another instance may be running, or queue is in use |
| No effect on traffic | Check iptables rules: `sudo iptables -L -n` |

### macOS
| Error | Solution |
|-------|----------|
| "Cannot create divert socket" | Run with `sudo`, check SIP status |
| No effect on traffic | Check pf rules: `sudo pfctl -sr` |
| Interface mismatch | Edit `setup-pf.sh` to use your interface (check with `ifconfig`) |

---

## Similar Projects

- **[zapret](https://github.com/bol-van/zapret)** by @bol-van (Linux, macOS, Windows)
- **[ByeDPI](https://github.com/hufrea/byedpi)** (Linux, Windows) + **[ByeDPIAndroid](https://github.com/dovecoteescapee/ByeDPIAndroid/)**
- **[SpoofDPI](https://github.com/xvzc/SpoofDPI)** by @xvzc (macOS, Linux)
- **[Green Tunnel](https://github.com/SadeghHayeri/GreenTunnel)** by @SadeghHayeri (macOS, Linux, Windows)
- **[PowerTunnel](https://github.com/krlvm/PowerTunnel)** by @krlvm (Windows, macOS, Linux)
- **[GhosTCP](https://github.com/macronut/ghostcp)** by @macronut (Windows)
- **[youtubeUnblock](https://github.com/Waujito/youtubeUnblock/)** by @Waujito (OpenWRT/Linux)

---

## Credits

- **[ValdikSS](https://github.com/ValdikSS)** — Original GoodbyeDPI author
- **[basil00](https://github.com/basil00)** — [WinDivert](https://github.com/basil00/Divert) library
- **[BlockCheck](https://github.com/ValdikSS/blockcheck)** contributors — DPI behavior research

---

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
