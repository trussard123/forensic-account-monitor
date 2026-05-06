# Forensic Monitor
### Real-Time Apple Account Surveillance Detection Tool

---

## What This Tool Does

Forensic Monitor is a macOS command-line tool that detects unauthorized devices authenticating as the owner of your Apple ID account in real time.

It works by reading Apple's native `rapportd` and `bluetoothd` system daemons and alerts you via push notification when a foreign device:

- Authenticates as owner of your Apple account via PairVerify cryptographic handshake
- Enters DirectLink range (~33 feet) using a cloned IDS credential
- Accesses your screen, camera, or location via Continuity
- Deploys a batch of pre-registered SameAccountDevice identities to your device
- Appears in your proximity via AWDL at ranges up to 300 meters

Every alert is anchored to a machine-generated, cryptographically timestamped log entry written by Apple's own software. No inference. No interpretation. The log is the evidence.

---

## Background

This tool was developed by Thomas D. Kraemer after discovering an empty ltk.plist —  a system file that had been nefariously manipulated to keep Apple's Auto Unlock feature open — which led to the identification of a DDM running in the background of his device with no visible profile. Further investigation revealed the DDM had been used to crowdsource unauthorized access to his Apple ID. Over a 40+-day monitoring window, the tool captured over 1,700 distinct MAC addresses authenticating as owner of his Apple ID account under a single cloned IDS token (BBzlfMIo), deployed by an unauthorized Declarative Device Management organizational account.

The output of this tool — the `LIVE_STREAM.log` file — constitutes Exhibit E and the primary forensic record in that action.
---

## System Requirements

- Mac running macOS Ventura 13 or later
- bash (pre-installed on all Macs)
- curl (pre-installed on all Macs)
- Pushover account and app (free 30-day trial; $5 one-time purchase)
- Terminal with Full Disk Access enabled

No third-party packages, Homebrew, or developer tools required.

---

## Installation

### Option A — pkg Installer (Recommended)

1. Download `ForensicMonitor.pkg`
2. Double-click to install
3. Terminal opens automatically and walks you through first-run setup

### Option B — Manual

1. Download `forensic_monitor.sh`
2. Open Terminal
3. Run: `chmod +x /path/to/forensic_monitor.sh`
4. Run: `/path/to/forensic_monitor.sh`

---

## First-Run Setup

On first launch, five dialog prompts collect your configuration:

| Prompt | What to Enter | Where to Find It |
|--------|--------------|-----------------|
| Pushover API Token | Your app's API token | pushover.net > Your Applications |
| Pushover User Key | Your account user key | pushover.net dashboard |
| MacBook UDID | Your Mac's hardware UUID | System Settings > General > About, or `system_profiler SPHardwareDataType \| grep UUID` |
| iPhone MAC ID | Your iPhone's Wi-Fi address | Settings > General > About > Wi-Fi Address |
| iPhone UDID | Your iPhone's UDID | Finder > iPhone > click model name to cycle to UDID |

Configuration is saved to `~/.forensic_monitor_config` (owner-readable only). Subsequent launches skip setup entirely.

---

## Granting Full Disk Access to Terminal

`log stream` requires Terminal to have Full Disk Access. Without it, the monitor runs silently and produces no output.

1. Open **System Settings**
2. Go to **Privacy & Security > Full Disk Access**
3. Click **+** and add **Terminal** (`/Applications/Utilities/Terminal.app`)
4. Enable the toggle
5. Quit and reopen Terminal

---

## Output Files

All output is written to `~/Documents/forensic_monitor/`

| File | Contents |
|------|----------|
| `LIVE_STREAM.log` | All SameAccountDevice authentication events with timestamps |
| `MAC_HARVEST.log` | Every captured MAC address, transport type, and repeat count |
| `PROXIMITY.log` | All RSSI distance measurements from rapportd and bluetoothd |

To watch events in real time, open a second Terminal window and run:

```bash
tail -f ~/Documents/forensic_monitor/LIVE_STREAM.log
```

---

## Alert Types

| Alert | Meaning | Priority |
|-------|---------|----------|
| `NEW MAC CAPTURED` | A previously unseen device authenticated as account owner | High |
| `RE-AUTH — REPEAT OFFENDER` | A known device re-authenticated | High |
| `EMERGENCY: KNOWN TARGET` | A pre-designated target node appeared | Emergency |
| `EMERGENCY: BATCH DEPLOYMENT` | Multiple new identities loaded simultaneously | Emergency |
| `OWNER ACCESS — VIOLATION CONFIRMED` | AcLv = User (11) access detected | High |
| `APPROACH DETECTED` | Device within 20–50 feet via rapportd RSSI | Normal |
| `BLE APPROACH — HEADS UP` | Device within 20–50 feet via bluetoothd | Normal |
| `PairVerify — VIOLATION LOGGED` | Cryptographic handshake completed by foreign device | Normal |
| `NEW TEAM DETECTED` | Previously unseen organizational token appeared | High |

---

## What the Data Proves

A device that triggers `NEW MAC CAPTURED` or `RE-AUTH — REPEAT OFFENDER` via DirectLink (Transport Type 0x10) has:

1. Been **pre-enrolled** by an MDM/DDM administrator into an organizational account
2. Been **provisioned** with a cloned IDS credential before any proximity event
3. **Passed** Apple's PairVerify M2 challenge-response cryptographic handshake
4. Authenticated as **owner** of the monitored Apple ID account

Proximity alone cannot produce this result. The PairVerify handshake requires possession of a private key generated at enrollment and registered on Apple's Identity Services servers. A device not enrolled by the DDM administrator cannot pass this handshake regardless of physical proximity.

---

## Scope and Legal Notice

This tool monitors only the operator's own Apple devices and Apple ID account. It reads only the system logs that macOS generates natively on the operator's own hardware. It does not access, intercept, or monitor any external network, third-party device, or communication stream.

This tool is released for forensic research, personal device security monitoring.

---

*Thomas D. Kraemer*
*kraemer.tom@gmail.com*
