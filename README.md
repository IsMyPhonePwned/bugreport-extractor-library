<p align="center"><img width="120" src="./.github/logo.png"></p>
<h2 align="center">Bugreport Extractor Library</h2>

# bugreport-extractor-library: Read and extract data from Android BugReport in pure Rust

<div align="center">

![Powered By: IsMyPhonePwned](https://img.shields.io/badge/androguard-green?style=for-the-badge&label=Powered%20by&link=https%3A%2F%2Fgithub.com%2Fandroguard)
![Sponsor](https://img.shields.io/badge/sponsor-nlnet-blue?style=for-the-badge&link=https%3A%2F%2Fnlnet.nl%2F)

</div>

This Rust project provides a framework for parsing [Android Bugreport](https://source.android.com/docs/core/tests/debug/read-bug-reports) using a modular and extensible parser system. It is designed for speed and efficiency by using memory-mapped file I/O and parallel processing with Rayon, allowing multiple parsers to run concurrently on the same data source.

## Key Features

- Memory-Mapped Files: Uses memmap2 to handle large files (200MB+) with minimal RAM usage.

- Concurrent Parsing: Uses rayon to run multiple parsers in parallel, taking advantage of multi-core processors.

- Extensible Architecture: Easily add new parsers by implementing a simple Parser trait.


## Build

Build the project:

```
cargo build --release
```

## Parsers

The library includes the following parsers, each extracting specific information from Android bug reports:

### Header Parser
Extracts metadata from the dumpstate header section.
- **Timestamp**: When the bug report was generated
- **Build information**: Build fingerprint, version, etc.
- **Device information**: Model, manufacturer, etc.
- **Key-value pairs**: All metadata fields from the header

### Memory Parser
Extracts memory statistics from `/proc/meminfo`.
- **Memory metrics**: Total, free, available, cached, buffers
- **Swap information**: Swap total, free, cached
- **Kernel memory**: Slab, page tables, etc.
- **Multiple snapshots**: Can extract multiple memory info sections if present

### Package Parser
Extracts installed application information from the package manager dump.
- **Package details**: Name, version, UID, installation path
- **Permissions**: Granted and requested permissions per package
- **User-specific data**: Per-user installation status, data directories
- **Installation logs**: Timestamps and details of package installations/updates
- **App components**: Activities, services, receivers, providers
- **Signing information**: Package signatures and certificates

### Power Parser
Extracts power-related events and reset reasons.
- **Power events**: Shutdown, reboot, screen on/off events
- **Reset reasons**: Why the device was reset (crash, user action, etc.)
- **Power history**: Timeline of power state changes
- **Event details**: Flags, timestamps, and additional context

### Process Parser
Extracts running processes and thread information.
- **Process information**: PID, user, command, memory usage (VSS, RSS)
- **Thread details**: TID, CPU usage, status, thread names
- **CPU statistics**: Per-process and per-thread CPU percentages
- **Process hierarchy**: Parent-child relationships

### USB Parser
Extracts USB device and port information.
- **USB devices**: Vendor ID (VID), Product ID (PID), manufacturer, product name
- **USB ports**: Port status, connection state, power/data roles
- **Device events**: Timeline of add, bind, unbind, remove, change events
- **Interface information**: USB interfaces and drivers
- **Timestamps**: First seen, last seen, and state change times

### Battery Parser
Extracts comprehensive battery and power usage statistics.
- **App battery stats**: 
  - Network usage (mobile/WiFi TX/RX bytes)
  - CPU time (user/system)
  - Wakelocks (name, type, duration, count)
  - Background jobs (name, time, count)
  - Foreground service time
- **Hardware information**: 
  - Voltage (main, sub, charger input)
  - Current (now, average, charging)
  - State of charge (SOC) percentages
  - Temperature readings (battery, USB, charger, wireless, etc.)
- **Battery history**: 
  - Status changes (charging, discharging, not-charging)
  - Health status
  - Plug type (AC, USB, wireless, none)
  - Voltage, current, charge levels over time
  - Temperature readings
  - State change flags
- **Version information**: SDK version and build numbers

### Crash Parser
Extracts crash dumps (tombstones) and ANR (Application Not Responding) events.
- **Tombstones**:
  - Process information (PID, TID, UID, process name)
  - Signal and fault address
  - Stack traces with backtrace frames
  - Register states (PC, SP, LR, etc.)
  - Build fingerprint and ABI
  - Abort messages
- **ANR files**:
  - Process and thread information
  - ANR reason and stack traces
  - CPU usage at time of ANR
  - File permissions and metadata

### Network Parser
Extracts network connectivity and statistics.
- **Socket connections**: 
  - TCP/UDP sockets with local/remote addresses and ports
  - Connection state, UID, inode
  - Receive/send queue sizes
- **Network interfaces**: 
  - Interface names, IP addresses (IPv4/IPv6)
  - Flags, MTU
  - RX/TX byte statistics
- **Network statistics**: 
  - Per-UID network usage (mobile/WiFi)
  - Packet counts
  - Network type, RAT type, metered status
  - WiFi network names, subscriber IDs

### Bluetooth Parser
Extracts Bluetooth device information.
- **Bonded devices**: MAC addresses (masked and full), device names
- **Connected devices**: Connection status, transport type
- **Device details**: 
  - Device class, manufacturer
  - Services and UUIDs
  - Identity addresses
  - Link types

### Device Policy Parser
Extracts device administration and policy information.
- **Device admins**: Enabled device admin receivers per user
- **Profile owners**: Work profile owner information
- **App restrictions**: Per-app policy restrictions
- **Policy configurations**: Key-value policy settings
- **Component information**: Package and receiver details

### ADB Parser
Extracts Android Debug Bridge (ADB) connection information.
- **ADB state**: Connection status, debugging enabled
- **Authorized keys**: List of authorized ADB keys
- **PC connections**: Connected computer information
- **Debugging manager**: Detailed debugging state

### Authentication Parser
Extracts user authentication events.
- **Authentication events**: 
  - Timestamp, user ID, success status
  - Authentication type (biometric, passcode, password, pattern)
  - Event source (keystore2, PowerManagerService)
  - Wake reasons (for screen wake events)
  - Process UID/PID (for PowerManagerService events)
- **Event timeline**: Chronological list of all authentication attempts

### VPN Parser
Extracts VPN configuration and network properties.
- **Current VPNs**: 
  - User ID to VPN package mapping
  - VPN package names
- **Network properties**: 
  - VPN-related network configuration
  - Key-value property pairs

Each parser extracts data from specific sections within the dumpstate file, and some parsers may gather information from multiple sections to provide a complete picture.

## Usage

Run multiple parsers from the command line:

```
cargo run --release -- --file-path=dumpstate.txt --parser-type header --parser-type memory
```

it will allow the header and the memory parse to run.

# Detection

The bugreport extractor includes two complementary detection systems for identifying security threats in Android bugreports:

## 1. Internal Exploitation Detection

The internal detection system analyzes battery usage patterns and crash data to identify compromised applications and active attacks.

### Detection Modes

#### Battery-Based Exploitation Detection

Analyzes behavioral patterns in battery statistics to detect various exploitation types:

- **Remote Code Execution (RCE)**
  - Abnormal system CPU usage patterns
  - Excessive process spawning
  - Code injection indicators

- **Command & Control (C2)**
  - Regular beaconing patterns via alarms
  - GCM/FCM infrastructure abuse
  - Rapid polling behavior

- **Data Exfiltration**
  - Upload-heavy network traffic
  - Cellular network preference (avoiding monitoring)
  - Large background data transmission

- **Remote Access Trojan (RAT)**
  - Long-running foreground services
  - Frequent wakelock acquisition
  - Screen/media capture activity

- **Backdoor**
  - Persistent boot receivers
  - Hidden services with background activity
  - Package update monitoring

- **Privilege Escalation**
  - System call dominance
  - Root access attempts
  - Permission abuse patterns

- **Lateral Movement**
  - Excessive IPC activity
  - Content provider access to other apps

#### Crash-Based Exploitation Detection

Analyzes crash dumps (tombstones) and ANR events to detect memory exploitation attempts:

- **Memory Exploitation Patterns**
  - Heap spray detection
  - ROP chain likelihood analysis
  - NULL pointer dereference patterns
  - Stack pivot detection

- **Register Corruption Analysis**
  - Program Counter (PC) corruption
  - Stack Pointer (SP) manipulation
  - Link Register (LR) patterns

- **ANR Detection**
  - Critical process deadlocks
  - Resource exhaustion patterns
  - Binder exploitation indicators

- **Critical Process Monitoring**
  - System server crashes
  - Zygote crashes
  - Other critical Android processes

- **Vulnerable Library Detection**
  - Known vulnerable libraries (libwebviewchromium, libimagecodec, etc.)
  - Native code exploitation patterns

#### Coordinated Threat Detection (Advanced)

Cross-correlates battery and crash indicators to identify multi-vector attacks:

- **Multi-Vector Attack Detection**
  - Apps showing BOTH behavioral anomalies AND suspicious crashes
  - Automatic severity escalation for combined threats
  - Attack pattern description generation
  - Enhanced confidence scoring

- **Attack Pattern Examples**
  ```
  🚨 COORDINATED ATTACK
  Package: com.suspicious.app
  - RCE via battery analysis (87% confidence)
  - Memory exploitation via crashes (heap spray + ROP chain)
  → Multi-vector attack pattern indicates active compromise
  ```

#### Crash Timeline Analysis (Advanced)

Analyzes temporal patterns in crashes to identify exploitation techniques:

- **Regular Interval Detection**
  - Crashes at consistent intervals (fuzzing indicator)
  - Automated probing patterns

- **Burst Pattern Detection**
  - Multiple crashes in short time window
  - Coordinated exploitation attempts

- **Progressive Exploitation**
  - Attack stage progression (NULL → heap spray → ROP)
  - Systematic vulnerability probing

- **Scheduled Patterns**
  - Time-based attack triggers
  - Crashes during specific hours

- **Escalating Frequency**
  - Increasing crash rate over time
  - Attack intensification detection

### Usage

#### Basic Detection

```bash
# Battery-based detection only
./bugreport_extractor -f bugreport.txt -p battery --detection

# Crash-based detection only
./bugreport_extractor -f bugreport.txt -p crash --detection

# Unified detection (recommended - uses both)
./bugreport_extractor -f bugreport.txt -p battery -p crash --detection
```

#### Custom Detection Configuration

```bash
# Use custom detection thresholds
./bugreport_extractor -f bugreport.txt -p battery -p crash --detection config.json

# Strict mode (high-security environments)
./bugreport_extractor -f bugreport.txt -p battery --detection strict

# Lenient mode (corporate/MDM environments)
./bugreport_extractor -f bugreport.txt -p battery --detection lenient
```

#### Detection Configuration File

Create a `config.json` file to customize detection thresholds:

```json
{
  "description": "Custom detection configuration",
  "enable_crash_detection": true,
  "rce": {
    "suspicious_cpu_system_ratio": 4.0,
    "min_system_cpu_ms": 30000,
    "unexpected_process_spawn_count": 10
  },
  "c2": {
    "beaconing_alarm_count": 100,
    "beaconing_avg_duration_ms": 500,
    "regular_interval_variance": 0.3,
    "gcm_abuse_count": 50
  },
  "exfiltration": {
    "tx_rx_ratio": 3.0,
    "min_upload_bytes": 50000000,
    "cellular_preference_ratio": 2.5,
    "background_upload_threshold": 20000000
  }
}
```

### Output Example

```
=== Security Detection Analysis ===

🔴 Critical Threat | 1 battery-based exploitation(s) | 2 suspicious crash(es)
Overall Severity: Critical
Total Indicators: 8

🔋 Battery-Based Exploitation Detected:

  Package: com.suspicious.app
  Type: Remote Code Execution (RCE)
  Severity: Critical
  Confidence: 87%
  Indicators:
    • RCE indicator: Abnormal system CPU usage - 45000ms system vs 8000ms user
    • RCE indicator: Excessive process spawning - 25 process-related jobs

💥 Crash-Based Security Issues:
  Total Crashes: 15
  Suspicious Crashes: 2
  Total ANRs: 1
  Suspicious ANRs: 1

  [Critical] system_server
  Signal: SIGSEGV
  Fault Address: 0xdeadbeef
  ⚠️  Heap spray detected!
  ⚠️  ROP chain likely!
  Indicators:
    • Critical system process crash
    • Exploitation-prone crash code: SEGV_ACCERR
    • Memory corruption detected

🚨 COORDINATED MULTI-VECTOR ATTACKS DETECTED:
  Package: com.suspicious.app
  Combined Severity: Critical
  Confidence: 94%
  
  Attack Pattern:
  Remote Code Execution detected via behavioral analysis, combined with 
  2 suspicious crashes showing heap spray, ROP chain. This multi-vector 
  attack pattern strongly indicates active compromise.

⏱️  TEMPORAL ATTACK PATTERNS:
  Risk Level: Critical
  
  🔄 Regular Interval Attack
     10 crashes every ~60 seconds
     ⚠️  Indicates automated fuzzing/probing
     
  🎯 Progressive Exploitation Detected
     Attack stages: NULL deref → heap spray → ROP chain
     🚨 CRITICAL: Systematic exploitation in progress!

📋 Recommendations:
  🚨 CRITICAL: com.suspicious.app shows RCE indicators - isolate device immediately
  🚨 Critical memory exploitation detected - immediate forensic analysis required
  🔧 Update vulnerable libraries: libimagecodec, libwebviewchromium
  📊 Multiple high-risk crashes detected - device may be under active attack
```

---

## 2. Sigma Rule Detection

The tool integrates with the [Sigma](https://github.com/SigmaHQ/sigma) and [Sigma Zero](https://github.com/ping2A/sigmazero) detection format to identify suspicious patterns in parsed Android logs using community-maintained detection rules.

### What is Sigma?

Sigma is a generic signature format for SIEM systems that allows you to describe suspicious events in a structured way. The bugreport extractor can evaluate Sigma rules against parsed Android data.

### Supported Log Sources

Sigma rules can be applied to any parsed data:

- **Battery Stats** - Process activity, network usage, wakelocks
- **Process Logs** - Running processes, memory usage, CPU activity
- **Crash Logs** - Tombstones, stack traces, signals
- **Package Information** - Installed apps, permissions, versions
- **USB Events** - Device connections, ADB usage
- **Power Events** - Screen state, battery changes
- **Memory Statistics** - RAM usage, low memory events

### Usage

```bash
# Run Sigma detection with rules directory
./bugreport_extractor \
    -f bugreport.txt \
    -p battery -p process -p crash \
    --rules-dir /path/to/sigma/rules

# Filter by minimum severity level
./bugreport_extractor \
    -f bugreport.txt \
    -p battery \
    --rules-dir ./rules \
    --min-level high

# Show detailed log information with matches
./bugreport_extractor \
    -f bugreport.txt \
    -p battery \
    --rules-dir ./rules \
    --show-log-details
```

### Creating Sigma Rules for Android

Example Sigma rule for detecting suspicious app behavior:

```yaml
title: Suspicious Background Network Activity
id: 12345678-1234-1234-1234-123456789abc
status: experimental
description: Detects apps with excessive background network usage
logsource:
    product: android
    service: battery
detection:
    selection:
        network_tx_mobile: '>50000000'  # >50MB uploaded
        foreground_time_ms: '<300000'   # <5 minutes foreground
    condition: selection
falsepositives:
    - Cloud backup applications
    - Sync services
level: medium
tags:
    - android
    - data_exfiltration
```

Example rule for crash detection:

```yaml
title: Critical Process Crash
id: 87654321-4321-4321-4321-210987654321
status: stable
description: Detects crashes in critical Android system processes
logsource:
    product: android
    service: crash
detection:
    selection:
        process_name:
            - 'system_server'
            - 'zygote'
            - 'surfaceflinger'
        signal: 'SIGSEGV'
    condition: selection
falsepositives:
    - Known system bugs
level: high
tags:
    - android
    - system_crash
```

### Sigma Output

```
=== Sigma Rule Evaluation ===

[HIGH] Suspicious Background Network Activity
  Package: com.suspicious.app
  Details: 75MB uploaded with only 2 minutes foreground time
  Tags: android, data_exfiltration
  
[CRITICAL] Critical Process Crash
  Process: system_server
  Signal: SIGSEGV
  Fault Address: 0xdeadbeef
  Tags: android, system_crash

Summary:
  Total logs evaluated: 1,245
  Matches found: 12
  Critical: 2
  High: 5
  Medium: 3
  Low: 2
```

### Combining Internal and Sigma Detection

Both detection systems can run simultaneously:

```bash
# Run both detection systems
./bugreport_extractor \
    -f bugreport.txt \
    -p battery -p crash \
    --detection \
    --rules-dir ./sigma-rules

# This will:
# 1. Parse battery and crash data
# 2. Run internal exploitation detection (battery + crash + coordinated)
# 3. Evaluate Sigma rules against all parsed data
# 4. Output combined security assessment
```

The internal detection focuses on exploitation techniques and behavioral patterns, while Sigma rules can be customized for specific threats, compliance requirements, or organizational policies.

### Advantages of Each System

**Internal Detection:**
- ✅ Purpose-built for Android exploitation
- ✅ Cross-correlation between data sources
- ✅ Temporal pattern analysis
- ✅ No configuration needed (works out-of-box)
- ✅ Automatic severity escalation

**Sigma Detection:**
- ✅ Flexible rule creation
- ✅ Community-maintained rule sets
- ✅ Easy to customize for specific threats
- ✅ Portable across different tools
- ✅ Compliance and policy enforcement

**Recommended:** Use both systems together for comprehensive threat detection - internal detection for exploitation and Sigma for custom/organizational rules.

---

## Detection Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Bugreport File                          │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
         ┌───────────────────────────────┐
         │      Parallel Parsing          │
         │  (Battery, Crash, Process...)  │
         └───────────────────────────────┘
                         │
            ┌────────────┴────────────┐
            ▼                         ▼
   ┌────────────────┐        ┌────────────────┐
   │ Internal       │        │ Sigma Rule     │
   │ Detection      │        │ Evaluation     │
   └────────────────┘        └────────────────┘
            │                         │
            ▼                         ▼
   ┌────────────────┐        ┌────────────────┐
   │ • Battery      │        │ • Pattern      │
   │   Exploitation │        │   Matching     │
   │ • Crash        │        │ • Custom       │
   │   Analysis     │        │   Rules        │
   │ • Coordinated  │        │ • Severity     │
   │   Threats      │        │   Levels       │
   │ • Timeline     │        │                │
   │   Patterns     │        │                │
   └────────────────┘        └────────────────┘
            │                         │
            └────────────┬────────────┘
                         ▼
              ┌──────────────────┐
              │ Unified Security │
              │ Report           │
              └──────────────────┘
```

---


## License

Distributed under the [Apache License, Version 2.0](LICENSE).