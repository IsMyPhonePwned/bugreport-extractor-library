# Sigma Rule Fields Reference

Complete reference for all fields available in Sigma log entries generated from parsed Android bug report data.

## Package Parser Fields

### Installation Event Fields (`event_type: START_INSTALL`, `INSTALL_RESULT`, etc.)

These fields are extracted from installation log entries in the bug report:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `event_type` | string | Type of installation event | `START_INSTALL`, `INSTALL_RESULT`, `START_DELETE`, `DELETE_RESULT` |
| `timestamp` | string | When the event occurred | `2025-11-09 09:32:45.123` |
| `pkg` | string | Package being installed/deleted | `com.example.app` |
| `versionCode` | integer | Version code of the package | `42` |
| `observer` | string | Installation observer ID | `987654321` |
| `stagedDir` | string | Staging directory path | `/data/app/vmdl123456.tmp` |
| `request_from` | string | Package that requested the operation | `com.android.vending` |
| **`initiatingPackageName`** | **string** | **Package that initiated the installation** | **`com.google.android.packageinstaller`** |
| **`originatingPackageName`** | **string** | **Package where install originated** | **`com.sec.android.app.sbrowser`** |
| **`installerPackageName`** | **string** | **Installer package (e.g., Play Store)** | **`com.android.vending`** |

### Package Metadata Fields

These fields are extracted from the Packages section for each installed package:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `package_name` | string | Package identifier | `com.example.app` |
| `appId` | integer | Application UID | `10333` |
| `uid` | integer | Application UID (alias) | `10333` |
| **`installerPackageName`** | **string** | **Installer package** | **`com.android.vending`** |
| **`initiatingPackageName`** | **string** | **Initiating package** | **`com.google.android.packageinstaller`** |
| **`originatingPackageName`** | **string** | **Originating package** | **`com.sec.android.app.sbrowser`** |
| `firstInstallTime` | string | First installation time | `2025-08-26 13:40:46` |
| `lastUpdateTime` | string | Last update time | `2025-08-26 13:40:57` |
| `timeStamp` | string | Package timestamp | `2025-08-26 13:40:46` |
| `codePath` | string | Package code path | `/data/app/~~test/com.example.app` |
| `resourcePath` | string | Package resource path | `/data/app/~~test/com.example.app` |
| `targetSdkVersion` | integer | Target SDK version | `34` |
| `versionCode` | string | Package version code | `1.2.3` |
| `versionName` | string | Human-readable version | `1.2.3` |
| `packageSource` | string | Package source type | `4` |

## Understanding Package Name Fields

### initiatingPackageName
The package that **initiated** the installation process. This is typically:
- `com.google.android.packageinstaller` - Standard Android installer
- `com.android.packageinstaller` - AOSP installer
- `com.android.vending` - Google Play Store
- `com.sec.android.app.samsungapps` - Samsung Galaxy Store
- Other installer apps

**Use Case**: Detect installations from unexpected initiators, which may indicate:
- Sideloading from unknown sources
- Malware self-installing additional payloads
- Exploitation of installer vulnerabilities

### originatingPackageName
The package where the installation **originated from**. This could be:
- Browser packages if APK was downloaded from web
- File manager if APK was opened from storage
- Messaging apps if APK was shared via chat
- Email apps if APK came as attachment

**Use Case**: Identify the delivery mechanism:
- Browser-based delivery (phishing, drive-by downloads)
- Social engineering via messaging apps
- Email attachments
- Physical USB transfers

### installerPackageName
The **installer package** that actually performed the installation. Usually:
- `com.android.vending` - Google Play Store
- `com.google.android.packageinstaller` - System installer
- MDM packages for enterprise apps
- null for pre-installed system apps

**Use Case**: Verify packages were installed through legitimate channels.

## Example Detection Scenarios

### Scenario 1: Sideloaded Malware from Browser

```yaml
title: Suspicious Sideload from Browser
detection:
    selection:
        event_type: START_INSTALL
        originatingPackageName|contains:
            - 'browser'
            - 'chrome'
    filter_store:
        installerPackageName:
            - 'com.android.vending'
            - 'com.google.android.packageinstaller'
    condition: selection and not filter_store
```

**What it detects**: APKs downloaded by a browser but not installed through official channels.

### Scenario 2: Unknown Installer Package

```yaml
title: Installation from Unknown Initiator
detection:
    selection:
        event_type: START_INSTALL
    filter_trusted:
        initiatingPackageName:
            - 'com.android.vending'
            - 'com.google.android.packageinstaller'
            - 'com.android.managedprovisioning'  # MDM
            - 'com.sec.android.app.samsungapps'
    condition: selection and not filter_trusted
```

**What it detects**: Packages installed by non-standard initiators, potentially malicious installers.

### Scenario 3: Self-Installing Malware Chain

```yaml
title: Package Installing Other Packages
detection:
    selection:
        event_type: START_INSTALL
        initiatingPackageName: 'com.suspicious.app'
    condition: selection
```

**What it detects**: A specific package installing other apps, which may indicate malware dropping additional payloads.

### Scenario 4: Multiple Installations from Same Origin

```yaml
title: Bulk Installation Campaign
detection:
    selection:
        event_type: START_INSTALL
        originatingPackageName: 'com.example.suspicious'
    condition: selection | count(pkg) by originatingPackageName > 5
```

**What it detects**: Many packages being installed from the same source, potentially a malware campaign.

## Tombstone and Backtrace Fields

Crash (tombstone) output produces two kinds of log entries for Sigma:

1. **Tombstone-level** (`event_type: native_crash`, `crash_type: tombstone`) – one entry per native crash.
2. **Backtrace-frame-level** (`event_type: tombstone_backtrace`) – one entry per backtrace frame, so rules can match on library, function, `build_id`, etc.

### Tombstone-Level Fields

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `event_type` | string | `native_crash` | `native_crash` |
| `crash_type` | string | `tombstone` | `tombstone` |
| `pid` | integer | Process ID | `1234` |
| `tid` | integer | Thread ID | `1235` |
| `uid` | integer | User ID | `10100` |
| `process_name` | string | Crashed process name | `com.example.app` |
| `signal` | string | Signal (e.g. SIGSEGV, SIGABRT) | `SIGSEGV` |
| `code` | string | Signal code | `SEGV_MAPERR` |
| `fault_addr` | string | Fault address | `0x0000000000000000` |
| `timestamp` | string | When the crash occurred | `2025-11-08 17:54:03` |
| `abort_message` | string | Abort message if any | (optional) |
| `backtrace_frames` | integer | Number of backtrace frames | `12` |

### Backtrace-Frame Fields (tombstone_backtrace entries)

Each backtrace frame is emitted as a separate log entry with `event_type: tombstone_backtrace`. The entry includes all tombstone-level fields above plus:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `event_type` | string | `tombstone_backtrace` | `tombstone_backtrace` |
| `backtrace_frame_index` | integer | Index of this frame in the backtrace | `0` |
| `frame` | integer | Frame number | `0` |
| `pc` | string | Program counter | `00000000001de20c` |
| `library` | string | Path to the loaded library | `/system/lib64/libimagecodec.quram.so` |
| `function` | string | Symbol name (if available) | `QuramDngOpcodeScalePerColumn::processArea(...)` |
| `offset` | string | Offset within the function | `552` |
| `build_id` | string | Build ID of the library | `995700b69e2632866b44243e378997c680105a42` |
| `raw_line` | string | Original backtrace line | `#00 pc 00000000001de20c  /system/lib64/...` |

**Use case**: Write Sigma rules that match on specific libraries (e.g. known vulnerable codecs), function names, or `build_id` to detect exploitation or vulnerable components in crash dumps.

### Example: Tombstone backtrace by library

```yaml
title: Suspicious Native Crash in Image Codec
detection:
    selection:
        event_type: tombstone_backtrace
        library|contains:
            - 'libimagecodec'
            - 'libstagefright'
    condition: selection
```

### Example: Tombstone backtrace by function

```yaml
title: Tombstone Backtrace in QuramDngOpcodeScalePerColumn::processArea
detection:
    selection:
        event_type: tombstone_backtrace
        function|contains:
            - 'QuramDngOpcodeScalePerColumn::processArea'
    condition: selection
```

### Example: CVE rule (library + function)

```yaml
title: CVE-2025-21055 – Quram DNG codec
detection:
    codec_library:
        event_type: tombstone_backtrace
        library|contains:
            - 'libimagecodec.quram.so'
    function_crash:
        function|contains:
            - 'QuramDngOpcodeScalePerColumn::processArea'
    condition: codec_library and function_crash
```

### ANR event fields (anr_file, anr_trace)

| Event type | Fields | Description |
|------------|--------|-------------|
| `anr_file` | `filename`, `size`, `timestamp`, `owner`, `crash_type: anr` | ANR file metadata from bug report |
| `anr_trace` | `pid`, `cmd_line`, `subject`, `thread_count`, `crash_type: anr` | Parsed ANR trace (VM traces at last ANR) |

## Process Parser Fields

Process parser output produces one log entry per running process:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `event_type` | string | `process_running` | `process_running` |
| `pid` | integer | Process ID | `1234` |
| `user` | string | Process owner (user) | `u0_a123` |
| `cmd` | string | Command line | `com.example.app` |
| `thread_count` | integer | Number of threads (if available) | `12` |

## Power Parser Fields

| Event type | Fields | Description |
|------------|--------|-------------|
| `power_event` | `timestamp`, `power_event_type`, `flags`, `details` | Power history events |
| `reset_reason` | `reason`, `stack_trace` | Reset reasons with optional stack trace |

## Battery Parser Fields

| Event type | Fields | Description |
|------------|--------|-------------|
| `battery_app_stats` | `uid`, `package_name`, `cpu_user_time_ms`, `cpu_system_time_ms`, `foreground_service_time_ms`, `total_network_bytes`, `total_wakelock_time_ms`, `total_job_count` | Per-app battery stats |
| `battery_history` | `timestamp`, `status`, `volt`, `temp`, `charge` | Battery history samples |

## USB Parser Fields

| Event type | Fields | Description |
|------------|--------|-------------|
| `usb_port` | `port_id`, `connected`, `mode` | USB port state |
| `usb_device` | `device_id`, `vendor_id`, `product_id`, etc. | Connected USB device info |

## Bluetooth Parser Fields

Bluetooth parser output produces one log entry per bonded device from the bug report:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `event_type` | string | `bluetooth_device` | `bluetooth_device` |
| `mac_address` | string | Full MAC address (if available) | `a0:0c:e2:1e:53:25` |
| `masked_address` | string | Masked MAC (privacy) | `XX:XX:XX:XX:53:25` |
| `identity_address` | string | Identity address if different | (optional) |
| `name` | string | Device name | `OpenFit 2+ by Shokz` |
| `transport_type` | string | `LE`, `DUAL`, or `BR/EDR` | `DUAL` |
| `device_class` | string | Bluetooth device class (hex) | `0x240404` |
| `connected` | boolean | Whether device is currently connected | `true` |
| `services` | array of strings | Service UUIDs or names | `["SPP", "AudioSink"]` |
| `manufacturer` | integer | Manufacturer ID | `688` |
| `device_type` | integer | Device type code | `3` |
| `link_type` | integer | Link type code | (optional) |

**Use case**: Detect specific Bluetooth devices (e.g. vulnerable WhisperPair devices), unexpected bonded devices, or device classes of interest.

## Network Parser Fields

Network parser output produces several event types from sockets, interfaces, network stats, and WiFi scanner data.

### Socket entries (`event_type: network_socket`)

One log entry per socket connection (from netstat/ss):

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `event_type` | string | `network_socket` | `network_socket` |
| `protocol` | string | Protocol (tcp, udp, etc.) | `tcp` |
| `local_address` | string | Local address:port | `127.0.0.1:12345` |
| `remote_address` | string | Remote address:port | `10.0.0.1:443` |
| `local_ip` | string | Local IP | `127.0.0.1` |
| `local_port` | integer | Local port | `12345` |
| `remote_ip` | string | Remote IP | `10.0.0.1` |
| `remote_port` | integer | Remote port | `443` |
| `state` | string | Connection state (e.g. ESTABLISHED) | `ESTABLISHED` |
| `uid` | integer | Owning UID | `10100` |
| `inode` | integer | Socket inode | (optional) |
| `recv_q`, `send_q` | integer | Queue sizes | (optional) |
| `socket_key`, `additional_info` | string | Extra details | (optional) |

### Interface entries (`event_type: network_interface`)

One log entry per network interface:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `event_type` | string | `network_interface` | `network_interface` |
| `name` | string | Interface name | `wlan0` |
| `ip_addresses` | array of strings | IP addresses | `["192.168.1.100"]` |
| `flags` | array of strings | Interface flags | `["UP", "BROADCAST"]` |
| `mtu` | integer | MTU | `1500` |
| `rx_bytes`, `tx_bytes` | integer | Traffic counters | (optional) |

### Network stats entries (`event_type: network_stats`)

One log entry per aggregated interface (WIFI or MOBILE):

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `event_type` | string | `network_stats` | `network_stats` |
| `rx_bytes`, `tx_bytes` | integer | Bytes received/sent | `2000000` |
| `rx_packets`, `tx_packets` | integer | Packets | (optional) |
| `network_type` | string | `WIFI` or `MOBILE` | `WIFI` |
| `wifi_network_name` | string | WiFi SSID (for WIFI) | `MyNetwork` |
| `subscriber_id` | string | Mobile subscriber (for MOBILE) | (optional) |
| `rat_type` | string | Radio access type | `COMBINED` |
| `metered` | boolean | Metered network | `false` |
| `default_network` | boolean | Default network | `true` |

### WiFi scanner entries

| Event type | Fields | Description |
|------------|--------|-------------|
| `wifi_saved_network` | `ssid` | Saved WiFi network (PNO) |
| `wifi_scan_result` | `scan_section`, `bssid`, `frequency`, `rssi`, `age`, `ssid`, `security` | Nearby network from scan |
| `wifi_scan_event` | `timestamp`, `scan_event_type`, `uid`, `package`, `attribution_tag`, `work_source` | App-initiated scan event |

**Use case**: Detect suspicious connections (remote_ip/port), unexpected interfaces, or apps performing WiFi scans.

## Rules directory layout

Example and CVE rules are under `testdata/rules/`:

- **Package / install**: `browser_to_non_store_install.yml`, `match_package.yml`, `suspicious_initiator.yml`
- **Crash / tombstone**: `tombstone_backtrace_imagecodec.yml` (library-based), and rules matching on `function` (e.g. QuramDngOpcodeScalePerColumn::processArea)
- **CVE rules**: `testdata/rules/CVE/` (e.g. `CVE-2025-21055.yaml`)
- **Example rules (full field coverage)**: `testdata/rules/examples/` — one rule file per parser/event type, each referencing every Sigma field for that source (see `testdata/rules/examples/README.md`).

When running the CLI, point `--rules-dir` at `./testdata/rules` to include all subdirectories (including `CVE/` and `examples/`).

## Testing Rules

To test your Sigma rules:

```bash
# Test against a sample bug report
bel-cli --file-path=testdata/sample_bugreport.txt \
  --rules-dir=./your_rules/ \
  --detection-type=sigma \
  --show-log-details

# Check how many log entries are generated
bel-cli --file-path=bugreport.zip \
  --parser-type=package \
  --rules-dir=./your_rules/ \
  --detection-type=sigma \
  -v
```

## Available Parsers with Sigma Support

| Parser | Sigma Support | Primary Event Types |
|--------|---------------|---------------------|
| Package | ✅ Yes | `package_install`, `START_INSTALL`, `START_DELETE` |
| Battery | ✅ Yes | `battery_app_stats`, `battery_history` |
| Crash | ✅ Yes | `native_crash`, `tombstone_backtrace`, `anr_file`, `anr_trace` |
| Process | ✅ Yes | `process_running` |
| Power | ✅ Yes | `power_event`, `reset_reason` |
| USB | ✅ Yes | `usb_port`, `usb_device` |
| Bluetooth | ✅ Yes | `bluetooth_device` |
| Network | ✅ Yes | `network_socket`, `network_interface`, `network_stats`, `wifi_saved_network`, `wifi_scan_result`, `wifi_scan_event` |
| Device Policy | ❌ No | - |
| ADB | ❌ No | - |
| Authentication | ❌ No | - |
| VPN | ❌ No | - |

## Contributing Rules

When creating new Sigma rules:

1. **Use specific field names** - Refer to this document for exact field names
2. **Test thoroughly** - Verify against real bug reports
3. **Document false positives** - List known scenarios that may trigger false positives
4. **Set appropriate severity** - Use `critical`, `high`, `medium`, `low`, or `informational`
5. **Add MITRE ATT&CK tags** - Use standard mobile attack technique IDs when applicable

## Support

For questions or issues with Sigma integration:
- Check verbose output: `-v` flag
- Show log details: `--show-log-details` flag
- Verify log entry generation: Look for "Extracted X log entries" in logs
- Check rule syntax: Ensure YAML is valid
