# Example Sigma Rules (Field Coverage)

These example rules **cover every field** exposed by the Sigma integration. They are intended for:

- **Testing** that all parsers and fields are correctly emitted as log entries
- **Reference** when writing new rules (see which field names to use)
- **Validation** of the integration (run with `--rules-dir=./testdata/rules/examples`)

They are **not** tuned for real-world detection; use the rules in the parent directory and `CVE/` for that.

## File → Parser / Event Types

| File | Parser | Event types / fields covered |
|------|--------|-----------------------------|
| `example_01_package_install.yml` | Package | Install: `event_type`, `timestamp`, `pkg`, `versionCode`, `observer`, `stagedDir`, `request_from`, `initiatingPackageName`, `originatingPackageName`, `installerPackageName` |
| `example_02_package_metadata.yml` | Package | Metadata: `package_name`, `appId`, `uid`, `codePath`, `resourcePath`, `firstInstallTime`, `lastUpdateTime`, `timeStamp`, `targetSdkVersion`, `versionCode`, `versionName`, `packageSource`, `installerPackageName`, `initiatingPackageName`, `originatingPackageName` |
| `example_03_process.yml` | Process | `event_type`, `pid`, `user`, `cmd`, `thread_count` |
| `example_04_power.yml` | Power | `power_event`: `timestamp`, `power_event_type`, `flags`, `details`; `reset_reason`: `reason`, `stack_trace` |
| `example_05_battery.yml` | Battery | `battery_app_stats`: `uid`, `package_name`, `cpu_user_time_ms`, `cpu_system_time_ms`, `foreground_service_time_ms`, `total_network_bytes`, `total_wakelock_time_ms`, `total_job_count`; `battery_history`: `timestamp`, `status`, `volt`, `temp`, `charge` |
| `example_06_usb.yml` | USB | `usb_port`: `port_id`, `connected`, `mode`; `usb_device`: `vendor_id`, `product_id`, `product_name`, `manufacturer` |
| `example_07_bluetooth.yml` | Bluetooth | `mac_address`, `masked_address`, `identity_address`, `name`, `transport_type`, `device_class`, `connected`, `services`, `manufacturer`, `device_type`, `link_type` |
| `example_08_crash_tombstone.yml` | Crash | Tombstone: `event_type`, `crash_type`, `pid`, `tid`, `uid`, `process_name`, `signal`, `code`, `fault_addr`, `timestamp`, `abort_message`, `backtrace_frames` |
| `example_09_crash_backtrace.yml` | Crash | Backtrace: `backtrace_frame_index`, `frame`, `pc`, `library`, `function`, `offset`, `build_id`, `raw_line` |
| `example_10_crash_anr.yml` | Crash | `anr_file`: `filename`, `size`, `timestamp`, `owner`; `anr_trace`: `pid`, `cmd_line`, `subject`, `thread_count` |
| `example_11_network_socket.yml` | Network | `protocol`, `local_address`, `remote_address`, `local_ip`, `local_port`, `remote_ip`, `remote_port`, `state`, `uid`, `inode`, `recv_q`, `send_q`, `socket_key`, `additional_info` |
| `example_12_network_interface.yml` | Network | `name`, `ip_addresses`, `flags`, `mtu`, `rx_bytes`, `tx_bytes` |
| `example_13_network_stats.yml` | Network | `rx_bytes`, `tx_bytes`, `rx_packets`, `tx_packets`, `network_type`, `wifi_network_name`, `subscriber_id`, `rat_type`, `metered`, `default_network` |
| `example_14_wifi.yml` | Network | `wifi_saved_network`: `ssid`; `wifi_scan_result`: `scan_section`, `bssid`, `frequency`, `rssi`, `age`, `ssid`, `security`; `wifi_scan_event`: `timestamp`, `scan_event_type`, `uid`, `package`, `attribution_tag` |

## How to run

```bash
# Run all parsers and evaluate example rules (from repo root)
bel-cli --file-path=path/to/bugreport.zip \
  --rules-dir=./testdata/rules/examples \
  --detection-type=sigma \
  -v

# Run a single parser (e.g. Network) with example rules
bel-cli --file-path=path/to/bugreport.zip \
  --parser-type=network \
  --rules-dir=./testdata/rules/examples \
  --detection-type=sigma
```

See [docs/SIGMA_FIELDS.md](../../../docs/SIGMA_FIELDS.md) for the full field reference.
