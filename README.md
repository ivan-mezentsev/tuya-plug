# tuya-plug

Minimal Tuya protocol 3.3 LAN client: `status` / `on` / `off` / `toggle` for a
single Wi-Fi plug or switch. One static binary, zero runtime dependencies —
drop it into your Home Assistant `/config` and drive it from a `command_line`
switch, no HACS, no cloud polling.

```sh
tuya-plug --ip <plug-ip> --id <dev-id> (--key <local-key> | --key-file <path>) \
  [--port 6668] [--timeout 5] status|on|off|toggle [--json]
```

Plain `status` prints `ON` / `OFF`; `--json` prints a machine-readable object.
`--key-file` keeps the local key out of the process list and YAML.

## Build

```sh
cargo build --release --target x86_64-unknown-linux-musl      # generic x86-64
cargo build --release --target aarch64-unknown-linux-musl     # e.g. Raspberry Pi 4
```

## Home Assistant example

```yaml
command_line:
  - switch:
      name: kitchen_smart_plug
      unique_id: tuya_wifi_plug_kitchen
      command_state: /config/tuya-plug/bin/tuya-plug --ip 192.168.1.50 --id YOUR_DEVICE_ID --key-file /config/tuya-plug/.plug_key --timeout 6 status
      value_template: "{{ value.strip() == 'ON' }}"
      command_on: /config/tuya-plug/bin/tuya-plug --ip 192.168.1.50 --id YOUR_DEVICE_ID --key-file /config/tuya-plug/.plug_key --timeout 6 on
      command_off: /config/tuya-plug/bin/tuya-plug --ip 192.168.1.50 --id YOUR_DEVICE_ID --key-file /config/tuya-plug/.plug_key --timeout 6 off
      scan_interval: 60
```

Give the plug a static DHCP lease first. On current Home Assistant use the
top-level `command_line:` format (the legacy `switch: platform: command_line`
form is silently ignored).

## Getting the local key

Stock Tuya firmware needs a one-time cloud step to reveal the per-device
`local_key` (16 chars): pair the plug in Smart Life / Tuya app once, then
extract `device_id` + `local_key` via `python -m tinytuya wizard` or the
`tuya-local` integration's cloud-assisted setup, and store the key in a
root-only file. After that the plug is driven over LAN. Note: re-pairing the
plug in the vendor app rotates the key.

## Protocol notes

- Tuya 3.3 over TCP 6668: AES-128-ECB + CRC32 `55AA` frames (tinytuya-compatible,
  frames verified byte-identical against tinytuya).
- `DP_QUERY(10)` is sent without the `3.3` version header, `CONTROL(7)` with it.
- DPS `1` is the switch channel on plugs (some plugs expose extra DPs, e.g.
  countdown timers — see `--json` output).
- Only protocol 3.3 is implemented; many plugs speak it even when the cloud
  reports otherwise.
