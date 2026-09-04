// tuya-plug: minimal Tuya protocol 3.3 LAN client (status/on/off/toggle).
// Single static binary (musl), no runtime dependencies.
//
// Usage:
//   tuya-plug --ip <plug-ip> --id <dev-id> (--key <local-key> | --key-file <path>) [--port 6668] [--timeout 5] status|on|off|toggle [--json]
//
// Wire format (protocol 3.3, tinytuya-compatible):
//   DP_QUERY(10): {"gwId":id,"devId":id,"uid":id,"t":"<unix>"} -> AES-128-ECB -> 55AA frame (no version header)
//   CONTROL(7):   {"devId":id,"uid":id,"t":"<unix>","dps":{"1":bool}} -> AES-128-ECB -> "3.3"+12x00 header -> 55AA frame
//   Frame: prefix(4)=55AA seqno(4BE) cmd(4BE) len(4BE) [retcode(4) + data] crc32(4BE) suffix(4BE)=AA55
//   Replies may start with an empty ACK frame; the data frame follows on the same connection.
//   Reply payload: optional "3.3"+12x00 header -> AES-128-ECB decrypt -> JSON, dps at root or under "data".
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{SystemTime, UNIX_EPOCH};

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use crc32fast::Hasher as Crc32;
use serde_json::{json, Value};

const PREFIX: u32 = 0x0000_55AA;
const SUFFIX: u32 = 0x0000_AA55;
const CMD_CONTROL: u32 = 7;
const CMD_DP_QUERY: u32 = 10;
const VER_HDR: &[u8; 15] = b"3.3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
const MAX_FRAME_LEN: usize = 1024 * 1024;

fn usage() -> ! {
    eprintln!(
        "usage: tuya-plug --ip <plug-ip> --id <dev-id> (--key <16char> | --key-file <path>) \
         [--port 6668] [--timeout 5] status|on|off|toggle [--json]"
    );
    std::process::exit(2);
}

fn now_t() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into())
}

fn pkcs7_pad(mut v: Vec<u8>) -> Vec<u8> {
    let pad = 16 - (v.len() % 16);
    let pad = if pad == 0 { 16 } else { pad };
    v.extend(std::iter::repeat_n(pad as u8, pad));
    v
}

fn aes_ecb_encrypt(key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut out = Vec::with_capacity(data.len());
    let (chunks, remainder) = data.as_chunks::<16>();
    debug_assert!(remainder.is_empty());
    for chunk in chunks {
        let mut block = GenericArray::from(*chunk);
        cipher.encrypt_block(&mut block);
        out.extend_from_slice(&block);
    }
    out
}

fn aes_ecb_decrypt(key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, String> {
    if !data.len().is_multiple_of(16) {
        return Err(format!("bad cipher len {}", data.len()));
    }
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut out = Vec::with_capacity(data.len());
    let (chunks, remainder) = data.as_chunks::<16>();
    debug_assert!(remainder.is_empty());
    for chunk in chunks {
        let mut block = GenericArray::from(*chunk);
        cipher.decrypt_block(&mut block);
        out.extend_from_slice(&block);
    }
    let &last = out.last().ok_or("empty plaintext")?;
    let pad = last as usize;
    if !(1..=16).contains(&pad) || out.len() < pad {
        return Err("bad padding".into());
    }
    if out[out.len() - pad..].iter().any(|&b| b as usize != pad) {
        return Err("bad padding bytes".into());
    }
    out.truncate(out.len() - pad);
    Ok(out)
}

fn pack_frame(seqno: u32, cmd: u32, payload: &[u8]) -> Vec<u8> {
    // len covers payload + crc(4) + suffix(4); crc covers header + payload.
    let len = (payload.len() + 8) as u32;
    let mut buf = Vec::with_capacity(16 + payload.len() + 8);
    buf.extend_from_slice(&PREFIX.to_be_bytes());
    buf.extend_from_slice(&seqno.to_be_bytes());
    buf.extend_from_slice(&cmd.to_be_bytes());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(payload);
    let mut h = Crc32::new();
    h.update(&buf);
    buf.extend_from_slice(&h.finalize().to_be_bytes());
    buf.extend_from_slice(&SUFFIX.to_be_bytes());
    buf
}

fn read_exact_n(s: &mut TcpStream, n: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).map_err(|e| format!("read: {e}"))?;
    Ok(buf)
}

/// Read one 55AA frame, resynchronising on the prefix if needed.
/// Returns the decrypted-payload bytes (retcode stripped).
fn read_frame(s: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut hdr = read_exact_n(s, 16)?;
    while u32::from_be_bytes(hdr[0..4].try_into().unwrap()) != PREFIX {
        hdr.drain(..1);
        let mut one = [0u8; 1];
        s.read_exact(&mut one).map_err(|e| format!("read: {e}"))?;
        hdr.push(one[0]);
    }
    parse_frame_body(s, &hdr)
}

fn parse_frame_body(s: &mut TcpStream, hdr: &[u8]) -> Result<Vec<u8>, String> {
    let len = u32::from_be_bytes(hdr[12..16].try_into().unwrap()) as usize;
    if !(12..=MAX_FRAME_LEN).contains(&len) {
        return Err(format!("bad frame len {len}"));
    }
    let rest = read_exact_n(s, len)?;
    // Layout after header: [retcode(4) + data] + crc32(4) + suffix(4).
    if rest.len() < 8 {
        return Err("frame too short".into());
    }
    let (body, tail) = rest.split_at(rest.len() - 8);
    let crc_got = u32::from_be_bytes(tail[0..4].try_into().unwrap());
    let suffix = u32::from_be_bytes(tail[4..8].try_into().unwrap());
    if suffix != SUFFIX {
        return Err("bad suffix".into());
    }
    let mut h = Crc32::new();
    h.update(hdr);
    h.update(body);
    if h.finalize() != crc_got {
        return Err("crc mismatch".into());
    }
    if body.len() < 4 {
        return Err("no retcode".into());
    }
    Ok(body[4..].to_vec())
}

fn enc_payload(key: &[u8; 16], cmd: u32, plain_json: &[u8]) -> Vec<u8> {
    // tinytuya parity: DP_QUERY goes without the version header, CONTROL with it.
    // The header is prepended AFTER AES encryption.
    let enc = aes_ecb_encrypt(key, &pkcs7_pad(plain_json.to_vec()));
    if cmd == CMD_DP_QUERY {
        enc
    } else {
        let mut p = Vec::with_capacity(VER_HDR.len() + enc.len());
        p.extend_from_slice(VER_HDR);
        p.extend_from_slice(&enc);
        p
    }
}

fn dec_payload(key: &[u8; 16], payload: &[u8]) -> Result<Value, String> {
    let mut p = payload;
    if p.starts_with(b"3.3") {
        p = &p[VER_HDR.len().min(p.len())..];
    }
    let plain = aes_ecb_decrypt(key, p)?;
    serde_json::from_slice(&plain)
        .map_err(|e| format!("json: {e} body={:?}", String::from_utf8_lossy(&plain)))
}

fn send_recv(
    ip: &str,
    port: u16,
    timeout_s: u64,
    key: &[u8; 16],
    seqno: &mut u32,
    cmd: u32,
    plain: Vec<u8>,
) -> Result<Value, String> {
    let addr = format!("{ip}:{port}");
    let sock_addr = addr
        .to_socket_addrs()
        .map_err(|e| format!("dns/resolve: {e}"))?
        .next()
        .ok_or("no addr")?;
    let mut s = TcpStream::connect_timeout(&sock_addr, std::time::Duration::from_secs(timeout_s))
        .map_err(|e| format!("connect {addr}: {e}"))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(timeout_s)))
        .map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(std::time::Duration::from_secs(timeout_s)))
        .map_err(|e| e.to_string())?;
    let frame = pack_frame(*seqno, cmd, &enc_payload(key, cmd, &plain));
    *seqno = seqno.wrapping_add(1);
    s.write_all(&frame).map_err(|e| format!("write: {e}"))?;
    // The first reply may be an empty ACK frame; keep reading until data arrives.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_s);
    loop {
        if std::time::Instant::now() > deadline {
            return Err("timeout waiting for data frame".into());
        }
        let payload = read_frame(&mut s)?;
        if payload.is_empty() {
            continue;
        }
        return dec_payload(key, &payload);
    }
}

fn get_dps(v: &Value) -> Option<serde_json::Map<String, Value>> {
    if let Some(dps) = v.get("dps").and_then(|d| d.as_object()) {
        return Some(dps.clone());
    }
    if let Some(dps) = v
        .get("data")
        .and_then(|d| d.get("dps"))
        .and_then(|d| d.as_object())
    {
        return Some(dps.clone());
    }
    None
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut ip = String::new();
    let mut id = String::new();
    let mut key = String::new();
    let mut key_file: Option<String> = None;
    let mut port: u16 = 6668;
    let mut timeout: u64 = 5;
    let mut cmd = String::new();
    let mut want_json = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--ip" => {
                i += 1;
                ip = args.get(i).cloned().unwrap_or_default();
            }
            "--id" => {
                i += 1;
                id = args.get(i).cloned().unwrap_or_default();
            }
            "--key" => {
                i += 1;
                key = args.get(i).cloned().unwrap_or_default();
            }
            "--key-file" => {
                i += 1;
                key_file = args.get(i).cloned();
            }
            "--port" => {
                i += 1;
                port = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(6668);
            }
            "--timeout" => {
                i += 1;
                timeout = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(5);
            }
            "--json" => want_json = true,
            "status" | "on" | "off" | "toggle" => cmd = args[i].clone(),
            _ => {}
        }
        i += 1;
    }
    if let Some(f) = key_file {
        key = std::fs::read_to_string(&f)
            .map_err(|e| format!("read key file: {e}"))
            .unwrap_or_else(|e| {
                eprintln!("error: {e}");
                std::process::exit(1);
            })
            .trim()
            .to_string();
    }
    if ip.is_empty() || id.is_empty() || key.is_empty() || cmd.is_empty() {
        usage();
    }
    if key.len() != 16 {
        eprintln!("error: key must be 16 chars, got {}", key.len());
        std::process::exit(1);
    }
    let kb: &[u8; 16] = key.as_bytes().try_into().unwrap();
    let keyarr = *kb;
    // Nonce-like start value; the device does not validate it.
    let mut seqno: u32 = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(1)
        & 0x7FFF_FFFF)
        .max(1);

    let fail = |msg: String| -> ! {
        if want_json {
            println!("{}", json!({"ok": false, "error": msg}));
        } else {
            eprintln!("error: {msg}");
        }
        std::process::exit(1);
    };

    let do_query = |seqno: &mut u32| -> Result<Value, String> {
        let t = now_t();
        let plain =
            format!(r#"{{"gwId":"{id}","devId":"{id}","uid":"{id}","t":"{t}"}}"#).into_bytes();
        send_recv(&ip, port, timeout, &keyarr, seqno, CMD_DP_QUERY, plain)
    };

    let do_set = |seqno: &mut u32, target: bool| -> Result<Value, String> {
        let t = now_t();
        let plain = format!(r#"{{"devId":"{id}","uid":"{id}","t":"{t}","dps":{{"1":{target}}}}}"#)
            .into_bytes();
        send_recv(&ip, port, timeout, &keyarr, seqno, CMD_CONTROL, plain)
    };

    match cmd.as_str() {
        "status" => match do_query(&mut seqno) {
            Ok(v) => {
                let dps = get_dps(&v);
                let on = dps
                    .as_ref()
                    .and_then(|d| d.get("1"))
                    .and_then(|x| x.as_bool());
                if want_json {
                    println!("{}", json!({"ok": true, "on": on, "dps": dps, "raw": v}));
                } else {
                    println!(
                        "{}",
                        match on {
                            Some(true) => "ON",
                            Some(false) => "OFF",
                            None => "UNKNOWN",
                        }
                    );
                }
            }
            Err(e) => fail(e),
        },
        "on" | "off" => {
            let target = cmd == "on";
            match do_set(&mut seqno, target) {
                Ok(v) => {
                    if want_json {
                        println!("{}", json!({"ok": true, "cmd": cmd, "result": v}));
                    } else {
                        println!("OK {cmd}");
                    }
                }
                Err(e) => fail(e),
            }
        }
        "toggle" => {
            let cur = do_query(&mut seqno)
                .map_err(|e| e.clone())
                .unwrap_or_else(|e| fail(e));
            let on = get_dps(&cur)
                .and_then(|d| d.get("1").and_then(|x| x.as_bool()))
                .unwrap_or(false);
            let target = !on;
            match do_set(&mut seqno, target) {
                Ok(v) => {
                    if want_json {
                        println!(
                            "{}",
                            json!({"ok": true, "cmd": "toggle", "now_on": target, "result": v})
                        );
                    } else {
                        println!("OK toggle -> {}", if target { "ON" } else { "OFF" });
                    }
                }
                Err(e) => fail(e),
            }
        }
        _ => usage(),
    }
}
