#!/usr/bin/env python3
"""
Anker Prime 26250mAh (26K) BLE client + live telemetry monitor.

Adapted from atc1441's 27650mAh WebBluetooth tool. Model differences handled here:
  * GATT service  : 8c850001-0302-41c5-b46e-cf057c562025   (27650 used 22150001-4002-81c5-...)
  * write char    : 8c850002-0302-41c5-b46e-cf057c562025
  * notify char   : 8c850003-0302-41c5-b46e-cf057c562025
  * advertised svc: 0xFF09                                  (27650 advertised 0x2215)
  * AES-CBC IV    : FIRST 16 bytes of the 17-byte serial    (27650 serial was 16 bytes)
  * telemetry     : firmware v0.0.5.2 uses different commands / TLV layout than the 27650
                    (see decode below). The 27650 status command 0x0500 only returns an ack.

Telemetry (firmware v0.0.5.2), all under group 0x11, AES-CBC encrypted:
  * cmd 0x0200 -> response 0x0A00 : full status snapshot (settings, battery, temps, limits)
  * cmd 0x0700 -> response 0x0300 : live power status; the device then STREAMS 0x0300 frames.
  Live-frame TLVs (each value = [type_byte, data...]; type 0x04 = struct):
    A2 = battery %            (data[0])
    A6 = total output power   ([04, mode, u16le x0.1 W])
    A8 = USB-C1 port          ([04, mode, u16le V x0.1, u16le A x0.1, u16le W x0.1, ...])
    A9 = USB-C2 port          (same layout)
    A7 = USB-A port           (idle here; layout to confirm under load)
    A3 / A5 = input-side power scalars (0 while discharging; confirm with a charge test)
    AF = temperature 1 (C),  B0 = temperature 2 (C)
"""
import asyncio, sys, struct, time
from bleak import BleakClient, BleakScanner
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as pkpad

SVC    = "8c850001-0302-41c5-b46e-cf057c562025"
WRITE  = "8c850002-0302-41c5-b46e-cf057c562025"
NOTIFY = "8c850003-0302-41c5-b46e-cf057c562025"
ADVERTISED_16 = "0000ff09-0000-1000-8000-00805f9b34fb"

A2_STATIC   = bytes.fromhex('32633337376466613039636462373932343838396534323932613337663631633863356564353264')
INITIAL_KEY = A2_STATIC[:16]           # ascii "2c377dfa09cdb792"

def xor_cksum(d):
    c = 0
    for b in d: c ^= b
    return c

def build_tlv(tlvs):
    o = bytearray()
    for t, v in tlvs: o += bytes([t, len(v)]) + v
    return bytes(o)

def build_request(cmd, tlvs, group=0x01):
    return bytes([0x03, 0x00, group, (cmd >> 8) & 0xFF, cmd & 0xFF]) + build_tlv(tlvs)

def frame(payload):
    msg = bytes([0xff, 0x09]) + struct.pack('<H', len(payload) + 5) + payload
    return msg + bytes([xor_cksum(msg)])

def enc(key, iv, pt):
    p = pkpad.PKCS7(128).padder(); data = p.update(pt) + p.finalize()
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor(); return e.update(data) + e.finalize()

def dec(key, iv, ct):
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor(); raw = d.update(ct) + d.finalize()
    try:
        u = pkpad.PKCS7(128).unpadder(); return u.update(raw) + u.finalize()
    except Exception:
        return raw

def parse_tlv(p, off=0):
    i, out = off, []
    while i < len(p) - 1:
        t, ln = p[i], p[i+1]
        if i + 2 + ln > len(p): break
        out.append((t, p[i+2:i+2+ln])); i += 2 + ln
    return out

def u16(b, o=0): return struct.unpack_from('<H', b, o)[0] if len(b) >= o + 2 else 0

def decode_port(v):
    """type-0x04 port struct: [04, mode, Vx0.1(u16), Ax0.1(u16), Wx0.1(u16), tail]"""
    if len(v) < 8 or v[0] != 0x04:
        return {'mode': 'off', 'V': 0.0, 'A': 0.0, 'W': 0.0}
    on = v[1] != 0
    return {
        'mode': 'output' if on else 'off',
        'V': round(u16(v, 2) / 10.0, 2),
        'A': round(u16(v, 4) / 10.0, 3),
        'W': round(u16(v, 6) / 10.0, 2),
    }

def parse_live(payload):
    off = 1 if (payload and payload[0] == 0x00) else 0
    d = {}
    for t, v in parse_tlv(payload, off):
        if t == 0xA2 and len(v) >= 2: d['battery'] = v[1]
        elif t == 0xA6 and len(v) >= 4: d['out_W'] = round(u16(v, 2) / 10.0, 2)
        elif t == 0xA3 and len(v) >= 4: d['in_A3_W'] = round(u16(v, 2) / 10.0, 2)
        elif t == 0xA5 and len(v) >= 4: d['in_A5_W'] = round(u16(v, 2) / 10.0, 2)
        elif t == 0xA8: d['C1'] = decode_port(v)
        elif t == 0xA9: d['C2'] = decode_port(v)
        elif t == 0xA7: d['A'] = decode_port(v)
        elif t == 0xAF and len(v) >= 2: d['temp1'] = v[1]
        elif t == 0xB0 and len(v) >= 2: d['temp2'] = v[1]
    return d

class Sess:
    def __init__(self):
        self.q = asyncio.Queue(); self.serial = None; self.version = None; self.mac = None
        self.key = None; self.iv = None; self.crypto = 'INACTIVE'; self.sk = None

S = Sess()

def notif(_, data):
    raw = bytes(data)
    if len(raw) < 5: return
    body = raw[4:-1]
    if len(body) < 5: return
    hi, lo = body[3], body[4]
    encd = (hi & 0x40) != 0
    full = ((hi & ~0x40) << 8) | lo
    if encd and S.key is not None:
        try: content = dec(S.key, S.iv, body[5:])
        except Exception: return
        if S.crypto == 'Initial':
            off = 1 if (content and content[0] == 0x00) else 0
            for t, v in parse_tlv(content, off):
                if t == 0xA1 and len(v) == 16: S.sk = v
        S.q.put_nowait((full, content))
    else:
        for t, v in parse_tlv(body, 6):
            if t == 0xA3: S.version = v.decode('latin1', 'replace')
            elif t == 0xA4 and len(v) >= 16: S.serial = v.decode('latin1', 'replace')
            elif t == 0xA5: S.mac = ':'.join(f'{b:02x}' for b in v[:6])
        S.q.put_nowait((full, body))

async def wait(t=1.5):
    try: return await asyncio.wait_for(S.q.get(), t)
    except asyncio.TimeoutError: return None

async def find():
    d = await BleakScanner.find_device_by_filter(
        lambda dev, adv: ADVERTISED_16 in [u.lower() for u in (adv.service_uuids or [])]
        or (dev.name or '').upper().startswith('AFYDN'), timeout=15.0)
    return d

def fmt_port(name, p):
    if not p or p['mode'] == 'off':
        return f"  {name}: off"
    return f"  {name}: {p['V']}V  {p['A']}A  {p['W']}W"

async def run(addr, monitor, duration):
    dev = None
    if addr:
        dev = await BleakScanner.find_device_by_address(addr, timeout=12.0)
    if dev is None:
        print("Scanning for Anker Prime (0xFF09 / AFYDN*)...")
        dev = await find()
        if not dev: print("Device not found."); return
    print(f"Connecting {dev.address} ...")
    async with BleakClient(dev, timeout=20.0) as cli:
        print("Connected:", cli.is_connected)
        await cli.start_notify(NOTIFY, notif)
        ts = struct.pack('<I', int(time.time()))
        async def snd(p): await cli.write_gatt_char(WRITE, frame(p), response=False)

        # unencrypted handshake
        await snd(build_request(0x0001, [(0xA1, ts), (0xA2, A2_STATIC)])); await wait()
        await snd(build_request(0x0003, [(0xA1, ts), (0xA2, A2_STATIC), (0xA3, b'\x20'), (0xA4, b'\x00\xf0')])); await wait()
        for _ in range(3):
            await snd(build_request(0x0029, [(0xA1, ts), (0xA2, A2_STATIC)]))
            for _ in range(4):
                await wait(0.6)
                if S.serial: break
            if S.serial: break
        await snd(build_request(0x0005, [(0xA1, ts), (0xA2, A2_STATIC), (0xA3, b'\x20'), (0xA4, b'\x00\xf0'), (0xA5, b'\x02')])); await wait()
        if not S.serial: print("Handshake failed (no serial)."); return
        print(f"Serial : {S.serial}")
        print(f"FW ver : {S.version}")
        print(f"MAC    : {S.mac}")

        # crypto: IV = first 16 bytes of the 17-byte serial
        S.key = INITIAL_KEY; S.iv = S.serial.encode('latin1')[:16]; S.crypto = 'Initial'
        tlv = build_tlv([(0xA1, ts), (0xA2, A2_STATIC), (0xA3, bytes(4)), (0xA5, bytes(40))])
        await snd(bytes([0x03, 0x00, 0x01, 0x40, 0x22]) + enc(S.key, S.iv, tlv))
        for _ in range(8):
            await wait(1.0)
            if S.sk: break
        if not S.sk: print("No session key."); return
        S.key = S.sk; S.crypto = 'Session'
        print(f"Session: established\n")

        async def send_enc(g, cmd, tlvs):
            await snd(bytes([0x03, 0x00, g, ((cmd >> 8) & 0xFF) | 0x40, cmd & 0xFF]) + enc(S.key, S.iv, build_tlv(tlvs)))

        # prime with a full-status request, then subscribe to live telemetry
        await send_enc(0x11, 0x0200, [(0xA1, b'\x21')]); await wait(0.8)
        await send_enc(0x11, 0x0700, [(0xA1, b'\x21')])
        t_end = time.time() + (duration if monitor else 8.0)
        shown = False
        while time.time() < t_end:
            ev = await wait(1.0)
            if ev is None:
                await send_enc(0x11, 0x0700, [(0xA1, b'\x21')]); continue
            full, payload = ev
            if full != 0x0300:
                continue
            d = parse_live(payload)
            line = (f"[{time.strftime('%H:%M:%S')}] battery {d.get('battery')}%   "
                    f"out {d.get('out_W')}W   temp {d.get('temp1')}/{d.get('temp2')}C")
            print(line)
            print(fmt_port("USB-C1", d.get('C1')))
            print(fmt_port("USB-C2", d.get('C2')))
            print(fmt_port("USB-A ", d.get('A')))
            shown = True
            if not monitor:
                break
        await cli.stop_notify(NOTIFY)
        if not shown:
            print("No live telemetry frame received.")

def main():
    args = [a for a in sys.argv[1:]]
    monitor = '--monitor' in args
    args = [a for a in args if a != '--monitor']
    addr = None
    duration = 3600.0 if monitor else 3.0
    for a in args:
        if a.replace('.', '').isdigit():
            duration = float(a)
        else:
            addr = a
    asyncio.run(run(addr, monitor, duration))

if __name__ == "__main__":
    main()
