#!/usr/bin/env python3
"""
Anker Prime 26250mAh (26K) BLE client.

Adapted from atc1441's 27650mAh WebBluetooth tool. Model differences handled here:
  * GATT service  : 8c850001-0302-41c5-b46e-cf057c562025   (27650 used 22150001-4002-81c5-...)
  * write char    : 8c850002-0302-41c5-b46e-cf057c562025
  * notify char   : 8c850003-0302-41c5-b46e-cf057c562025
  * advertised svc: 0xFF09                                  (27650 advertised 0x2215)
  * AES-CBC IV    : FIRST 16 bytes of the 17-byte serial    (27650 serial was 16 bytes)
Everything else (0xff09 framing, XOR checksum, static key, TLV handshake) is identical.
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

def parse_tlv(p, off):
    i, out = off, []
    while i < len(p) - 1:
        t, ln = p[i], p[i+1]
        if i + 2 + ln > len(p): break
        out.append((t, p[i+2:i+2+ln])); i += 2 + ln
    return out

class Sess:
    def __init__(self):
        self.q = asyncio.Queue(); self.serial=None; self.version=None; self.mac=None
        self.key=None; self.iv=None; self.crypto='INACTIVE'; self.session_key=None
        self.telemetry = []

S = Sess()

def mode_str(b): return {0:'Off',1:'Input',2:'Output'}.get(b, f'Unknown(0x{b:02x})')

def parse_port(v):
    if len(v) < 12: return None
    m = mode_str(v[2])
    if m == 'Off': return {'mode':m}
    volt = struct.unpack_from('<H', v, 3)[0] / 10.0
    curr = struct.unpack_from('<H', v, 5)[0] / 10.0
    return {'mode':m, 'V':round(volt,2), 'A':round(curr,3), 'W':round(volt*curr,2)}

def parse_status(payload):
    off = 1 if (payload and payload[0]==0x00) else 0
    res = {}
    for t, v in parse_tlv(payload, off):
        if t == 0xA2 and len(v) >= 10:
            res['battery_%'] = f"{v[8]}.{v[9]:02d}"
        elif t == 0xA4: res['C1'] = parse_port(v)
        elif t == 0xA5: res['C2'] = parse_port(v)
        elif t == 0xA6: res['A']  = parse_port(v)
        elif t == 0xAE and len(v) >= 5:
            res['out_W'] = struct.unpack_from('<H', v, 1)[0]/10.0
            res['in_W']  = struct.unpack_from('<H', v, 3)[0]/10.0
        elif t == 0xB3 and len(v) >= 3:
            res['temp'] = f"{v[1]}C/{v[2]}F"
    return res

def notif(_, data):
    raw = bytes(data)
    if len(raw) < 5: S.q.put_nowait(('short', raw)); return
    body = raw[4:-1]
    if len(body) < 5: S.q.put_nowait(('short', body)); return
    hi, lo = body[3], body[4]
    encd = (hi & 0x40) != 0
    full = ((hi & ~0x40) << 8) | lo
    content = body
    if encd and S.key is not None:
        try: content = dec(S.key, S.iv, body[5:])
        except Exception as e: S.q.put_nowait(('decfail', repr(e))); return
        if S.crypto == 'Initial':
            off = 1 if (content and content[0]==0x00) else 0
            for t, v in parse_tlv(content, off):
                if t == 0xA1 and len(v) == 16: S.session_key = v
        if full in (0x0500, 0x0D00, 0x050E):
            st = parse_status(content)
            if st: S.telemetry.append((full, st))
        S.q.put_nowait(('dec', full, content))
    else:
        for t, v in parse_tlv(body, 6):
            if t == 0xA3: S.version = v.decode('latin1','replace')
            elif t == 0xA4: S.serial = v.decode('latin1','replace')
            elif t == 0xA5: S.mac = ':'.join(f'{b:02x}' for b in v[:6])
        S.q.put_nowait(('plain', full, body))

async def wait(t=3.0):
    try: return await asyncio.wait_for(S.q.get(), t)
    except asyncio.TimeoutError: return ('timeout',)

async def find():
    d = await BleakScanner.find_device_by_filter(
        lambda dev, adv: ADVERTISED_16 in [u.lower() for u in (adv.service_uuids or [])]
        or (dev.name or '').upper().startswith('AFYDN'), timeout=15.0)
    return d.address if d else None

async def run(addr):
    if addr is None:
        print("Scanning for Anker Prime (0xFF09 / AFYDN*)...")
        addr = await find()
        if not addr: print("Device not found."); return
    print(f"Connecting {addr} ...")
    async with BleakClient(addr, timeout=20.0) as cli:
        print("Connected:", cli.is_connected)
        await cli.start_notify(NOTIFY, notif)
        ts = struct.pack('<I', int(time.time()))
        async def snd(p): await cli.write_gatt_char(WRITE, frame(p), response=False)

        # unencrypted handshake
        await snd(build_request(0x0001, [(0xA1,ts),(0xA2,A2_STATIC)])); await wait()
        await snd(build_request(0x0003, [(0xA1,ts),(0xA2,A2_STATIC),(0xA3,b'\x20'),(0xA4,b'\x00\xf0')])); await wait()
        await snd(build_request(0x0029, [(0xA1,ts),(0xA2,A2_STATIC)])); await wait()
        await snd(build_request(0x0005, [(0xA1,ts),(0xA2,A2_STATIC),(0xA3,b'\x20'),(0xA4,b'\x00\xf0'),(0xA5,b'\x02')])); await wait()
        if not S.serial: print("Handshake failed (no serial)."); return
        print(f"Serial : {S.serial}")
        print(f"FW ver : {S.version}")
        print(f"MAC    : {S.mac}")

        # crypto: IV = first 16 bytes of the 17-byte serial
        S.key = INITIAL_KEY; S.iv = S.serial.encode('latin1')[:16]; S.crypto = 'Initial'
        tlv = build_tlv([(0xA1,ts),(0xA2,A2_STATIC),(0xA3,bytes(4)),(0xA5,bytes(40))])
        await snd(bytes([0x03,0x00,0x01,0x40,0x22]) + enc(S.key,S.iv,tlv))
        for _ in range(6):
            await wait(1.2)
            if S.session_key: break
        if not S.session_key: print("No session key."); return
        print(f"Session: established (key {S.session_key.hex()})")
        S.key = S.session_key; S.crypto = 'Session'

        # comprehensive status + listen a few seconds for live telemetry
        stat_tlv = build_tlv([(0xA1, b'\x21')])
        await snd(bytes([0x03,0x00,0x11,0x45,0x00]) + enc(S.key,S.iv,stat_tlv))
        t_end = time.time() + 6
        while time.time() < t_end:
            await wait(1.0)
        await cli.stop_notify(NOTIFY)

        print("\n=== Telemetry ===")
        if not S.telemetry:
            print("(no structured telemetry frames decoded)")
        seen = {}
        for cmd, st in S.telemetry:
            seen.update(st)
        for k, v in seen.items():
            print(f"  {k}: {v}")

if __name__ == "__main__":
    a = sys.argv[1] if len(sys.argv) > 1 else None
    asyncio.run(run(a))
