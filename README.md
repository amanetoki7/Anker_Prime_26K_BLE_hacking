# Anker Prime 26250mAh (26K) BLE hacking

Overview of the BLE enabled Anker Prime 26250mAh Power Bank.

This is a fork of [atc1441/Anker_Prime_BLE_hacking](https://github.com/atc1441/Anker_Prime_BLE_hacking), which
targeted the **27650mAh** model. This fork adapts the connection layer to the **26250mAh** model and adds tools that
have been verified against a real device (serial `AFYDNWH0G05600621`, firmware `v0.0.5.2`).

Since Anker only allows the BLE connection to the Power Bank via their App and only via a valid user we ended up here^^

The BLE connection is done in an encrypted way but uses a fixed key exchanged based on the Serial Number as well as the
Anker Account ID. Funny enough the Master (App) defines the encryption way and also allows to use no encryption at all,
which means anyone can connect to your Power bank (and up to Fw 1.6.1 also upload a malicious firmware update).

Explanation video for the original 27650mAh work (click on the image):

[https://www.youtube.com/watch?v=WtEIjkMUH_8](https://www.youtube.com/watch?v=WtEIjkMUH_8)

[![YoutubeVideo](https://img.youtube.com/vi/WtEIjkMUH_8/0.jpg)](https://www.youtube.com/watch?v=WtEIjkMUH_8)

![](Overview.jpg)

# 26250mAh model differences

The BLE **protocol** is identical to the 27650mAh model (same `0xff09` framing, XOR checksum, static AES key, TLV
handshake commands `0x0001` / `0x0003` / `0x0029` / `0x0005` / `0x0022`, and serial-based IV). Only the following
changed and had to be adapted:

| Item | 27650mAh (upstream) | 26250mAh (this fork) |
| --- | --- | --- |
| Advertised service | `0x2215` | `0xFF09` |
| Full service UUID | `22150001-4002-81c5-b46e-cf057c562025` | `8c850001-0302-41c5-b46e-cf057c562025` |
| Write characteristic | `22150002-4002-81c5-b46e-cf057c562025` | `8c850002-0302-41c5-b46e-cf057c562025` |
| Notify characteristic | `22150003-4002-81c5-b46e-cf057c562025` | `8c850003-0302-41c5-b46e-cf057c562025` |
| Serial length | 16 chars | 17 chars (e.g. `AFYDNWH0G05600621`) |
| AES-CBC IV | ASCII of full serial (16 bytes) | ASCII of serial, **first 16 bytes** |

The static initial AES-128-CBC key is unchanged: the ASCII string `2c377dfa09cdb792` (first 16 bytes of the fixed
40-byte token `2c377dfa09cdb7924889e4292a37f61c8c5ed52d`). The IV is the ASCII of the serial number; because the
26250mAh serial is 17 bytes it must be truncated to the first 16 bytes to be a valid CBC IV.

The unencrypted handshake and the full encrypted session (initial key -> session key -> encrypted commands) have been
confirmed working on the 26250mAh model with these changes.

**Known gap:** on firmware `v0.0.5.2` the live telemetry / comprehensive status commands differ from the 27650mAh
firmware. The status request that returns battery / port / power data on the 27650mAh model (`0x0500`) is acknowledged
by the 26250mAh device with a short `00 a1 01 31` reply instead of the telemetry dump, so the port/battery parsers are
not yet mapped for this firmware. Connection, authentication and the encrypted channel all work; mapping the telemetry
command set is future work.

# WebTool

The upstream WebBluetooth tool for the 27650mAh model is here:
[https://atc1441.github.io/AnkerPrimeWebBle.html](https://atc1441.github.io/AnkerPrimeWebBle.html)

This fork ships an adapted copy for the 26250mAh model in [AnkerPrime26KWebBle.html](AnkerPrime26KWebBle.html)
(UUIDs and IV adjusted per the table above). Open it in a WebBluetooth-capable browser (Chrome / Edge) over `https://`
or `file://` and click Connect.

[![WebToolOverview.png](WebToolOverview.png)](AnkerPrime26KWebBle.html)

# Python CLI

[anker26k.py](anker26k.py) is a standalone client that scans for the power bank, runs the unencrypted handshake, then
establishes the full encrypted session and prints the serial, firmware version and MAC.

```bash
pip install bleak cryptography
python anker26k.py                 # scan for an Anker Prime (0xFF09 / AFYDN*) and connect
python anker26k.py 7C:E9:13:99:6E:A8   # connect to a specific MAC
```

Requires a Bluetooth LE adapter. On Windows it uses the WinRT backend via bleak; Bluetooth must be powered on and the
power bank must be advertising (not already connected to the Anker app).

# Firmware Backups

You can find the firmware files for both the GD32F303 as well as the TLSR8253 [here](Firmware_Files).
These are the 27650mAh backups inherited from upstream; the 26250mAh unit tested here reports firmware `v0.0.5.2`.

# Hardware Infos

The case is pretty much closed and can not be opened without damaging the plastic.

Main SoC: GD32F303 ARM 512KB Flash 64KB RAM

BLE SoC: Telink TLSR8253 TC32 512KB Flash 64KB RAM

LCD ST7789 Based 240x240

LiPo Batteries (26250mAh on this model; 27650mAh on the upstream model)


![](Block_diagram.png)

![](PCB_view.jpg)



# Possible GD32F303 OTA Exploit

The firmware upload uses a uint32_t variable to define the size of firmware and so far it looks unchecked.

This will be used to write to the external flash and to check the firmware signature etc.

Since the external flash is 0x8000000 (8MB) in size it would loop around this memory region and would allow to write to
a region twice. Since the LCD images are stored on the lower area of memory, at least these could be overwritten (bits
only from 1 to 0 as this region will not be erased before writing to it) and would "damage" the Power bank as there is
no function to upload new images.

![](OverflowWriting.png)

## Firmware checking the ECDSA Signature

![](Fw_comparisson_1.6.1_to_1.6.2.png)

![](CheckingFunction.png)

---

Original research and tooling by [atc1441](https://github.com/atc1441/Anker_Prime_BLE_hacking). 26250mAh model
adaptation in this fork.
