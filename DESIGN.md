# smart-logistics-dropbox - Design Blueprint (Act VI, IRON COURIER)

Repo: `smart-logistics-dropbox`
Companion CTF repo: `CTF_smart-logistics-dropbox` (artifact prefix `ACT-VI`)
Codename: IRON COURIER
Author: Kevin Thomas (kevin@mytechnotalent.com)

## Act VI of the OPERATION COLD IRON saga

Act I the lie. Act II the door. Act III the payload. Act IV the payload that
would not die. Act V the payload that spreads. Act VI is the payload that steals.

The drop-box is a courier handoff locker. FROSTLINE's implant here is a covert
channel: it harvests synthetic delivery data (package ids, unlock attempts,
timestamps) and exfiltrates it to the Ministry by hiding it in the timing and
preamble of its LoRa traffic, so the locker looks perfectly normal while it
leaks. WHITEOUT must find the channel and cut it.

## Safety contract

- No network, no internet, no host impact. Bare-metal RP2350, no OS.
- The channel targets ONLY the local classroom hub. No external address.
- The exfiltrated data is SYNTHETIC (generated test values), never real.
- Effects are confined to GPIO: the locker servo, the LEDs, the LCD.
- A `SANDBOX_ONLY` build guard disables the implant.
- Every act ends in analysis and neutralization.

## Parity contract

Same repo layout, crypto stack, tooling, pin map, README top/footer standard,
and telescreen legal disclaimer as Acts I-V.

## Pin map (identical, new roles)

| Pin | Act VI role |
| --- | ---------- |
| DHT11 GP4 | locker internal climate |
| LCD SDA GP2 / SCL GP3 | delivery status |
| IR GP5 | local courier remote |
| Servo GP14 | locker latch |
| Red GP16 | DENIED |
| Yellow GP17 | COURIER WAITING |
| Green GP18 | UNLOCKED |
| Button GP15 | courier arrived |
| RYLR998 GP8/9 | delivery link |
| Debug Probe | covert-channel analysis |
| Onboard GP25 | heartbeat |

## Fix track

- The UNLOCK_CODE must be sealed and authorized (no replay).
- The courier button must not silently bypass authorization.
- The node must fail locked on a lost link.

## Malware track (covert channel, benign)

Module `include/implant.h` + `src/implant.c`, only under `SANDBOX_ONLY`:

- **Harvest.** Collect synthetic delivery records (package id, attempts, ticks).
- **Covert channel.** Exfiltrate the staged data by encoding it into the timing
  and preamble of LoRa frames, so the traffic looks like normal telemetry.
- **Staging marker.** Write a staging marker into the reserved flash sector.
- **Anti-debug.** Reads DHCSR and behaves benignly under a probe.
- **Neutralization.** Disable the channel, clear the staging buffer and marker.

## Companion CTF: ACT-VI, four deep tasks

| Task | Points | Objective |
| ---- | ------ | --------- |
| 1 | 10 | Setup and analysis |
| 2 | 20 | Cut the covert channel (exfil encoder) |
| 3 | 20 | Stop the harvest |
| 4 | 20 | Clear the staging marker |
| 5 | 20 | Seal the UNLOCK_CODE path (fix track) |
| 6 | 10 | Export, verify, hardware proof, reflection |

Every patch is in-place and same-size.

## Naming

Project `smart-logistics-dropbox`; companion `CTF_smart-logistics-dropbox`;
prefix `ACT-VI`.
