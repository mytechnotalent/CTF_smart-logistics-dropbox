# OPERATION IRON COURIER - Requirements & Grading Criteria

```
+--------------------------------------------------------------------------------+
|                                                                                |
|                 OPERATION IRON COURIER                                         |
|                                                                                |
|                 REQUIREMENTS & GRADING CRITERIA                                |
|                                                                                |
|   TARGET: NorthPharma smart logistics drop-box (courier handoff locker)        |
|   ARTIFACT: ACT-VI.bin / ACT-VI.uf2 (compromised)                              |
|   CREW: FROSTLINE            OPERATIVE: NIGHTINGALE                            |
|                                                                                |
+--------------------------------------------------------------------------------+
```

---

## Project Overview

NorthPharma moves the parcels that hold what the state does not discuss, and its
smart logistics drop-box built on a Pico 2 is the handoff locker on that route. A
contractor called **FROSTLINE** planted an implant in the node image: a raw-frame
covert channel that emits the `ICV1` preamble and a timing side channel, a
synthetic harvest that stages delivery records into an eight-slot ring, a
reserved-sector staging marker that re-arms the channel on every boot, and an
inverted unlock command authorization verdict. Operative **NIGHTINGALE**
recovered the compromised image as `ACT-VI.bin`.

Students are the reverse-engineering reserve. They reverse engineer `ACT-VI.bin`
with Ghidra, find and patch all four defects, defeat the CoreDebug `DHCSR`
anti-debug under GDB to observe the marker write, export a corrected image, flash
it to a real Pico 2, and prove the corrected behavior on the breadboard. The
machine check is `scripts/verify_ctf.py`.

The challenge is a standalone capstone exercise and contains no answer, constant,
address, bug, or patch belonging to any other course assignment.

---

## Learning Objectives

- Decode an ARM Cortex-M33 vector and boot table and identify the reset handler
  and initial stack pointer.
- Map a stripped firmware image into modules by tracing calls from `main` and the
  monitor loop.
- Locate four corrupted bytes: a covert-channel encoder gate, a synthetic harvest
  gate, a reserved-sector marker gate, and an authorization verdict branch.
- Analyze `cbz`, `cbnz`, `beq`, and `bne` condition semantics and branch
  inversion.
- Explain why a raw pre-authentication payload path is invisible to a sealed
  protocol and why a covert channel never needs the cipher.
- Explain why hiding data in the preamble and the timing of legitimate traffic is
  a confidentiality failure, not an integrity failure.
- Explain why reserved-flash state survives a firmware reflash.
- Read CoreDebug `DHCSR`, explain the anti-debug trap, and defeat it under GDB.
- Explain why authentication is not authorization and why a verdict must be
  verified before the command is applied.

Students must use only the course concepts: ARM registers, stack behavior,
USB-CDC and UART consoles, GDB, Ghidra static analysis and binary patching,
vector tables, reset startup, XIP, Thumb addressing, condition-code analysis,
stateful security, and the Argon2id plus XChaCha20-Poly1305 authenticated
envelope.

---

## Deliverables Checklist

| # | Deliverable | Format | Criterion |
|---|-------------|--------|-----------|
| 1 | Ghidra project screenshot | PNG/JPG | Task 1 |
| 2 | Vector table and boot table | Inside `ACT-VI-Answers.md` | Task 1 |
| 3 | `main` and monitor-loop table | Inside `ACT-VI-Answers.md` | Task 1 |
| 4 | Module map | Inside `ACT-VI-Answers.md` | Task 1 |
| 5 | Covert channel evidence and patch | Inside `ACT-VI-Answers.md` | Task 2 |
| 6 | Harvest gate evidence and patch | Inside `ACT-VI-Answers.md` | Task 3 |
| 7 | Anti-debug GDB proof, reserved-sector evidence, and patch | Inside `ACT-VI-Answers.md` | Task 4 |
| 8 | UNLOCK authorization evidence and patch | Inside `ACT-VI-Answers.md` | Task 5 |
| 9 | `ACT-VI_fixed.bin` | BIN file | Task 6 |
| 10 | `ACT-VI_fixed.uf2` | UF2 file | Task 6 |
| 11 | Hardware proof and reflection | Inside `ACT-VI-Answers.md` | Task 6 |

---

## Required Tools and Equipment

| Tool | Purpose |
|------|---------|
| Raspberry Pi Pico 2 | Isolated target node |
| Debug Probe (OpenOCD) | SWD connection for GDB inspection and the anti-debug work |
| arm-none-eabi-gdb | Runtime breakpoints, `DHCSR` clearing, and reserved-sector observation |
| Ghidra | Static analysis and binary patching |
| Python 3 with `uf2conv.py` | UF2 conversion and artifact checks |
| DHT11, 1602 I2C LCD, RYLR998, IR receiver, SG90 servo, 3 LEDs, courier button | Breadboard hardware proof |
| `ACT-VI.bin` and `ACT-VI.uf2` | Supplied compromised artifacts |

Console settings: **USB-CDC virtual COM port, 115200 baud, 8 data bits, no
parity, 1 stop bit**. Radio UART settings: **UART1, 115200, network ID 18**.

---

## Artifact Identity

The instructor-issued artifact hashes are:

```text
ACT-VI.bin        de54394f53391a8cfc76913e7fd2db5e69ea5dc28bf5ed2e844d39f0855806f0
ACT-VI.uf2        20bc7b7fba79f9c7e507d84ff235efe91ad3b19740b5e7e47c8f83e1125699aa
ACT-VI_fixed.bin  7da0f0c66d25711f9ab793d37da417fd6b0ccd0e35e4ef54ec6a22648d9fd8a5
ACT-VI_fixed.uf2  0bc7b8fa0830828fe1a633283d6efe8dff09c40a5004ba76844f434eef0e166e
```

The verifier checks the `ACT-VI.bin` and `ACT-VI_fixed.bin` hashes specifically,
asserts the four fixed bytes, and requires that only those four offsets differ
between the two `.bin` images. Both `.bin` images are 51,420 bytes and both
`.uf2` images are 103,424 bytes.

---

## Grading Rubric - Detailed Breakdown

### Task 1: Setup and Initial Analysis (10 points)

| Criterion | Points | Full credit | Partial credit | No credit |
|-----------|--------|-------------|----------------|-----------|
| **[DOCUMENT]** Ghidra project created with the correct name and settings | 2 | Project `IronCourier_Investigation`, raw binary import | One item off | Not set up |
| **[DOCUMENT]** Processor configured as ARM Cortex 32 little endian default | 2 | Screenshot shows the correct processor | Wrong language | Missing |
| **[DOCUMENT]** Base address set to 0x10000000 | 2 | Base `0x10000000` | Wrong base | Missing |
| **[DOCUMENT]** Vector table, initial stack pointer, and reset handler identified | 2 | Base `0x10000000`, initial SP `0x20082000`, reset handler `0x1000015D` | One missing | Not found |
| **[DOCUMENT]** main and the drop-box monitor state machine (monitor_step) addresses identified | 1 | `main` `0x10000234`, `monitor_step` `0x100065C0` | One correct | Neither |
| **[DOCUMENT]** Module map identifies the locker, control, dropbox_auth, implant, and monitor anchors | 1 | At least one correct anchor per module | Partial | Missing |

### Task 2: Bug #1 The Covert Channel (20 points)

| Criterion | Points | Full credit | Partial credit | No credit |
|-----------|--------|-------------|----------------|-----------|
| **[DOCUMENT]** Located the covert channel encoder branch at 0x1000A369 | 5 | Address and function (`implant_tick`, inlined `implant_send_channel`) identified | Approximate | Not found |
| **[DOCUMENT]** Documented the ICV1 channel and the timing side channel | 5 | 4-byte `ICV1` magic, 250 us per byte, eight-slot ring payload | Partial | Wrong |
| **[DOCUMENT & PATCH]** Patched 0xD1 to 0xD0 so the channel does not send | 7 | Byte `0xD1` changed to `0xD0` | Wrong byte | Not patched |
| **[DOCUMENT]** Explained why the covert channel needs no cipher and hides in the preamble and timing | 3 | Raw path under the sealed envelope and timing carries the data | Vague | Missing |

### Task 3: Bug #2 The Harvest (20 points)

| Criterion | Points | Full credit | Partial credit | No credit |
|-----------|--------|-------------|----------------|-----------|
| **[DOCUMENT]** Located the harvest gate branch at 0x1000A329 | 5 | Address and function (`implant_tick`, inlined `implant_stage_write`) identified | Approximate | Not found |
| **[DOCUMENT]** Documented the synthetic harvest and the eight-slot staging ring | 5 | Package LE16, attempts u8, tick LE32, 8 slots | Partial | Wrong |
| **[DOCUMENT & PATCH]** Patched 0xD1 to 0xD0 so no synthetic record is staged | 7 | Byte `0xD1` changed to `0xD0` | Wrong byte | Not patched |
| **[DOCUMENT]** Explained why a staging ring is a separate control from the channel | 3 | The ring stores, the channel transports | Vague | Missing |

### Task 4: Bug #3 The Staging Marker (20 points)

| Criterion | Points | Full credit | Partial credit | No credit |
|-----------|--------|-------------|----------------|-----------|
| **[DOCUMENT]** Located the staging marker branch at 0x1000A5CF | 5 | Address and inlined `implant_init` path identified | Approximate | Not found |
| **[DOCUMENT]** Documented the CoreDebug DHCSR anti-debug and how it is defeated under GDB | 5 | `0xE000EDF0`, `C_DEBUGEN` and `C_HALT`, and a real defeat method | Partial | Wrong |
| **[DOCUMENT & PATCH]** Patched 0xB9 to 0xB1 so no marker is written to 0x103FF000 | 7 | Byte `0xB9` changed to `0xB1` | Wrong byte | Not patched |
| **[DOCUMENT]** Explained the reserved sector 0x103FF000 and the write-once marker byte 0xC7 | 3 | Marker, reserved sector, write-once first run | Vague | Missing |

### Task 5: Bug #4 The UNLOCK Authorization (20 points)

| Criterion | Points | Full credit | Partial credit | No credit |
|-----------|--------|-------------|----------------|-----------|
| **[DOCUMENT]** Located the UNLOCK authorization branch at 0x1000757D | 5 | Address and function (`control_handle_frame`) identified | Approximate | Not found |
| **[DOCUMENT]** Documented the authorization verdict inversion and the branch condition | 5 | Reject when the verdict is false | Partial | Wrong |
| **[DOCUMENT & PATCH]** Patched 0xB9 to 0xB1 so failed and replayed authorizations are rejected | 7 | Byte `0xB9` changed to `0xB1` | Wrong byte | Not patched |
| **[DOCUMENT]** Explained why an unauthenticated or replayed UNLOCK envelope must be rejected | 3 | The applied command must see only an authorized verdict | Vague | Missing |

### Task 6: Export and Verify (10 points)

| Criterion | Points | Full credit | Partial credit | No credit |
|-----------|--------|-------------|----------------|-----------|
| **[PATCH]** Exported ACT-VI_fixed.bin from Ghidra | 2 | Valid patched binary | Corrupt | Not submitted |
| **[PATCH]** Converted to ACT-VI_fixed.uf2 with the correct base and family | 2 | `--base 0x10000000 --family 0xe48bff59` | Wrong flags | Not submitted |
| **[DOCUMENT]** scripts/verify_ctf.py passes and hardware proves the correct behavior | 3 | Verifier passes and the hardware proof is shown | Partial proof | No proof |
| **[DOCUMENT]** Reflection maps each of the four defects to a real-world control-system failure | 3 | Specific mapping for all four | Partial | Missing |

---

## Common Pitfalls

| Pitfall | Consequence | Avoidance |
|---------|-------------|-----------|
| Reading the channel gate backwards | The node still emits the `ICV1` frame | Suppress only on the clear-gate branch (`beq`, `0xD0`) |
| Reading the harvest gate backwards | The node still stages synthetic records | Neutralize only when the gate is clear (`beq`, `0xD0`) |
| Confusing `cbz` and `cbnz` at `0xA5CF` or `0x757D` | The marker is still written, or a failed authorization is still accepted | Neutralize only when the gate or verdict is clear (`cbz`, `0xB1`) |
| Searching for a standalone `implant_infect` or `implant_send_channel` symbol | Cannot find the inlined gates | Look inside `implant_init` at `0x1000A5CF` and `implant_tick` at `0x1000A369` |
| Confusing the harvest with the channel | Both gates sit in `implant_tick`, at `0xA329` and `0xA369` | Patch the harvest gate first, then the channel gate |
| Patching the shipped image before observing the write | You never prove the marker write | Defeat `DHCSR` under GDB first, then patch the artifact |
| Fabricating the GDB session | Verification fails | Show the command sequence and the real observed code path |
| Treating the anti-debug as a defect to patch | Wasted effort; it is identical in both images | Defeat it in a scratch copy or with GDB, then patch the real defect |
| Missing that the authorization branch is a verdict | Unauthenticated commands still reach the applied command and package | Accept only when the verdict is true (`cbz` to reject, `0xB1`) |
| Forgetting UF2 conversion | Raw binary will not flash | Use `uf2conv.py` with family `0xe48bff59` |

---

## How To Breadboard

| Device | Pin on device | Pico 2 GPIO | Notes |
|--------|---------------|-------------|-------|
| DHT11 locker climate sensor | DATA | GP4 | 10 kOhm pull-up to 3.3 V if the module needs it |
| 1602 LCD | SDA | GP2 | I2C1, backpack address `0x27` |
| 1602 LCD | SCL | GP3 | I2C1, 100 kHz |
| 1602 LCD | VCC / GND | VBUS 5 V / GND | The backpack needs 5 V, not 3.3 V |
| RYLR998 | RX | GP8 (Pico TX) | UART1, 115200, network ID 18 |
| RYLR998 | TX | GP9 (Pico RX) | UART1 |
| IR receiver | OUT | GP5 | VS1838B, internal pull-up enabled |
| Servo | signal | GP14 | PWM 50 Hz; 1000 uF bulk cap across servo 5 V and GND |
| Red LED | anode | GP16 | DENIED, 220 to 330 ohm to GND |
| Yellow LED | anode | GP17 | COURIER WAITING, 220 to 330 ohm to GND |
| Green LED | anode | GP18 | UNLOCKED, 220 to 330 ohm to GND |
| Courier-arrival button | leg 1 | GP15 | Internal pull-up; leg 2 to GND, never to 3.3 V |
| Onboard LED | built in | GP25 | Heartbeat |
| Debug Probe | SWCLK / SWDIO / GND | debug header | For GDB only |

Use 3.3 V logic on every GPIO. The only 5 V connection is the LCD backpack
supply. Keep the 1000 uF capacitor on the servo rail to absorb the SG90 current
spike.

---

## Memory Map Reference

| Region | Address | Purpose |
|--------|---------|---------|
| Bootrom | `0x00000000` | Immutable boot code |
| Flash/XIP | `0x10000000` | Vector table, code, rodata, data image |
| SRAM | `0x20000000` | Stack and writable state |
| CoreDebug `DHCSR` | `0xE000EDF0` | Anti-debug register read by the implant |
| Implant reserved sector | `0x103FF000` | Staging marker target (sector) |
| Implant tick counter | `0x20013748` | Incremented once per `implant_tick` |
| Implant stage count | `0x20013744` | Number of staged synthetic records |
| Implant staging ring | `0x2001370C` | Eight-slot ring of 7-byte records |
| Implant armed flag | `0x20013D24` | Set when the payload handler arms |
| Implant channel flag | `0x20013D25` | Reports whether the channel is enabled |
| Implant channel gate | `0x20013D26` | Gates the `ICV1` timing encoder |
| Implant harvest flag | `0x20013D27` | Reports whether harvest is enabled |
| Implant harvest gate | `0x20013D28` | Gates the synthetic staging logic |
| Implant marker gate | `0x20013D29` | Gates the reserved-sector marker write |
| Control ready gate | `0x20013D21` | Gates the sealed command path |
| Applied command | `0x20013D20` | Command after a true verdict |
| Applied package | `0x20013D16` | Package after a true verdict |
| Auth state record | `0x200136AC` | Anti-replay and state-tag record |
| Control field key | `0x200136C8` | Derived field key for the envelope |
| Locker state | `0x20013D2B` | Locker latch state |
| Locker target | `0x20013D2C` | Requested latch position |

The VA of any file offset is the file offset plus `0x10000000`.

---

## Deadline & Submission

- Create a folder containing the Ghidra screenshot, `ACT-VI_fixed.bin`, and
  `ACT-VI_fixed.uf2`.
- Write all written answers in `ACT-VI-Answers.md` inside that folder.
- Include the output of `python scripts/verify_ctf.py`.
- ZIP the folder as `lastname-firstname-ACT-VI.zip`.
- Submit the ZIP before the posted deadline; late submissions lose 10 percent
  per day.

---

## Grade Scale

| Grade | Percentage | Points |
|-------|------------|--------|
| A+ | 97-100% | 97-100 |
| A  | 93-96% | 93-96 |
| A- | 90-92% | 90-92 |
| B+ | 87-89% | 87-89 |
| B  | 84-86% | 84-86 |
| B- | 80-83% | 80-83 |
| C  | 70-79% | 70-79 |
| F  | 0-69% | 0-69% |

---

## Academic Integrity

Use only the supplied Pico 2 and firmware. Do not connect the exercise to an
operational logistics network, a pharmaceutical network, a building-management
system, a public network, a military system, or a third-party device. This is a
controlled, isolated educational exercise. All analysis and patches must be your
own work; sharing binaries, addresses, keys, passphrases, or answers is a
violation of the academic integrity policy.

---

## Reference Material

| Topic | Reference |
|-------|-----------|
| ARM Cortex-M33 registers and stack | Course block 1 |
| USB-CDC and UART console capture | Course block 2 |
| Vector tables, reset startup, and XIP | Course block 3 |
| Ghidra static analysis and binary patching | Course block 4 |
| Raw delivery payloads, magic preambles, and pre-authentication surface | Course block 5 |
| Covert channels, timing side channels, and confidentiality | Course block 6 |
| Staging rings, reserved-flash persistence, and boot re-install | Course block 7 |
| CoreDebug `DHCSR` and anti-debug | Course block 8 |
| Argon2id and XChaCha20-Poly1305 authenticated envelope | Course block 9 |
