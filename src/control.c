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
// File:    control.c
// Desc:    Implements the sealed drop-box command path that opens,
//          authorizes, and applies remote unlock codes with a guarded
//          command set and a bounded package band.
// Created: 2026

#include "control.h"
#include "dropbox_auth.h"
#include "envelope.h"
#include "dropbox.h"
#include "crypto_aead.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
 * @brief Derived field key used to open sealed command envelopes.
 */
static uint8_t g_control_key[CRYPTO_AEAD_KEY_LEN];

/**
 * @brief True once the field key has been installed.
 */
static bool g_control_key_ready;

/**
 * @brief Anti-replay authorization record for remote commands.
 */
static dropbox_auth_t g_control_auth;

/**
 * @brief Command byte recovered from the last accepted remote command.
 */
static uint8_t g_control_command;

/**
 * @brief Package recovered from the last accepted remote command.
 */
static int16_t g_control_package;

/**
 * @brief Read one 32-bit little-endian value.
 *
 * @param p Pointer to four little-endian bytes.
 * @return uint32_t Decoded value.
 */
static uint32_t control_get_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8u) |
           ((uint32_t)p[2] << 16u) | ((uint32_t)p[3] << 24u);
}

/**
 * @brief Read one 16-bit little-endian signed package.
 *
 * @param p Pointer to two little-endian bytes.
 * @return int16_t Decoded package identifier.
 */
static int16_t control_get_i16(const uint8_t *p) {
    return (int16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8u));
}

/**
 * @brief Report whether a decoded package is inside the provisioned band.
 *
 * @param package Package identifier to classify.
 * @return bool true when the package is inside the provisioning band.
 */
static bool control_package_ok(int16_t package) {
    return (package >= DROPBOX_PACKAGE_MIN) &&
           (package <= DROPBOX_PACKAGE_MAX);
}

/**
 * @brief Report whether a command byte is in the guarded drop-box set.
 *
 * @param command Command byte to classify.
 * @return bool true when the command is one of the guarded command codes.
 */
static bool control_command_ok(uint8_t command) {
    return (command == DROPBOX_COMMAND_UNLOCK) ||
           (command == DROPBOX_COMMAND_LOCK) ||
           (command == DROPBOX_COMMAND_DENY);
}

/**
 * @brief Range check a recovered command body and its pointers.
 *
 * @param pt Pointer to the recovered command plaintext.
 * @param len Number of recovered plaintext bytes.
 * @param seq Pointer to store the sequence number.
 * @param tag Pointer to the tag output buffer.
 * @param command Pointer to store the guarded command byte.
 * @param package Pointer to store the decoded package.
 * @return bool true when the body is well formed and in the guarded set.
 */
static bool control_args_ok(const uint8_t *pt, size_t len, uint32_t *seq,
                            uint8_t *tag, uint8_t *command, int16_t *package) {
    (void)pt;
    (void)len;
    return (seq != NULL) && (tag != NULL) && (command != NULL) &&
           (package != NULL) && (len >= CONTROL_COMMAND_LEN);
}

/**
 * @brief Report whether a decoded command and package are both in band.
 *
 * @param command Guarded command byte to classify.
 * @param package Package identifier to classify.
 * @return bool true when both the command and package are accepted.
 */
static bool control_body_ok(uint8_t command, int16_t package) {
    return control_command_ok(command) && control_package_ok(package);
}

/**
 * @brief Parse a recovered command body into sequence, tag, command, package.
 *
 * @param pt Pointer to the recovered command plaintext.
 * @param len Number of recovered plaintext bytes.
 * @param seq Pointer to store the little-endian sequence number.
 * @param tag Pointer to the 16-byte tag output buffer.
 * @param command Pointer to store the guarded command byte.
 * @param package Pointer to store the decoded package.
 * @return bool true when the body is well formed and in the guarded set.
 */
static bool control_parse(const uint8_t *pt, size_t len, uint32_t *seq,
                          uint8_t tag[CRYPTO_AEAD_TAG_LEN], uint8_t *command,
                          int16_t *package) {
    if (!control_args_ok(pt, len, seq, tag, command, package)) {
        return false;
    }
    *command = pt[4];
    *package = control_get_i16(&pt[5]);
    if (!control_body_ok(*command, *package)) return false;
    *seq = control_get_u32(pt);
    memcpy(tag, pt + 7u, CRYPTO_AEAD_TAG_LEN);
    return true;
}

/**
 * @brief Open one sealed command envelope under the field key.
 *
 * @param hex Pointer to the NUL-terminated hex envelope.
 * @param pt Pointer to the plaintext output buffer.
 * @param len Pointer to store the recovered plaintext length.
 * @return bool true when the envelope authenticated and opened.
 */
static bool control_open(const char *hex, uint8_t *pt, size_t *len) {
    uint8_t ad = (uint8_t)DROPBOX_NODE_ID;
    if (!g_control_key_ready || hex == NULL) {
        return false;
    }
    return envelope_open_hex(g_control_key, &ad, 1u, hex, pt,
                             ENVELOPE_MAX_PLAINTEXT, len);
}

/**
 * @brief Open and parse one sealed drop-box command envelope.
 *
 * @param hex Pointer to the NUL-terminated hex envelope.
 * @param seq Pointer to store the recovered sequence number.
 * @param tag Pointer to the 16-byte tag output buffer.
 * @param command Pointer to store the guarded command byte.
 * @param package Pointer to store the decoded package.
 * @return bool true when the envelope opened and the body parsed.
 */
static bool control_decode(const char *hex, uint32_t *seq,
                           uint8_t tag[CRYPTO_AEAD_TAG_LEN], uint8_t *command,
                           int16_t *package) {
    uint8_t pt[ENVELOPE_MAX_PLAINTEXT];
    size_t len;
    if (!control_open(hex, pt, &len)) {
        return false;
    }
    return control_parse(pt, len, seq, tag, command, package);
}

void control_init(void) {
    g_control_key_ready = false;
    g_control_command = DROPBOX_COMMAND_LOCK;
    g_control_package = 0;
    memset(g_control_key, 0, sizeof(g_control_key));
    dropbox_auth_init(&g_control_auth);
    dropbox_auth_set_key(NULL);
}

void control_deinit(void) {
    g_control_key_ready = false;
    dropbox_auth_set_key(NULL);
}

bool control_set_key(const uint8_t key[CRYPTO_AEAD_KEY_LEN]) {
    if (key == NULL) {
        control_deinit();
        return false;
    }
    memcpy(g_control_key, key, CRYPTO_AEAD_KEY_LEN);
    g_control_key_ready = true;
    dropbox_auth_set_key(g_control_key);
    return true;
}

bool control_authorize(uint32_t seq, const uint8_t tag[CRYPTO_AEAD_TAG_LEN]) {
    return dropbox_auth_apply(&g_control_auth, seq, tag);
}

/**
 * @brief Decode and authorize one sealed drop-box command envelope.
 *
 * @param hex Pointer to the NUL-terminated hex envelope.
 * @param seq Pointer to store the recovered sequence number.
 * @param tag Pointer to the 16-byte tag output buffer.
 * @param command Pointer to store the guarded command byte.
 * @param package Pointer to store the decoded package.
 * @return bool true when the command opened and passed the window.
 */
static bool control_authorized_decode(const char *hex, uint32_t *seq,
                                      uint8_t tag[CRYPTO_AEAD_TAG_LEN],
                                      uint8_t *command, int16_t *package) {
    return control_decode(hex, seq, tag, command, package) &&
           control_authorize(*seq, tag);
}

/**
 * @brief Store the accepted command and package in the module state.
 *
 * @param command Guarded command byte to store.
 * @param package Package identifier to store.
 * @return void
 */
static void control_store(uint8_t command, int16_t package) {
    g_control_command = command;
    g_control_package = package;
}

bool control_handle_frame(const char *hex) {
    uint32_t seq;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    uint8_t command;
    int16_t package;
    if (!control_authorized_decode(hex, &seq, tag, &command, &package)) {
        return false;
    }
    control_store(command, package);
    return true;
}

uint8_t control_command(void) {
    return g_control_command;
}

int16_t control_package(void) {
    return g_control_package;
}
