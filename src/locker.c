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
// File:    locker.c
// Desc:    Implements the locker latch state machine that sequences the
//          SG90 locker actuator and fails locked on loss of authority.
// Created: 2026

#include "pico/time.h"
#include "locker.h"
#include "servo.h"
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Current locker latch position and health state.
 */
static locker_state_t g_locker_state;

/**
 * @brief Pending travel target, true when the latch is unlocking.
 */
static bool g_locker_target_unlock;

/**
 * @brief Absolute time in microseconds when the pending travel completes.
 */
static uint64_t g_locker_move_until_us;

/**
 * @brief Complete a pending travel by driving the locker actuator.
 *
 * @param void No parameters.
 * @return void
 */
static void locker_complete(void) {
    if (g_locker_target_unlock) {
        locker_unlock();
        g_locker_state = LOCKER_STATE_UNLOCKED;
        return;
    }
    locker_lock();
    g_locker_state = LOCKER_STATE_LOCKED;
}

void locker_init(void) {
    g_locker_target_unlock = false;
    g_locker_state = LOCKER_STATE_LOCKED;
    locker_lock();
}

locker_state_t locker_state(void) {
    return g_locker_state;
}

bool locker_is_unlocked(void) {
    return g_locker_state == LOCKER_STATE_UNLOCKED;
}

void locker_apply_command(bool unlock, bool authorized) {
    if (!authorized) {
        return;
    }
    g_locker_target_unlock = unlock;
    g_locker_state = LOCKER_STATE_MOVING;
    g_locker_move_until_us = time_us_64() + (uint64_t)LOCKER_TRAVEL_MS * 1000u;
}

void locker_tick(void) {
    if (g_locker_state != LOCKER_STATE_MOVING) {
        return;
    }
    if (time_us_64() < g_locker_move_until_us) {
        return;
    }
    locker_complete();
}

void locker_fail_safe(void) {
    locker_lock();
    g_locker_target_unlock = false;
    g_locker_state = LOCKER_STATE_DENIED;
}
