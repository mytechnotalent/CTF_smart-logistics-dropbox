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
// File:    locker.h
// Desc:    Declares the locker latch state machine that sequences the
//          SG90 locker actuator and fails locked on loss of authority.
// Created: 2026

#ifndef LOCKER_H
#define LOCKER_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Bounded locker latch travel time in milliseconds.
 */
#define LOCKER_TRAVEL_MS 1000u

/**
 * @brief Locker latch position and health states.
 */
typedef enum locker_state {
    /**
     * @brief Latch is seated locked, the safe parcel state.
     */
    LOCKER_STATE_LOCKED = 0,
    /**
     * @brief Latch is held fully unlocked for an authorized handoff.
     */
    LOCKER_STATE_UNLOCKED = 1,
    /**
     * @brief Latch has failed locked after a rejected or lost authority.
     */
    LOCKER_STATE_DENIED = 2,
    /**
     * @brief Latch actuator is travelling between positions.
     */
    LOCKER_STATE_MOVING = 3,
} locker_state_t;

/**
 * @brief Initialize the locker state machine and seat the latch locked.
 *
 * @param void No parameters.
 * @return void
 */
void locker_init(void);

/**
 * @brief Return the current locker state.
 *
 * @param void No parameters.
 * @return locker_state_t Current locker state.
 */
locker_state_t locker_state(void);

/**
 * @brief Report whether the latch is currently fully unlocked.
 *
 * @param void No parameters.
 * @return bool true when the latch is unlocked.
 */
bool locker_is_unlocked(void);

/**
 * @brief Apply an authorized unlock or lock command to the latch.
 *
 * Unauthorized commands are refused. An authorized command starts a
 * bounded travel interval that locker_tick completes. This is the guarded
 * command path that replaces the unauthenticated local open injection.
 *
 * @param unlock True to drive the latch unlocked, false to seat it locked.
 * @param authorized True when the caller has validated the command.
 * @return void
 */
void locker_apply_command(bool unlock, bool authorized);

/**
 * @brief Advance the locker state machine by one tick.
 *
 * Completes a pending travel once the bounded interval has elapsed.
 *
 * @param void No parameters.
 * @return void
 */
void locker_tick(void);

/**
 * @brief Force the latch locked and record the denied posture.
 *
 * This is the fail-locked posture taken when the delivery link is lost or
 * the local courier request cannot be authorized.
 *
 * @param void No parameters.
 * @return void
 */
void locker_fail_safe(void);

#endif // LOCKER_H
