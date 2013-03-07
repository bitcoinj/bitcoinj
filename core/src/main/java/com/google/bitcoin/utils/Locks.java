/**
 * Copyright 2013 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.bitcoin.utils;

import com.google.common.util.concurrent.CycleDetectingLockFactory;

import java.util.concurrent.locks.ReentrantLock;

/**
 * A wrapper around explicit lock creation that lets you control whether bitcoinj performs cycle detection or not.
 */
public class Locks {

    static {
        // Default policy goes here. If you want to change this, use one of the static methods before
        // instantiating any bitcoinj objects. The policy change will take effect only on new objects
        // from that point onwards.
        warnOnLockCycles();
    }

    public static CycleDetectingLockFactory factory = null;

    public static ReentrantLock lock(String name) {
        if (factory != null)
            return factory.newReentrantLock(name);
        else
            return new ReentrantLock();
    }

    public static void warnOnLockCycles() {
        factory = CycleDetectingLockFactory.newInstance(CycleDetectingLockFactory.Policies.WARN);
    }

    public static void throwOnLockCycles() {
        factory = CycleDetectingLockFactory.newInstance(CycleDetectingLockFactory.Policies.THROW);
    }

    public static void ignoreLockCycles() {
        factory = null;
    }
}
