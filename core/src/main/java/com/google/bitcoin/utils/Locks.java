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

import static com.google.common.base.Preconditions.checkState;

/**
 * A wrapper around explicit lock creation that lets you control whether bitcoinj performs cycle detection or not.
 */
public class Locks {

    static {
        // Default policy goes here. If you want to change this, use one of the static methods before
        // instantiating any bitcoinj objects. The policy change will take effect only on new objects
        // from that point onwards.
        throwOnLockCycles();
    }

    private static CycleDetectingLockFactory.Policy policy;
    public static CycleDetectingLockFactory factory;

    public static ReentrantLock lock(String name) {
        return factory.newReentrantLock(name);
    }

    public static void warnOnLockCycles() {
        setPolicy(CycleDetectingLockFactory.Policies.WARN);
    }

    public static void throwOnLockCycles() {
        setPolicy(CycleDetectingLockFactory.Policies.THROW);
    }

    public static void ignoreLockCycles() {
        setPolicy(CycleDetectingLockFactory.Policies.DISABLED);
    }

    public static void setPolicy(CycleDetectingLockFactory.Policy policy) {
        Locks.policy = policy;
        factory = CycleDetectingLockFactory.newInstance(policy);
    }

    public static CycleDetectingLockFactory.Policy getPolicy() {
        return policy;
    }
}
