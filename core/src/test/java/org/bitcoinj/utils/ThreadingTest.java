/*
 * Copyright 2019 Michael Sean Gilligan
 * Copyright 2019 Tim Strasser
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
package org.bitcoinj.utils;

import org.junit.BeforeClass;
import org.junit.Test;

import java.lang.reflect.Method;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Basic test of Threading
 */
public class ThreadingTest {

    private static Method takeUninterruptibly;
    private static Method putUninterruptibly;
    private final BlockingQueue<Runnable> q = new LinkedBlockingQueue<>();

    @BeforeClass
    public static void setupReflection() throws Exception {
        //Loads inner class UserThread and gets the method reference from it, since those are private methods
        Class<?> userThreadClass = Class.forName("org.bitcoinj.utils.Threading$UserThread");
        takeUninterruptibly = userThreadClass.getDeclaredMethod("takeUninterruptibly", BlockingQueue.class);
        putUninterruptibly = userThreadClass.getDeclaredMethod("putUninterruptibly", BlockingQueue.class, Runnable.class);

        takeUninterruptibly.setAccessible(true);
        putUninterruptibly.setAccessible(true);
    }

    @Test
    public void testTakeUninterruptibly_NoInterrupt() throws Exception {
        Runnable expected = () -> {};
        q.put(expected);
        Runnable actual = (Runnable) takeUninterruptibly.invoke(null, q);
        assertSame(expected, actual);
        assertFalse(Thread.currentThread().isInterrupted());
    }

    @Test
    public void testTakeUninterruptibly_WithInterruptBefore() throws Exception {
        Thread.currentThread().interrupt();
        q.add(() -> {});
        Runnable actual = (Runnable) takeUninterruptibly.invoke(null, q);
        assertNotNull(actual);
        assertTrue(Thread.currentThread().isInterrupted());
    }

    @Test
    public void testTakeUninterruptibly_WithInterruptDuringBlock() throws Exception {
        final BlockingQueue<Runnable> emptyQ = new LinkedBlockingQueue<>();
        Thread thread = new Thread(() -> {
            try {
                takeUninterruptibly.invoke(null, emptyQ);
            } catch (Exception e) {
                fail("Should not throw: " + e.getMessage());
            }
        });
        thread.start();
        Thread.sleep(100);
        thread.interrupt();

        assertTrue(thread.isAlive());

        emptyQ.put(() -> {});
        thread.join(1000);
        assertTrue(thread.isInterrupted());
    }

    @Test
    public void testPutUninterruptibly_NoInterrupt() throws Exception {
        Runnable command = () -> {};
        putUninterruptibly.invoke(null, q, command);
        assertEquals(1, q.size());
        assertFalse(Thread.currentThread().isInterrupted());
    }

    @Test
    public void testPutUninterruptibly_WithInterruptBefore() throws Exception {
        Thread.currentThread().interrupt();
        putUninterruptibly.invoke(null, q, (Runnable) () -> {});
        assertEquals(1, q.size());
        assertTrue(Thread.currentThread().isInterrupted());
    }

    @Test
    public void testPutUninterruptibly_WithInterruptDuringFullBlock() throws Exception {
        Thread.currentThread().interrupt();
        putUninterruptibly.invoke(null, q, (Runnable) () -> {});
        assertTrue(Thread.currentThread().isInterrupted());
    }
}
