// Copyright 2012 Google Inc. All Rights Reserved.

package com.google.bitcoin.utils;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Semaphore;

/**
 * @author miron@google.com (Miron Cuperman)
 *
 */
public class NamedSemaphores {
    private Map<String, Semaphore> lockMap = new HashMap<String, Semaphore>();
    
    public void acquire(String name) throws InterruptedException {
        Semaphore s = getSemaphore(name);
        s.acquire();
    }

    public boolean tryAcquire(String name) {
        Semaphore s = getSemaphore(name);
        return s.tryAcquire();
    }
    
    public void release(String name) {
        Semaphore s = getSemaphore(name);
        s.release();
    }

    private Semaphore getSemaphore(String name) {
        synchronized (lockMap) {
            Semaphore s = lockMap.get(name);
            if (s == null) {
                s = new Semaphore(1);
                lockMap.put(name, s);
            }
            return s;
        }
    }
}
