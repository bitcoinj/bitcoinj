/*
 * Copyright by the original author or authors.
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

package org.bitcoinj.base.internal;

import org.junit.Test;

import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNull;

import java.lang.reflect.Field;

public class InternalUtilsTest {

    private static void setCause(Throwable current, Throwable cause) throws Exception {
        Field f = Throwable.class.getDeclaredField("cause");
        f.setAccessible(true);
        f.set(current, cause);
    }

    @Test
    void testNormalChain() {
        Throwable root = new IllegalArgumentException("root");
        Throwable top = new RuntimeException("top", root);
        assertSame(root, InternalUtils.getRootCause(top));
    }

    @Test
    void testCycleDetection() throws Exception {
        Throwable a = new RuntimeException("A");
        Throwable b = new RuntimeException("B");
        setCause(a, b);
        setCause(b, a);  
        
        Throwable result = InternalUtils.getRootCause(a);
        assertTrue(result == a || result == b);  
    }

    @Test
    void testNullInput() {
        assertNull(InternalUtils.getRootCause(null));
    }
}
