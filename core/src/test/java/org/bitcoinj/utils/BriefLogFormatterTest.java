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

package org.bitcoinj.utils;

import org.junit.Test;

import java.time.Instant;
import java.util.logging.Level;
import java.util.logging.LogRecord;

import static org.junit.Assert.assertEquals;

public class BriefLogFormatterTest {
    @Test
    public void format() {
        BriefLogFormatter formatter = new BriefLogFormatter();
        LogRecord record = new LogRecord(Level.INFO, "message");
        record.setSourceClassName("org.example.Class");
        record.setSourceMethodName("method");
        record.setMillis(Instant.EPOCH.toEpochMilli());
        record.setThreadID(123);
        assertEquals("00:00:00 123 Class.method: message\n", formatter.format(record));
    }
}
