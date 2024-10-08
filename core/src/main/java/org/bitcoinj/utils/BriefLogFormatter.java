/*
 * Copyright 2011 Google Inc.
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

import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.text.MessageFormat;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * A Java logging formatter that writes more compact output than the default.
 */
public class BriefLogFormatter extends Formatter {
    private static final MessageFormat messageFormat = new MessageFormat("{3} {0} {1}.{2}: {4}\n{5}");

    // OpenJDK made a questionable, backwards incompatible change to the Logger implementation. It internally uses
    // weak references now which means simply fetching the logger and changing its configuration won't work. We must
    // keep a reference to our custom logger around.
    private static final Logger logger = Logger.getLogger("");

    public static void init() {
        init(Level.INFO);
    }

    /** Configures JDK logging to use this class for everything. */
    public static void init(Level level) {
        final Handler[] handlers = logger.getHandlers();
        // In regular Java there is always a handler. Avian doesn't install one however.
        if (handlers.length > 0)
            handlers[0].setFormatter(new BriefLogFormatter());
        logger.setLevel(level);
    }

    public static void initVerbose() {
        init(Level.ALL);
        logger.log(Level.FINE, "test");
    }

    public static void initWithSilentBitcoinJ() {
        init();
        Logger.getLogger("org.bitcoinj").setLevel(Level.SEVERE);
    }

    @Override
    public String format(LogRecord logRecord) {
        Object[] arguments = new Object[6];
        arguments[0] = logRecord.getThreadID();
        String fullClassName = logRecord.getSourceClassName();
        int lastDot = fullClassName.lastIndexOf('.');
        String className = fullClassName.substring(lastDot + 1);
        arguments[1] = className;
        arguments[2] = logRecord.getSourceMethodName();
        arguments[3] = DateTimeFormatter.ISO_LOCAL_TIME.format(
                LocalDateTime.ofInstant(Instant.ofEpochMilli(logRecord.getMillis()), ZoneOffset.UTC));
        arguments[4] = logRecord.getMessage();
        if (logRecord.getThrown() != null) {
            Writer result = new StringWriter();
            logRecord.getThrown().printStackTrace(new PrintWriter(result));
            arguments[5] = result.toString();
        } else {
            arguments[5] = "";
        }
        return messageFormat.format(arguments);
    }
}
