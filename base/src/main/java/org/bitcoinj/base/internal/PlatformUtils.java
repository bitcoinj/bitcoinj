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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Locale;

/**
 * Utilities for determining platform information (OS and runtime)
 */
public class PlatformUtils {
    private static final Logger log = LoggerFactory.getLogger(PlatformUtils.class);
    public enum Runtime {
        ANDROID, OPENJDK, ORACLE_JAVA
    }

    public enum OS {
        LINUX, WINDOWS, MAC_OS
    }

    public static Runtime runtime = null;
    public static OS os = null;

    static {
        String runtimeProp = System.getProperty("java.runtime.name", "").toLowerCase(Locale.US);
        if (runtimeProp.equals(""))
            PlatformUtils.runtime = null;
        else if (runtimeProp.contains("android"))
            PlatformUtils.runtime = PlatformUtils.Runtime.ANDROID;
        else if (runtimeProp.contains("openjdk"))
            PlatformUtils.runtime = PlatformUtils.Runtime.OPENJDK;
        else if (runtimeProp.contains("java(tm) se"))
            PlatformUtils.runtime = PlatformUtils.Runtime.ORACLE_JAVA;
        else
            log.info("Unknown java.runtime.name '{}'", runtimeProp);

        String osProp = System.getProperty("os.name", "").toLowerCase(Locale.US);
        if (osProp.equals(""))
            PlatformUtils.os = null;
        else if (osProp.contains("linux"))
            PlatformUtils.os = PlatformUtils.OS.LINUX;
        else if (osProp.contains("win"))
            PlatformUtils.os = PlatformUtils.OS.WINDOWS;
        else if (osProp.contains("mac"))
            PlatformUtils.os = PlatformUtils.OS.MAC_OS;
        else
            log.info("Unknown os.name '{}'", runtimeProp);
    }

    public static boolean isAndroidRuntime() {
        return runtime == Runtime.ANDROID;
    }

    public static boolean isOpenJDKRuntime() {
        return runtime == Runtime.OPENJDK;
    }

    public static boolean isOracleJavaRuntime() {
        return runtime == Runtime.ORACLE_JAVA;
    }

    public static boolean isLinux() {
        return os == OS.LINUX;
    }

    public static boolean isWindows() {
        return os == OS.WINDOWS;
    }

    public static boolean isMac() {
        return os == OS.MAC_OS;
    }
}
