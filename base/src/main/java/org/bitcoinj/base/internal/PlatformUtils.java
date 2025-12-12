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

import java.util.Locale;

/**
 * Utilities for determining platform information (OS and runtime)
 */
public class PlatformUtils {
    public enum Runtime {
        ANDROID, OPENJDK, ORACLE_JAVA, GRAALVM, UNKNOWN
    }

    public enum OS {
        LINUX, WINDOWS, MAC_OS, UNKNOWN
    }

    public static final Runtime runtime;
    public static final OS os;

    static {
        String runtimeProp = System.getProperty("java.runtime.name", "").toLowerCase(Locale.US);
        Runtime runtimeEnum;
        if (runtimeProp.isEmpty())
            runtimeEnum= PlatformUtils.Runtime.UNKNOWN;
        else if (runtimeProp.contains("android"))
            runtimeEnum = PlatformUtils.Runtime.ANDROID;
        else if (runtimeProp.contains("openjdk"))
            runtimeEnum = PlatformUtils.Runtime.OPENJDK;
        else if (runtimeProp.contains("java(tm) se"))
            runtimeEnum = PlatformUtils.Runtime.ORACLE_JAVA;
        else if (runtimeProp.contains("graalvm"))
            runtimeEnum = PlatformUtils.Runtime.GRAALVM;
        else
            runtimeEnum = PlatformUtils.Runtime.UNKNOWN;
        runtime = runtimeEnum;

        String osProp = System.getProperty("os.name", "").toLowerCase(Locale.US);
        OS osEnum;
        if (osProp.isEmpty())
            osEnum = PlatformUtils.OS.UNKNOWN;
        else if (osProp.contains("linux"))
            osEnum = PlatformUtils.OS.LINUX;
        else if (osProp.contains("win"))
            osEnum = PlatformUtils.OS.WINDOWS;
        else if (osProp.contains("mac"))
            osEnum = PlatformUtils.OS.MAC_OS;
        else
            osEnum = PlatformUtils.OS.UNKNOWN;
        os = osEnum;
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

    public static boolean isGraalVMRuntime() {
        return runtime == Runtime.GRAALVM;
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
