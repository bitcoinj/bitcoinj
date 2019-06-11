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

import org.bitcoinj.core.Utils;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Find/create App Data Directory in correct platform-specific location.
 * This class is based on the conventions used in Bitcoin Core which
 * uses the following locations:
 * <dl>
 *     <dt>Windows</dt><dd>{@code ${APPDATA}/.bitcoin}</dd>
 *     <dt>macOS</dt><dd>{@code ${HOME}/Library/Application Support/Bitcoin}</dd>
 *     <dt>Linux</dt><dd>{@code ${HOME}/.bitcoin}</dd>
 * </dl>
 * Note that {@code appName} is converted to lower-case on Windows and Linux/Unix.
 */
public class AppDataDirectory {

    /**
     * Get and create if necessary the Path to the application data directory.
     *
     * @param appName The name of the current application
     * @return Path to the application data directory
     */
    public static Path get(String appName) {
        final Path applicationDataDirectory = getPath(appName);

        try {
            Files.createDirectories(applicationDataDirectory);
        } catch (IOException ioe) {
            throw new RuntimeException("Couldn't find/create AppDataDirectory", ioe);
        }

        return applicationDataDirectory;
    }

    /**
     * Return the Path to the application data directory without making
     * sure it exists or creating it. (No disk I/O)
     *
     * @param appName The name of the current application
     * @return Path to the application data directory
     */
    public static Path getPath(String appName) {
        final Path applicationDataDirectory;

        if (Utils.isWindows()) {
            applicationDataDirectory = pathOf(System.getenv("APPDATA"), appName.toLowerCase());
        } else if (Utils.isMac()) {
            applicationDataDirectory = pathOf(System.getProperty("user.home"),"Library/Application Support", appName);
        } else if (Utils.isLinux()) {
            applicationDataDirectory = pathOf(System.getProperty("user.home"), "." + appName.toLowerCase());
        } else {
            // Unknown, assume unix-like
            applicationDataDirectory = pathOf(System.getProperty("user.home"), "." + appName.toLowerCase());
        }
        return applicationDataDirectory;
    }

    /**
     * Create a {@code Path} by joining path strings. Same functionality as Path.of() in JDK 11+
     * @param first A base path string
     * @param additional additional components to add
     * @return the joined {@code Path}
     */
    private static Path pathOf(String first, String... additional) {
        return FileSystems.getDefault().getPath(first, additional);
    }
}
