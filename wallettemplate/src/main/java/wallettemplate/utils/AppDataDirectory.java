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

package wallettemplate.utils;

import org.bitcoinj.core.Utils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Find/create App Data Directory in correct platform-specific location.
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

    private static Path getPath(String appName) {
        final Path applicationDataDirectory;

        if (Utils.isWindows()) {
            applicationDataDirectory = Path.of(System.getenv("APPDATA"), appName);
        } else if (Utils.isMac()) {
            applicationDataDirectory = Path.of(System.getProperty("user.home"),"Library/Application Support", appName);
        } else if (Utils.isLinux()) {
            applicationDataDirectory = Path.of(System.getProperty("user.home"), "." + appName);
        } else {
            // Unknown, assume unix-like
            applicationDataDirectory = Path.of(System.getProperty("user.home"), "." + appName);
        }
        return applicationDataDirectory;
    }
}
