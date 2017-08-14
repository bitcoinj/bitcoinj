/*
 * Copyright 2014 Andreas Schildbach
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

package org.bitcoincashj.crypto;

import javax.annotation.Nonnull;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;

/**
 * An implementation of TrustStoreLoader handles fetching a KeyStore from the operating system, a file, etc. It's
 * necessary because the Java {@link java.security.KeyStore} abstraction is not completely seamless and for example
 * we sometimes need slightly different techniques to load the key store on different versions of Android, MacOS,
 * Windows, etc.
 */
public interface TrustStoreLoader {
    KeyStore getKeyStore() throws FileNotFoundException, KeyStoreException;

    String DEFAULT_KEYSTORE_TYPE = KeyStore.getDefaultType();
    String DEFAULT_KEYSTORE_PASSWORD = "changeit";

    class DefaultTrustStoreLoader implements TrustStoreLoader {
        @Override
        public KeyStore getKeyStore() throws FileNotFoundException, KeyStoreException {

            String keystorePath = null;
            String keystoreType = DEFAULT_KEYSTORE_TYPE;
            try {
                // Check if we are on Android.
                Class<?> version = Class.forName("android.os.Build$VERSION");
                // Build.VERSION_CODES.ICE_CREAM_SANDWICH is 14.
                if (version.getDeclaredField("SDK_INT").getInt(version) >= 14) {
                    return loadIcsKeyStore();
                } else {
                    keystoreType = "BKS";
                    keystorePath = System.getProperty("java.home")
                            + "/etc/security/cacerts.bks".replace('/', File.separatorChar);
                }
            } catch (ClassNotFoundException e) {
                // NOP. android.os.Build is not present, so we are not on Android. Fall through.
            } catch (NoSuchFieldException e) {
                throw new RuntimeException(e); // Should never happen.
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e); // Should never happen.
            }
            if (keystorePath == null) {
                keystorePath = System.getProperty("javax.net.ssl.trustStore");
            }
            if (keystorePath == null) {
                return loadFallbackStore();
            }
            try {
                return X509Utils.loadKeyStore(keystoreType, DEFAULT_KEYSTORE_PASSWORD,
                        new FileInputStream(keystorePath));
            } catch (FileNotFoundException e) {
                // If we failed to find a system trust store, load our own fallback trust store. This can fail on
                // Android but we should never reach it there.
                return loadFallbackStore();
            }
        }

        private KeyStore loadIcsKeyStore() throws KeyStoreException {
            try {
                // After ICS, Android provided this nice method for loading the keystore,
                // so we don't have to specify the location explicitly.
                KeyStore keystore = KeyStore.getInstance("AndroidCAStore");
                keystore.load(null, null);
                return keystore;
            } catch (IOException x) {
                throw new KeyStoreException(x);
            } catch (GeneralSecurityException x) {
                throw new KeyStoreException(x);
            }
        }

        private KeyStore loadFallbackStore() throws FileNotFoundException, KeyStoreException {
            return X509Utils.loadKeyStore("JKS", DEFAULT_KEYSTORE_PASSWORD, getClass().getResourceAsStream("cacerts"));
        }
    }

    class FileTrustStoreLoader implements TrustStoreLoader {
        private final File path;

        public FileTrustStoreLoader(@Nonnull File path) throws FileNotFoundException {
            if (!path.exists())
                throw new FileNotFoundException(path.toString());
            this.path = path;
        }

        @Override
        public KeyStore getKeyStore() throws FileNotFoundException, KeyStoreException {
            return X509Utils.loadKeyStore(DEFAULT_KEYSTORE_TYPE, DEFAULT_KEYSTORE_PASSWORD, new FileInputStream(path));
        }
    }
}
