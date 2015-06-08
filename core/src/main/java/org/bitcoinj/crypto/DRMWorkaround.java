package org.bitcoinj.crypto;

import org.bitcoinj.core.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class DRMWorkaround {
    private static Logger log = LoggerFactory.getLogger(DRMWorkaround.class);

    private static boolean done = false;

    public static void maybeDisableExportControls() {
        // This sorry story is documented in https://bugs.openjdk.java.net/browse/JDK-7024850
        // Oracle received permission to ship AES-256 by default in 2011, but didn't get around to it for Java 8
        // even though that shipped in 2014! That's dumb. So we disable the ridiculous US government mandated DRM
        // for AES-256 here, as Tor/BIP38 requires it.

        if (done) return;
        done = true;

        if (Utils.isAndroidRuntime())
            return;
        try {
            Field gate = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
            gate.setAccessible(true);
            gate.setBoolean(null, false);
            final Field allPerm = Class.forName("javax.crypto.CryptoAllPermission").getDeclaredField("INSTANCE");
            allPerm.setAccessible(true);
            Object accessAllAreasCard = allPerm.get(null);
            final Constructor<?> constructor = Class.forName("javax.crypto.CryptoPermissions").getDeclaredConstructor();
            constructor.setAccessible(true);
            Object coll = constructor.newInstance();
            Method addPerm = Class.forName("javax.crypto.CryptoPermissions").getDeclaredMethod("add", java.security.Permission.class);
            addPerm.setAccessible(true);
            addPerm.invoke(coll, accessAllAreasCard);
            Field defaultPolicy = Class.forName("javax.crypto.JceSecurity").getDeclaredField("defaultPolicy");
            defaultPolicy.setAccessible(true);
            defaultPolicy.set(null, coll);
        } catch (Exception e) {
            log.warn("Failed to deactivate AES-256 barrier logic, Tor mode/BIP38 decryption may crash if this JVM requires it: " + e.getMessage());
        }
    }
}
