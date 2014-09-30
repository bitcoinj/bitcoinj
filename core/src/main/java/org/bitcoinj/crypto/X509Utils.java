/**
 * Copyright 2014 The bitcoinj authors.
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

package org.bitcoinj.crypto;

import com.google.common.base.Joiner;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.ASN1String;
import org.spongycastle.asn1.x500.AttributeTypeAndValue;
import org.spongycastle.asn1.x500.RDN;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x500.style.RFC4519Style;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

/**
 * X509Utils provides tools for working with X.509 certificates and keystores, as used in the BIP 70 payment protocol.
 * For more details on this, see {@link org.bitcoinj.protocols.payments.PaymentSession}, the article "Working with
 * the payment protocol" on the bitcoinj website, or the Bitcoin developer guide.
 */
public class X509Utils {
    /**
     * Returns either a string that "sums up" the certificate for humans, in a similar manner to what you might see
     * in a web browser, or null if one cannot be extracted. This will typically be the common name (CN) field, but
     * can also be the org (O) field, org+location+country if withLocation is set, or the email
     * address for S/MIME certificates.
     */
    public static @Nullable String getDisplayNameFromCertificate(@Nonnull X509Certificate certificate, boolean withLocation) throws CertificateParsingException {
        X500Name name = new X500Name(certificate.getSubjectX500Principal().getName());
        String commonName = null, org = null, location = null, country = null;
        for (RDN rdn : name.getRDNs()) {
            AttributeTypeAndValue pair = rdn.getFirst();
            String val = ((ASN1String) pair.getValue()).getString();
            ASN1ObjectIdentifier type = pair.getType();
            if (type.equals(RFC4519Style.cn))
                commonName = val;
            else if (type.equals(RFC4519Style.o))
                org = val;
            else if (type.equals(RFC4519Style.l))
                location = val;
            else if (type.equals(RFC4519Style.c))
                country = val;
        }
        final Collection<List<?>> subjectAlternativeNames = certificate.getSubjectAlternativeNames();
        String altName = null;
        if (subjectAlternativeNames != null)
            for (final List<?> subjectAlternativeName : subjectAlternativeNames)
                if ((Integer) subjectAlternativeName.get(0) == 1) // rfc822name
                    altName = (String) subjectAlternativeName.get(1);

        if (org != null) {
            return withLocation ? Joiner.on(", ").skipNulls().join(org, location, country) : org;
        } else if (commonName != null) {
            return commonName;
        } else {
            return altName;
        }
    }

    /** Returns a key store loaded from the given stream. Just a convenience around the Java APIs. */
    public static KeyStore loadKeyStore(String keystoreType, @Nullable String keystorePassword, InputStream is)
            throws KeyStoreException {
        try {
            KeyStore keystore = KeyStore.getInstance(keystoreType);
            keystore.load(is, keystorePassword != null ? keystorePassword.toCharArray() : null);
            return keystore;
        } catch (IOException x) {
            throw new KeyStoreException(x);
        } catch (GeneralSecurityException x) {
            throw new KeyStoreException(x);
        } finally {
            try {
                is.close();
            } catch (IOException x) {
                // Ignored.
            }
        }
    }
}
