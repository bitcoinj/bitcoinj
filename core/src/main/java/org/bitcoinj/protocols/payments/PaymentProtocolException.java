/*
 * Copyright 2013 Google Inc.
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

package org.bitcoinj.protocols.payments;

import java.security.cert.X509Certificate;
import java.util.List;

public class PaymentProtocolException extends Exception {
    public PaymentProtocolException(String msg) {
        super(msg);
    }

    public PaymentProtocolException(Exception e) {
        super(e);
    }

    public static class Expired extends PaymentProtocolException {
        public Expired(String msg) {
            super(msg);
        }
    }

    public static class InvalidPaymentRequestURL extends PaymentProtocolException {
        public InvalidPaymentRequestURL(String msg) {
            super(msg);
        }

        public InvalidPaymentRequestURL(Exception e) {
            super(e);
        }
    }

    public static class InvalidPaymentURL extends PaymentProtocolException {
        public InvalidPaymentURL(Exception e) {
            super(e);
        }

        public InvalidPaymentURL(String msg) {
            super(msg);
        }
    }

    public static class InvalidOutputs extends PaymentProtocolException {
        public InvalidOutputs(String msg) {
            super(msg);
        }
    }

    public static class InvalidVersion extends PaymentProtocolException {
        public InvalidVersion(String msg) {
            super(msg);
        }
    }

    public static class InvalidNetwork extends PaymentProtocolException {
        public InvalidNetwork(String msg) {
            super(msg);
        }
    }

    public static class InvalidPkiType extends PaymentProtocolException {
        public InvalidPkiType(String msg) {
            super(msg);
        }
    }

    public static class InvalidPkiData extends PaymentProtocolException {
        public InvalidPkiData(String msg) {
            super(msg);
        }

        public InvalidPkiData(Exception e) {
            super(e);
        }
    }

    public static class PkiVerificationException extends PaymentProtocolException {
        public List<X509Certificate> certificates;

        public PkiVerificationException(String msg) {
            super(msg);
        }

        public PkiVerificationException(Exception e) {
            super(e);
        }

        public PkiVerificationException(Exception e, List<X509Certificate> certificates) {
            super(e);
            this.certificates = certificates;
        }
    }
}
