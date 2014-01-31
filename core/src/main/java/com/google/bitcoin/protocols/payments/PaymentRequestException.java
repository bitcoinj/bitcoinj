/**
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

package com.google.bitcoin.protocols.payments;

public class PaymentRequestException extends Exception {
    public PaymentRequestException(String msg) {
        super(msg);
    }

    public PaymentRequestException(Exception e) {
        super(e);
    }

    public static class Expired extends PaymentRequestException {
        public Expired(String msg) {
            super(msg);
        }
    }

    public static class InvalidPaymentRequestURL extends PaymentRequestException {
        public InvalidPaymentRequestURL(String msg) {
            super(msg);
        }

        public InvalidPaymentRequestURL(Exception e) {
            super(e);
        }
    }

    public static class InvalidPaymentURL extends PaymentRequestException {
        public InvalidPaymentURL(Exception e) {
            super(e);
        }

        public InvalidPaymentURL(String msg) {
            super(msg);
        }
    }

    public static class InvalidOutputs extends PaymentRequestException {
        public InvalidOutputs(String msg) {
            super(msg);
        }
    }

    public static class InvalidVersion extends PaymentRequestException {
        public InvalidVersion(String msg) {
            super(msg);
        }
    }

    public static class InvalidNetwork extends PaymentRequestException {
        public InvalidNetwork(String msg) {
            super(msg);
        }
    }

    public static class InvalidPkiType extends PaymentRequestException {
        public InvalidPkiType(String msg) {
            super(msg);
        }
    }

    public static class InvalidPkiData extends PaymentRequestException {
        public InvalidPkiData(String msg) {
            super(msg);
        }

        public InvalidPkiData(Exception e) {
            super(e);
        }
    }

    public static class PkiVerificationException extends PaymentRequestException {
        public PkiVerificationException(String msg) {
            super(msg);
        }

        public PkiVerificationException(Exception e) {
            super(e);
        }
    }
}
