/*
 * Copyright 2014 The bitcoinj team
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

package com.google.bitcoin.tools;

import com.google.bitcoin.protocols.payments.PaymentRequestException;
import com.google.bitcoin.protocols.payments.PaymentSession;
import com.google.bitcoin.uri.BitcoinURI;
import com.google.bitcoin.uri.BitcoinURIParseException;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;
import java.util.concurrent.ExecutionException;

import static java.lang.String.format;

/** Takes a URL or bitcoin URI and prints information about the payment request. */
public class PaymentProtocol {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Provide a bitcoin URI or URL as the argument.");
            return;
        }
        dump(args[0]);
    }

    private static void dump(String arg) {
        try {
            URI uri = new URI(arg);
            PaymentSession session;
            if (uri.getScheme().equals("http")) {
                session = PaymentSession.createFromUrl(arg).get();
            } else if (uri.getScheme().equals("bitcoin")) {
                BitcoinURI bcuri = new BitcoinURI(arg);
                final String paymentRequestUrl = bcuri.getPaymentRequestUrl();
                if (paymentRequestUrl == null) {
                    System.err.println("No r= param in bitcoin URI");
                    return;
                }
                session = PaymentSession.createFromBitcoinUri(bcuri).get();
            } else {
                System.err.println("Unknown URI scheme: " + uri.getScheme());
                return;
            }
            final int version = session.getPaymentRequest().getPaymentDetailsVersion();
            StringBuilder output = new StringBuilder(
                    format("Bitcoin payment request, version %d%nDate: %s%n", version, session.getDate()));
            PaymentSession.PkiVerificationData pki = session.verifyPki();
            if (pki != null) {
                output.append(format("Signed by: %s%nIdentity verified by: %s%n", pki.name, pki.rootAuthorityName));
            }
            if (session.getPaymentDetails().hasExpires()) {
                output.append(format("Expires: %s%n", new Date(session.getPaymentDetails().getExpires() * 1000)));
            }
            if (session.getMemo() != null) {
                output.append(format("Memo: %s%n", session.getMemo()));
            }
            output.append(format("%n%n%s%n%s", session.getPaymentRequest(), session.getPaymentDetails()));
            System.out.println(output);
        } catch (URISyntaxException e) {
            System.err.println("Could not parse URI: " + e.getMessage());
        } catch (BitcoinURIParseException e) {
            System.err.println("Could not parse URI: " + e.getMessage());
        } catch (PaymentRequestException e) {
            System.err.println("Could not handle payment URL: " + e.getMessage());
        } catch (InterruptedException e) {
            System.err.println("Interrupted whilst processing/downloading.");
        } catch (ExecutionException e) {
            System.err.println("Failed whilst retrieving payment URL: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
