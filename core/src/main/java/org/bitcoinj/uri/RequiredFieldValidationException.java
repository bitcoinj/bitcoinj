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

package org.bitcoinj.uri;

/**
 * <p>Exception to provide the following to {@link BitcoinURI}:</p>
 * <ul>
 * <li>Provision of parsing error messages</li>
 * </ul>
 * <p>This exception occurs when a required field is detected (under the BIP21 rules) and fails
 * to pass the associated test (such as {@code req-expires} being out of date), or the required field is unknown
 * to this version of the client in which case it should fail for security reasons.</p>
 *
 * @since 0.3.0
 *         
 */
public class RequiredFieldValidationException extends BitcoinURIParseException {

    public RequiredFieldValidationException(String s) {
        super(s);
    }

    public RequiredFieldValidationException(String s, Throwable throwable) {
        super(s, throwable);
    }
}
