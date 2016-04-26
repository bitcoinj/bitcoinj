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

package org.bitcoinj.protocols.channels;

import org.bitcoinj.core.Coin;
import com.google.protobuf.ByteString;

import javax.annotation.Nullable;

/**
 * An acknowledgement of a payment increase
 */
public class PaymentIncrementAck {
    private final Coin value;
    @Nullable private final ByteString info;

    public PaymentIncrementAck(Coin value, @Nullable ByteString info) {
        this.value = value;
        this.info = info;
    }

    public Coin getValue() {
        return value;
    }

    @Nullable
    public ByteString getInfo() {
        return info;
    }
}
