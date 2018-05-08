/*
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

package org.bitcoinj.core;

import static org.junit.Assert.*;
import org.junit.Test;

public class TransactionWitnessTest {

    @Test
    public void testToString() throws Exception {
        TransactionWitness w1 = new TransactionWitness(0);
        assertEquals("", w1.toString());

        TransactionWitness w2 = new TransactionWitness(2);
        assertEquals("", w2.toString());

        TransactionWitness w3 = new TransactionWitness(3);
        w3.setPush(0, Utils.HEX.decode("123aaa"));
        w3.setPush(1, Utils.HEX.decode("123bbb"));
        w3.setPush(3, Utils.HEX.decode("123ccc"));
        assertEquals("123aaa 123bbb EMPTY 123ccc", w3.toString());
    }
}
