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

import org.bitcoinj.base.Base58;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;

public class Base58Test {
    @Test
    public void alphabetHas58Chars() {
        assertEquals(58, Base58.alphabet().size());
    }

    @Test
    public void alphabetIsImmutable() {
        List<Character> alphabet1 = Base58.alphabet();
        char previousChar = alphabet1.remove(0);
        alphabet1.add(0, '₿');
        List<Character> alphabet2 = Base58.alphabet();
        assertEquals(previousChar, alphabet2.get(0).charValue());
    }
}
