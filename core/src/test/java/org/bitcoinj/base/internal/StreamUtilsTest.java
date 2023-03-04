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

package org.bitcoinj.base.internal;

import org.bitcoinj.base.internal.StreamUtils;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class StreamUtilsTest {
    @Test
    public void convertToUnmodifiableProducesFaithfulCopy() {
        List<Integer> list = Arrays.asList(1, 2, 3);
        List<Integer> unmodifiable = list.stream().collect(StreamUtils.toUnmodifiableList());

        assertEquals(list, unmodifiable);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void convertToUnmodifiableProducesUnmodifiable() {
        List<Integer> list = Arrays.asList(1, 2, 3);
        List<Integer> unmodifiable = list.stream().collect(StreamUtils.toUnmodifiableList());

        unmodifiable.add(666);
    }
}
