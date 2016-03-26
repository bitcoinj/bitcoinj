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

package org.bitcoinj.utils;

import com.google.protobuf.ByteString;

import javax.annotation.Nullable;
import java.util.Map;

/**
 * <p>An object that can carry around and possibly serialize a map of strings to immutable byte arrays. Tagged objects
 * can have data stored on them that might be useful for an application developer. For example a wallet can store tags,
 * and thus this would be a reasonable place to put any important data items that the bitcoinj API does not allow for:
 * things like exchange rates at the time a transaction was made would currently fall into this category. Of course,
 * it helps interop and other developers if you introduce a real type safe API for a new feature instead of using this
 * so please consider that path, if you find yourself tempted to store tags!</p>
 *
 * <p>Good tag names won't conflict with other people's code, should you one day decide to merge them. Choose tag names
 * like "com.example:keyowner:02b7e6dc316dfaa19c5a599f63d88ffeae398759b857ca56b2f69de3e815381343" instead of
 * "owner" or just "o". Also, it's good practice to create constants for each string you use, to help avoid typos
 * in string parameters causing confusing bugs!</p>
 */
public interface TaggableObject {
    /** Returns the immutable byte array associated with the given tag name, or null if there is none. */
    @Nullable ByteString maybeGetTag(String tag);

    /**
     * Returns the immutable byte array associated with the given tag name, or throws {@link java.lang.IllegalArgumentException}
     * if that tag wasn't set yet.
     */
    ByteString getTag(String tag);

    /** Associates the given immutable byte array with the string tag. See the docs for TaggableObject to learn more. */
    void setTag(String tag, ByteString value);

    /** Returns a copy of all the tags held by this object. */
    Map<String, ByteString> getTags();
}
