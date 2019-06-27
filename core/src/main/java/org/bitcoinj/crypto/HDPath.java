/*
 * Copyright 2019 Michael Sean Gilligan.
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

import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * HD Key derivation path. {@code HDPath} can be used to represent a full path or a relative path.
 * The {@code hasPrivateKey} {@code boolean} is used for rendering to {@code String}
 * but (at present) not much else. It defaults to {@code false} which will also be the setting for a relative path.
 * <p>
 * {@code HDPath} is immutable and uses the {@code Collections.UnmodifiableList} type internally.
 * <p>
 * It implements {@code java.util.List<ChildNumber>} to ease migration
 * from the previous Guava {@code ImmutableList<ChildNumber>}. It should be a minor breaking change
 * to replace {@code ImmutableList<ChildNumber>} with {@code List<ChildNumber>} where necessary in your code. Although
 * it is recommended to use the {@code HDPath} type for clarity and for access to {@code HDPath}-specific functionality.
 */
public class HDPath extends AbstractList<ChildNumber> {
    private static final char PREFIX_PRIVATE = 'm';
    private static final char PREFIX_PUBLIC = 'M';
    private static final char SEPARATOR = '/';
    protected final boolean hasPrivateKey;
    protected final List<ChildNumber> unmodifiableList;

    public HDPath(boolean hasPrivateKey, List<ChildNumber> list) {
        this.hasPrivateKey = hasPrivateKey;
        this.unmodifiableList = Collections.unmodifiableList(list);
    }

    public HDPath(List<ChildNumber> list) {
        this(false, list);
    }

    private static HDPath of(boolean hasPrivateKey, List<ChildNumber> list) {
        return new HDPath(hasPrivateKey, list);
    }

    public static HDPath of(List<ChildNumber> list) {
        return HDPath.of(false, list);
    }

    public static HDPath of(ChildNumber childNumber) {
        return HDPath.of(Collections.singletonList(childNumber));
    }

    public static HDPath of() {
        return HDPath.of(Collections.<ChildNumber>emptyList());
    }

    /**
     * Is this a path to a private key?
     *
     * @return true if yes, false if no or a partial path
     */
    public boolean hasPrivateKey() {
        return hasPrivateKey;
    }

    /**
     * Extend the path by appending a ChildNumber
     *
     * @param child the child to append
     * @return A new immutable path
     */
    public HDPath extend(ChildNumber child) {
        List<ChildNumber> mutable = new ArrayList<>(this.unmodifiableList); // Mutable copy
        mutable.add(child);
        return new HDPath(this.hasPrivateKey, mutable);
    }

    /**
     * Extend the path by appending two ChildNumber objects.
     *
     * @param child1 the first child to append
     * @param child2 the second child to append
     * @return A new immutable path
     */
    public HDPath extend(ChildNumber child1, ChildNumber child2) {
        List<ChildNumber> mutable = new ArrayList<>(this.unmodifiableList); // Mutable copy
        mutable.add(child1);
        mutable.add(child2);
        return new HDPath(this.hasPrivateKey, mutable);
    }

    /**
     * Extend the path by appending a relative path.
     *
     * @param path2 the relative path to append
     * @return A new immutable path
     */
    public HDPath extend(HDPath path2) {
        List<ChildNumber> mutable = new ArrayList<>(this.unmodifiableList); // Mutable copy
        mutable.addAll(path2);
        return new HDPath(this.hasPrivateKey, mutable);
    }

    /**
     * Extend the path by appending a relative path.
     *
     * @param path2 the relative path to append
     * @return A new immutable path
     */
    public HDPath extend(List<ChildNumber> path2) {
        return this.extend(HDPath.of(path2));
    }

    @Override
    public ChildNumber get(int index) {
        return unmodifiableList.get(index);
    }

    @Override
    public int size() {
        return unmodifiableList.size();
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder();
        b.append(hasPrivateKey ? HDPath.PREFIX_PRIVATE : HDPath.PREFIX_PUBLIC);
        for (ChildNumber segment : unmodifiableList) {
            b.append(HDPath.SEPARATOR);
            b.append(segment.toString());
        }
        return b.toString();
    }
}
