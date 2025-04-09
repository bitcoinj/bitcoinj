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

import org.bitcoinj.base.internal.StreamUtils;
import org.bitcoinj.base.internal.InternalUtils;

import javax.annotation.Nonnull;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.bitcoinj.base.internal.Preconditions.checkArgument;

/**
 * HD Key derivation path. {@code HDPath} can be used to represent a full path or a relative path.
 * The {@code hasPrivateKey} {@code boolean} is used for rendering to {@code String}
 * but (at present) not much else. It defaults to {@code false} which is the preferred setting for a relative path.
 * <p>
 * {@code HDPath} is immutable and uses the {@code Collections.UnmodifiableList} type internally.
 * <p>
 * It implements {@code java.util.List<ChildNumber>} to ease migration
 * from the previous implementation. When an {@code HDPath} is returned you can treat it as a {@code List<ChildNumber>}
 * where necessary in your code. Although it is recommended to use the {@code HDPath} type for clarity and for
 * access to {@code HDPath}-specific functionality.
 * <p>
 * Note that it is possible for {@code HDPath} to be an empty list.
 * <p>
 * Take note of the overloaded factory methods {@link HDPath#M()} and {@link HDPath#m()}. These can be used to very
 * concisely create HDPath objects (especially when statically imported.)
 */
public abstract class HDPath /* extends AbstractList<ChildNumber> */ {
    public enum Prefix {
        PRIVATE('m'),
        PUBLIC('M');

        private final char symbol;

        Prefix(char symbol) {
            this.symbol = symbol;
        }

        static Optional<Prefix> of(char c) {
            Optional<Prefix> prefix;
            switch (c) {
                case 'm': prefix = Optional.of(Prefix.PRIVATE); break;
                case 'M': prefix = Optional.of(Prefix.PUBLIC); break;
                default: prefix = Optional.empty();
            }
            return prefix;
        }

        static Optional<Prefix> of(String string) {
            return string.length() == 1
                    ? Prefix.of(string.charAt(0))
                    : Optional.empty();
        }

        public Character symbol() {
            return this.symbol;
        }

        public String toString() {
            return symbol().toString();
        }
    }
    private static final String SEPARATOR = "/";
    private static final InternalUtils.Splitter SEPARATOR_SPLITTER = s -> Stream.of(s.split(SEPARATOR))
            .map(String::trim)
            .collect(Collectors.toList());

    //private final List<ChildNumber> childNumbers;
    int[] children;

    /** Partial path with BIP44 purpose */
    public static final HDPartialPath BIP44_PARENT = partial(ChildNumber.PURPOSE_BIP44);
    /** Partial path with BIP84 purpose */
    public static final HDPartialPath BIP84_PARENT = partial(ChildNumber.PURPOSE_BIP84);
    /** Partial path with BIP86 purpose */
    public static final HDPartialPath BIP86_PARENT = partial(ChildNumber.PURPOSE_BIP86);

    public static class HDFullPath extends HDPath {
        private final boolean hasPrivateKey;

        /**
         * Constructs a path for a public or private key. Should probably be a private constructor.
         *
         * @param hasPrivateKey Whether it is a path to a private key or not
         * @param list          List of children in the path
         */
        public HDFullPath(boolean hasPrivateKey, List<ChildNumber> list) {
            super(list);
            this.hasPrivateKey = hasPrivateKey;
        }

        private HDFullPath(boolean hasPrivateKey, int[] array) {
            super(array);
            this.hasPrivateKey = hasPrivateKey;
        }

        /**
         * Constructs a path for a public or private key. Should probably be a private constructor.
         *
         * @param prefix 'M' or 'm'
         * @param list   List of children in the path
         */
        public HDFullPath(Prefix prefix, List<ChildNumber> list) {
            super(list);
            this.hasPrivateKey = prefix == Prefix.PRIVATE;
        }

        private HDFullPath(Prefix prefix, int[] array) {
            super(array);
            this.hasPrivateKey = prefix == Prefix.PRIVATE;
        }

        /**
         * Return the correct prefix for this path.
         *
         * @return prefix
         */
        public Prefix prefix() {
            return hasPrivateKey ? Prefix.PRIVATE : Prefix.PUBLIC;
        }

        /**
         * Is this a path to a private key?
         *
         * @return true if yes, false if no or a partial path
         */
        public boolean hasPrivateKey() {
            return hasPrivateKey;
        }

        @Override
        public HDFullPath extend(ChildNumber child1, ChildNumber... children) {
            return new HDFullPath(this.hasPrivateKey, extendInternal(child1, children));
        }

        @Override
        public HDFullPath extend(HDPath.HDPartialPath partialPath) {
            return new HDFullPath(this.hasPrivateKey, extendInternal(partialPath.list()));
        }

        @Override
        public HDFullPath extend(List<ChildNumber> partialPath) {
            return new HDFullPath(this.hasPrivateKey, extendInternal(partialPath));
        }

        @Override
        public HDFullPath parent() {
            return new HDFullPath(this.hasPrivateKey, parentInternal());
        }

        @Override
        public HDFullPath ancestorByDepth(int depth) {
            return (HDFullPath) super.ancestorByDepth(depth);
        }

        @Override
        public HDPartialPath asPartial() {
            return new HDPartialPath(this.list());
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if ((o == null) || getClass() != o.getClass()) return false;
            HDFullPath other = (HDFullPath) o;
            return Objects.equals(this.hasPrivateKey, other.hasPrivateKey) &&
                    super.equals(other);
        }

        @Override
        public int hashCode() {
            return Objects.hash(this.hasPrivateKey, super.hashCode());
        }
    }

    public static class HDPartialPath extends HDPath {

        private HDPartialPath(List<ChildNumber> list) {
            super(list);
        }

        private HDPartialPath(int[] list) {
            super(list);
        }

        @Override
        public HDPartialPath extend(ChildNumber child1, ChildNumber... children) {
            return new HDPartialPath(extendInternal(child1, children));
        }

        @Override
        public HDPartialPath extend(HDPath.HDPartialPath partialPath) {
            return new HDPartialPath(extendInternal(partialPath.list()));
        }

        @Override
        public HDPartialPath extend(List<ChildNumber> partialPath) {
            return new HDPartialPath(extendInternal(partialPath));
        }

        @Override
        public HDPartialPath parent() {
            return new HDPartialPath(parentInternal());
        }

        @Override
        public HDPartialPath ancestorByDepth(int depth) {
            return (HDPartialPath) super.ancestorByDepth(depth);
        }

        @Override
        public HDPartialPath asPartial() {
            return this;
        }

        public HDFullPath asFull(Prefix prefix) {
            return new HDFullPath(prefix, this.children);
        }

        public HDFullPath asPublic() {
            return asFull(Prefix.PUBLIC);
        }

        public HDFullPath asPrivate() {
            return asFull(Prefix.PRIVATE);
        }
    }

    private HDPath(List<ChildNumber> list) {
        this(childrenAsArray(list));
    }

    private static int[] childrenAsArray(List<ChildNumber> list) {
        int[] array = new int[list.size()];
        for (int i = 0; i < array.length; i++) {
            array[i] = list.get(i).i();
        }
        return array;
    }

    // Canonical superclass constructor
    private HDPath(int[] childNumbers) {
        children = new int[childNumbers.length];
        System.arraycopy(childNumbers, 0, children, 0, childNumbers.length);
    }

    /**
     * Returns a path for a public or private key.
     *
     * @param prefix Indicates if it is a path to a public or private key
     * @param list List of children in the path
     */
    public static HDFullPath of(Prefix prefix, List<ChildNumber> list) {
        return new HDFullPath(prefix, list);
    }

    /**
     * Returns a path for a public or private key.
     *
     * @param hasPrivateKey Whether it is a path to a private key or not
     * @param list List of children in the path
     */
    private static HDFullPath of(boolean hasPrivateKey, List<ChildNumber> list) {
        return new HDFullPath(hasPrivateKey, list);
    }

    /**
     * Deserialize a list of integers into an HDPartialPath (internal use only)
     * @param integerList A list of integers (what we use in ProtoBuf for an HDPath)
     * @return a deserialized HDPartialPath
     */
    public static HDPartialPath deserialize(List<Integer> integerList) {
        return HDPath.partial(integerList.stream()
                .map(ChildNumber::new)
                .collect(StreamUtils.toUnmodifiableList()));
    }

    /**
     * Returns a partial path.
     *
     * @param list list of children
     */
    public static HDPartialPath partial(List<ChildNumber> list) {
        return new HDPartialPath(list);
    }

    /**
     * Returns a partial path.
     *
     * @param childNumber Single child in path
     */
    public static HDPartialPath partial(ChildNumber childNumber) {
        return partial(Collections.singletonList(childNumber));
    }

    /**
     * Returns a partial path.
     *
     * @param children Children in the path
     */
    public static HDPartialPath partial(ChildNumber... children) {
        return partial(Arrays.asList(children));
    }

    /**
     * Returns a path for a public key.
     *
     * @param list List of children in the path
     */
    public static HDFullPath M(List<ChildNumber> list) {
        return HDPath.of(Prefix.PUBLIC, list);
    }

    /**
     * Returns an empty path for a public key.
     */
    public static HDFullPath M() {
        return HDPath.M(Collections.emptyList());
    }

    /**
     * Returns a path for a public key.
     *
     * @param childNumber Single child in path
     */
    public static HDFullPath M(ChildNumber childNumber) {
        return HDPath.M(Collections.singletonList(childNumber));
    }

    /**
     * Returns a path for a public key.
     *
     * @param children Children in the path
     */
    public static HDFullPath M(ChildNumber... children) {
        return HDPath.M(Arrays.asList(children));
    }

    /**
     * Returns a path for a private key.
     *
     * @param list List of children in the path
     */
    public static HDFullPath m(List<ChildNumber> list) {
        return HDPath.of(Prefix.PRIVATE, list);
    }

    /**
     * Returns an empty path for a private key.
     */
    public static HDFullPath m() {
        return HDPath.m(Collections.emptyList());
    }

    /**
     * Returns a path for a private key.
     *
     * @param childNumber Single child in path
     */
    public static HDFullPath m(ChildNumber childNumber) {
        return HDPath.m(Collections.singletonList(childNumber));
    }

    /**
     * Returns a path for a private key.
     *
     * @param children Children in the path
     */
    public static HDFullPath m(ChildNumber... children) {
        return HDPath.m(Arrays.asList(children));
    }

    /**
     * Create an HDPath from a path string. The path string is a human-friendly representation of the deterministic path. For example:
     * <p>
     * {@code 44H / 0H / 0H / 1 / 1}
     * <p>
     * Where a letter {@code H} means hardened key. Spaces are ignored.
     */
    public static HDPath parsePath(@Nonnull String path) {
        List<String> parsedNodes = SEPARATOR_SPLITTER.splitToList(path);
        Optional<Prefix> prefix = parsedNodes.isEmpty() ? Optional.empty() : Prefix.of(parsedNodes.get(0));

        List<ChildNumber> nodes = parsedNodes.stream()
                .skip(prefix.isPresent() ? 1 : 0)  // skip prefix, if present
                .filter(n -> !n.isEmpty())
                .map(ChildNumber::parse)
                .collect(StreamUtils.toUnmodifiableList());

        return prefix.isPresent()
            ? HDPath.of(prefix.get(), nodes)
            : new HDPath.HDPartialPath(nodes);
    }

    // return mutable array
    private ArrayList<ChildNumber> children() {
        ArrayList<ChildNumber> list = new ArrayList<>(children.length);
        for (int child : children) {
            list.add(new ChildNumber(child));
        }
        return list;
    }

    List<ChildNumber> childNumbers() {
        ArrayList<ChildNumber> list = new ArrayList<>(children.length);
        for (int child : children) {
            list.add(new ChildNumber(child));
        }
        return list;
    }

    /**
     * Extend the path by appending additional ChildNumber objects.
     *
     * @param child1 the first child to append
     * @param children zero or more additional children to append
     * @return A new immutable path
     */
    public abstract HDPath extend(ChildNumber child1, ChildNumber... children);

    protected List<ChildNumber> extendInternal(ChildNumber child1, ChildNumber... children) {
        List<ChildNumber> mutable = children(); // Mutable copy
        mutable.add(child1);
        mutable.addAll(Arrays.asList(children));
        return mutable;
    }

    /**
     * Extend the path by appending a relative path.
     *
     * @param path2 the relative path to append
     * @return A new immutable path
     */
    public abstract HDPath extend(HDPath.HDPartialPath path2);

    /**
     * Extend the path by appending a relative path.
     *
     * @param path2 the relative path to append
     * @return A new immutable path
     */
    public abstract HDPath extend(List<ChildNumber> path2);

    protected List<ChildNumber> extendInternal(List<ChildNumber> children) {
        List<ChildNumber> mutable = children(); // Mutable copy
        mutable.addAll(children);
        return mutable;
    }

    /**
     * Return a simple list of {@link ChildNumber}
     * @return an unmodifiable list of {@code ChildNumber}
     */
    public List<ChildNumber> list() {
        return Collections.unmodifiableList(children());
    }

    /**
     * Return the parent path.
     * <p>
     * Note that this method defines the parent of a root path as the empty path and the parent
     * of the empty path as the empty path. This behavior is what one would expect
     * of an unmodifiable, copy-on-modify list. If you need to check for edge cases, you can use
     * {@link HDPath#isEmpty()} before or after using {@code HDPath#parent()}
     * @return parent path (which can be empty -- see above)
     */
    public abstract HDPath parent();

    protected int[] parentInternal() {
        return children.length > 1 ?
                shorten(children):
                new int[0];
    }

    private int[] shorten(int[] in) {
        int[] out = new int[in.length - 1];

        // Copy elements from input to result
        System.arraycopy(in, 0, out, 0, out.length);

        return out;
    }

    /**
     * Convert to a partial path, if necessary
     * @return New or existing partial path
     */
    abstract public HDPartialPath asPartial();

    /**
     * Return a list of all ancestors of this path
     * @return unmodifiable list of ancestors
     */
    public List<HDPath> ancestors() {
        return ancestors(false);
    }

    /**
     * Return a list of all ancestors of this path
     * @param includeSelf true if include path for self
     * @return unmodifiable list of ancestors
     */
    public List<HDPath> ancestors(boolean includeSelf) {
        int endExclusive =  children.length + (includeSelf ? 0 : -1);
        return IntStream.range(0, endExclusive)
                .mapToObj(this::ancestorByIndex)
                .collect(StreamUtils.toUnmodifiableList());
    }

    public HDPath ancestorByIndex(int index) {
        checkArgument(index >= 0 && index < children.length, () -> String.format("Index %s out of bounds (0, %s)", index, children.length - 1));
        List<ChildNumber> subList = subListInternal(index + 1);
        return cloneWithPath(subList);
    }

    // Depth of 0, returns empty path, Depth of d returns ancestorByIndex(d-1)
    public HDPath ancestorByDepth(int depth) {
        checkArgument(depth >= 0 && depth <= children.length, () -> String.format("Depth %s out of bounds (0, %s)", depth, children.length));
        return depth == 0
                ? cloneEmpty()
                : this.ancestorByIndex(depth - 1);
    }

    private List<ChildNumber> subListInternal(int to) {
        return list().subList(0, to);
    }

    private HDPath cloneWithPath(List<ChildNumber> newPath) {
        return this instanceof HDFullPath
                ? new HDFullPath(((HDFullPath) this).hasPrivateKey, newPath)
                : new HDPartialPath(newPath);
    }

    private HDPath cloneEmpty() {
        return this instanceof HDFullPath
                ? new HDFullPath(((HDFullPath) this).hasPrivateKey, Collections.emptyList())
                : new HDPartialPath(Collections.emptyList());
    }

    public ChildNumber get(int index) {
        return new ChildNumber(children[index]);
    }

    public int size() {
        return children.length;
    }

    public boolean isEmpty() {
        return children.length == 0;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if ((o == null) || getClass() != o.getClass()) return false;
        HDPath other = (HDPath) o;
        return Arrays.equals(this.children, other.children);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(this.children);
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder();
        if (this instanceof HDFullPath) {
            b.append(((HDFullPath) this).prefix());
        }
        for (int child : children) {
            b.append(SEPARATOR);
            b.append(new ChildNumber(child));
        }
        return b.toString();
    }
}
