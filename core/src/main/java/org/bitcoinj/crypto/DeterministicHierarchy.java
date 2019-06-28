/*
 * Copyright 2013 Matija Mazi.
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

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static com.google.common.base.Preconditions.checkArgument;

// TODO: This whole API feels a bit object heavy. Do we really need ChildNumber and so many maps, etc?
// TODO: Should we be representing this using an actual tree arrangement in memory instead of a bunch of hashmaps?

/**
 * <p>A DeterministicHierarchy calculates and keeps a whole tree (hierarchy) of keys originating from a single
 * root key. This implements part of the BIP 32 specification. A deterministic key tree is useful because
 * Bitcoin's privacy system require new keys to be created for each transaction, but managing all these
 * keys quickly becomes unwieldy. In particular it becomes hard to back up and distribute them. By having
 * a way to derive random-looking but deterministic keys we can make wallet backup simpler and gain the
 * ability to hand out {@link DeterministicKey}s to other people who can then create new addresses
 * on the fly, without having to contact us.</p>
 *
 * <p>The hierarchy is started from a single root key, and a location in the tree is given by a path which
 * is a list of {@link ChildNumber}s.</p>
 */
public class DeterministicHierarchy {
    private final Map<HDPath, DeterministicKey> keys = new HashMap<>();
    private final HDPath rootPath;
    // Keep track of how many child keys each node has. This is kind of weak.
    private final Map<HDPath, ChildNumber> lastChildNumbers = new HashMap<>();

    public static final int BIP32_STANDARDISATION_TIME_SECS = 1369267200;

    /**
     * Constructs a new hierarchy rooted at the given key. Note that this does not have to be the top of the tree.
     * You can construct a DeterministicHierarchy for a subtree of a larger tree that you may not own.
     */
    public DeterministicHierarchy(DeterministicKey rootKey) {
        putKey(rootKey);
        rootPath = rootKey.getPath();
    }

    /**
     * Inserts a key into the hierarchy. Used during deserialization: you normally don't need this. Keys must be
     * inserted in order.
     */
    public final void putKey(DeterministicKey key) {
        HDPath path = key.getPath();
        // Update our tracking of what the next child in each branch of the tree should be. Just assume that keys are
        // inserted in order here.
        final DeterministicKey parent = key.getParent();
        if (parent != null)
            lastChildNumbers.put(parent.getPath(), key.getChildNumber());
        keys.put(path, key);
    }

    /**
     * Returns a key for the given path, optionally creating it.
     *
     * @param path the path to the key
     * @param relativePath whether the path is relative to the root path
     * @param create whether the key corresponding to path should be created (with any necessary ancestors) if it doesn't exist already
     * @return next newly created key using the child derivation function
     * @throws IllegalArgumentException if create is false and the path was not found.
     */
    public DeterministicKey get(List<ChildNumber> path, boolean relativePath, boolean create) {
        HDPath inputPath = HDPath.M(path);
        HDPath absolutePath = relativePath
                ? rootPath.extend(path)
                : inputPath;
        if (!keys.containsKey(absolutePath)) {
            if (!create)
                throw new IllegalArgumentException(String.format(Locale.US, "No key found for %s path %s.",
                    relativePath ? "relative" : "absolute", inputPath.toString()));
            checkArgument(absolutePath.size() > 0, "Can't derive the master key: nothing to derive from.");
            DeterministicKey parent = get(absolutePath.subList(0, absolutePath.size() - 1), false, true);
            putKey(HDKeyDerivation.deriveChildKey(parent, absolutePath.get(absolutePath.size() - 1)));
        }
        return keys.get(absolutePath);
    }

    /**
     * Extends the tree by calculating the next key that hangs off the given parent path. For example, if you pass a
     * path of 1/2 here and there are already keys 1/2/1 and 1/2/2 then it will derive 1/2/3.
     *
     * @param parentPath the path to the parent
     * @param relative whether the path is relative to the root path
     * @param createParent whether the parent corresponding to path should be created (with any necessary ancestors) if it doesn't exist already
     * @param privateDerivation whether to use private or public derivation
     * @return next newly created key using the child derivation function
     * @throws IllegalArgumentException if the parent doesn't exist and createParent is false.
     */
    public DeterministicKey deriveNextChild(List<ChildNumber> parentPath, boolean relative, boolean createParent, boolean privateDerivation) {
        DeterministicKey parent = get(parentPath, relative, createParent);
        int nAttempts = 0;
        while (nAttempts++ < HDKeyDerivation.MAX_CHILD_DERIVATION_ATTEMPTS) {
            try {
                ChildNumber createChildNumber = getNextChildNumberToDerive(parent.getPath(), privateDerivation);
                return deriveChild(parent, createChildNumber);
            } catch (HDDerivationException ignore) { }
        }
        throw new HDDerivationException("Maximum number of child derivation attempts reached, this is probably an indication of a bug.");
    }

    private ChildNumber getNextChildNumberToDerive(HDPath path, boolean privateDerivation) {
        ChildNumber lastChildNumber = lastChildNumbers.get(path);
        ChildNumber nextChildNumber = new ChildNumber(lastChildNumber != null ? lastChildNumber.num() + 1 : 0, privateDerivation);
        lastChildNumbers.put(path, nextChildNumber);
        return nextChildNumber;
    }

    public int getNumChildren(HDPath path) {
        final ChildNumber cn = lastChildNumbers.get(path);
        if (cn == null)
            return 0;
        else
            return cn.num() + 1;   // children start with zero based childnumbers
    }

    /**
     * Extends the tree by calculating the requested child for the given path. For example, to get the key at position
     * 1/2/3 you would pass 1/2 as the parent path and 3 as the child number.
     *
     * @param parentPath the path to the parent
     * @param relative whether the path is relative to the root path
     * @param createParent whether the parent corresponding to path should be created (with any necessary ancestors) if it doesn't exist already
     * @return the requested key.
     * @throws IllegalArgumentException if the parent doesn't exist and createParent is false.
     */
    public DeterministicKey deriveChild(List<ChildNumber> parentPath, boolean relative, boolean createParent, ChildNumber createChildNumber) {
        return deriveChild(get(parentPath, relative, createParent), createChildNumber);
    }

    private DeterministicKey deriveChild(DeterministicKey parent, ChildNumber createChildNumber) {
        DeterministicKey childKey = HDKeyDerivation.deriveChildKey(parent, createChildNumber);
        putKey(childKey);
        return childKey;
    }

    /**
     * Returns the root key that the {@link DeterministicHierarchy} was created with.
     */
    public DeterministicKey getRootKey() {
        return get(rootPath, false, false);
    }
}
