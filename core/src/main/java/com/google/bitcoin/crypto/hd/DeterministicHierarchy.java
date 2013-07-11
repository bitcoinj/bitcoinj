/**
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

package com.google.bitcoin.crypto.hd;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

/**
 * A DeterministicHierarchy calculates and keeps a whole tree (hierarchy) of keys originating from a single
 * root key.
 */
public class DeterministicHierarchy implements Serializable {
    /**
     * Child derivation may fail (although with extremely low probability); in such case it is re-attempted.
     * This is the maximum number of re-attempts (to avoid an infinite loop in case of bugs etc.).
     */
    private static final int MAX_CHILD_DERIVATION_ATTEMPTS = 100;

    private final Map<ImmutableList<ChildNumber>, ExtendedHierarchicKey> keys = Maps.newHashMap();
    private final ImmutableList<ChildNumber> rootPath;
    private final Map<ImmutableList<ChildNumber>, ChildNumber> lastPrivDerivedNumbers = Maps.newHashMap();
    private final Map<ImmutableList<ChildNumber>, ChildNumber> lastPubDerivedNumbers = Maps.newHashMap();

    public DeterministicHierarchy(ExtendedHierarchicKey rootKey) {
        putKey(rootKey);
        rootPath = rootKey.getChildNumberPath();
    }

    private void putKey(ExtendedHierarchicKey key) {
        keys.put(key.getChildNumberPath(), key);
    }

    /**
     * @param path the path to the key
     * @param relativePath whether the path is relative to the root path
     * @param create whether the key corresponding to path should be created (with any necessary ancestors) if it doesn't exist already
     * @return next newly created key using the child derivation funtcion
     */
    public ExtendedHierarchicKey get(List<ChildNumber> path, boolean relativePath, boolean create) {
        ImmutableList<ChildNumber> absolutePath = relativePath
                ? ImmutableList.<ChildNumber>builder().addAll(rootPath).addAll(path).build()
                : ImmutableList.copyOf(path);
        if (!keys.containsKey(absolutePath)) {
            Preconditions.checkArgument(create, "No key found for {} path {}.", relativePath ? "relative" : "absolute", path);
            Preconditions.checkArgument(absolutePath.size() > 0, "Can't derive the master key: nothing to derive from.");
            ExtendedHierarchicKey parent = get(absolutePath.subList(0, absolutePath.size() - 1), relativePath, create);
            putKey(HDKeyDerivation.deriveChildKey(parent, absolutePath.get(absolutePath.size() - 1)));
        }
        return keys.get(absolutePath);
    }

    /**
     * @param parentPath the path to the parent
     * @param relativePath whether the path is relative to the root path
     * @param createParent whether the parent corresponding to path should be created (with any necessary ancestors) if it doesn't exist already
     * @param privateDerivation whether to use private or public derivation
     * @return next newly created key using the child derivation funtcion
     */
    public ExtendedHierarchicKey deriveNextChild(ImmutableList<ChildNumber> parentPath, boolean relativePath, boolean createParent, boolean privateDerivation) {
        ExtendedHierarchicKey parent = get(parentPath, relativePath, createParent);
        int nAttempts = 0;
        while (nAttempts++ < MAX_CHILD_DERIVATION_ATTEMPTS) {
            try {
                ChildNumber createChildNumber = getNextChildNumberToDerive(parent.getChildNumberPath(), privateDerivation);
                return deriveChild(parent, createChildNumber);
            } catch (HDDerivationException ignore) { }
        }
        throw new HDDerivationException("Maximum number of child derivation attempts reached, this is probably an indication of a bug.");
    }

    private ChildNumber getNextChildNumberToDerive(ImmutableList<ChildNumber> path, boolean privateDerivation) {
        Map<ImmutableList<ChildNumber>, ChildNumber> lastDerivedNumbers = getLastDerivedNumbers(privateDerivation);
        ChildNumber lastChildNumber = lastDerivedNumbers.get(path);
        ChildNumber nextChildNumber = new ChildNumber(lastChildNumber != null ? lastChildNumber.getChildNumber() + 1 : 0, privateDerivation);
        lastDerivedNumbers.put(path, nextChildNumber);
        return nextChildNumber;
    }

    public ExtendedHierarchicKey deriveChild(List<ChildNumber> parentPath, boolean relativePath, boolean createParent, ChildNumber createChildNumber) {
        return deriveChild(get(parentPath, relativePath, createParent), createChildNumber);
    }

    private ExtendedHierarchicKey deriveChild(ExtendedHierarchicKey parent, ChildNumber createChildNumber) {
        ExtendedHierarchicKey childKey = HDKeyDerivation.deriveChildKey(parent, createChildNumber);
        putKey(childKey);
        return childKey;
    }

    public ExtendedHierarchicKey getRootKey() {
        return get(rootPath, false, false);
    }

    private Map<ImmutableList<ChildNumber>, ChildNumber> getLastDerivedNumbers(boolean privateDerivation) {
        return privateDerivation ? lastPrivDerivedNumbers : lastPubDerivedNumbers;
    }
}
