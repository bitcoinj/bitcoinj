/*
 * Copyright (c) 2018.
 * Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.bitcoinj.core;

import java.util.ArrayList;
import java.util.List;

public class BlockLocator {
    List<Sha256Hash> blockLocator;
    public BlockLocator(int startCount){
        blockLocator = new ArrayList<>(startCount);
    }
    public BlockLocator(){
        blockLocator = new ArrayList<>();
    }
    public void add(Sha256Hash hash){
        blockLocator.add(hash);
    }
    public int size(){
        return blockLocator.size();
    }
    public int hashCode(int initial){
        int hashCode = initial;
        for (Sha256Hash aLocator : blockLocator) hashCode ^= aLocator.hashCode();
        return hashCode;
    }
    public boolean containsAll(BlockLocator other){
        return equals(other);
    }
    public void clear(){
        blockLocator.clear();
    }
    @Override
    public String toString(){
        return "Block locator with " + size() + " blocks \n " + Utils.SPACE_JOINER.join(blockLocator);
    }

    public Sha256Hash get(int i) {
        return blockLocator.get(i);
    }
}
