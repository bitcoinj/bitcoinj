/**
 * Copyright 2014 Mike Hearn
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

package com.google.bitcoin.wallet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bitcoinj.wallet.Protos;
import org.junit.Test;
import org.spongycastle.util.encoders.Hex;

import com.google.bitcoin.core.Address;
import com.google.bitcoin.core.BloomFilter;
import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.core.Utils;
import com.google.bitcoin.crypto.DeterministicKey;
import com.google.bitcoin.params.MainNetParams;
import com.google.bitcoin.utils.BriefLogFormatter;
import com.google.bitcoin.wallet.KeyChain.KeyPurpose;
import com.google.common.collect.ImmutableList;

public class MarriedKeyChainGroupTest {
    // Number of initial keys in this tests HD wallet, including interior keys.
    private static final int INITIAL_KEYS = 4;
    private static final int LOOKAHEAD_SIZE = 5;
    private KeyChainGroup group;

    public MarriedKeyChainGroupTest() throws Exception {
        BriefLogFormatter.init();
        Utils.setMockClock();
        DeterministicKeyChain master = new DeterministicKeyChain(new DeterministicSeed(Arrays.asList("aerobic toe save section draw warm cute upon raccoon mother priority pilot taste sweet next traffic fatal sword dentist original crisp team caution rebel".split(" ")),0L));
    	master.setLookaheadSize(LOOKAHEAD_SIZE);
    	DeterministicKeyChain shadowChain = new DeterministicKeyChain(new SecureRandom(),master);
    	List<DeterministicKeyChain> chains = new ArrayList<DeterministicKeyChain>();
    	chains.add(shadowChain);
    	chains.add(master);
    	group = new KeyChainGroup(chains);
    }

    @Test
    public void freshCurrentKeys() throws Exception {
        assertEquals(2 * INITIAL_KEYS, group.numKeys());
        assertEquals(4 * INITIAL_KEYS, group.getBloomFilterElementCount());
        Address a1 = group.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS, MainNetParams.get());
        final int keyCount = INITIAL_KEYS*2 + LOOKAHEAD_SIZE + 1;
        assertEquals(keyCount, group.numKeys());
        assertEquals(2 * keyCount, group.getBloomFilterElementCount());

        ECKey i1 = new ECKey();
        group.importKeys(i1);
        assertEquals(keyCount + 1, group.numKeys());
        assertEquals(2 * (keyCount + 1), group.getBloomFilterElementCount());

        Address r2 = group.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS, MainNetParams.get());
        assertEquals(a1, r2);
        Address c1 = group.currentAddress(KeyChain.KeyPurpose.CHANGE,MainNetParams.get());
        assertNotEquals(a1, c1);
        Address r3 = group.freshAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS,MainNetParams.get());
        assertNotEquals(a1, r3);
        Address c2 = group.freshAddress(KeyChain.KeyPurpose.CHANGE,MainNetParams.get());
        assertNotEquals(r3, c2);
        Address r4 = group.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS,MainNetParams.get());
        assertEquals(r3, r4);
        Address c3 = group.currentAddress(KeyChain.KeyPurpose.CHANGE,MainNetParams.get());
        assertEquals(c2, c3);
    }

    @Test
    public void imports() throws Exception {
        ECKey key1 = new ECKey();
        assertFalse(group.removeImportedKey(key1));
        assertEquals(1, group.importKeys(ImmutableList.of(key1)));
        assertEquals(INITIAL_KEYS*2 + 1, group.numKeys());   // Lookahead is triggered by requesting a key, so none yet.
        group.removeImportedKey(key1);
        assertEquals(INITIAL_KEYS*2, group.numKeys());
    }

    /*
     * TODO: finish
     */
    @Test
    public void bloom() throws Exception {
        assertEquals(INITIAL_KEYS * 4, group.getBloomFilterElementCount());
        Address a1 = group.freshAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS,MainNetParams.get());
        ECKey key2 = new ECKey();
        final int size = (INITIAL_KEYS * 2 + LOOKAHEAD_SIZE + 1 /* for the just created key */) * 2;
        assertEquals(size, group.getBloomFilterElementCount());
        BloomFilter filter = group.getBloomFilter(size, 0.001, (long)(Math.random() * Long.MAX_VALUE));
        //assertTrue(filter.contains(a1.getHash160()));
        assertFalse(filter.contains(key2.getPubKey()));
        // Check that the filter contains the lookahead buffer.
        for (int i = 0; i < LOOKAHEAD_SIZE; i++) {
            Address k = group.freshAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS,MainNetParams.get());
            //assertTrue(filter.contains(k.getHash160()));
        }
        // We ran ahead of the lookahead buffer.
        assertFalse(filter.contains(group.freshAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS,MainNetParams.get()).getHash160()));
        group.importKeys(key2);
        filter = group.getBloomFilter(group.getBloomFilterElementCount(), 0.001, (long)(Math.random() * Long.MAX_VALUE));
        //assertTrue(filter.contains(a1.getHash160()));
        assertTrue(filter.contains(key2.getPubKey())); //TODO: should this be possible
    }

    @Test
    public void constructWithShadow() throws Exception {
    	//construct with one shadow
    }
    
    @Test
    public void constructWithShadows() throws Exception {
    	//construct with two shadows
    }
    
    @Test
    public void retrieveShadows() throws Exception {
    	assertTrue(group.isMarried(group.getActiveKeyChain()));
    	assertTrue(null!=group.getMarriedChains(group.getActiveKeyChain()));
    	DeterministicKeyChain chain = group.getChain(group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS));
    	assertEquals(chain, group.getActiveKeyChain());
    }
    
    @Test
    public void testKey() throws Exception{
    	DeterministicKeyChain master = new DeterministicKeyChain(new SecureRandom());
    	master.setLookaheadSize(6);
    	DeterministicKeyChain shadowChain = new DeterministicKeyChain(group.getActiveKeyChain().getWatchingKey(),master);
    	shadowChain.setLookaheadSize(0);
    	List<DeterministicKeyChain> chains = new ArrayList<DeterministicKeyChain>();
    	chains.add(shadowChain);
    	chains.add(master);
    	KeyChainGroup msGroup = new KeyChainGroup(chains);
    	for(ECKey key: msGroup.getActiveKeyChain().getKeys()){
    		if (((DeterministicKey)key).getPathAsString().length()>2){
    			System.out.println(((DeterministicKey)key).getPathAsString());
    			System.out.println("key:    "+Hex.toHexString(key.getPubKey()));
    			System.out.println("shadow: "+Hex.toHexString(msGroup.getShadows((DeterministicKey)key).toArray(new ECKey[0])[0].getPubKey()));
    		}
    	}
    	
        List<Protos.Key> protoKeys2 = msGroup.serializeToProtobuf();
        
        msGroup = KeyChainGroup.fromProtobufUnencrypted(protoKeys2);
    	for(ECKey key: msGroup.getActiveKeyChain().getKeys()){
    		if (((DeterministicKey)key).getPathAsString().length()>2){
    			System.out.println(((DeterministicKey)key).getPathAsString());
    			System.out.println("key:    "+Hex.toHexString(key.getPubKey()));
    			System.out.println("shadow: "+Hex.toHexString(msGroup.getShadows((DeterministicKey)key).toArray(new ECKey[0])[0].getPubKey()));
    		}
    	}
    	
    }
    
}
