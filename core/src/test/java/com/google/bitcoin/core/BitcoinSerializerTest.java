/**
 * Copyright 2011 Noa Resare
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

package com.google.bitcoin.core;


import com.google.bitcoin.params.MainNetParams;
import org.junit.Test;
import org.spongycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import static org.junit.Assert.*;

public class BitcoinSerializerTest {
    private final byte[] addrMessage = Hex.decode("f9beb4d96164647200000000000000001f000000" +
            "ed52399b01e215104d010000000000000000000000000000000000ffff0a000001208d");

    private final byte[] txMessage = Hex.decode(
            "F9 BE B4 D9 74 78 00 00  00 00 00 00 00 00 00 00" +
            "02 01 00 00 E2 93 CD BE  01 00 00 00 01 6D BD DB" +
            "08 5B 1D 8A F7 51 84 F0  BC 01 FA D5 8D 12 66 E9" +
            "B6 3B 50 88 19 90 E4 B4  0D 6A EE 36 29 00 00 00" +
            "00 8B 48 30 45 02 21 00  F3 58 1E 19 72 AE 8A C7" +
            "C7 36 7A 7A 25 3B C1 13  52 23 AD B9 A4 68 BB 3A" +
            "59 23 3F 45 BC 57 83 80  02 20 59 AF 01 CA 17 D0" +
            "0E 41 83 7A 1D 58 E9 7A  A3 1B AE 58 4E DE C2 8D" +
            "35 BD 96 92 36 90 91 3B  AE 9A 01 41 04 9C 02 BF" +
            "C9 7E F2 36 CE 6D 8F E5  D9 40 13 C7 21 E9 15 98" +
            "2A CD 2B 12 B6 5D 9B 7D  59 E2 0A 84 20 05 F8 FC" +
            "4E 02 53 2E 87 3D 37 B9  6F 09 D6 D4 51 1A DA 8F" +
            "14 04 2F 46 61 4A 4C 70  C0 F1 4B EF F5 FF FF FF" +
            "FF 02 40 4B 4C 00 00 00  00 00 19 76 A9 14 1A A0" +
            "CD 1C BE A6 E7 45 8A 7A  BA D5 12 A9 D9 EA 1A FB" +
            "22 5E 88 AC 80 FA E9 C7  00 00 00 00 19 76 A9 14" +
            "0E AB 5B EA 43 6A 04 84  CF AB 12 48 5E FD A0 B7" +
            "8B 4E CC 52 88 AC 00 00  00 00");

    @Test
    public void testAddr() throws Exception {
    	BitcoinSerializer bs = new BitcoinSerializer(MainNetParams.get());
        // the actual data from https://en.bitcoin.it/wiki/Protocol_specification#addr
        ByteArrayInputStream bais = new ByteArrayInputStream(addrMessage);
        AddressMessage a = (AddressMessage)bs.deserialize(bais);
        assertEquals(1, a.getAddresses().size());
        PeerAddress pa = a.getAddresses().get(0);
        assertEquals(8333, pa.getPort());
        assertEquals("10.0.0.1", pa.getAddr().getHostAddress());
        ByteArrayOutputStream bos = new ByteArrayOutputStream(addrMessage.length);
        bs.serialize(a, bos);
        
        //this wont be true due to dynamic timestamps.
        //assertTrue(LazyParseByteCacheTest.arrayContains(bos.toByteArray(), addrMessage));
    }

    @Test
    public void testLazyParsing()  throws Exception {
    	BitcoinSerializer bs = new BitcoinSerializer(MainNetParams.get(), true, false);
    	
    	ByteArrayInputStream bais = new ByteArrayInputStream(txMessage);
    	Transaction tx = (Transaction)bs.deserialize(bais);
        assertNotNull(tx);
        assertEquals(false, tx.isParsed());
        assertEquals(true, tx.isCached());
        tx.getInputs();
        assertEquals(true, tx.isParsed());
        
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bs.serialize(tx, bos);
        assertEquals(true, Arrays.equals(txMessage, bos.toByteArray()));
        
    }
    
    @Test 
    public void testCachedParsing()  throws Exception {
    	testCachedParsing(true);
    	testCachedParsing(false);
    }
    
    private void testCachedParsing(boolean lazy)  throws Exception {
    	BitcoinSerializer bs = new BitcoinSerializer(MainNetParams.get(), lazy, true);
    	
    	//first try writing to a fields to ensure uncaching and children are not affected
    	ByteArrayInputStream bais = new ByteArrayInputStream(txMessage);
    	Transaction tx = (Transaction)bs.deserialize(bais);
        assertNotNull(tx);
        assertEquals(!lazy, tx.isParsed());
        assertEquals(true, tx.isCached());
        
        tx.setLockTime(1);
        //parent should have been uncached
        assertEquals(false, tx.isCached());
        //child should remain cached.
        assertEquals(true, tx.getInputs().get(0).isCached());
        
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bs.serialize(tx, bos);
        assertEquals(true, !Arrays.equals(txMessage, bos.toByteArray()));
    	
      //now try writing to a child to ensure uncaching is propagated up to parent but not to siblings
    	bais = new ByteArrayInputStream(txMessage);
    	tx = (Transaction)bs.deserialize(bais);
    	assertNotNull(tx);
        assertEquals(!lazy, tx.isParsed());
        assertEquals(true, tx.isCached());
        
        tx.getInputs().get(0).setSequenceNumber(1);
        //parent should have been uncached
        assertEquals(false, tx.isCached());
        //so should child
        assertEquals(false, tx.getInputs().get(0).isCached());
        
        bos = new ByteArrayOutputStream();
        bs.serialize(tx, bos);
        assertEquals(true, !Arrays.equals(txMessage, bos.toByteArray()));
        
      //deserialize/reserialize to check for equals.
        bais = new ByteArrayInputStream(txMessage);
    	tx = (Transaction)bs.deserialize(bais);
    	assertNotNull(tx);
        assertEquals(!lazy, tx.isParsed());
        assertEquals(true, tx.isCached());
        bos = new ByteArrayOutputStream();
        bs.serialize(tx, bos);
        assertEquals(true, Arrays.equals(txMessage, bos.toByteArray()));
        
      //deserialize/reserialize to check for equals.  Set a field to it's existing value to trigger uncache
        bais = new ByteArrayInputStream(txMessage);
    	tx = (Transaction)bs.deserialize(bais);
    	assertNotNull(tx);
        assertEquals(!lazy, tx.isParsed());
        assertEquals(true, tx.isCached());
       
        tx.getInputs().get(0).setSequenceNumber(tx.getInputs().get(0).getSequenceNumber());
        
        bos = new ByteArrayOutputStream();
        bs.serialize(tx, bos);
        assertEquals(true, Arrays.equals(txMessage, bos.toByteArray()));
        
    }


    /**
     * Get 1 header of the block number 1 (the first one is 0) in the chain
     */
    @Test
    public void testHeaders1() throws Exception {
        BitcoinSerializer bs = new BitcoinSerializer(MainNetParams.get());

        ByteArrayInputStream bais = new ByteArrayInputStream(Hex.decode("f9beb4d9686561" +
                "646572730000000000520000005d4fab8101010000006fe28c0ab6f1b372c1a6a246ae6" +
                "3f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677b" +
                "a1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e3629900"));

        HeadersMessage hm = (HeadersMessage) bs.deserialize(bais);

        // The first block after the genesis
        // http://blockexplorer.com/b/1
        Block block = hm.getBlockHeaders().get(0);
        String hash = block.getHashAsString();
        assertEquals(hash, "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048");

        assertNull(block.transactions);

        assertEquals(Utils.bytesToHexString(block.getMerkleRoot().getBytes()),
                "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098");
    }


    @Test
    /**
     * Get 6 headers of blocks 1-6 in the chain
     */
    public void testHeaders2() throws Exception {
        BitcoinSerializer bs = new BitcoinSerializer(MainNetParams.get());

        ByteArrayInputStream bais = new ByteArrayInputStream(Hex.decode("f9beb4d96865616465" +
                "72730000000000e701000085acd4ea06010000006fe28c0ab6f1b372c1a6a246ae63f74f931e" +
                "8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1c" +
                "db606e857233e0e61bc6649ffff001d01e3629900010000004860eb18bf1b1620e37e9490fc8a" +
                "427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36" +
                "ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd610001000000bddd99ccfda39da1b108ce1" +
                "a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387" +
                "af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d00010000004944469562ae1c2c74" +
                "d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec" +
                "5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9000100000085144a84488e" +
                "a88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000e11c48fecdd9e72510ca84f023" +
                "370c9a38bf91ac5cae88019bee94d24528526344c36649ffff001d1d03e4770001000000fc33f5" +
                "96f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4" +
                "ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c9700"));

        HeadersMessage hm = (HeadersMessage) bs.deserialize(bais);

        int nBlocks = hm.getBlockHeaders().size();
        assertEquals(nBlocks, 6);

        // index 0 block is the number 1 block in the block chain
        // http://blockexplorer.com/b/1
        Block zeroBlock = hm.getBlockHeaders().get(0);
        String zeroBlockHash = zeroBlock.getHashAsString();

        assertEquals("00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
                zeroBlockHash);
        assertEquals(zeroBlock.getNonce(), 2573394689L);


        Block thirdBlock = hm.getBlockHeaders().get(3);
        String thirdBlockHash = thirdBlock.getHashAsString();

        // index 3 block is the number 4 block in the block chain
        // http://blockexplorer.com/b/4
        assertEquals("000000004ebadb55ee9096c9a2f8880e09da59c0d68b1c228da88e48844a1485",
                thirdBlockHash);
        assertEquals(thirdBlock.getNonce(), 2850094635L);
    }


}
