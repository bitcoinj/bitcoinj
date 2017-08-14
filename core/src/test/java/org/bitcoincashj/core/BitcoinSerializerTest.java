/*
 * Copyright 2011 Noa Resare
 * Copyright 2014 Andreas Schildbach
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

package org.bitcoincashj.core;

import org.bitcoincashj.params.MainNetParams;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Arrays;

import static org.bitcoincashj.core.Utils.HEX;
import static org.junit.Assert.*;

public class BitcoinSerializerTest {
    private static final byte[] ADDRESS_MESSAGE_BYTES = HEX.decode("f9beb4d96164647200000000000000001f000000" +
            "ed52399b01e215104d010000000000000000000000000000000000ffff0a000001208d");

    private static final byte[] TRANSACTION_MESSAGE_BYTES = HEX.withSeparator(" ", 2).decode(
            "f9 be b4 d9 74 78 00 00  00 00 00 00 00 00 00 00" +
            "02 01 00 00 e2 93 cd be  01 00 00 00 01 6d bd db" +
            "08 5b 1d 8a f7 51 84 f0  bc 01 fa d5 8d 12 66 e9" +
            "b6 3b 50 88 19 90 e4 b4  0d 6a ee 36 29 00 00 00" +
            "00 8b 48 30 45 02 21 00  f3 58 1e 19 72 ae 8a c7" +
            "c7 36 7a 7a 25 3b c1 13  52 23 ad b9 a4 68 bb 3a" +
            "59 23 3f 45 bc 57 83 80  02 20 59 af 01 ca 17 d0" +
            "0e 41 83 7a 1d 58 e9 7a  a3 1b ae 58 4e de c2 8d" +
            "35 bd 96 92 36 90 91 3b  ae 9a 01 41 04 9c 02 bf" +
            "c9 7e f2 36 ce 6d 8f e5  d9 40 13 c7 21 e9 15 98" +
            "2a cd 2b 12 b6 5d 9b 7d  59 e2 0a 84 20 05 f8 fc" +
            "4e 02 53 2e 87 3d 37 b9  6f 09 d6 d4 51 1a da 8f" +
            "14 04 2f 46 61 4a 4c 70  c0 f1 4b ef f5 ff ff ff" +
            "ff 02 40 4b 4c 00 00 00  00 00 19 76 a9 14 1a a0" +
            "cd 1c be a6 e7 45 8a 7a  ba d5 12 a9 d9 ea 1a fb" +
            "22 5e 88 ac 80 fa e9 c7  00 00 00 00 19 76 a9 14" +
            "0e ab 5b ea 43 6a 04 84  cf ab 12 48 5e fd a0 b7" +
            "8b 4e cc 52 88 ac 00 00  00 00");

    @Test
    public void testAddr() throws Exception {
        final NetworkParameters params = MainNetParams.get();
        MessageSerializer serializer = params.getDefaultSerializer();
        // the actual data from https://en.bitcoin.it/wiki/Protocol_specification#addr
        AddressMessage addressMessage = (AddressMessage) serializer.deserialize(ByteBuffer.wrap(ADDRESS_MESSAGE_BYTES));
        assertEquals(1, addressMessage.getAddresses().size());
        PeerAddress peerAddress = addressMessage.getAddresses().get(0);
        assertEquals(8333, peerAddress.getPort());
        assertEquals("10.0.0.1", peerAddress.getAddr().getHostAddress());
        ByteArrayOutputStream bos = new ByteArrayOutputStream(ADDRESS_MESSAGE_BYTES.length);
        serializer.serialize(addressMessage, bos);

        assertEquals(31, addressMessage.getMessageSize());
        addressMessage.addAddress(new PeerAddress(params, InetAddress.getLocalHost()));
        assertEquals(61, addressMessage.getMessageSize());
        addressMessage.removeAddress(0);
        assertEquals(31, addressMessage.getMessageSize());

        //this wont be true due to dynamic timestamps.
        //assertTrue(LazyParseByteCacheTest.arrayContains(bos.toByteArray(), addrMessage));
    }

    @Test
    public void testCachedParsing() throws Exception {
        MessageSerializer serializer = MainNetParams.get().getSerializer(true);
        
        // first try writing to a fields to ensure uncaching and children are not affected
        Transaction transaction = (Transaction) serializer.deserialize(ByteBuffer.wrap(TRANSACTION_MESSAGE_BYTES));
        assertNotNull(transaction);
        assertTrue(transaction.isCached());

        transaction.setLockTime(1);
        // parent should have been uncached
        assertFalse(transaction.isCached());
        // child should remain cached.
        assertTrue(transaction.getInputs().get(0).isCached());

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        serializer.serialize(transaction, bos);
        assertFalse(Arrays.equals(TRANSACTION_MESSAGE_BYTES, bos.toByteArray()));

        // now try writing to a child to ensure uncaching is propagated up to parent but not to siblings
        transaction = (Transaction) serializer.deserialize(ByteBuffer.wrap(TRANSACTION_MESSAGE_BYTES));
        assertNotNull(transaction);
        assertTrue(transaction.isCached());

        transaction.getInputs().get(0).setSequenceNumber(1);
        // parent should have been uncached
        assertFalse(transaction.isCached());
        // so should child
        assertFalse(transaction.getInputs().get(0).isCached());

        bos = new ByteArrayOutputStream();
        serializer.serialize(transaction, bos);
        assertFalse(Arrays.equals(TRANSACTION_MESSAGE_BYTES, bos.toByteArray()));

        // deserialize/reserialize to check for equals.
        transaction = (Transaction) serializer.deserialize(ByteBuffer.wrap(TRANSACTION_MESSAGE_BYTES));
        assertNotNull(transaction);
        assertTrue(transaction.isCached());
        bos = new ByteArrayOutputStream();
        serializer.serialize(transaction, bos);
        assertTrue(Arrays.equals(TRANSACTION_MESSAGE_BYTES, bos.toByteArray()));

        // deserialize/reserialize to check for equals.  Set a field to it's existing value to trigger uncache
        transaction = (Transaction) serializer.deserialize(ByteBuffer.wrap(TRANSACTION_MESSAGE_BYTES));
        assertNotNull(transaction);
        assertTrue(transaction.isCached());

        transaction.getInputs().get(0).setSequenceNumber(transaction.getInputs().get(0).getSequenceNumber());

        bos = new ByteArrayOutputStream();
        serializer.serialize(transaction, bos);
        assertTrue(Arrays.equals(TRANSACTION_MESSAGE_BYTES, bos.toByteArray()));
    }

    /**
     * Get 1 header of the block number 1 (the first one is 0) in the chain
     */
    @Test
    public void testHeaders1() throws Exception {
        MessageSerializer serializer = MainNetParams.get().getDefaultSerializer();

        byte[] headersMessageBytes = HEX.decode("f9beb4d9686561" +
                "646572730000000000520000005d4fab8101010000006fe28c0ab6f1b372c1a6a246ae6" +
                "3f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677b" +
                "a1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e3629900");
        HeadersMessage headersMessage = (HeadersMessage) serializer.deserialize(ByteBuffer.wrap(headersMessageBytes));

        // The first block after the genesis
        // http://blockexplorer.com/b/1
        Block block = headersMessage.getBlockHeaders().get(0);
        assertEquals("00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048", block.getHashAsString());
        assertNotNull(block.transactions);
        assertEquals("0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098", Utils.HEX.encode(block.getMerkleRoot().getBytes()));

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        serializer.serialize(headersMessage, byteArrayOutputStream);
        byte[] serializedBytes = byteArrayOutputStream.toByteArray();
        assertArrayEquals(headersMessageBytes, serializedBytes);
    }

    /**
     * Get 6 headers of blocks 1-6 in the chain
     */
    @Test
    public void testHeaders2() throws Exception {
        MessageSerializer serializer = MainNetParams.get().getDefaultSerializer();

        byte[] headersMessageBytes = HEX.decode("f9beb4d96865616465" +
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
                "ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c9700");
        HeadersMessage headersMessage = (HeadersMessage) serializer.deserialize(ByteBuffer.wrap(headersMessageBytes));

        assertEquals(6, headersMessage.getBlockHeaders().size());

        // index 0 block is the number 1 block in the block chain
        // http://blockexplorer.com/b/1
        Block zeroBlock = headersMessage.getBlockHeaders().get(0);
        assertEquals("00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
                zeroBlock.getHashAsString());
        assertEquals(2573394689L, zeroBlock.getNonce());

        // index 3 block is the number 4 block in the block chain
        // http://blockexplorer.com/b/4
        Block thirdBlock = headersMessage.getBlockHeaders().get(3);
        assertEquals("000000004ebadb55ee9096c9a2f8880e09da59c0d68b1c228da88e48844a1485",
                thirdBlock.getHashAsString());
        assertEquals(2850094635L, thirdBlock.getNonce());

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        serializer.serialize(headersMessage, byteArrayOutputStream);
        byte[] serializedBytes = byteArrayOutputStream.toByteArray();
        assertArrayEquals(headersMessageBytes, serializedBytes);
    }

    @Test(expected = BufferUnderflowException.class)
    public void testBitcoinPacketHeaderTooShort() {
        new BitcoinSerializer.BitcoinPacketHeader(ByteBuffer.wrap(new byte[] { 0 }));
    }

    @Test(expected = ProtocolException.class)
    public void testBitcoinPacketHeaderTooLong() {
        // Message with a Message size which is 1 too big, in little endian format.
        byte[] wrongMessageLength = HEX.decode("000000000000000000000000010000020000000000");
        new BitcoinSerializer.BitcoinPacketHeader(ByteBuffer.wrap(wrongMessageLength));
    }

    @Test(expected = BufferUnderflowException.class)
    public void testSeekPastMagicBytes() {
        // Fail in another way, there is data in the stream but no magic bytes.
        byte[] brokenMessage = HEX.decode("000000");
        MainNetParams.get().getDefaultSerializer().seekPastMagicBytes(ByteBuffer.wrap(brokenMessage));
    }

    /**
     * Tests serialization of an unknown message.
     */
    @Test(expected = Error.class)
    public void testSerializeUnknownMessage() throws Exception {
        MessageSerializer serializer = MainNetParams.get().getDefaultSerializer();

        Message unknownMessage = new Message() {
            @Override
            protected void parse() throws ProtocolException {
            }
        };
        ByteArrayOutputStream bos = new ByteArrayOutputStream(ADDRESS_MESSAGE_BYTES.length);
        serializer.serialize(unknownMessage, bos);
    }
}
