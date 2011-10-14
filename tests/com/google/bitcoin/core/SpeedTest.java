package com.google.bitcoin.core;

import static com.google.bitcoin.core.TestUtils.createFakeBlock;
import static com.google.bitcoin.core.TestUtils.createFakeTx;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.util.encoders.Hex;

import com.google.bitcoin.core.Address;
import com.google.bitcoin.core.BitcoinSerializer;
import com.google.bitcoin.core.Block;
import com.google.bitcoin.core.BlockChain;
import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.core.NetworkParameters;
import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.core.TransactionOutput;
import com.google.bitcoin.core.Utils;
import com.google.bitcoin.core.Wallet;
import com.google.bitcoin.store.BlockStore;
import com.google.bitcoin.store.MemoryBlockStore;

public class SpeedTest {
	private final byte[] addrMessage = Hex.decode("fabfb5da6164647200000000000000001f000000"
			+ "ed52399b01e215104d010000000000000000000000000000000000ffff0a000001208d");

	private final byte[] txMessage = Hex.decode("F9 BE B4 D9 74 78 00 00  00 00 00 00 00 00 00 00"
			+ "02 01 00 00 E2 93 CD BE  01 00 00 00 01 6D BD DB" + "08 5B 1D 8A F7 51 84 F0  BC 01 FA D5 8D 12 66 E9"
			+ "B6 3B 50 88 19 90 E4 B4  0D 6A EE 36 29 00 00 00" + "00 8B 48 30 45 02 21 00  F3 58 1E 19 72 AE 8A C7"
			+ "C7 36 7A 7A 25 3B C1 13  52 23 AD B9 A4 68 BB 3A" + "59 23 3F 45 BC 57 83 80  02 20 59 AF 01 CA 17 D0"
			+ "0E 41 83 7A 1D 58 E9 7A  A3 1B AE 58 4E DE C2 8D" + "35 BD 96 92 36 90 91 3B  AE 9A 01 41 04 9C 02 BF"
			+ "C9 7E F2 36 CE 6D 8F E5  D9 40 13 C7 21 E9 15 98" + "2A CD 2B 12 B6 5D 9B 7D  59 E2 0A 84 20 05 F8 FC"
			+ "4E 02 53 2E 87 3D 37 B9  6F 09 D6 D4 51 1A DA 8F" + "14 04 2F 46 61 4A 4C 70  C0 F1 4B EF F5 FF FF FF"
			+ "FF 02 40 4B 4C 00 00 00  00 00 19 76 A9 14 1A A0" + "CD 1C BE A6 E7 45 8A 7A  BA D5 12 A9 D9 EA 1A FB"
			+ "22 5E 88 AC 80 FA E9 C7  00 00 00 00 19 76 A9 14" + "0E AB 5B EA 43 6A 04 84  CF AB 12 48 5E FD A0 B7"
			+ "8B 4E CC 52 88 AC 00 00  00 00");

	private final byte[] txMessagePart = Hex.decode("08 5B 1D 8A F7 51 84 F0  BC 01 FA D5 8D 12 66 E9"
			+ "B6 3B 50 88 19 90 E4 B4  0D 6A EE 36 29 00 00 00" + "00 8B 48 30 45 02 21 00  F3 58 1E 19 72 AE 8A C7"
			+ "C7 36 7A 7A 25 3B C1 13  52 23 AD B9 A4 68 BB 3A");

	private static final NetworkParameters testNet = NetworkParameters.testNet();
	private BlockChain testNetChain;

	private Wallet wallet;
	private BlockChain chain;
	private BlockStore blockStore;
	private Address coinbaseTo;
	private NetworkParameters unitTestParams;

	AddressMessage addr1;
	byte[] addr1BytesWithHeader;

	Block b1;
	private byte[] b1Bytes;
	private byte[] b1BytesWithHeader;

	Transaction tx1;
	private byte[] tx1Bytes;
	private byte[] tx1BytesWithHeader;

	private byte[] tx2Bytes;
	private byte[] tx2BytesWithHeader;

	List<SerializerEntry> bss;
	List<SerializerEntry> singleBs;
	List<Manipulator<Transaction>> txMans = new ArrayList();
	List<Manipulator<Block>> blockMans = new ArrayList();
	List<Manipulator<AddressMessage>> addrMans = new ArrayList();
	List<Manipulator> genericMans = new ArrayList();

	public static void main(String[] args) throws Exception {
		SpeedTest test = new SpeedTest();
		test.setUp();
		test.start(50000, 50000, false);
	}

	public static final boolean RECACHE = false;
	
	public void start(int warmupIterations, int iterations, boolean pauseForKeyPress) {

		if (pauseForKeyPress) {
			System.out.println("Attach profiler or whatever and press enter to start test");
			InputStreamReader r = new InputStreamReader(System.in);
			BufferedReader reader = new BufferedReader(r);
			try {
				reader.readLine();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		// allocate some arrays to prefill memory and hopefully push up the head
		// size.
		System.out
				.println("Filling memory to 80% of maximum mb: " + (Runtime.getRuntime().maxMemory() / (1024 * 1024)));
		List junk = new ArrayList();
		while (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory() < Runtime.getRuntime()
				.maxMemory() * 0.8) {
			junk.add(new byte[10000]);
			if (junk.size() % 10000 == 0)
				System.out.println("totalMemory: "
						+ ((Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / (1024 * 1024))
						+ "mb");
		}

		junk = null;

		System.out.println("******************************");
		System.out.println("***      Generic Tests     ***");
		System.out.println("******************************");
		for (Manipulator<AddressMessage> man : genericMans) {
			testManipulator(man, "warmup", warmupIterations * 10, singleBs, null, b1Bytes);
		}
		for (Manipulator<AddressMessage> man : genericMans) {
			testManipulator(man, "main test", iterations * 10, singleBs, null, b1Bytes);
		}
		
		System.out.println("******************************");
		System.out.println("***      WARMUP PHASE      ***");
		System.out.println("******************************");
		for (Manipulator<AddressMessage> man : addrMans) {
			testManipulator(man, "warmup", warmupIterations, bss, addr1, addr1BytesWithHeader);
		}
		for (Manipulator<Transaction> man : txMans) {
			testManipulator(man, "warmup", warmupIterations, bss, tx1, tx1BytesWithHeader);
		}
		for (Manipulator<Block> man : blockMans) {
			testManipulator(man, "warmup", warmupIterations, bss, b1, b1BytesWithHeader);
		}

		System.out.println("******************************");
		System.out.println("***      TEST PHASE        ***");
		System.out.println("******************************");
		for (Manipulator<AddressMessage> man : addrMans) {
			testManipulator(man, "main test", iterations, bss, addr1, addr1BytesWithHeader);
		}
		for (Manipulator<Transaction> man : txMans) {
			testManipulator(man, "main test", iterations, bss, tx1, tx1BytesWithHeader);
		}
		for (Manipulator<Block> man : blockMans) {
			testManipulator(man, "main test", iterations, bss, b1, b1BytesWithHeader);
		}
	}

	private void resetBlockStore() {
		blockStore = new MemoryBlockStore(unitTestParams);
	}

	public void setUp() throws Exception {
		testNetChain = new BlockChain(testNet, new Wallet(testNet), new MemoryBlockStore(testNet));
		unitTestParams = NetworkParameters.unitTests();
		wallet = new Wallet(unitTestParams);
		wallet.addKey(new ECKey());

		resetBlockStore();
		chain = new BlockChain(unitTestParams, wallet, blockStore);

		coinbaseTo = wallet.keychain.get(0).toAddress(unitTestParams);

		tx1 = createFakeTx(unitTestParams, Utils.toNanoCoins(2, 0), wallet.keychain.get(0).toAddress(unitTestParams));

		// add a second input so can test granularity of byte cache.
		Transaction prevTx = new Transaction(unitTestParams);
		TransactionOutput prevOut = new TransactionOutput(unitTestParams, prevTx, Utils.toNanoCoins(1, 0),
				wallet.keychain.get(0).toAddress(unitTestParams));
		prevTx.addOutput(prevOut);
		// Connect it.
		tx1.addInput(prevOut);

		Transaction tx2 = createFakeTx(unitTestParams, Utils.toNanoCoins(1, 0), new ECKey().toAddress(unitTestParams));

		b1 = createFakeBlock(unitTestParams, blockStore, tx1, tx2).block;

		BitcoinSerializer bs = new BitcoinSerializer(unitTestParams, true, null);

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		addr1 = (AddressMessage) bs.deserialize(new ByteArrayInputStream(addrMessage));
		bs.serialize(addr1, bos);
		addr1BytesWithHeader = bos.toByteArray();

		bos.reset();
		bs.serialize(tx1, bos);
		tx1BytesWithHeader = bos.toByteArray();
		tx1Bytes = tx1.bitcoinSerialize();

		bos.reset();
		bs.serialize(tx2, bos);
		tx2BytesWithHeader = bos.toByteArray();
		tx2Bytes = tx2.bitcoinSerialize();

		bos.reset();
		bs.serialize(b1, bos);
		b1BytesWithHeader = bos.toByteArray();
		b1Bytes = b1.bitcoinSerialize();

		bss = new ArrayList();
		bss.add(new SerializerEntry(bs, "Standard (Non-lazy, No cached)"));
		singleBs = new ArrayList(bss);
		// add 2 because when profiling the first seems to take a lot longer
		// than usual.
		// bss.add(new SerializerEntry(bs, "Standard (Non-lazy, No cached)"));

		bss.add(new SerializerEntry(new BitcoinSerializer(unitTestParams, true, true, true, null), "Lazy, Cached"));
		bss.add(new SerializerEntry(new BitcoinSerializer(unitTestParams, true, true, false, null), "Lazy, No cache"));
		bss.add(new SerializerEntry(new BitcoinSerializer(unitTestParams, true, true, true, null), "Non-Lazy, Cached"));
		buildManipulators();
	}

	private void buildManipulators() {
		
		Manipulator reverseBytes = new Manipulator<AddressMessage>() {

			byte[] bytes = new byte[32];
			
			@Override
			public void manipulate(BitcoinSerializer bs, AddressMessage message) throws Exception {
				Utils.reverseBytes(bytes);
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
			}

			@Override
			public String getDescription() {
				return "Reverse 32 bytes";
			}

		};
		genericMans.add(reverseBytes);
		
		Manipulator doubleDigest32Bytes = new Manipulator<AddressMessage>() {

			byte[] bytes = new byte[32];
			
			@Override
			public void manipulate(BitcoinSerializer bs, AddressMessage message) throws Exception {
				Utils.doubleDigest(bytes);
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
			}

			@Override
			public String getDescription() {
				return "Double Digest 32 bytes";
			}

		};
		genericMans.add(doubleDigest32Bytes);
		
		Manipulator doubleDigestBytes = new Manipulator<AddressMessage>() {

			int len = -1;
			
			@Override
			public void manipulate(BitcoinSerializer bs, AddressMessage message) throws Exception {
				
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
				if (len == -1)
					len = bytes.length;
				Utils.doubleDigest(bytes);
			}

			@Override
			public String getDescription() {
				return "Double Digest " + len + " bytes";
				
			}
		};
		genericMans.add(doubleDigestBytes);

		Manipulator seralizeAddr = new Manipulator<AddressMessage>() {

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			@Override
			public void manipulate(BitcoinSerializer bs, AddressMessage message) throws Exception {
				bos.reset();
				bs.serialize(message, bos);
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
			}

			@Override
			public String getDescription() {
				return "Serialize Address";
			}

		};
		addrMans.add(seralizeAddr);

		Manipulator deseralizeAddr = new Manipulator<AddressMessage>() {

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			@Override
			public void manipulate(BitcoinSerializer bs, AddressMessage message) throws Exception {
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
				AddressMessage addr = (AddressMessage) bs.deserialize(new ByteArrayInputStream(bytes));
			}

			@Override
			public String getDescription() {
				return "Deserialize Address";
			}

		};
		addrMans.add(deseralizeAddr);

		Manipulator seralizeAddr_1 = new Manipulator<AddressMessage>() {

			AddressMessage addr;
			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			@Override
			public void manipulate(BitcoinSerializer bs, AddressMessage message) throws Exception {
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
				if (addr == null) {
					addr = (AddressMessage) bs.deserialize(new ByteArrayInputStream(bytes));
				}
				bos.reset();
				bs.serialize(addr, bos);
			}
			
			public void beforeTest() {
				addr = null;
			}

			@Override
			public String getDescription() {
				return "Serialize cached Address";
			}

		};
		addrMans.add(seralizeAddr_1);

		Manipulator deserSerAddr1 = new Manipulator<AddressMessage>() {

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			@Override
			public void manipulate(BitcoinSerializer bs, AddressMessage message) throws Exception {
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
				AddressMessage addr = (AddressMessage) bs.deserialize(new ByteArrayInputStream(bytes));
				addr.getAddresses().get(0).getAddr();
			}

			@Override
			public String getDescription() {
				return "Deserialize Address, read field";
			}

		};
		addrMans.add(deserSerAddr1);

		Manipulator deserSerAddr2 = new Manipulator<AddressMessage>() {

			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			PeerAddress peer;

			@Override
			public void manipulate(BitcoinSerializer bs, AddressMessage message) throws Exception {
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
				if (peer == null) {
					peer = new PeerAddress(InetAddress.getLocalHost(), 8332);
				}
				AddressMessage addr = (AddressMessage) bs.deserialize(new ByteArrayInputStream(bytes));
				addr.addAddress(peer);
				bos.reset();
				bs.serialize(addr, bos);
			}

			@Override
			public String getDescription() {
				return "Deserialize Address, Add Address, Serialize";
			}

		};
		addrMans.add(deserSerAddr2);

		Manipulator seralizeTx = new Manipulator<Transaction>() {

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			@Override
			public void manipulate(BitcoinSerializer bs, Transaction message) throws Exception {
				bos.reset();
				bs.serialize(message, bos);
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
			}

			@Override
			public String getDescription() {
				return "Serialize Transaction";
			}

		};
		txMans.add(seralizeTx);

		Manipulator deSeralizeTx = new Manipulator<Transaction>() {

			@Override
			public void manipulate(BitcoinSerializer bs, Transaction message) throws Exception {
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
				ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
				Transaction tx = (Transaction) bs.deserialize(bis);
			}

			@Override
			public String getDescription() {
				return "Deserialize Transaction";
			}

		};
		txMans.add(deSeralizeTx);
		
		Manipulator serDeeralizeTx_1 = new Manipulator<Transaction>() {

			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			
			@Override
			public void manipulate(BitcoinSerializer bs, Transaction message) throws Exception {
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
				ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
				Transaction tx = (Transaction) bs.deserialize(bis);
				bos.reset();
				bs.serialize(tx, bos);
			}

			@Override
			public String getDescription() {
				return "Deserialize Transaction, Serialize";
			}

		};
		txMans.add(serDeeralizeTx_1);
		
		Manipulator serDeeralizeTx = new Manipulator<Transaction>() {

			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			
			@Override
			public void manipulate(BitcoinSerializer bs, Transaction message) throws Exception {
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
				ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
				Transaction tx = (Transaction) bs.deserialize(bis);
				tx.addInput(tx.getInputs().get(0));
				bos.reset();
				bs.serialize(tx, bos);
			}

			@Override
			public String getDescription() {
				return "Deserialize Transaction, modify, Serialize";
			}

		};
		txMans.add(serDeeralizeTx);

		Manipulator deSeralizeTx_1 = new Manipulator<Transaction>() {

			Transaction tx;
			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			@Override
			public void manipulate(BitcoinSerializer bs, Transaction message) throws Exception {
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
				if (tx == null) {
					ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
					tx = (Transaction) bs.deserialize(bis);
				}
				bos.reset();
				bs.serialize(tx, bos);
			}
			
			public void beforeTest() {
				tx = null;
			}

			@Override
			public String getDescription() {
				return "Serialize cached Transaction";
			}

		};
		txMans.add(deSeralizeTx_1);

		Manipulator seralizeBlock = new Manipulator<Block>() {

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			@Override
			public void manipulate(BitcoinSerializer bs, Block message) throws Exception {
				bos.reset();
				bs.serialize(message, bos);
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
			}

			@Override
			public String getDescription() {
				return "Serialize Block";
			}

		};
		blockMans.add(seralizeBlock);

		Manipulator deSeralizeBlock = new Manipulator<Block>() {

			@Override
			public void manipulate(BitcoinSerializer bs, Block message) throws Exception {
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
				ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
				Block block = (Block) bs.deserialize(bis);
			}

			@Override
			public String getDescription() {
				return "Deserialize Block";
			}

		};
		blockMans.add(deSeralizeBlock);

		Manipulator deSeralizeBlock_1 = new Manipulator<Block>() {

			Block block;
			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			@Override
			public void manipulate(BitcoinSerializer bs, Block message) throws Exception {
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
				if (block == null) {
					ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
					block = (Block) bs.deserialize(bis);
				}
				bos.reset();
				bs.serialize(block, bos);
			}
			
			public void beforeTest() {
				block = null;
			}

			@Override
			public String getDescription() {
				return "Serialize cached Block";
			}

		};
		blockMans.add(deSeralizeBlock_1);

		Manipulator deSerReadReser1 = new Manipulator<Block>() {

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			@Override
			public void manipulate(BitcoinSerializer bs, Block message) throws Exception {
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
				ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
				Block block = (Block) bs.deserialize(bis);
				block.getNonce();
				bos.reset();
				bs.serialize(block, bos);
			}

			@Override
			public String getDescription() {
				return "Deserialize Block, Read nonce header, Serialize";
			}

		};
		blockMans.add(deSerReadReser1);

		Manipulator deSerReadReser1_1 = new Manipulator<Block>() {

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			@Override
			public void manipulate(BitcoinSerializer bs, Block message) throws Exception {
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
				ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
				Block block = (Block) bs.deserialize(bis);
				block.getHash();
			}

			@Override
			public String getDescription() {
				return "Deserialize Block, Calculate hash";
			}

		};
		blockMans.add(deSerReadReser1_1);

		Manipulator deSerReadReser1_2 = new Manipulator<Block>() {

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			@Override
			public void manipulate(BitcoinSerializer bs, Block message) throws Exception {
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
				ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
				Block block = (Block) bs.deserialize(bis);
				block.getHash();
				bos.reset();
				bs.serialize(block, bos);
			}

			@Override
			public String getDescription() {
				return "Deserialize Block, Calculate hash, Serialize";
			}

		};
		blockMans.add(deSerReadReser1_2);

		Manipulator deSerReadReser2 = new Manipulator<Block>() {

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			@Override
			public void manipulate(BitcoinSerializer bs, Block message) throws Exception {
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
				ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
				Block block = (Block) bs.deserialize(bis);
				block.getTransactions().get(0).getInputs().get(0).getFromAddress();
				bos.reset();
				bs.serialize(block, bos);
			}

			@Override
			public String getDescription() {
				return "Deserialize Block, Read tx input address, Serialize";
			}

		};
		blockMans.add(deSerReadReser2);

		Manipulator deSerReadReser2_1 = new Manipulator<Block>() {

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			@Override
			public void manipulate(BitcoinSerializer bs, Block message) throws Exception {
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
				ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
				Block block = (Block) bs.deserialize(bis);
				for (Transaction tx : block.getTransactions()) {
					tx.getLockTime();
					tx.getVersion();
					for (TransactionInput in : tx.getInputs()) {
						in.getScriptBytes();
						in.getOutpoint().getIndex();
					}
					for (TransactionOutput out : tx.getOutputs()) {
						out.getScriptBytes();
						out.getValue();
					}
				}

				bos.reset();
				bs.serialize(block, bos);
			}

			@Override
			public String getDescription() {
				return "Deserialize Block, read all tx fields, Serialize";
			}

		};
		blockMans.add(deSerReadReser2_1);

		Manipulator deSerReadReser3 = new Manipulator<Block>() {

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			@Override
			public void manipulate(BitcoinSerializer bs, Block message) throws Exception {
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
				ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
				Block block = (Block) bs.deserialize(bis);
				block.setNonce(55);
				bos.reset();
				bs.serialize(block, bos);
			}

			@Override
			public String getDescription() {
				return "Deserialize Block, Write nonce, Serialize";
			}

		};
		blockMans.add(deSerReadReser3);

		Manipulator deSerReadReser4 = new Manipulator<Block>() {

			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			Transaction tx;

			@Override
			public void manipulate(BitcoinSerializer bs, Block message) throws Exception {
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
				if (tx == null) {
					tx = (Transaction) bs.deserialize(new ByteArrayInputStream(tx1BytesWithHeader));
					tx.ensureParsed();
					for (TransactionInput input : tx.getInputs()) {
						input.ensureParsed();
					}
					for (TransactionOutput output : tx.getOutputs()) {
						output.ensureParsed();
					}
				}
				ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
				Block block = (Block) bs.deserialize(bis);
				block.addTransaction(tx);
				bos.reset();
				bs.serialize(block, bos);
			}

			@Override
			public String getDescription() {
				return "Deserialize Block, add tx, Serialize";
			}

		};
		blockMans.add(deSerReadReser4);

		Manipulator deSerReadReser5 = new Manipulator<Block>() {

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			@Override
			public void manipulate(BitcoinSerializer bs, Block message) throws Exception {
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
				ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
				Block block = (Block) bs.deserialize(bis);
				for (Transaction tx : block.getTransactions()) {
					tx.getHash();
				}
			}

			@Override
			public String getDescription() {
				return "Deserialize Block, scan tx hashes";
			}

		};
		blockMans.add(deSerReadReser5);

		Manipulator deSerReadReser6 = new Manipulator<Block>() {

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			@Override
			public void manipulate(BitcoinSerializer bs, Block message) throws Exception {
			}

			@Override
			public void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception {
				ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
				Block block = (Block) bs.deserialize(bis);
				for (Transaction tx : block.getTransactions()) {
					tx.getHash();
				}
				bos.reset();
				bs.serialize(block, bos);
			}

			@Override
			public String getDescription() {
				return "Deserialize Block, scan tx hashes, Serialize";
			}

		};
		blockMans.add(deSerReadReser6);

	}

	public <M extends Message> void testManipulator(Manipulator<M> man, String phaseName, int iterations, List<SerializerEntry> bss,
			M message, byte[] bytes) {
		long allStart = System.currentTimeMillis();
		System.out.println("Beginning " + phaseName + " run for manipulator: [" + man.getDescription() + "]");
		int pause = iterations / 100;
		pause = pause < 200 ? 200 : pause;
		pause = pause > 1000 ? 1000 : pause;
		long bestTime = Long.MAX_VALUE;
		long worstTime = 0;
		for (SerializerEntry entry : bss) {
			System.gc();
			pause(pause);
			long start = System.currentTimeMillis();
			long memStart = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
			boolean fail = false;
			int completed = 0;
			man.beforeTest();
			for (int i = 0; i < iterations; i++) {
				try {
					man.manipulate(entry.bs, bytes);
					man.manipulate(entry.bs, message);
				} catch (Exception e) {
					completed = i;
					e.printStackTrace();
					break;
				}
			}
			man.afterTest();
			if (fail) {
				System.out.println("Test failed after " + completed + " iterations");
			} else {
				long time = System.currentTimeMillis() - start;
				if (time < bestTime)
					bestTime = time;
				if (time > worstTime)
					worstTime = time;
				long mem = (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory() - memStart) / (1024);
				System.out.println("Completed " + iterations + " iterations in " + time + "ms.  Consumed memory: "
						+ mem + "kb. Using Serializer: [" + entry.name + "]");
			}
		}
		long time = System.currentTimeMillis() - allStart;
		System.out.println("Finished test run for manipulator: " + man.getDescription() + " in " + time + "ms");
		NumberFormat nf = NumberFormat.getInstance();
		nf.setMaximumFractionDigits(2);
		long diff = worstTime - bestTime;
		float perc = ((float) worstTime / bestTime - 1) * 100;
		float perc2 = (1 - (float) bestTime / worstTime) * 100;
		System.out.println("Best/Worst time diff: " + diff + "ms. (" + nf.format(perc2) + "% gain)\n");
	}

	public static void pause(int millis) {
		try {
			Thread.sleep(millis);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public class SerializerEntry {
		public BitcoinSerializer bs;
		public String name;

		public SerializerEntry(BitcoinSerializer bs, String name) {
			super();
			this.bs = bs;
			this.name = name;
		}

	}

}
