package org.bitcoinj.core;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertEquals;

import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

import org.bitcoinj.core.TransactionConfidence.ConfidenceType;
import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.testing.FakeTxBuilder;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

/**
 * Just check the Transaction.verify() method. Most methods that have complicated logic in Transaction are tested
 * elsewhere, e.g. signing and hashing are well exercised by the wallet tests, the full block chain tests and so on.
 * The verify method is also exercised by the full block chain tests, but it can also be used by API users alone,
 * so we make sure to cover it here as well.
 */
public class TransactionTest {
    private static final NetworkParameters PARAMS = UnitTestParams.get();
    private Transaction tx;
    private Transaction dummy;

    public static final Address ADDRESS = new ECKey().toAddress(PARAMS);

    @Before
    public void setUp() throws Exception {
        dummy = FakeTxBuilder.createFakeTx(PARAMS, Coin.COIN, ADDRESS);
        tx = newTransaction();
    }

    private Transaction newTransaction(boolean newToAddress) {
    	Address addr = ADDRESS;
    	
    	if (newToAddress) {
			addr = new ECKey().toAddress(PARAMS);
		}
    	
    	return newTransaction(new TransactionOutput(PARAMS, null, Coin.COIN, addr));
    }
    
    private Transaction newTransaction() {
        return newTransaction(new TransactionOutput(PARAMS, null, Coin.COIN, ADDRESS));
	}
	
	private Transaction newTransaction(TransactionOutput to) {
		Transaction rtn = new Transaction(PARAMS);
        rtn.addOutput(to);
        rtn.addInput(dummy.getOutput(0));
        
        return rtn;
	}

    @Test(expected = VerificationException.EmptyInputsOrOutputs.class)
    public void emptyOutputs() throws Exception {
        tx.clearOutputs();
        tx.verify();
    }

    @Test(expected = VerificationException.EmptyInputsOrOutputs.class)
    public void emptyInputs() throws Exception {
        tx.clearInputs();
        tx.verify();
    }

    @Test(expected = VerificationException.LargerThanMaxBlockSize.class)
    public void tooHuge() throws Exception {
        tx.addInput(dummy.getOutput(0)).setScriptBytes(new byte[Block.MAX_BLOCK_SIZE]);
        tx.verify();
    }

    @Test(expected = VerificationException.DuplicatedOutPoint.class)
    public void duplicateOutPoint() throws Exception {
        TransactionInput input = tx.getInput(0);
        input.setScriptBytes(new byte[1]);
        tx.addInput(input.duplicateDetached());
        tx.verify();
    }
    
    @Test(expected = VerificationException.NegativeValueOutput.class)
    public void negativeOutput() throws Exception {
        tx.getOutput(0).setValue(Coin.NEGATIVE_SATOSHI);
        tx.verify();
    }

    @Test(expected = VerificationException.ExcessiveValue.class)
    public void exceedsMaxMoney2() throws Exception {
        Coin half = NetworkParameters.MAX_MONEY.divide(2).add(Coin.SATOSHI);
        tx.getOutput(0).setValue(half);
        tx.addOutput(half, ADDRESS);
        tx.verify();
    }

    @Test(expected = VerificationException.UnexpectedCoinbaseInput.class)
    public void coinbaseInputInNonCoinbaseTX() throws Exception {
        tx.addInput(Sha256Hash.ZERO_HASH, 0xFFFFFFFFL, new ScriptBuilder().data(new byte[10]).build());
        tx.verify();
    }

    @Test(expected = VerificationException.CoinbaseScriptSizeOutOfRange.class)
    public void coinbaseScriptSigTooSmall() throws Exception {
        tx.clearInputs();
        tx.addInput(Sha256Hash.ZERO_HASH, 0xFFFFFFFFL, new ScriptBuilder().build());
        tx.verify();
    }

    @Test(expected = VerificationException.CoinbaseScriptSizeOutOfRange.class)
    public void coinbaseScriptSigTooLarge() throws Exception {
        tx.clearInputs();
        TransactionInput input = tx.addInput(Sha256Hash.ZERO_HASH, 0xFFFFFFFFL, new ScriptBuilder().data(new byte[99]).build());
        assertEquals(101, input.getScriptBytes().length);
        tx.verify();
    }
    
    @Test
    public void isConsistentReturnsFalseAsExpected() {
    	TransactionBag mockTB = createMock(TransactionBag.class);
    	
    	TransactionOutput to = createMock(TransactionOutput.class);
    	EasyMock.expect(to.isAvailableForSpending()).andReturn(true);
    	EasyMock.expect(to.isMineOrWatched(mockTB)).andReturn(true);
    	EasyMock.expect(to.getSpentBy()).andReturn(new TransactionInput(PARAMS, null, new byte[0]));
    	
    	Transaction sut = newTransaction(to);
    	
    	replay(to);
    	
		boolean rtn = sut.isConsistent(mockTB, false);
    	
    	assertEquals(rtn, false);
    }

    @Test
    public void isConsistentReturnsFalseAsExpected_WhenAvailableForSpendingEqualsFalse() {
    	TransactionOutput to = createMock(TransactionOutput.class);
    	EasyMock.expect(to.isAvailableForSpending()).andReturn(false);
    	EasyMock.expect(to.getSpentBy()).andReturn(null);
    	
    	Transaction sut = newTransaction(to);
    	
    	replay(to);
    	
    	boolean rtn = sut.isConsistent(createMock(TransactionBag.class), false);
    	
    	assertEquals(rtn, false);
    }
    
    @Test
    public void testIsEveryOutputSpent_withZeroOutputsAvailableForSpending() {
    	TransactionOutput to = createMock(TransactionOutput.class);
    	EasyMock.expect(to.isAvailableForSpending()).andReturn(false);
    	
    	Transaction sut = newTransaction(to);
    	
    	replay(to);
    	
    	boolean rtn = sut.isEveryOutputSpent();
    	
    	assertEquals(rtn, true);
    }

    @Test
    public void testIsEveryOutputSpent_withOutputsAvailableForSpending() {
    	TransactionOutput to = createMock(TransactionOutput.class);
    	EasyMock.expect(to.isAvailableForSpending()).andReturn(true);
    	
    	Transaction sut = newTransaction(to);
    	
    	replay(to);
    	
    	boolean rtn = sut.isEveryOutputSpent();
    	
    	assertEquals(rtn, false);
    }
    
    @Test
    public void testEstimatedLockTime_WhenParameterSignifiesBlockHeight() {
    	int TEST_LOCK_TIME = 20;
    	Date now = Calendar.getInstance().getTime();
    	
    	BlockChain mockBlockChain = createMock(BlockChain.class);
    	
		EasyMock.expect(mockBlockChain.estimateBlockTime(TEST_LOCK_TIME)).andReturn(now);
		
    	Transaction sut = newTransaction();

    	sut.setLockTime(TEST_LOCK_TIME); // less than five hundred million 
    	
    	replay(mockBlockChain);
    	
    	Date estimateLockTime = sut.estimateLockTime(mockBlockChain);
    	
    	assertEquals(estimateLockTime, now);
    }
    
    @Test
    public void testEstimatedLockTime_WhenParameterSignifiesSeconds() {
    	int TEST_LOCK_TIME = Transaction.LOCKTIME_THRESHOLD + 1;
    	
    	BlockChain mockBlockChain = createMock(BlockChain.class);
    	
    	Transaction sut = newTransaction();

    	sut.setLockTime(TEST_LOCK_TIME); // more than five hundred million 
    	
    	replay(mockBlockChain);
    	
    	Date estimateLockTime = sut.estimateLockTime(mockBlockChain);
    	
    	Calendar cal = Calendar.getInstance();
    	cal.set(1985, 10, 4, 17, 53, 21);
    	cal.set(Calendar.MILLISECOND, 0);
    	
    	assertEquals(cal.getTime().equals(estimateLockTime), true);
    }
    
    @Test
    public void testOptimalEncodingMessageSize() {
		Transaction sut = new Transaction(PARAMS);
		
		int length = sut.length;
		
		// add basic transaction input, check the length
		sut.addOutput(new TransactionOutput(PARAMS, null, Coin.COIN, ADDRESS));
		length += getCombinedLength(sut.getOutputs());
		
		// add basic output, check the length
		sut.addInput(dummy.getOutput(0));
		length += getCombinedLength(sut.getInputs());
		
		// optimal encoding size should equal the length we just calculated
		assertEquals(sut.getOptimalEncodingMessageSize(), length);
    }
    
    private int getCombinedLength(List<? extends Message> list) {
    	int rtn = 0;
    	
    	for (Message m: list) {
    		rtn += m.getMessageSize() + 1;
    	}

    	return rtn;
    }
    
    @Test
    public void testIsMatureReturnsFalseIfTransactionIsCoinbaseAndConfidenceTypeIsNotEqualToBuilding() {
    	Transaction sut = new Transaction(PARAMS);
    	sut.addInput(dummy.getOutput(0));
    	
    	// make this into a coinbase transaction
    	TransactionInput input = sut.getInput(0);
    	input.getOutpoint().setHash(Sha256Hash.ZERO_HASH);
    	input.getOutpoint().setIndex(-1);

    	sut.getConfidence().setConfidenceType(ConfidenceType.UNKNOWN);
    	assertEquals(sut.isMature(), false);
    	
    	sut.getConfidence().setConfidenceType(ConfidenceType.PENDING);
    	assertEquals(sut.isMature(), false);
    	
    	sut.getConfidence().setConfidenceType(ConfidenceType.DEAD);
    	assertEquals(sut.isMature(), false);
    }
    
    @Test
    public void testToStringWhenLockTimeIsSpecifiedInBlockHeight() {
		Transaction sut = newTransaction();
		
		TransactionInput input = sut.getInput(0);
		input.setSequenceNumber(42);
		
		int TEST_LOCK_TIME = 20;
		sut.setLockTime(TEST_LOCK_TIME);
		
		Calendar cal = Calendar.getInstance();
		cal.set(2085, 10, 4, 17, 53, 21);
		cal.set(Calendar.MILLISECOND, 0);
		
		BlockChain mockBlockChain = createMock(BlockChain.class);
		EasyMock.expect(mockBlockChain.estimateBlockTime(TEST_LOCK_TIME)).andReturn(cal.getTime());
		
		replay(mockBlockChain);
		
		String str = sut.toString(mockBlockChain);
		
		assertEquals(str.contains("block " + TEST_LOCK_TIME), true);
		assertEquals(str.contains("estimated to be reached at"), true);
    }
    
    @Test
    public void testToStringWhenIteratingOverAnInputCatchesAnException() {
    	Transaction sut = newTransaction();
    	TransactionInput ti = new TransactionInput(PARAMS, sut, new byte[0]) { 
    		@Override
    		public Script getScriptSig() throws ScriptException {
    			throw new ScriptException("");
    		}
    	};
    	
    	sut.addInput(ti);
    	
		String str = sut.toString();
		
		assertEquals(str.contains("[exception: "), true);
    }
    
    @Test
    public void testToStringWhenThereAreZeroInputs() {
    	Transaction sut = new Transaction(PARAMS);
		
		String str = sut.toString();
		
		assertEquals(str.contains("No inputs!"), true);
    }
    
    @Test
    public void testTheTXByHeightComparator() {
    	final boolean USE_UNIQUE_ADDRESS = true;
    	Transaction sut1 = newTransaction(USE_UNIQUE_ADDRESS);
    	sut1.getConfidence().setAppearedAtChainHeight(1);
    	
    	Transaction sut2 = newTransaction(USE_UNIQUE_ADDRESS);
    	sut2.getConfidence().setAppearedAtChainHeight(2);
    	
    	Transaction sut3 = newTransaction(USE_UNIQUE_ADDRESS);
    	sut3.getConfidence().setAppearedAtChainHeight(3);
    	
    	SortedSet<Transaction> set = new TreeSet<Transaction>(Transaction.SORT_TX_BY_HEIGHT);
    	set.add(sut2);
    	set.add(sut1);
    	set.add(sut3);
    	
    	Iterator<Transaction> iterator = set.iterator();
    	
    	assertEquals(sut1.equals(sut2), false);
    	assertEquals(sut1.equals(sut3), false);
    	assertEquals(sut1.equals(sut1), true);
    	
    	assertEquals(iterator.next().equals(sut3), true);
    	assertEquals(iterator.next().equals(sut2), true);
    	assertEquals(iterator.next().equals(sut1), true);
    	assertEquals(iterator.hasNext(), false);
    }

    @Test(expected = ScriptException.class)
    public void testAddSignedInputThrowsExceptionWhenScriptIsNotToRawPubKeyAndIsNotToAddress() {
    	ECKey key = new ECKey();
    	Address addr = key.toAddress(PARAMS);
    	Transaction fakeTx = FakeTxBuilder.createFakeTx(PARAMS, Coin.COIN, addr);
    	
    	Transaction sut = new Transaction(PARAMS);
    	sut.addOutput(fakeTx.getOutput(0));
    	
    	Script mockScript = new Script(new byte[0]) {
    		public boolean isSentToRawPubKey() {
    			return false;
    		}
    		
    		public boolean isSentToAddress() {
    			return false;
    		}
    	};
    	
    	sut.addSignedInput(fakeTx.getOutput(0).getOutPointFor(), mockScript, key);
    }
}
