package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Arrays;

/**
 * implementation of SHA-3 based on following KeccakNISTInterface.c from http://keccak.noekeon.org/
 * <p>
 * Following the naming conventions used in the C source code to enable easy review of the implementation.
 */
public class SHA3Digest
    implements ExtendedDigest
{
    private static long[] KeccakRoundConstants = keccakInitializeRoundConstants();

    private static int[] KeccakRhoOffsets = keccakInitializeRhoOffsets();

    private static long[] keccakInitializeRoundConstants()
    {
        long[] keccakRoundConstants = new long[24];
        byte[] LFSRstate = new byte[1];

        LFSRstate[0] = 0x01;
        int i, j, bitPosition;

        for (i = 0; i < 24; i++)
        {
            keccakRoundConstants[i] = 0;
            for (j = 0; j < 7; j++)
            {
                bitPosition = (1 << j) - 1;
                if (LFSR86540(LFSRstate))
                {
                    keccakRoundConstants[i] ^= 1L << bitPosition;
                }
            }
        }

        return keccakRoundConstants;
    }

    private static boolean LFSR86540(byte[] LFSR)
    {
        boolean result = (((LFSR[0]) & 0x01) != 0);
        if (((LFSR[0]) & 0x80) != 0)
        {
            LFSR[0] = (byte)(((LFSR[0]) << 1) ^ 0x71);
        }
        else
        {
            LFSR[0] <<= 1;
        }

        return result;
    }

    private static int[] keccakInitializeRhoOffsets()
    {
        int[] keccakRhoOffsets = new int[25];
        int x, y, t, newX, newY;

        keccakRhoOffsets[(((0) % 5) + 5 * ((0) % 5))] = 0;
        x = 1;
        y = 0;
        for (t = 0; t < 24; t++)
        {
            keccakRhoOffsets[(((x) % 5) + 5 * ((y) % 5))] = ((t + 1) * (t + 2) / 2) % 64;
            newX = (0 * x + 1 * y) % 5;
            newY = (2 * x + 3 * y) % 5;
            x = newX;
            y = newY;
        }

        return keccakRhoOffsets;
    }

    private byte[] state = new byte[(1600 / 8)];
    private byte[] dataQueue = new byte[(1536 / 8)];
    private int rate;
    private int bitsInQueue;
    private int fixedOutputLength;
    private boolean squeezing;
    private int bitsAvailableForSqueezing;
    private byte[] chunk;
    private byte[] oneByte;

    private void clearDataQueueSection(int off, int len)
    {
        for (int i = off; i != off + len; i++)
        {
            dataQueue[i] = 0;
        }
    }

    public SHA3Digest()
    {
        init(0);
    }

    public SHA3Digest(int bitLength)
    {
        init(bitLength);
    }

    public SHA3Digest(SHA3Digest source) {
        System.arraycopy(source.state, 0, this.state, 0, source.state.length);
        System.arraycopy(source.dataQueue, 0, this.dataQueue, 0, source.dataQueue.length);
        this.rate = source.rate;
        this.bitsInQueue = source.bitsInQueue;
        this.fixedOutputLength = source.fixedOutputLength;
        this.squeezing = source.squeezing;
        this.bitsAvailableForSqueezing = source.bitsAvailableForSqueezing;
        this.chunk = Arrays.clone(source.chunk);
        this.oneByte = Arrays.clone(source.oneByte);
    }

    public String getAlgorithmName()
    {
        return "SHA3-" + fixedOutputLength;
    }

    public int getDigestSize()
    {
        return fixedOutputLength / 8;
    }

    public void update(byte in)
    {
        oneByte[0] = in;

        doUpdate(oneByte, 0, 8L);
    }

    public void update(byte[] in, int inOff, int len)
    {
        doUpdate(in, inOff, len * 8L);
    }

    public int doFinal(byte[] out, int outOff)
    {
        squeeze(out, outOff, fixedOutputLength);

        reset();

        return getDigestSize();
    }

    public void reset()
    {
        init(fixedOutputLength);
    }

    /**
     * Return the size of block that the compression function is applied to in bytes.
     *
     * @return internal byte length of a block.
     */
    public int getByteLength()
    {
        return rate / 8;
    }

    private void init(int bitLength)
    {
        switch (bitLength)
        {
        case 0:
        case 288:
            initSponge(1024, 576);
            break;
        case 224:
            initSponge(1152, 448);
            break;
        case 256:
            initSponge(1088, 512);
            break;
        case 384:
            initSponge(832, 768);
            break;
        case 512:
            initSponge(576, 1024);
            break;
        default:
            throw new IllegalArgumentException("bitLength must be one of 224, 256, 384, or 512.");
        }
    }

    private void doUpdate(byte[] data, int off, long databitlen)
    {
        if ((databitlen % 8) == 0)
        {
            absorb(data, off, databitlen);
        }
        else
        {
            absorb(data, off, databitlen - (databitlen % 8));

            byte[] lastByte = new byte[1];

            lastByte[0] = (byte)(data[off + (int)(databitlen / 8)] >> (8 - (databitlen % 8)));
            absorb(lastByte, off, databitlen % 8);
        }
    }

    private void initSponge(int rate, int capacity)
    {
        if (rate + capacity != 1600)
        {
            throw new IllegalStateException("rate + capacity != 1600");
        }
        if ((rate <= 0) || (rate >= 1600) || ((rate % 64) != 0))
        {
            throw new IllegalStateException("invalid rate value");
        }

        this.rate = rate;
        // this is never read, need to check to see why we want to save it
        //  this.capacity = capacity;
        this.fixedOutputLength = 0;
        Arrays.fill(this.state, (byte)0);
        Arrays.fill(this.dataQueue, (byte)0);
        this.bitsInQueue = 0;
        this.squeezing = false;
        this.bitsAvailableForSqueezing = 0;
        this.fixedOutputLength = capacity / 2;
        this.chunk = new byte[rate / 8];
        this.oneByte = new byte[1];
    }

    private void absorbQueue()
    {
        KeccakAbsorb(state, dataQueue, rate / 8);

        bitsInQueue = 0;
    }

    private void absorb(byte[] data, int off, long databitlen)
    {
        long i, j, wholeBlocks;

        if ((bitsInQueue % 8) != 0)
        {
            throw new IllegalStateException("attempt to absorb with odd length queue.");
        }
        if (squeezing)
        {
            throw new IllegalStateException("attempt to absorb while squeezing.");
        }

        i = 0;
        while (i < databitlen)
        {
            if ((bitsInQueue == 0) && (databitlen >= rate) && (i <= (databitlen - rate)))
            {
                wholeBlocks = (databitlen - i) / rate;

                for (j = 0; j < wholeBlocks; j++)
                {
                    System.arraycopy(data, (int)(off + (i / 8) + (j * chunk.length)), chunk, 0, chunk.length);

//                            displayIntermediateValues.displayBytes(1, "Block to be absorbed", curData, rate / 8);

                    KeccakAbsorb(state, chunk, chunk.length);
                }

                i += wholeBlocks * rate;
            }
            else
            {
                int partialBlock = (int)(databitlen - i);
                if (partialBlock + bitsInQueue > rate)
                {
                    partialBlock = rate - bitsInQueue;
                }
                int partialByte = partialBlock % 8;
                partialBlock -= partialByte;
                System.arraycopy(data, off + (int)(i / 8), dataQueue, bitsInQueue / 8, partialBlock / 8);

                bitsInQueue += partialBlock;
                i += partialBlock;
                if (bitsInQueue == rate)
                {
                    absorbQueue();
                }
                if (partialByte > 0)
                {
                    int mask = (1 << partialByte) - 1;
                    dataQueue[bitsInQueue / 8] = (byte)(data[off + ((int)(i / 8))] & mask);
                    bitsInQueue += partialByte;
                    i += partialByte;
                }
            }
        }
    }

    private void padAndSwitchToSqueezingPhase()
    {
        if (bitsInQueue + 1 == rate)
        {
            dataQueue[bitsInQueue / 8] |= 1 << (bitsInQueue % 8);
            absorbQueue();
            clearDataQueueSection(0, rate / 8);
        }
        else
        {
            clearDataQueueSection((bitsInQueue + 7) / 8, rate / 8 - (bitsInQueue + 7) / 8);
            dataQueue[bitsInQueue / 8] |= 1 << (bitsInQueue % 8);
        }
        dataQueue[(rate - 1) / 8] |= 1 << ((rate - 1) % 8);
        absorbQueue();


//            displayIntermediateValues.displayText(1, "--- Switching to squeezing phase ---");


        if (rate == 1024)
        {
            KeccakExtract1024bits(state, dataQueue);
            bitsAvailableForSqueezing = 1024;
        }
        else

        {
            KeccakExtract(state, dataQueue, rate / 64);
            bitsAvailableForSqueezing = rate;
        }

//            displayIntermediateValues.displayBytes(1, "Block available for squeezing", dataQueue, bitsAvailableForSqueezing / 8);

        squeezing = true;
    }

    private void squeeze(byte[] output, int offset, long outputLength)
    {
        long i;
        int partialBlock;

        if (!squeezing)
        {
            padAndSwitchToSqueezingPhase();
        }
        if ((outputLength % 8) != 0)
        {
            throw new IllegalStateException("outputLength not a multiple of 8");
        }

        i = 0;
        while (i < outputLength)
        {
            if (bitsAvailableForSqueezing == 0)
            {
                keccakPermutation(state);

                if (rate == 1024)
                {
                    KeccakExtract1024bits(state, dataQueue);
                    bitsAvailableForSqueezing = 1024;
                }
                else

                {
                    KeccakExtract(state, dataQueue, rate / 64);
                    bitsAvailableForSqueezing = rate;
                }

//                    displayIntermediateValues.displayBytes(1, "Block available for squeezing", dataQueue, bitsAvailableForSqueezing / 8);

            }
            partialBlock = bitsAvailableForSqueezing;
            if ((long)partialBlock > outputLength - i)
            {
                partialBlock = (int)(outputLength - i);
            }

            System.arraycopy(dataQueue, (rate - bitsAvailableForSqueezing) / 8, output, offset + (int)(i / 8), partialBlock / 8);
            bitsAvailableForSqueezing -= partialBlock;
            i += partialBlock;
        }
    }

    private void fromBytesToWords(long[] stateAsWords, byte[] state)
    {
        for (int i = 0; i < (1600 / 64); i++)
        {
            stateAsWords[i] = 0;
            int index = i * (64 / 8);
            for (int j = 0; j < (64 / 8); j++)
            {
                stateAsWords[i] |= ((long)state[index + j] & 0xff) << ((8 * j));
            }
        }
    }

    private void fromWordsToBytes(byte[] state, long[] stateAsWords)
    {
        for (int i = 0; i < (1600 / 64); i++)
        {
            int index = i * (64 / 8);
            for (int j = 0; j < (64 / 8); j++)
            {
                state[index + j] = (byte)((stateAsWords[i] >>> ((8 * j))) & 0xFF);
            }
        }
    }

    private void keccakPermutation(byte[] state)
    {
        long[] longState = new long[state.length / 8];

        fromBytesToWords(longState, state);

//        displayIntermediateValues.displayStateAsBytes(1, "Input of permutation", longState);

        keccakPermutationOnWords(longState);

//        displayIntermediateValues.displayStateAsBytes(1, "State after permutation", longState);

        fromWordsToBytes(state, longState);
    }

    private void keccakPermutationAfterXor(byte[] state, byte[] data, int dataLengthInBytes)
    {
        int i;

        for (i = 0; i < dataLengthInBytes; i++)
        {
            state[i] ^= data[i];
        }

        keccakPermutation(state);
    }

    private void keccakPermutationOnWords(long[] state)
    {
        int i;

//        displayIntermediateValues.displayStateAs64bitWords(3, "Same, with lanes as 64-bit words", state);

        for (i = 0; i < 24; i++)
        {
//            displayIntermediateValues.displayRoundNumber(3, i);

            theta(state);
//            displayIntermediateValues.displayStateAs64bitWords(3, "After theta", state);

            rho(state);
//            displayIntermediateValues.displayStateAs64bitWords(3, "After rho", state);

            pi(state);
//            displayIntermediateValues.displayStateAs64bitWords(3, "After pi", state);

            chi(state);
//            displayIntermediateValues.displayStateAs64bitWords(3, "After chi", state);

            iota(state, i);
//            displayIntermediateValues.displayStateAs64bitWords(3, "After iota", state);
        }
    }

    long[] C = new long[5];

    private void theta(long[] A)
    {
        for (int x = 0; x < 5; x++)
        {
            C[x] = 0;
            for (int y = 0; y < 5; y++)
            {
                C[x] ^= A[x + 5 * y];
            }
        }
        for (int x = 0; x < 5; x++)
        {
            long dX = ((((C[(x + 1) % 5]) << 1) ^ ((C[(x + 1) % 5]) >>> (64 - 1)))) ^ C[(x + 4) % 5];
            for (int y = 0; y < 5; y++)
            {
                A[x + 5 * y] ^= dX;
            }
        }
    }

    private void rho(long[] A)
    {
        for (int x = 0; x < 5; x++)
        {
            for (int y = 0; y < 5; y++)
            {
                int index = x + 5 * y;
                A[index] = ((KeccakRhoOffsets[index] != 0) ? (((A[index]) << KeccakRhoOffsets[index]) ^ ((A[index]) >>> (64 - KeccakRhoOffsets[index]))) : A[index]);
            }
        }
    }

    long[] tempA = new long[25];

    private void pi(long[] A)
    {
        System.arraycopy(A, 0, tempA, 0, tempA.length);

        for (int x = 0; x < 5; x++)
        {
            for (int y = 0; y < 5; y++)
            {
                A[y + 5 * ((2 * x + 3 * y) % 5)] = tempA[x + 5 * y];
            }
        }
    }

    long[] chiC = new long[5];

    private void chi(long[] A)
    {
        for (int y = 0; y < 5; y++)
        {
            for (int x = 0; x < 5; x++)
            {
                chiC[x] = A[x + 5 * y] ^ ((~A[(((x + 1) % 5) + 5 * y)]) & A[(((x + 2) % 5) + 5 * y)]);
            }
            for (int x = 0; x < 5; x++)
            {
                A[x + 5 * y] = chiC[x];
            }
        }
    }

    private void iota(long[] A, int indexRound)
    {
        A[(((0) % 5) + 5 * ((0) % 5))] ^= KeccakRoundConstants[indexRound];
    }

    private void KeccakAbsorb(byte[] byteState, byte[] data, int dataInBytes)
    {
        keccakPermutationAfterXor(byteState, data, dataInBytes);
    }


    private void KeccakExtract1024bits(byte[] byteState, byte[] data)
    {
        System.arraycopy(byteState, 0, data, 0, 128);
    }


    private void KeccakExtract(byte[] byteState, byte[] data, int laneCount)
    {
        System.arraycopy(byteState, 0, data, 0, laneCount * 8);
    }
}
