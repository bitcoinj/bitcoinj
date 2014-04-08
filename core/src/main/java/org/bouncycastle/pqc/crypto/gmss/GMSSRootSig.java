package org.bouncycastle.pqc.crypto.gmss;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.crypto.gmss.util.GMSSRandom;
import org.bouncycastle.util.encoders.Hex;


/**
 * This class implements the distributed signature generation of the Winternitz
 * one-time signature scheme (OTSS), described in C.Dods, N.P. Smart, and M.
 * Stam, "Hash Based Digital Signature Schemes", LNCS 3796, pages 96&#8211;115,
 * 2005. The class is used by the GMSS classes.
 */
public class GMSSRootSig
{

    /**
     * The hash function used by the OTS
     */
    private Digest messDigestOTS;

    /**
     * The length of the message digest and private key
     */
    private int mdsize, keysize;

    /**
     * The private key
     */
    private byte[] privateKeyOTS;

    /**
     * The message bytes
     */
    private byte[] hash;

    /**
     * The signature bytes
     */
    private byte[] sign;

    /**
     * The Winternitz parameter
     */
    private int w;

    /**
     * The source of randomness for OTS private key generation
     */
    private GMSSRandom gmssRandom;

    /**
     * Sizes of the message
     */
    private int messagesize;

    /**
     * Some precalculated values
     */
    private int k;

    /**
     * Some variables for storing the actual status of distributed signing
     */
    private int r, test, counter, ii;

    /**
     * variables for storing big numbers for the actual status of distributed
     * signing
     */
    private long test8, big8;

    /**
     * The necessary steps of each updateSign() call
     */
    private int steps;

    /**
     * The checksum part
     */
    private int checksum;

    /**
     * The height of the tree
     */
    private int height;

    /**
     * The current intern OTSseed
     */
    private byte[] seed;

    /**
     * This constructor regenerates a prior GMSSRootSig object used by the
     * GMSSPrivateKeyASN.1 class
     *
     * @param digest     an array of strings, containing the digest of the used hash
     *                 function, the digest of the PRGN and the names of the
     *                 corresponding providers
     * @param statByte status byte array
     * @param statInt  status int array
     */
    public GMSSRootSig(Digest digest, byte[][] statByte, int[] statInt)
    {
        messDigestOTS = digest;
        gmssRandom = new GMSSRandom(messDigestOTS);

        this.counter = statInt[0];
        this.test = statInt[1];
        this.ii = statInt[2];
        this.r = statInt[3];
        this.steps = statInt[4];
        this.keysize = statInt[5];
        this.height = statInt[6];
        this.w = statInt[7];
        this.checksum = statInt[8];

        this.mdsize = messDigestOTS.getDigestSize();

        this.k = (1 << w) - 1;

        int mdsizeBit = mdsize << 3;
        this.messagesize = (int)Math.ceil((double)(mdsizeBit) / (double)w);

        this.privateKeyOTS = statByte[0];
        this.seed = statByte[1];
        this.hash = statByte[2];

        this.sign = statByte[3];

        this.test8 = ((statByte[4][0] & 0xff))
            | ((long)(statByte[4][1] & 0xff) << 8)
            | ((long)(statByte[4][2] & 0xff) << 16)
            | ((long)(statByte[4][3] & 0xff)) << 24
            | ((long)(statByte[4][4] & 0xff)) << 32
            | ((long)(statByte[4][5] & 0xff)) << 40
            | ((long)(statByte[4][6] & 0xff)) << 48
            | ((long)(statByte[4][7] & 0xff)) << 56;

        this.big8 = ((statByte[4][8] & 0xff))
            | ((long)(statByte[4][9] & 0xff) << 8)
            | ((long)(statByte[4][10] & 0xff) << 16)
            | ((long)(statByte[4][11] & 0xff)) << 24
            | ((long)(statByte[4][12] & 0xff)) << 32
            | ((long)(statByte[4][13] & 0xff)) << 40
            | ((long)(statByte[4][14] & 0xff)) << 48
            | ((long)(statByte[4][15] & 0xff)) << 56;
    }

    /**
     * The constructor generates the PRNG and initializes some variables
     *
     * @param digest   an array of strings, containing the digest of the used hash
     *               function, the digest of the PRGN and the names of the
     *               corresponding providers
     * @param w      the winternitz parameter
     * @param height the heigth of the tree
     */
    public GMSSRootSig(Digest digest, int w, int height)
    {
        messDigestOTS = digest;
        gmssRandom = new GMSSRandom(messDigestOTS);

        this.mdsize = messDigestOTS.getDigestSize();
        this.w = w;
        this.height = height;

        this.k = (1 << w) - 1;

        int mdsizeBit = mdsize << 3;
        this.messagesize = (int)Math.ceil((double)(mdsizeBit) / (double)w);
    }

    /**
     * This method initializes the distributed sigature calculation. Variables
     * are reseted and necessary steps are calculated
     *
     * @param seed0   the initial OTSseed
     * @param message the massage which will be signed
     */
    public void initSign(byte[] seed0, byte[] message)
    {

        // create hash of message m
        this.hash = new byte[mdsize];
        messDigestOTS.update(message, 0, message.length);
        this.hash = new byte[messDigestOTS.getDigestSize()];
        messDigestOTS.doFinal(this.hash, 0);

        // variables for calculation of steps
        byte[] messPart = new byte[mdsize];
        System.arraycopy(hash, 0, messPart, 0, mdsize);
        int checkPart = 0;
        int sumH = 0;
        int checksumsize = getLog((messagesize << w) + 1);

        // ------- calculation of necessary steps ------
        if (8 % w == 0)
        {
            int dt = 8 / w;
            // message part
            for (int a = 0; a < mdsize; a++)
            {
                // count necessary hashs in 'sumH'
                for (int b = 0; b < dt; b++)
                {
                    sumH += messPart[a] & k;
                    messPart[a] = (byte)(messPart[a] >>> w);
                }
            }
            // checksum part
            this.checksum = (messagesize << w) - sumH;
            checkPart = checksum;
            // count necessary hashs in 'sumH'
            for (int b = 0; b < checksumsize; b += w)
            {
                sumH += checkPart & k;
                checkPart >>>= w;
            }
        } // end if ( 8 % w == 0 )
        else if (w < 8)
        {
            long big8;
            int ii = 0;
            int dt = mdsize / w;

            // first d*w bytes of hash (main message part)
            for (int i = 0; i < dt; i++)
            {
                big8 = 0;
                for (int j = 0; j < w; j++)
                {
                    big8 ^= (messPart[ii] & 0xff) << (j << 3);
                    ii++;
                }
                // count necessary hashs in 'sumH'
                for (int j = 0; j < 8; j++)
                {
                    sumH += (int)(big8 & k);
                    big8 >>>= w;
                }
            }
            // rest of message part
            dt = mdsize % w;
            big8 = 0;
            for (int j = 0; j < dt; j++)
            {
                big8 ^= (messPart[ii] & 0xff) << (j << 3);
                ii++;
            }
            dt <<= 3;
            // count necessary hashs in 'sumH'
            for (int j = 0; j < dt; j += w)
            {
                sumH += (int)(big8 & k);
                big8 >>>= w;
            }
            // checksum part
            this.checksum = (messagesize << w) - sumH;
            checkPart = checksum;
            // count necessary hashs in 'sumH'
            for (int i = 0; i < checksumsize; i += w)
            {
                sumH += checkPart & k;
                checkPart >>>= w;
            }
        }// end if(w<8)
        else if (w < 57)
        {
            long big8;
            int r = 0;
            int s, f, rest, ii;

            // first a*w bits of hash where a*w <= 8*mdsize < (a+1)*w (main
            // message part)
            while (r <= ((mdsize << 3) - w))
            {
                s = r >>> 3;
                rest = r % 8;
                r += w;
                f = (r + 7) >>> 3;
                big8 = 0;
                ii = 0;
                for (int j = s; j < f; j++)
                {
                    big8 ^= (messPart[j] & 0xff) << (ii << 3);
                    ii++;
                }
                big8 >>>= rest;
                // count necessary hashs in 'sumH'
                sumH += (big8 & k);

            }
            // rest of message part
            s = r >>> 3;
            if (s < mdsize)
            {
                rest = r % 8;
                big8 = 0;
                ii = 0;
                for (int j = s; j < mdsize; j++)
                {
                    big8 ^= (messPart[j] & 0xff) << (ii << 3);
                    ii++;
                }

                big8 >>>= rest;
                // count necessary hashs in 'sumH'
                sumH += (big8 & k);
            }
            // checksum part
            this.checksum = (messagesize << w) - sumH;
            checkPart = checksum;
            // count necessary hashs in 'sumH'
            for (int i = 0; i < checksumsize; i += w)
            {
                sumH += (checkPart & k);
                checkPart >>>= w;
            }
        }// end if(w<57)

        // calculate keysize
        this.keysize = messagesize
            + (int)Math.ceil((double)checksumsize / (double)w);

        // calculate steps: 'keysize' times PRNG, 'sumH' times hashing,
        // (1<<height)-1 updateSign() calls
        this.steps = (int)Math.ceil((double)(keysize + sumH)
            / (double)((1 << height)));
        // ----------------------------

        // reset variables
        this.sign = new byte[keysize * mdsize];
        this.counter = 0;
        this.test = 0;
        this.ii = 0;
        this.test8 = 0;
        this.r = 0;
        // define the private key messagesize
        this.privateKeyOTS = new byte[mdsize];
        // copy the seed
        this.seed = new byte[mdsize];
        System.arraycopy(seed0, 0, this.seed, 0, mdsize);

    }

    /**
     * This Method performs <code>steps</code> steps of distributed signature
     * calculaion
     *
     * @return true if signature is generated completly, else false
     */
    public boolean updateSign()
    {
        // steps times do

        for (int s = 0; s < steps; s++)
        { // do 'step' times

            if (counter < keysize)
            { // generate the private key or perform
                // the next hash
                oneStep();
            }
            if (counter == keysize)
            {// finish
                return true;
            }
        }

        return false; // leaf not finished yet
    }

    /**
     * @return The private OTS key
     */
    public byte[] getSig()
    {

        return sign;
    }

    /**
     * @return The one-time signature of the message, generated step by step
     */
    private void oneStep()
    {
        // -------- if (8 % w == 0) ----------
        if (8 % w == 0)
        {
            if (test == 0)
            {
                // get current OTSprivateKey
                this.privateKeyOTS = gmssRandom.nextSeed(seed);
                // System.arraycopy(privateKeyOTS, 0, hlp, 0, mdsize);

                if (ii < mdsize)
                { // for main message part
                    test = hash[ii] & k;
                    hash[ii] = (byte)(hash[ii] >>> w);
                }
                else
                { // for checksum part
                    test = checksum & k;
                    checksum >>>= w;
                }
            }
            else if (test > 0)
            { // hash the private Key 'test' times (on
                // time each step)
                messDigestOTS.update(privateKeyOTS, 0, privateKeyOTS.length);
                privateKeyOTS = new byte[messDigestOTS.getDigestSize()];
                messDigestOTS.doFinal(privateKeyOTS, 0);
                test--;
            }
            if (test == 0)
            { // if all hashes done copy result to siganture
                // array
                System.arraycopy(privateKeyOTS, 0, sign, counter * mdsize,
                    mdsize);
                counter++;

                if (counter % (8 / w) == 0)
                { // raise array index for main
                    // massage part
                    ii++;
                }
            }

        }// ----- end if (8 % w == 0) -----
        // ---------- if ( w < 8 ) ----------------
        else if (w < 8)
        {

            if (test == 0)
            {
                if (counter % 8 == 0 && ii < mdsize)
                { // after every 8th "add
                    // to signature"-step
                    big8 = 0;
                    if (counter < ((mdsize / w) << 3))
                    {// main massage
                        // (generate w*8 Bits
                        // every time) part
                        for (int j = 0; j < w; j++)
                        {
                            big8 ^= (hash[ii] & 0xff) << (j << 3);
                            ii++;
                        }
                    }
                    else
                    { // rest of massage part (once)
                        for (int j = 0; j < mdsize % w; j++)
                        {
                            big8 ^= (hash[ii] & 0xff) << (j << 3);
                            ii++;
                        }
                    }
                }
                if (counter == messagesize)
                { // checksum part (once)
                    big8 = checksum;
                }

                test = (int)(big8 & k);
                // generate current OTSprivateKey
                this.privateKeyOTS = gmssRandom.nextSeed(seed);
                // System.arraycopy(privateKeyOTS, 0, hlp, 0, mdsize);

            }
            else if (test > 0)
            { // hash the private Key 'test' times (on
                // time each step)
                messDigestOTS.update(privateKeyOTS, 0, privateKeyOTS.length);
                privateKeyOTS = new byte[messDigestOTS.getDigestSize()];
                messDigestOTS.doFinal(privateKeyOTS, 0);
                test--;
            }
            if (test == 0)
            { // if all hashes done copy result to siganture
                // array
                System.arraycopy(privateKeyOTS, 0, sign, counter * mdsize,
                    mdsize);
                big8 >>>= w;
                counter++;
            }

        }// ------- end if(w<8)--------------------------------
        // --------- if w < 57 -----------------------------
        else if (w < 57)
        {

            if (test8 == 0)
            {
                int s, f, rest;
                big8 = 0;
                ii = 0;
                rest = r % 8;
                s = r >>> 3;
                // --- message part---
                if (s < mdsize)
                {
                    if (r <= ((mdsize << 3) - w))
                    { // first message part
                        r += w;
                        f = (r + 7) >>> 3;
                    }
                    else
                    { // rest of message part (once)
                        f = mdsize;
                        r += w;
                    }
                    // generate long 'big8' with minimum w next bits of the
                    // message array
                    for (int i = s; i < f; i++)
                    {
                        big8 ^= (hash[i] & 0xff) << (ii << 3);
                        ii++;
                    }
                    // delete bits on the right side, which were used already by
                    // the last loop
                    big8 >>>= rest;
                    test8 = (big8 & k);
                }
                // --- checksum part
                else
                {
                    test8 = (checksum & k);
                    checksum >>>= w;
                }
                // generate current OTSprivateKey
                this.privateKeyOTS = gmssRandom.nextSeed(seed);
                // System.arraycopy(privateKeyOTS, 0, hlp, 0, mdsize);

            }
            else if (test8 > 0)
            { // hash the private Key 'test' times (on
                // time each step)
                messDigestOTS.update(privateKeyOTS, 0, privateKeyOTS.length);
                privateKeyOTS = new byte[messDigestOTS.getDigestSize()];
                messDigestOTS.doFinal(privateKeyOTS, 0);
                test8--;
            }
            if (test8 == 0)
            { // if all hashes done copy result to siganture
                // array
                System.arraycopy(privateKeyOTS, 0, sign, counter * mdsize,
                    mdsize);
                counter++;
            }

        }
    }

    /**
     * This method returns the least integer that is greater or equal to the
     * logarithm to the base 2 of an integer <code>intValue</code>.
     *
     * @param intValue an integer
     * @return The least integer greater or equal to the logarithm to the base 2
     *         of <code>intValue</code>
     */
    public int getLog(int intValue)
    {
        int log = 1;
        int i = 2;
        while (i < intValue)
        {
            i <<= 1;
            log++;
        }
        return log;
    }

    /**
     * This method returns the status byte array
     *
     * @return statBytes
     */
    public byte[][] getStatByte()
    {

        byte[][] statByte = new byte[5][mdsize];
        statByte[0] = privateKeyOTS;
        statByte[1] = seed;
        statByte[2] = hash;
        statByte[3] = sign;
        statByte[4] = this.getStatLong();

        return statByte;
    }

    /**
     * This method returns the status int array
     *
     * @return statInt
     */
    public int[] getStatInt()
    {
        int[] statInt = new int[9];
        statInt[0] = counter;
        statInt[1] = test;
        statInt[2] = ii;
        statInt[3] = r;
        statInt[4] = steps;
        statInt[5] = keysize;
        statInt[6] = height;
        statInt[7] = w;
        statInt[8] = checksum;
        return statInt;
    }

    /**
     * Converts the long parameters into byte arrays to store it in
     * statByte-Array
     */
    public byte[] getStatLong()
    {
        byte[] bytes = new byte[16];

        bytes[0] = (byte)((test8) & 0xff);
        bytes[1] = (byte)((test8 >> 8) & 0xff);
        bytes[2] = (byte)((test8 >> 16) & 0xff);
        bytes[3] = (byte)((test8 >> 24) & 0xff);
        bytes[4] = (byte)((test8) >> 32 & 0xff);
        bytes[5] = (byte)((test8 >> 40) & 0xff);
        bytes[6] = (byte)((test8 >> 48) & 0xff);
        bytes[7] = (byte)((test8 >> 56) & 0xff);

        bytes[8] = (byte)((big8) & 0xff);
        bytes[9] = (byte)((big8 >> 8) & 0xff);
        bytes[10] = (byte)((big8 >> 16) & 0xff);
        bytes[11] = (byte)((big8 >> 24) & 0xff);
        bytes[12] = (byte)((big8) >> 32 & 0xff);
        bytes[13] = (byte)((big8 >> 40) & 0xff);
        bytes[14] = (byte)((big8 >> 48) & 0xff);
        bytes[15] = (byte)((big8 >> 56) & 0xff);

        return bytes;
    }

    /**
     * returns a string representation of the instance
     *
     * @return a string representation of the instance
     */
    public String toString()
    {
        String out = "" + this.big8 + "  ";
        int[] statInt = new int[9];
        statInt = this.getStatInt();
        byte[][] statByte = new byte[5][mdsize];
        statByte = this.getStatByte();
        for (int i = 0; i < 9; i++)
        {
            out = out + statInt[i] + " ";
        }
        for (int i = 0; i < 5; i++)
        {
            out = out + new String(Hex.encode(statByte[i])) + " ";
        }

        return out;
    }

}
