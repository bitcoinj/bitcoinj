package org.bouncycastle.pqc.crypto.gmss;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.crypto.gmss.util.GMSSRandom;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;


/**
 * This class implements the distributed computation of the public key of the
 * Winternitz one-time signature scheme (OTSS). The class is used by the GMSS
 * classes for calculation of upcoming leafs.
 */
public class GMSSLeaf
{

    /**
     * The hash function used by the OTS and the PRNG
     */
    private Digest messDigestOTS;

    /**
     * The length of the message digest and private key
     */
    private int mdsize, keysize;

    /**
     * The source of randomness for OTS private key generation
     */
    private GMSSRandom gmssRandom;

    /**
     * Byte array for distributed computation of the upcoming leaf
     */
    private byte[] leaf;

    /**
     * Byte array for storing the concatenated hashes of private key parts
     */
    private byte[] concHashs;

    /**
     * indices for distributed computation
     */
    private int i, j;

    /**
     * storing 2^w
     */
    private int two_power_w;

    /**
     * Winternitz parameter w
     */
    private int w;

    /**
     * the amount of distributed computation steps when updateLeaf is called
     */
    private int steps;

    /**
     * the internal seed
     */
    private byte[] seed;

    /**
     * the OTS privateKey parts
     */
    byte[] privateKeyOTS;

    /**
     * This constructor regenerates a prior GMSSLeaf object
     *
     * @param digest   an array of strings, containing the name of the used hash
     *                 function and PRNG and the name of the corresponding
     *                 provider
     * @param otsIndex status bytes
     * @param numLeafs status ints
     */
    public GMSSLeaf(Digest digest, byte[][] otsIndex, int[] numLeafs)
    {
        this.i = numLeafs[0];
        this.j = numLeafs[1];
        this.steps = numLeafs[2];
        this.w = numLeafs[3];

        messDigestOTS = digest;

        gmssRandom = new GMSSRandom(messDigestOTS);

        // calulate keysize for private key and the help array
        mdsize = messDigestOTS.getDigestSize();
        int mdsizeBit = mdsize << 3;
        int messagesize = (int)Math.ceil((double)(mdsizeBit) / (double)w);
        int checksumsize = getLog((messagesize << w) + 1);
        this.keysize = messagesize
            + (int)Math.ceil((double)checksumsize / (double)w);
        this.two_power_w = 1 << w;

        // calculate steps
        // ((2^w)-1)*keysize + keysize + 1 / (2^h -1)

        // initialize arrays
        this.privateKeyOTS = otsIndex[0];
        this.seed = otsIndex[1];
        this.concHashs = otsIndex[2];
        this.leaf = otsIndex[3];
    }

    /**
     * The constructor precomputes some needed variables for distributed leaf
     * calculation
     *
     * @param digest     an array of strings, containing the digest of the used hash
     *                 function and PRNG and the digest of the corresponding
     *                 provider
     * @param w        the winterniz parameter of that tree the leaf is computed
     *                 for
     * @param numLeafs the number of leafs of the tree from where the distributed
     *                 computation is called
     */
    GMSSLeaf(Digest digest, int w, int numLeafs)
    {
        this.w = w;

        messDigestOTS = digest;

        gmssRandom = new GMSSRandom(messDigestOTS);

        // calulate keysize for private key and the help array
        mdsize = messDigestOTS.getDigestSize();
        int mdsizeBit = mdsize << 3;
        int messagesize = (int)Math.ceil((double)(mdsizeBit) / (double)w);
        int checksumsize = getLog((messagesize << w) + 1);
        this.keysize = messagesize
            + (int)Math.ceil((double)checksumsize / (double)w);
        this.two_power_w = 1 << w;

        // calculate steps
        // ((2^w)-1)*keysize + keysize + 1 / (2^h -1)
        this.steps = (int)Math
            .ceil((double)(((1 << w) - 1) * keysize + 1 + keysize)
                / (double)(numLeafs));

        // initialize arrays
        this.seed = new byte[mdsize];
        this.leaf = new byte[mdsize];
        this.privateKeyOTS = new byte[mdsize];
        this.concHashs = new byte[mdsize * keysize];
    }

    public GMSSLeaf(Digest digest, int w, int numLeafs, byte[] seed0)
    {
        this.w = w;

        messDigestOTS = digest;

        gmssRandom = new GMSSRandom(messDigestOTS);

        // calulate keysize for private key and the help array
        mdsize = messDigestOTS.getDigestSize();
        int mdsizeBit = mdsize << 3;
        int messagesize = (int)Math.ceil((double)(mdsizeBit) / (double)w);
        int checksumsize = getLog((messagesize << w) + 1);
        this.keysize = messagesize
            + (int)Math.ceil((double)checksumsize / (double)w);
        this.two_power_w = 1 << w;

        // calculate steps
        // ((2^w)-1)*keysize + keysize + 1 / (2^h -1)
        this.steps = (int)Math
            .ceil((double)(((1 << w) - 1) * keysize + 1 + keysize)
                / (double)(numLeafs));

        // initialize arrays
        this.seed = new byte[mdsize];
        this.leaf = new byte[mdsize];
        this.privateKeyOTS = new byte[mdsize];
        this.concHashs = new byte[mdsize * keysize];

        initLeafCalc(seed0);
    }

    private GMSSLeaf(GMSSLeaf original)
    {
        this.messDigestOTS = original.messDigestOTS;
        this.mdsize = original.mdsize;
        this.keysize = original.keysize;
        this.gmssRandom = original.gmssRandom;
        this.leaf = Arrays.clone(original.leaf);
        this.concHashs = Arrays.clone(original.concHashs);
        this.i = original.i;
        this.j = original.j;
        this.two_power_w = original.two_power_w;
        this.w = original.w;
        this.steps = original.steps;
        this.seed = Arrays.clone(original.seed);
        this.privateKeyOTS = Arrays.clone(original.privateKeyOTS);
    }

    /**
     * initialize the distributed leaf calculation reset i,j and compute OTSseed
     * with seed0
     *
     * @param seed0 the starting seed
     */
    // TODO: this really looks like it should be either always called from a constructor or nextLeaf.
    void initLeafCalc(byte[] seed0)
    {
        this.i = 0;
        this.j = 0;
        byte[] dummy = new byte[mdsize];
        System.arraycopy(seed0, 0, dummy, 0, seed.length);
        this.seed = gmssRandom.nextSeed(dummy);
    }

    GMSSLeaf nextLeaf()
    {
        GMSSLeaf nextLeaf = new GMSSLeaf(this);

        nextLeaf.updateLeafCalc();

        return nextLeaf;
    }

    /**
     * Processes <code>steps</code> steps of distributed leaf calculation
     *
     * @return true if leaf is completed, else false
     */
    private void updateLeafCalc()
    {
         byte[] buf = new byte[messDigestOTS.getDigestSize()];

        // steps times do
        // TODO: this really needs to be looked at, the 10000 has been added as
        // prior to this the leaf value always ended up as zeros.
        for (int s = 0; s < steps + 10000; s++)
        {
            if (i == keysize && j == two_power_w - 1)
            { // [3] at last hash the
                // concatenation
                messDigestOTS.update(concHashs, 0, concHashs.length);
                leaf = new byte[messDigestOTS.getDigestSize()];
                messDigestOTS.doFinal(leaf, 0);
                return;
            }
            else if (i == 0 || j == two_power_w - 1)
            { // [1] at the
                // beginning and
                // when [2] is
                // finished: get the
                // next private key
                // part
                i++;
                j = 0;
                // get next privKey part
                this.privateKeyOTS = gmssRandom.nextSeed(seed);
            }
            else
            { // [2] hash the privKey part
                messDigestOTS.update(privateKeyOTS, 0, privateKeyOTS.length);
                privateKeyOTS = buf;
                messDigestOTS.doFinal(privateKeyOTS, 0);
                j++;
                if (j == two_power_w - 1)
                { // after w hashes add to the
                    // concatenated array
                    System.arraycopy(privateKeyOTS, 0, concHashs, mdsize
                        * (i - 1), mdsize);
                }
            }
        }

       throw new IllegalStateException("unable to updateLeaf in steps: " + steps + " " + i + " " + j);
    }

    /**
     * Returns the leaf value.
     *
     * @return the leaf value
     */
    public byte[] getLeaf()
    {
        return Arrays.clone(leaf);
    }

    /**
     * This method returns the least integer that is greater or equal to the
     * logarithm to the base 2 of an integer <code>intValue</code>.
     *
     * @param intValue an integer
     * @return The least integer greater or equal to the logarithm to the base 2
     *         of <code>intValue</code>
     */
    private int getLog(int intValue)
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
     * Returns the status byte array used by the GMSSPrivateKeyASN.1 class
     *
     * @return The status bytes
     */
    public byte[][] getStatByte()
    {

        byte[][] statByte = new byte[4][];
        statByte[0] = new byte[mdsize];
        statByte[1] = new byte[mdsize];
        statByte[2] = new byte[mdsize * keysize];
        statByte[3] = new byte[mdsize];
        statByte[0] = privateKeyOTS;
        statByte[1] = seed;
        statByte[2] = concHashs;
        statByte[3] = leaf;

        return statByte;
    }

    /**
     * Returns the status int array used by the GMSSPrivateKeyASN.1 class
     *
     * @return The status ints
     */
    public int[] getStatInt()
    {

        int[] statInt = new int[4];
        statInt[0] = i;
        statInt[1] = j;
        statInt[2] = steps;
        statInt[3] = w;
        return statInt;
    }

    /**
     * Returns a String representation of the main part of this element
     *
     * @return a String representation of the main part of this element
     */
    public String toString()
    {
        String out = "";

        for (int i = 0; i < 4; i++)
        {
            out = out + this.getStatInt()[i] + " ";
        }
        out = out + " " + this.mdsize + " " + this.keysize + " "
            + this.two_power_w + " ";

        byte[][] temp = this.getStatByte();
        for (int i = 0; i < 4; i++)
        {
            if (temp[i] != null)
            {
                out = out + new String(Hex.encode(temp[i])) + " ";
            }
            else
            {
                out = out + "null ";
            }
        }
        return out;
    }
}
