package org.bouncycastle.pqc.crypto.gmss;

import java.security.SecureRandom;
import java.util.Vector;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.gmss.util.GMSSRandom;
import org.bouncycastle.pqc.crypto.gmss.util.WinternitzOTSVerify;
import org.bouncycastle.pqc.crypto.gmss.util.WinternitzOTSignature;


/**
 * This class implements key pair generation of the generalized Merkle signature
 * scheme (GMSS).
 *
 * @see GMSSSigner
 */
public class GMSSKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    /**
     * The source of randomness for OTS private key generation
     */
    private GMSSRandom gmssRandom;

    /**
     * The hash function used for the construction of the authentication trees
     */
    private Digest messDigestTree;

    /**
     * An array of the seeds for the PRGN (for main tree, and all current
     * subtrees)
     */
    private byte[][] currentSeeds;

    /**
     * An array of seeds for the PRGN (for all subtrees after next)
     */
    private byte[][] nextNextSeeds;

    /**
     * An array of the RootSignatures
     */
    private byte[][] currentRootSigs;

    /**
     * Class of hash function to use
     */
    private GMSSDigestProvider digestProvider;

    /**
     * The length of the seed for the PRNG
     */
    private int mdLength;

    /**
     * the number of Layers
     */
    private int numLayer;


    /**
     * Flag indicating if the class already has been initialized
     */
    private boolean initialized = false;

    /**
     * Instance of GMSSParameterset
     */
    private GMSSParameters gmssPS;

    /**
     * An array of the heights of the authentication trees of each layer
     */
    private int[] heightOfTrees;

    /**
     * An array of the Winternitz parameter 'w' of each layer
     */
    private int[] otsIndex;

    /**
     * The parameter K needed for the authentication path computation
     */
    private int[] K;

    private GMSSKeyGenerationParameters gmssParams;

    /**
     * The GMSS OID.
     */
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.3";

    /**
     * The standard constructor tries to generate the GMSS algorithm identifier
     * with the corresponding OID.
     *
     * @param digestProvider     provider for digest implementations.
     */
    public GMSSKeyPairGenerator(GMSSDigestProvider digestProvider)
    {
        this.digestProvider = digestProvider;
        messDigestTree = digestProvider.get();

        // set mdLength
        this.mdLength = messDigestTree.getDigestSize();
        // construct randomizer
        this.gmssRandom = new GMSSRandom(messDigestTree);

    }

    /**
     * Generates the GMSS key pair. The public key is an instance of
     * JDKGMSSPublicKey, the private key is an instance of JDKGMSSPrivateKey.
     *
     * @return Key pair containing a JDKGMSSPublicKey and a JDKGMSSPrivateKey
     */
    private AsymmetricCipherKeyPair genKeyPair()
    {
        if (!initialized)
        {
            initializeDefault();
        }

        // initialize authenticationPaths and treehash instances
        byte[][][] currentAuthPaths = new byte[numLayer][][];
        byte[][][] nextAuthPaths = new byte[numLayer - 1][][];
        Treehash[][] currentTreehash = new Treehash[numLayer][];
        Treehash[][] nextTreehash = new Treehash[numLayer - 1][];

        Vector[] currentStack = new Vector[numLayer];
        Vector[] nextStack = new Vector[numLayer - 1];

        Vector[][] currentRetain = new Vector[numLayer][];
        Vector[][] nextRetain = new Vector[numLayer - 1][];

        for (int i = 0; i < numLayer; i++)
        {
            currentAuthPaths[i] = new byte[heightOfTrees[i]][mdLength];
            currentTreehash[i] = new Treehash[heightOfTrees[i] - K[i]];

            if (i > 0)
            {
                nextAuthPaths[i - 1] = new byte[heightOfTrees[i]][mdLength];
                nextTreehash[i - 1] = new Treehash[heightOfTrees[i] - K[i]];
            }

            currentStack[i] = new Vector();
            if (i > 0)
            {
                nextStack[i - 1] = new Vector();
            }
        }

        // initialize roots
        byte[][] currentRoots = new byte[numLayer][mdLength];
        byte[][] nextRoots = new byte[numLayer - 1][mdLength];
        // initialize seeds
        byte[][] seeds = new byte[numLayer][mdLength];
        // initialize seeds[] by copying starting-seeds of first trees of each
        // layer
        for (int i = 0; i < numLayer; i++)
        {
            System.arraycopy(currentSeeds[i], 0, seeds[i], 0, mdLength);
        }

        // initialize rootSigs
        currentRootSigs = new byte[numLayer - 1][mdLength];

        // -------------------------
        // -------------------------
        // --- calculation of current authpaths and current rootsigs (AUTHPATHS,
        // SIG)------
        // from bottom up to the root
        for (int h = numLayer - 1; h >= 0; h--)
        {
            GMSSRootCalc tree = new GMSSRootCalc(this.heightOfTrees[h], this.K[h], digestProvider);
            try
            {
                // on lowest layer no lower root is available, so just call
                // the method with null as first parameter
                if (h == numLayer - 1)
                {
                    tree = this.generateCurrentAuthpathAndRoot(null, currentStack[h], seeds[h], h);
                }
                else
                // otherwise call the method with the former computed root
                // value
                {
                    tree = this.generateCurrentAuthpathAndRoot(currentRoots[h + 1], currentStack[h], seeds[h], h);
                }

            }
            catch (Exception e1)
            {
                e1.printStackTrace();
            }

            // set initial values needed for the private key construction
            for (int i = 0; i < heightOfTrees[h]; i++)
            {
                System.arraycopy(tree.getAuthPath()[i], 0, currentAuthPaths[h][i], 0, mdLength);
            }
            currentRetain[h] = tree.getRetain();
            currentTreehash[h] = tree.getTreehash();
            System.arraycopy(tree.getRoot(), 0, currentRoots[h], 0, mdLength);
        }

        // --- calculation of next authpaths and next roots (AUTHPATHS+, ROOTS+)
        // ------
        for (int h = numLayer - 2; h >= 0; h--)
        {
            GMSSRootCalc tree = this.generateNextAuthpathAndRoot(nextStack[h], seeds[h + 1], h + 1);

            // set initial values needed for the private key construction
            for (int i = 0; i < heightOfTrees[h + 1]; i++)
            {
                System.arraycopy(tree.getAuthPath()[i], 0, nextAuthPaths[h][i], 0, mdLength);
            }
            nextRetain[h] = tree.getRetain();
            nextTreehash[h] = tree.getTreehash();
            System.arraycopy(tree.getRoot(), 0, nextRoots[h], 0, mdLength);

            // create seed for the Merkle tree after next (nextNextSeeds)
            // SEEDs++
            System.arraycopy(seeds[h + 1], 0, this.nextNextSeeds[h], 0, mdLength);
        }
        // ------------

        // generate JDKGMSSPublicKey
        GMSSPublicKeyParameters publicKey = new GMSSPublicKeyParameters(currentRoots[0], gmssPS);

        // generate the JDKGMSSPrivateKey
        GMSSPrivateKeyParameters privateKey = new GMSSPrivateKeyParameters(currentSeeds, nextNextSeeds, currentAuthPaths,
            nextAuthPaths, currentTreehash, nextTreehash, currentStack, nextStack, currentRetain, nextRetain, nextRoots, currentRootSigs, gmssPS, digestProvider);

        // return the KeyPair
        return (new AsymmetricCipherKeyPair(publicKey, privateKey));
    }

    /**
     * calculates the authpath for tree in layer h which starts with seed[h]
     * additionally computes the rootSignature of underlaying root
     *
     * @param currentStack stack used for the treehash instance created by this method
     * @param lowerRoot    stores the root of the lower tree
     * @param seed        starting seeds
     * @param h            actual layer
     */
    private GMSSRootCalc generateCurrentAuthpathAndRoot(byte[] lowerRoot, Vector currentStack, byte[] seed, int h)
    {
        byte[] help = new byte[mdLength];

        byte[] OTSseed = new byte[mdLength];
        OTSseed = gmssRandom.nextSeed(seed);

        WinternitzOTSignature ots;

        // data structure that constructs the whole tree and stores
        // the initial values for treehash, Auth and retain
        GMSSRootCalc treeToConstruct = new GMSSRootCalc(this.heightOfTrees[h], this.K[h], digestProvider);

        treeToConstruct.initialize(currentStack);

        // generate the first leaf
        if (h == numLayer - 1)
        {
            ots = new WinternitzOTSignature(OTSseed, digestProvider.get(), otsIndex[h]);
            help = ots.getPublicKey();
        }
        else
        {
            // for all layers except the lowest, generate the signature of the
            // underlying root
            // and reuse this signature to compute the first leaf of acual layer
            // more efficiently (by verifiing the signature)
            ots = new WinternitzOTSignature(OTSseed, digestProvider.get(), otsIndex[h]);
            currentRootSigs[h] = ots.getSignature(lowerRoot);
            WinternitzOTSVerify otsver = new WinternitzOTSVerify(digestProvider.get(), otsIndex[h]);
            help = otsver.Verify(lowerRoot, currentRootSigs[h]);
        }
        // update the tree with the first leaf
        treeToConstruct.update(help);

        int seedForTreehashIndex = 3;
        int count = 0;

        // update the tree 2^(H) - 1 times, from the second to the last leaf
        for (int i = 1; i < (1 << this.heightOfTrees[h]); i++)
        {
            // initialize the seeds for the leaf generation with index 3 * 2^h
            if (i == seedForTreehashIndex && count < this.heightOfTrees[h] - this.K[h])
            {
                treeToConstruct.initializeTreehashSeed(seed, count);
                seedForTreehashIndex *= 2;
                count++;
            }

            OTSseed = gmssRandom.nextSeed(seed);
            ots = new WinternitzOTSignature(OTSseed, digestProvider.get(), otsIndex[h]);
            treeToConstruct.update(ots.getPublicKey());
        }

        if (treeToConstruct.wasFinished())
        {
            return treeToConstruct;
        }
        System.err.println("Baum noch nicht fertig konstruiert!!!");
        return null;
    }

    /**
     * calculates the authpath and root for tree in layer h which starts with
     * seed[h]
     *
     * @param nextStack stack used for the treehash instance created by this method
     * @param seed      starting seeds
     * @param h         actual layer
     */
    private GMSSRootCalc generateNextAuthpathAndRoot(Vector nextStack, byte[] seed, int h)
    {
        byte[] OTSseed = new byte[numLayer];
        WinternitzOTSignature ots;

        // data structure that constructs the whole tree and stores
        // the initial values for treehash, Auth and retain
        GMSSRootCalc treeToConstruct = new GMSSRootCalc(this.heightOfTrees[h], this.K[h], this.digestProvider);
        treeToConstruct.initialize(nextStack);

        int seedForTreehashIndex = 3;
        int count = 0;

        // update the tree 2^(H) times, from the first to the last leaf
        for (int i = 0; i < (1 << this.heightOfTrees[h]); i++)
        {
            // initialize the seeds for the leaf generation with index 3 * 2^h
            if (i == seedForTreehashIndex && count < this.heightOfTrees[h] - this.K[h])
            {
                treeToConstruct.initializeTreehashSeed(seed, count);
                seedForTreehashIndex *= 2;
                count++;
            }

            OTSseed = gmssRandom.nextSeed(seed);
            ots = new WinternitzOTSignature(OTSseed, digestProvider.get(), otsIndex[h]);
            treeToConstruct.update(ots.getPublicKey());
        }

        if (treeToConstruct.wasFinished())
        {
            return treeToConstruct;
        }
        System.err.println("N�chster Baum noch nicht fertig konstruiert!!!");
        return null;
    }

    /**
     * This method initializes the GMSS KeyPairGenerator using an integer value
     * <code>keySize</code> as input. It provides a simple use of the GMSS for
     * testing demands.
     * <p>
     * A given <code>keysize</code> of less than 10 creates an amount 2^10
     * signatures. A keySize between 10 and 20 creates 2^20 signatures. Given an
     * integer greater than 20 the key pair generator creates 2^40 signatures.
     *
     * @param keySize      Assigns the parameters used for the GMSS signatures. There are
     *                     3 choices:<br>
     *                     1. keysize &lt;= 10: creates 2^10 signatures using the
     *                     parameterset<br>
     *                     P = (2, (5, 5), (3, 3), (3, 3))<br>
     *                     2. keysize &gt; 10 and &lt;= 20: creates 2^20 signatures using the
     *                     parameterset<br>
     *                     P = (2, (10, 10), (5, 4), (2, 2))<br>
     *                     3. keysize &gt; 20: creates 2^40 signatures using the
     *                     parameterset<br>
     *                     P = (2, (10, 10, 10, 10), (9, 9, 9, 3), (2, 2, 2, 2))
     * @param secureRandom not used by GMSS, the SHA1PRNG of the SUN Provider is always
     *                     used
     */
    public void initialize(int keySize, SecureRandom secureRandom)
    {

        KeyGenerationParameters kgp;
        if (keySize <= 10)
        { // create 2^10 keys
            int[] defh = {10};
            int[] defw = {3};
            int[] defk = {2};
            // XXX sec random neede?
            kgp = new GMSSKeyGenerationParameters(secureRandom, new GMSSParameters(defh.length, defh, defw, defk));
        }
        else if (keySize <= 20)
        { // create 2^20 keys
            int[] defh = {10, 10};
            int[] defw = {5, 4};
            int[] defk = {2, 2};
            kgp = new GMSSKeyGenerationParameters(secureRandom, new GMSSParameters(defh.length, defh, defw, defk));
        }
        else
        { // create 2^40 keys, keygen lasts around 80 seconds
            int[] defh = {10, 10, 10, 10};
            int[] defw = {9, 9, 9, 3};
            int[] defk = {2, 2, 2, 2};
            kgp = new GMSSKeyGenerationParameters(secureRandom, new GMSSParameters(defh.length, defh, defw, defk));
        }

        // call the initializer with the chosen parameters
        this.initialize(kgp);

    }


    /**
     * Initalizes the key pair generator using a parameter set as input
     */
    public void initialize(KeyGenerationParameters param)
    {

        this.gmssParams = (GMSSKeyGenerationParameters)param;

        // generate GMSSParameterset
        this.gmssPS = new GMSSParameters(gmssParams.getParameters().getNumOfLayers(), gmssParams.getParameters().getHeightOfTrees(),
            gmssParams.getParameters().getWinternitzParameter(), gmssParams.getParameters().getK());

        this.numLayer = gmssPS.getNumOfLayers();
        this.heightOfTrees = gmssPS.getHeightOfTrees();
        this.otsIndex = gmssPS.getWinternitzParameter();
        this.K = gmssPS.getK();

        // seeds
        this.currentSeeds = new byte[numLayer][mdLength];
        this.nextNextSeeds = new byte[numLayer - 1][mdLength];

        // construct SecureRandom for initial seed generation
        SecureRandom secRan = new SecureRandom();

        // generation of initial seeds
        for (int i = 0; i < numLayer; i++)
        {
            secRan.nextBytes(currentSeeds[i]);
            gmssRandom.nextSeed(currentSeeds[i]);
        }

        this.initialized = true;
    }

    /**
     * This method is called by generateKeyPair() in case that no other
     * initialization method has been called by the user
     */
    private void initializeDefault()
    {
        int[] defh = {10, 10, 10, 10};
        int[] defw = {3, 3, 3, 3};
        int[] defk = {2, 2, 2, 2};

        KeyGenerationParameters kgp = new GMSSKeyGenerationParameters(new SecureRandom(), new GMSSParameters(defh.length, defh, defw, defk));
        this.initialize(kgp);

    }

    public void init(KeyGenerationParameters param)
    {
        this.initialize(param);

    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        return genKeyPair();
    }
}
