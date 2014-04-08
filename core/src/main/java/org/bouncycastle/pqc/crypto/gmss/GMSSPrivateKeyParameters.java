package org.bouncycastle.pqc.crypto.gmss;

import java.util.Vector;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.crypto.gmss.util.GMSSRandom;
import org.bouncycastle.pqc.crypto.gmss.util.WinternitzOTSignature;
import org.bouncycastle.util.Arrays;


/**
 * This class provides a specification for a GMSS private key.
 */
public class GMSSPrivateKeyParameters
    extends GMSSKeyParameters
{
    private int[] index;

    private byte[][] currentSeeds;
    private byte[][] nextNextSeeds;

    private byte[][][] currentAuthPaths;
    private byte[][][] nextAuthPaths;

    private Treehash[][] currentTreehash;
    private Treehash[][] nextTreehash;

    private Vector[] currentStack;
    private Vector[] nextStack;

    private Vector[][] currentRetain;
    private Vector[][] nextRetain;

    private byte[][][] keep;

    private GMSSLeaf[] nextNextLeaf;
    private GMSSLeaf[] upperLeaf;
    private GMSSLeaf[] upperTreehashLeaf;

    private int[] minTreehash;

    private GMSSParameters gmssPS;

    private byte[][] nextRoot;
    private GMSSRootCalc[] nextNextRoot;

    private byte[][] currentRootSig;
    private GMSSRootSig[] nextRootSig;

    private GMSSDigestProvider digestProvider;

    private boolean used = false;

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

    /**
     * the number of Layers
     */
    private int numLayer;

    /**
     * The hash function used to construct the authentication trees
     */
    private Digest messDigestTrees;

    /**
     * The message digest length
     */
    private int mdLength;

    /**
     * The PRNG used for private key generation
     */
    private GMSSRandom gmssRandom;


    /**
     * The number of leafs of one tree of each layer
     */
    private int[] numLeafs;


    /**
     * Generates a new GMSS private key
     *
     * @param currentSeed      seed for the generation of private OTS keys for the
     *                         current subtrees
     * @param nextNextSeed     seed for the generation of private OTS keys for the next
     *                         subtrees
     * @param currentAuthPath  array of current authentication paths
     * @param nextAuthPath     array of next authentication paths
     * @param currentTreehash  array of current treehash instances
     * @param nextTreehash     array of next treehash instances
     * @param currentStack     array of current shared stacks
     * @param nextStack        array of next shared stacks
     * @param currentRetain    array of current retain stacks
     * @param nextRetain       array of next retain stacks
     * @param nextRoot         the roots of the next subtree
     * @param currentRootSig   array of signatures of the roots of the current subtrees
     * @param gmssParameterset the GMSS Parameterset
     * @see org.bouncycastle.pqc.crypto.gmss.GMSSKeyPairGenerator
     */

    public GMSSPrivateKeyParameters(byte[][] currentSeed, byte[][] nextNextSeed,
                                    byte[][][] currentAuthPath, byte[][][] nextAuthPath,
                                    Treehash[][] currentTreehash, Treehash[][] nextTreehash,
                                    Vector[] currentStack, Vector[] nextStack,
                                    Vector[][] currentRetain, Vector[][] nextRetain, byte[][] nextRoot,
                                    byte[][] currentRootSig, GMSSParameters gmssParameterset,
                                    GMSSDigestProvider digestProvider)
    {
        this(null, currentSeed, nextNextSeed, currentAuthPath, nextAuthPath,
            null, currentTreehash, nextTreehash, currentStack, nextStack,
            currentRetain, nextRetain, null, null, null, null, nextRoot,
            null, currentRootSig, null, gmssParameterset, digestProvider);
    }

    /**
     * /**
     *
     * @param index             tree indices
     * @param keep              keep array for the authPath algorithm
     * @param currentTreehash   treehash for authPath algorithm of current tree
     * @param nextTreehash      treehash for authPath algorithm of next tree (TREE+)
     * @param currentStack      shared stack for authPath algorithm of current tree
     * @param nextStack         shared stack for authPath algorithm of next tree (TREE+)
     * @param currentRetain     retain stack for authPath algorithm of current tree
     * @param nextRetain        retain stack for authPath algorithm of next tree (TREE+)
     * @param nextNextLeaf      array of upcoming leafs of the tree after next (LEAF++) of
     *                          each layer
     * @param upperLeaf         needed for precomputation of upper nodes
     * @param upperTreehashLeaf needed for precomputation of upper treehash nodes
     * @param minTreehash       index of next treehash instance to receive an update
     * @param nextRoot          the roots of the next trees (ROOT+)
     * @param nextNextRoot      the roots of the tree after next (ROOT++)
     * @param currentRootSig    array of signatures of the roots of the current subtrees
     *                          (SIG)
     * @param nextRootSig       array of signatures of the roots of the next subtree
     *                          (SIG+)
     * @param gmssParameterset  the GMSS Parameterset
     */
    public GMSSPrivateKeyParameters(int[] index, byte[][] currentSeeds,
                                    byte[][] nextNextSeeds, byte[][][] currentAuthPaths,
                                    byte[][][] nextAuthPaths, byte[][][] keep,
                                    Treehash[][] currentTreehash, Treehash[][] nextTreehash,
                                    Vector[] currentStack, Vector[] nextStack,
                                    Vector[][] currentRetain, Vector[][] nextRetain,
                                    GMSSLeaf[] nextNextLeaf, GMSSLeaf[] upperLeaf,
                                    GMSSLeaf[] upperTreehashLeaf, int[] minTreehash, byte[][] nextRoot,
                                    GMSSRootCalc[] nextNextRoot, byte[][] currentRootSig,
                                    GMSSRootSig[] nextRootSig, GMSSParameters gmssParameterset,
                                    GMSSDigestProvider digestProvider)
    {

        super(true, gmssParameterset);

        // construct message digest

        this.messDigestTrees = digestProvider.get();
        this.mdLength = messDigestTrees.getDigestSize();


        // Parameter
        this.gmssPS = gmssParameterset;
        this.otsIndex = gmssParameterset.getWinternitzParameter();
        this.K = gmssParameterset.getK();
        this.heightOfTrees = gmssParameterset.getHeightOfTrees();
        // initialize numLayer
        this.numLayer = gmssPS.getNumOfLayers();

        // initialize index if null
        if (index == null)
        {
            this.index = new int[numLayer];
            for (int i = 0; i < numLayer; i++)
            {
                this.index[i] = 0;
            }
        }
        else
        {
            this.index = index;
        }

        this.currentSeeds = currentSeeds;
        this.nextNextSeeds = nextNextSeeds;

        this.currentAuthPaths = currentAuthPaths;
        this.nextAuthPaths = nextAuthPaths;

        // initialize keep if null
        if (keep == null)
        {
            this.keep = new byte[numLayer][][];
            for (int i = 0; i < numLayer; i++)
            {
                this.keep[i] = new byte[(int)Math.floor(heightOfTrees[i] / 2)][mdLength];
            }
        }
        else
        {
            this.keep = keep;
        }

        // initialize stack if null
        if (currentStack == null)
        {
            this.currentStack = new Vector[numLayer];
            for (int i = 0; i < numLayer; i++)
            {
                this.currentStack[i] = new Vector();
            }
        }
        else
        {
            this.currentStack = currentStack;
        }

        // initialize nextStack if null
        if (nextStack == null)
        {
            this.nextStack = new Vector[numLayer - 1];
            for (int i = 0; i < numLayer - 1; i++)
            {
                this.nextStack[i] = new Vector();
            }
        }
        else
        {
            this.nextStack = nextStack;
        }

        this.currentTreehash = currentTreehash;
        this.nextTreehash = nextTreehash;

        this.currentRetain = currentRetain;
        this.nextRetain = nextRetain;

        this.nextRoot = nextRoot;

        this.digestProvider = digestProvider;

        if (nextNextRoot == null)
        {
            this.nextNextRoot = new GMSSRootCalc[numLayer - 1];
            for (int i = 0; i < numLayer - 1; i++)
            {
                this.nextNextRoot[i] = new GMSSRootCalc(
                    this.heightOfTrees[i + 1], this.K[i + 1], this.digestProvider);
            }
        }
        else
        {
            this.nextNextRoot = nextNextRoot;
        }
        this.currentRootSig = currentRootSig;

        // calculate numLeafs
        numLeafs = new int[numLayer];
        for (int i = 0; i < numLayer; i++)
        {
            numLeafs[i] = 1 << heightOfTrees[i];
        }
        // construct PRNG
        this.gmssRandom = new GMSSRandom(messDigestTrees);

        if (numLayer > 1)
        {
            // construct the nextNextLeaf (LEAFs++) array for upcoming leafs in
            // tree after next (TREE++)
            if (nextNextLeaf == null)
            {
                this.nextNextLeaf = new GMSSLeaf[numLayer - 2];
                for (int i = 0; i < numLayer - 2; i++)
                {
                    this.nextNextLeaf[i] = new GMSSLeaf(digestProvider.get(), otsIndex[i + 1], numLeafs[i + 2], this.nextNextSeeds[i]);
                }
            }
            else
            {
                this.nextNextLeaf = nextNextLeaf;
            }
        }
        else
        {
            this.nextNextLeaf = new GMSSLeaf[0];
        }

        // construct the upperLeaf array for upcoming leafs in tree over the
        // actual
        if (upperLeaf == null)
        {
            this.upperLeaf = new GMSSLeaf[numLayer - 1];
            for (int i = 0; i < numLayer - 1; i++)
            {
                this.upperLeaf[i] = new GMSSLeaf(digestProvider.get(), otsIndex[i],
                    numLeafs[i + 1], this.currentSeeds[i]);
            }
        }
        else
        {
            this.upperLeaf = upperLeaf;
        }

        // construct the leafs for upcoming leafs in treehashs in tree over the
        // actual
        if (upperTreehashLeaf == null)
        {
            this.upperTreehashLeaf = new GMSSLeaf[numLayer - 1];
            for (int i = 0; i < numLayer - 1; i++)
            {
                this.upperTreehashLeaf[i] = new GMSSLeaf(digestProvider.get(), otsIndex[i], numLeafs[i + 1]);
            }
        }
        else
        {
            this.upperTreehashLeaf = upperTreehashLeaf;
        }

        if (minTreehash == null)
        {
            this.minTreehash = new int[numLayer - 1];
            for (int i = 0; i < numLayer - 1; i++)
            {
                this.minTreehash[i] = -1;
            }
        }
        else
        {
            this.minTreehash = minTreehash;
        }

        // construct the nextRootSig (RootSig++)
        byte[] dummy = new byte[mdLength];
        byte[] OTSseed = new byte[mdLength];
        if (nextRootSig == null)
        {
            this.nextRootSig = new GMSSRootSig[numLayer - 1];
            for (int i = 0; i < numLayer - 1; i++)
            {
                System.arraycopy(currentSeeds[i], 0, dummy, 0, mdLength);
                gmssRandom.nextSeed(dummy);
                OTSseed = gmssRandom.nextSeed(dummy);
                this.nextRootSig[i] = new GMSSRootSig(digestProvider.get(), otsIndex[i],
                    heightOfTrees[i + 1]);
                this.nextRootSig[i].initSign(OTSseed, nextRoot[i]);
            }
        }
        else
        {
            this.nextRootSig = nextRootSig;
        }
    }

    // we assume this only gets called from nextKey so used is never copied.
    private GMSSPrivateKeyParameters(GMSSPrivateKeyParameters original)
    {
        super(true, original.getParameters());

        this.index = Arrays.clone(original.index);
        this.currentSeeds = Arrays.clone(original.currentSeeds);
        this.nextNextSeeds = Arrays.clone(original.nextNextSeeds);
        this.currentAuthPaths = Arrays.clone(original.currentAuthPaths);
        this.nextAuthPaths = Arrays.clone(original.nextAuthPaths);
        this.currentTreehash = original.currentTreehash;
        this.nextTreehash = original.nextTreehash;
        this.currentStack = original.currentStack;
        this.nextStack = original.nextStack;
        this.currentRetain = original.currentRetain;
        this.nextRetain = original.nextRetain;
        this.keep = Arrays.clone(original.keep);
        this.nextNextLeaf = original.nextNextLeaf;
        this.upperLeaf = original.upperLeaf;
        this.upperTreehashLeaf = original.upperTreehashLeaf;
        this.minTreehash = original.minTreehash;
        this.gmssPS = original.gmssPS;
        this.nextRoot = Arrays.clone(original.nextRoot);
        this.nextNextRoot = original.nextNextRoot;
        this.currentRootSig = original.currentRootSig;
        this.nextRootSig = original.nextRootSig;
        this.digestProvider = original.digestProvider;
        this.heightOfTrees = original.heightOfTrees;
        this.otsIndex = original.otsIndex;
        this.K = original.K;
        this.numLayer = original.numLayer;
        this.messDigestTrees = original.messDigestTrees;
        this.mdLength = original.mdLength;
        this.gmssRandom = original.gmssRandom;
        this.numLeafs = original.numLeafs;
    }

    public boolean isUsed()
    {
        return this.used;
    }

    public void markUsed()
    {
        this.used = true;
    }

    public GMSSPrivateKeyParameters nextKey()
    {
        GMSSPrivateKeyParameters nKey = new GMSSPrivateKeyParameters(this);

        nKey.nextKey(gmssPS.getNumOfLayers() - 1);

        return nKey;
    }

    /**
     * This method updates the GMSS private key for the next signature
     *
     * @param layer the layer where the next key is processed
     */
    private void nextKey(int layer)
    {
        // only for lowest layer ( other layers indices are raised in nextTree()
        // method )
        if (layer == numLayer - 1)
        {
            index[layer]++;
        } // else System.out.println(" --- nextKey on layer " + layer + "
        // index is now : " + index[layer]);

        // if tree of this layer is depleted
        if (index[layer] == numLeafs[layer])
        {
            if (numLayer != 1)
            {
                nextTree(layer);
                index[layer] = 0;
            }
        }
        else
        {
            updateKey(layer);
        }
    }

    /**
     * Switch to next subtree if the current one is depleted
     *
     * @param layer the layer where the next tree is processed
     */
    private void nextTree(int layer)
    {
        // System.out.println("NextTree method called on layer " + layer);
        // dont create next tree for the top layer
        if (layer > 0)
        {
            // raise index for upper layer
            index[layer - 1]++;

            // test if it is already the last tree
            boolean lastTree = true;
            int z = layer;
            do
            {
                z--;
                if (index[z] < numLeafs[z])
                {
                    lastTree = false;
                }
            }
            while (lastTree && (z > 0));

            // only construct next subtree if last one is not already in use
            if (!lastTree)
            {
                gmssRandom.nextSeed(currentSeeds[layer]);

                // last step of distributed signature calculation
                nextRootSig[layer - 1].updateSign();

                // last step of distributed leaf calculation for nextNextLeaf
                if (layer > 1)
                {
                    nextNextLeaf[layer - 1 - 1] = nextNextLeaf[layer - 1 - 1].nextLeaf();
                }

                // last step of distributed leaf calculation for upper leaf
                upperLeaf[layer - 1] = upperLeaf[layer - 1].nextLeaf();

                // last step of distributed leaf calculation for all treehashs

                if (minTreehash[layer - 1] >= 0)
                {
                    upperTreehashLeaf[layer - 1] = upperTreehashLeaf[layer - 1].nextLeaf();
                    byte[] leaf = this.upperTreehashLeaf[layer - 1].getLeaf();
                    // if update is required use the precomputed leaf to update
                    // treehash
                    try
                    {
                        currentTreehash[layer - 1][minTreehash[layer - 1]]
                            .update(this.gmssRandom, leaf);
                        // System.out.println("UUUpdated TH " +
                        // minTreehash[layer - 1]);
                        if (currentTreehash[layer - 1][minTreehash[layer - 1]]
                            .wasFinished())
                        {
                            // System.out.println("FFFinished TH " +
                            // minTreehash[layer - 1]);
                        }
                    }
                    catch (Exception e)
                    {
                        System.out.println(e);
                    }
                }

                // last step of nextNextAuthRoot calculation
                this.updateNextNextAuthRoot(layer);

                // ******************************************************** /

                // NOW: advance to next tree on layer 'layer'

                // NextRootSig --> currentRootSigs
                this.currentRootSig[layer - 1] = nextRootSig[layer - 1]
                    .getSig();

                // -----------------------

                // nextTreehash --> currentTreehash
                // nextNextTreehash --> nextTreehash
                for (int i = 0; i < heightOfTrees[layer] - K[layer]; i++)
                {
                    this.currentTreehash[layer][i] = this.nextTreehash[layer - 1][i];
                    this.nextTreehash[layer - 1][i] = this.nextNextRoot[layer - 1]
                        .getTreehash()[i];
                }

                // NextAuthPath --> currentAuthPath
                // nextNextAuthPath --> nextAuthPath
                for (int i = 0; i < heightOfTrees[layer]; i++)
                {
                    System.arraycopy(nextAuthPaths[layer - 1][i], 0,
                        currentAuthPaths[layer][i], 0, mdLength);
                    System.arraycopy(nextNextRoot[layer - 1].getAuthPath()[i],
                        0, nextAuthPaths[layer - 1][i], 0, mdLength);
                }

                // nextRetain --> currentRetain
                // nextNextRetain --> nextRetain
                for (int i = 0; i < K[layer] - 1; i++)
                {
                    this.currentRetain[layer][i] = this.nextRetain[layer - 1][i];
                    this.nextRetain[layer - 1][i] = this.nextNextRoot[layer - 1]
                        .getRetain()[i];
                }

                // nextStack --> currentStack
                this.currentStack[layer] = this.nextStack[layer - 1];
                // nextNextStack --> nextStack
                this.nextStack[layer - 1] = this.nextNextRoot[layer - 1]
                    .getStack();

                // nextNextRoot --> nextRoot
                this.nextRoot[layer - 1] = this.nextNextRoot[layer - 1]
                    .getRoot();
                // -----------------------

                // -----------------
                byte[] OTSseed = new byte[mdLength];
                byte[] dummy = new byte[mdLength];
                // gmssRandom.setSeed(currentSeeds[layer]);
                System
                    .arraycopy(currentSeeds[layer - 1], 0, dummy, 0,
                        mdLength);
                OTSseed = gmssRandom.nextSeed(dummy); // only need OTSSeed
                OTSseed = gmssRandom.nextSeed(dummy);
                OTSseed = gmssRandom.nextSeed(dummy);
                // nextWinSig[layer-1]=new
                // GMSSWinSig(OTSseed,algNames,otsIndex[layer-1],heightOfTrees[layer],nextRoot[layer-1]);
                nextRootSig[layer - 1].initSign(OTSseed, nextRoot[layer - 1]);

                // nextKey for upper layer
                nextKey(layer - 1);
            }
        }
    }

    /**
     * This method computes the authpath (AUTH) for the current tree,
     * Additionally the root signature for the next tree (SIG+), the authpath
     * (AUTH++) and root (ROOT++) for the tree after next in layer
     * <code>layer</code>, and the LEAF++^1 for the next next tree in the
     * layer above are updated This method is used by nextKey()
     *
     * @param layer
     */
    private void updateKey(int layer)
    {
        // ----------current tree processing of actual layer---------
        // compute upcoming authpath for current Tree (AUTH)
        computeAuthPaths(layer);

        // -----------distributed calculations part------------
        // not for highest tree layer
        if (layer > 0)
        {

            // compute (partial) next leaf on TREE++ (not on layer 1 and 0)
            if (layer > 1)
            {
                nextNextLeaf[layer - 1 - 1] = nextNextLeaf[layer - 1 - 1].nextLeaf();
            }

            // compute (partial) next leaf on tree above (not on layer 0)
            upperLeaf[layer - 1] = upperLeaf[layer - 1].nextLeaf();

            // compute (partial) next leaf for all treehashs on tree above (not
            // on layer 0)

            int t = (int)Math
                .floor((double)(this.getNumLeafs(layer) * 2)
                    / (double)(this.heightOfTrees[layer - 1] - this.K[layer - 1]));

            if (index[layer] % t == 1)
            {
                // System.out.println(" layer: " + layer + " index: " +
                // index[layer] + " t : " + t);

                // take precomputed node for treehash update
                // ------------------------------------------------
                if (index[layer] > 1 && minTreehash[layer - 1] >= 0)
                {
                    byte[] leaf = this.upperTreehashLeaf[layer - 1].getLeaf();
                    // if update is required use the precomputed leaf to update
                    // treehash
                    try
                    {
                        currentTreehash[layer - 1][minTreehash[layer - 1]]
                            .update(this.gmssRandom, leaf);
                        // System.out.println("Updated TH " + minTreehash[layer
                        // - 1]);
                        if (currentTreehash[layer - 1][minTreehash[layer - 1]]
                            .wasFinished())
                        {
                            // System.out.println("Finished TH " +
                            // minTreehash[layer - 1]);
                        }
                    }
                    catch (Exception e)
                    {
                        System.out.println(e);
                    }
                    // ------------------------------------------------
                }

                // initialize next leaf precomputation
                // ------------------------------------------------

                // get lowest index of treehashs
                this.minTreehash[layer - 1] = getMinTreehashIndex(layer - 1);

                if (this.minTreehash[layer - 1] >= 0)
                {
                    // initialize leaf
                    byte[] seed = this.currentTreehash[layer - 1][this.minTreehash[layer - 1]]
                        .getSeedActive();
                    this.upperTreehashLeaf[layer - 1] = new GMSSLeaf(
                        this.digestProvider.get(), this.otsIndex[layer - 1], t, seed);
                    this.upperTreehashLeaf[layer - 1] = this.upperTreehashLeaf[layer - 1].nextLeaf();
                    // System.out.println("restarted treehashleaf (" + (layer -
                    // 1) + "," + this.minTreehash[layer - 1] + ")");
                }
                // ------------------------------------------------

            }
            else
            {
                // update the upper leaf for the treehash one step
                if (this.minTreehash[layer - 1] >= 0)
                {
                    this.upperTreehashLeaf[layer - 1] = this.upperTreehashLeaf[layer - 1].nextLeaf();
                    // if (minTreehash[layer - 1] > 3)
                    // System.out.print("#");
                }
            }

            // compute (partial) the signature of ROOT+ (RootSig+) (not on top
            // layer)
            nextRootSig[layer - 1].updateSign();

            // compute (partial) AUTHPATH++ & ROOT++ (not on top layer)
            if (index[layer] == 1)
            {
                // init root and authpath calculation for tree after next
                // (AUTH++, ROOT++)
                this.nextNextRoot[layer - 1].initialize(new Vector());
            }

            // update root and authpath calculation for tree after next (AUTH++,
            // ROOT++)
            this.updateNextNextAuthRoot(layer);
        }
        // ----------- end distributed calculations part-----------------
    }

    /**
     * This method returns the index of the next Treehash instance that should
     * receive an update
     *
     * @param layer the layer of the GMSS tree
     * @return index of the treehash instance that should get the update
     */
    private int getMinTreehashIndex(int layer)
    {
        int minTreehash = -1;
        for (int h = 0; h < heightOfTrees[layer] - K[layer]; h++)
        {
            if (currentTreehash[layer][h].wasInitialized()
                && !currentTreehash[layer][h].wasFinished())
            {
                if (minTreehash == -1)
                {
                    minTreehash = h;
                }
                else if (currentTreehash[layer][h].getLowestNodeHeight() < currentTreehash[layer][minTreehash]
                    .getLowestNodeHeight())
                {
                    minTreehash = h;
                }
            }
        }
        return minTreehash;
    }

    /**
     * Computes the upcoming currentAuthpath of layer <code>layer</code> using
     * the revisited authentication path computation of Dahmen/Schneider 2008
     *
     * @param layer the actual layer
     */
    private void computeAuthPaths(int layer)
    {

        int Phi = index[layer];
        int H = heightOfTrees[layer];
        int K = this.K[layer];

        // update all nextSeeds for seed scheduling
        for (int i = 0; i < H - K; i++)
        {
            currentTreehash[layer][i].updateNextSeed(gmssRandom);
        }

        // STEP 1 of Algorithm
        int Tau = heightOfPhi(Phi);

        byte[] OTSseed = new byte[mdLength];
        OTSseed = gmssRandom.nextSeed(currentSeeds[layer]);

        // STEP 2 of Algorithm
        // if phi's parent on height tau + 1 if left node, store auth_tau
        // in keep_tau.
        // TODO check it, formerly was
        // int L = Phi / (int) Math.floor(Math.pow(2, Tau + 1));
        // L %= 2;
        int L = (Phi >>> (Tau + 1)) & 1;

        byte[] tempKeep = new byte[mdLength];
        // store the keep node not in keep[layer][tau/2] because it might be in
        // use
        // wait until the space is freed in step 4a
        if (Tau < H - 1 && L == 0)
        {
            System.arraycopy(currentAuthPaths[layer][Tau], 0, tempKeep, 0,
                mdLength);
        }

        byte[] help = new byte[mdLength];
        // STEP 3 of Algorithm
        // if phi is left child, compute and store leaf for next currentAuthPath
        // path,
        // (obtained by veriying current signature)
        if (Tau == 0)
        {
            // LEAFCALC !!!
            if (layer == numLayer - 1)
            { // lowest layer computes the
                // necessary leaf completely at this
                // time
                WinternitzOTSignature ots = new WinternitzOTSignature(OTSseed,
                    digestProvider.get(), otsIndex[layer]);
                help = ots.getPublicKey();
            }
            else
            { // other layers use the precomputed leafs in
                // nextNextLeaf
                byte[] dummy = new byte[mdLength];
                System.arraycopy(currentSeeds[layer], 0, dummy, 0, mdLength);
                gmssRandom.nextSeed(dummy);
                help = upperLeaf[layer].getLeaf();
                this.upperLeaf[layer].initLeafCalc(dummy);

                // WinternitzOTSVerify otsver = new
                // WinternitzOTSVerify(algNames, otsIndex[layer]);
                // byte[] help2 = otsver.Verify(currentRoot[layer],
                // currentRootSig[layer]);
                // System.out.println(" --- " + layer + " " +
                // ByteUtils.toHexString(help) + " " +
                // ByteUtils.toHexString(help2));
            }
            System.arraycopy(help, 0, currentAuthPaths[layer][0], 0, mdLength);
        }
        else
        {
            // STEP 4a of Algorithm
            // get new left currentAuthPath node on height tau
            byte[] toBeHashed = new byte[mdLength << 1];
            System.arraycopy(currentAuthPaths[layer][Tau - 1], 0, toBeHashed,
                0, mdLength);
            // free the shared keep[layer][tau/2]
            System.arraycopy(keep[layer][(int)Math.floor((Tau - 1) / 2)], 0,
                toBeHashed, mdLength, mdLength);
            messDigestTrees.update(toBeHashed, 0, toBeHashed.length);
            currentAuthPaths[layer][Tau] = new byte[messDigestTrees.getDigestSize()];
            messDigestTrees.doFinal(currentAuthPaths[layer][Tau], 0);

            // STEP 4b and 4c of Algorithm
            // copy right nodes to currentAuthPath on height 0..Tau-1
            for (int i = 0; i < Tau; i++)
            {

                // STEP 4b of Algorithm
                // 1st: copy from treehashs
                if (i < H - K)
                {
                    if (currentTreehash[layer][i].wasFinished())
                    {
                        System.arraycopy(currentTreehash[layer][i]
                            .getFirstNode(), 0, currentAuthPaths[layer][i],
                            0, mdLength);
                        currentTreehash[layer][i].destroy();
                    }
                    else
                    {
                        System.err
                            .println("Treehash ("
                                + layer
                                + ","
                                + i
                                + ") not finished when needed in AuthPathComputation");
                    }
                }

                // 2nd: copy precomputed values from Retain
                if (i < H - 1 && i >= H - K)
                {
                    if (currentRetain[layer][i - (H - K)].size() > 0)
                    {
                        // pop element from retain
                        System.arraycopy(currentRetain[layer][i - (H - K)]
                            .lastElement(), 0, currentAuthPaths[layer][i],
                            0, mdLength);
                        currentRetain[layer][i - (H - K)]
                            .removeElementAt(currentRetain[layer][i
                                - (H - K)].size() - 1);
                    }
                }

                // STEP 4c of Algorithm
                // initialize new stack at heights 0..Tau-1
                if (i < H - K)
                {
                    // create stacks anew
                    int startPoint = Phi + 3 * (1 << i);
                    if (startPoint < numLeafs[layer])
                    {
                        // if (layer < 2) {
                        // System.out.println("initialized TH " + i + " on layer
                        // " + layer);
                        // }
                        currentTreehash[layer][i].initialize();
                    }
                }
            }
        }

        // now keep space is free to use
        if (Tau < H - 1 && L == 0)
        {
            System.arraycopy(tempKeep, 0,
                keep[layer][(int)Math.floor(Tau / 2)], 0, mdLength);
        }

        // only update empty stack at height h if all other stacks have
        // tailnodes with height >h
        // finds active stack with lowest node height, choses lower index in
        // case of tie

        // on the lowest layer leafs must be computed at once, no precomputation
        // is possible. So all treehash updates are done at once here
        if (layer == numLayer - 1)
        {
            for (int tmp = 1; tmp <= (H - K) / 2; tmp++)
            {
                // index of the treehash instance that receives the next update
                int minTreehash = getMinTreehashIndex(layer);

                // if active treehash is found update with a leaf
                if (minTreehash >= 0)
                {
                    try
                    {
                        byte[] seed = new byte[mdLength];
                        System.arraycopy(
                            this.currentTreehash[layer][minTreehash]
                                .getSeedActive(), 0, seed, 0, mdLength);
                        byte[] seed2 = gmssRandom.nextSeed(seed);
                        WinternitzOTSignature ots = new WinternitzOTSignature(
                            seed2, this.digestProvider.get(), this.otsIndex[layer]);
                        byte[] leaf = ots.getPublicKey();
                        currentTreehash[layer][minTreehash].update(
                            this.gmssRandom, leaf);
                    }
                    catch (Exception e)
                    {
                        System.out.println(e);
                    }
                }
            }
        }
        else
        { // on higher layers the updates are done later
            this.minTreehash[layer] = getMinTreehashIndex(layer);
        }
    }

    /**
     * Returns the largest h such that 2^h | Phi
     *
     * @param Phi the leaf index
     * @return The largest <code>h</code> with <code>2^h | Phi</code> if
     *         <code>Phi!=0</code> else return <code>-1</code>
     */
    private int heightOfPhi(int Phi)
    {
        if (Phi == 0)
        {
            return -1;
        }
        int Tau = 0;
        int modul = 1;
        while (Phi % modul == 0)
        {
            modul *= 2;
            Tau += 1;
        }
        return Tau - 1;
    }

    /**
     * Updates the authentication path and root calculation for the tree after
     * next (AUTH++, ROOT++) in layer <code>layer</code>
     *
     * @param layer
     */
    private void updateNextNextAuthRoot(int layer)
    {

        byte[] OTSseed = new byte[mdLength];
        OTSseed = gmssRandom.nextSeed(nextNextSeeds[layer - 1]);

        // get the necessary leaf
        if (layer == numLayer - 1)
        { // lowest layer computes the necessary
            // leaf completely at this time
            WinternitzOTSignature ots = new WinternitzOTSignature(OTSseed,
                digestProvider.get(), otsIndex[layer]);
            this.nextNextRoot[layer - 1].update(nextNextSeeds[layer - 1], ots
                .getPublicKey());
        }
        else
        { // other layers use the precomputed leafs in nextNextLeaf
            this.nextNextRoot[layer - 1].update(nextNextSeeds[layer - 1], nextNextLeaf[layer - 1].getLeaf());
            this.nextNextLeaf[layer - 1].initLeafCalc(nextNextSeeds[layer - 1]);
        }
    }

    public int[] getIndex()
    {
        return index;
    }

    /**
     * @return The current index of layer i
     */
    public int getIndex(int i)
    {
        return index[i];
    }

    public byte[][] getCurrentSeeds()
    {
        return Arrays.clone(currentSeeds);
    }

    public byte[][][] getCurrentAuthPaths()
    {
        return Arrays.clone(currentAuthPaths);
    }

    /**
     * @return The one-time signature of the root of the current subtree
     */
    public byte[] getSubtreeRootSig(int i)
    {
        return currentRootSig[i];
    }


    public GMSSDigestProvider getName()
    {
        return digestProvider;
    }

    /**
     * @return The number of leafs of each tree of layer i
     */
    public int getNumLeafs(int i)
    {
        return numLeafs[i];
    }
}
