package org.bouncycastle.pqc.crypto.gmss;

import java.util.Enumeration;
import java.util.Vector;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.encoders.Hex;


/**
 * This class computes a whole Merkle tree and saves the needed values for
 * AuthPath computation. It is used for precomputation of the root of a
 * following tree. After initialization, 2^H updates are required to complete
 * the root. Every update requires one leaf value as parameter. While computing
 * the root all initial values for the authentication path algorithm (treehash,
 * auth, retain) are stored for later use.
 */
public class GMSSRootCalc
{

    /**
     * max height of the tree
     */
    private int heightOfTree;

    /**
     * length of the messageDigest
     */
    private int mdLength;

    /**
     * the treehash instances of the tree
     */
    private Treehash[] treehash;

    /**
     * stores the retain nodes for authPath computation
     */
    private Vector[] retain;

    /**
     * finally stores the root of the tree when finished
     */
    private byte[] root;

    /**
     * stores the authentication path y_1(i), i = 0..H-1
     */
    private byte[][] AuthPath;

    /**
     * the value K for the authentication path computation
     */
    private int K;

    /**
     * Vector element that stores the nodes on the stack
     */
    private Vector tailStack;

    /**
     * stores the height of all nodes laying on the tailStack
     */
    private Vector heightOfNodes;
    /**
     * The hash function used for the construction of the authentication trees
     */
    private Digest messDigestTree;

    /**
     * An array of strings containing the name of the hash function used to
     * construct the authentication trees and used by the OTS.
     */
    private GMSSDigestProvider digestProvider;

    /**
     * stores the index of the current node on each height of the tree
     */
    private int[] index;

    /**
     * true if instance was already initialized, false otherwise
     */
    private boolean isInitialized;

    /**
     * true it instance was finished
     */
    private boolean isFinished;

    /**
     * Integer that stores the index of the next seed that has to be omitted to
     * the treehashs
     */
    private int indexForNextSeed;

    /**
     * temporary integer that stores the height of the next treehash instance
     * that gets initialized with a seed
     */
    private int heightOfNextSeed;

    /**
     * This constructor regenerates a prior treehash object
     *
     * @param digest     an array of strings, containing the digest of the used hash
     *                 function and PRNG and the digest of the corresponding
     *                 provider
     * @param statByte status bytes
     * @param statInt  status ints
     */
    public GMSSRootCalc(Digest digest, byte[][] statByte, int[] statInt,
                        Treehash[] treeH, Vector[] ret)
    {
        this.messDigestTree = digestProvider.get();
        this.digestProvider = digestProvider;
        // decode statInt
        this.heightOfTree = statInt[0];
        this.mdLength = statInt[1];
        this.K = statInt[2];
        this.indexForNextSeed = statInt[3];
        this.heightOfNextSeed = statInt[4];
        if (statInt[5] == 1)
        {
            this.isFinished = true;
        }
        else
        {
            this.isFinished = false;
        }
        if (statInt[6] == 1)
        {
            this.isInitialized = true;
        }
        else
        {
            this.isInitialized = false;
        }

        int tailLength = statInt[7];

        this.index = new int[heightOfTree];
        for (int i = 0; i < heightOfTree; i++)
        {
            this.index[i] = statInt[8 + i];
        }

        this.heightOfNodes = new Vector();
        for (int i = 0; i < tailLength; i++)
        {
            this.heightOfNodes.addElement(Integers.valueOf(statInt[8 + heightOfTree
                + i]));
        }

        // decode statByte
        this.root = statByte[0];

        this.AuthPath = new byte[heightOfTree][mdLength];
        for (int i = 0; i < heightOfTree; i++)
        {
            this.AuthPath[i] = statByte[1 + i];
        }

        this.tailStack = new Vector();
        for (int i = 0; i < tailLength; i++)
        {
            this.tailStack.addElement(statByte[1 + heightOfTree + i]);
        }

        // decode treeH
        this.treehash = GMSSUtils.clone(treeH);

        // decode ret
        this.retain = GMSSUtils.clone(ret);
    }

    /**
     * Constructor
     *
     * @param heightOfTree maximal height of the tree
     * @param digestProvider       an array of strings, containing the name of the used hash
     *                     function and PRNG and the name of the corresponding
     *                     provider
     */
    public GMSSRootCalc(int heightOfTree, int K, GMSSDigestProvider digestProvider)
    {
        this.heightOfTree = heightOfTree;
        this.digestProvider = digestProvider;
        this.messDigestTree = digestProvider.get();
        this.mdLength = messDigestTree.getDigestSize();
        this.K = K;
        this.index = new int[heightOfTree];
        this.AuthPath = new byte[heightOfTree][mdLength];
        this.root = new byte[mdLength];
        // this.treehash = new Treehash[this.heightOfTree - this.K];
        this.retain = new Vector[this.K - 1];
        for (int i = 0; i < K - 1; i++)
        {
            this.retain[i] = new Vector();
        }

    }

    /**
     * Initializes the calculation of a new root
     *
     * @param sharedStack the stack shared by all treehash instances of this tree
     */
    public void initialize(Vector sharedStack)
    {
        this.treehash = new Treehash[this.heightOfTree - this.K];
        for (int i = 0; i < this.heightOfTree - this.K; i++)
        {
            this.treehash[i] = new Treehash(sharedStack, i, this.digestProvider.get());
        }

        this.index = new int[heightOfTree];
        this.AuthPath = new byte[heightOfTree][mdLength];
        this.root = new byte[mdLength];

        this.tailStack = new Vector();
        this.heightOfNodes = new Vector();
        this.isInitialized = true;
        this.isFinished = false;

        for (int i = 0; i < heightOfTree; i++)
        {
            this.index[i] = -1;
        }

        this.retain = new Vector[this.K - 1];
        for (int i = 0; i < K - 1; i++)
        {
            this.retain[i] = new Vector();
        }

        this.indexForNextSeed = 3;
        this.heightOfNextSeed = 0;
    }

    /**
     * updates the root with one leaf and stores needed values in retain,
     * treehash or authpath. Additionally counts the seeds used. This method is
     * used when performing the updates for TREE++.
     *
     * @param seed the initial seed for treehash: seedNext
     * @param leaf the height of the treehash
     */
    public void update(byte[] seed, byte[] leaf)
    {
        if (this.heightOfNextSeed < (this.heightOfTree - this.K)
            && this.indexForNextSeed - 2 == index[0])
        {
            this.initializeTreehashSeed(seed, this.heightOfNextSeed);
            this.heightOfNextSeed++;
            this.indexForNextSeed *= 2;
        }
        // now call the simple update
        this.update(leaf);
    }

    /**
     * Updates the root with one leaf and stores the needed values in retain,
     * treehash or authpath
     */
    public void update(byte[] leaf)
    {

        if (isFinished)
        {
            System.out.print("Too much updates for Tree!!");
            return;
        }
        if (!isInitialized)
        {
            System.err.println("GMSSRootCalc not initialized!");
            return;
        }

        // a new leaf was omitted, so raise index on lowest layer
        index[0]++;

        // store the nodes on the lowest layer in treehash or authpath
        if (index[0] == 1)
        {
            System.arraycopy(leaf, 0, AuthPath[0], 0, mdLength);
        }
        else if (index[0] == 3)
        {
            // store in treehash only if K < H
            if (heightOfTree > K)
            {
                treehash[0].setFirstNode(leaf);
            }
        }

        if ((index[0] - 3) % 2 == 0 && index[0] >= 3)
        {
            // store in retain if K = H
            if (heightOfTree == K)
            // TODO: check it
            {
                retain[0].insertElementAt(leaf, 0);
            }
        }

        // if first update to this tree is made
        if (index[0] == 0)
        {
            tailStack.addElement(leaf);
            heightOfNodes.addElement(Integers.valueOf(0));
        }
        else
        {

            byte[] help = new byte[mdLength];
            byte[] toBeHashed = new byte[mdLength << 1];

            // store the new leaf in help
            System.arraycopy(leaf, 0, help, 0, mdLength);
            int helpHeight = 0;
            // while top to nodes have same height
            while (tailStack.size() > 0
                && helpHeight == ((Integer)heightOfNodes.lastElement())
                .intValue())
            {

                // help <-- hash(stack top element || help)
                System.arraycopy(tailStack.lastElement(), 0, toBeHashed, 0,
                    mdLength);
                tailStack.removeElementAt(tailStack.size() - 1);
                heightOfNodes.removeElementAt(heightOfNodes.size() - 1);
                System.arraycopy(help, 0, toBeHashed, mdLength, mdLength);

                messDigestTree.update(toBeHashed, 0, toBeHashed.length);
                help = new byte[messDigestTree.getDigestSize()];
                messDigestTree.doFinal(help, 0);

                // the new help node is one step higher
                helpHeight++;
                if (helpHeight < heightOfTree)
                {
                    index[helpHeight]++;

                    // add index 1 element to initial authpath
                    if (index[helpHeight] == 1)
                    {
                        System.arraycopy(help, 0, AuthPath[helpHeight], 0,
                            mdLength);
                    }

                    if (helpHeight >= heightOfTree - K)
                    {
                        if (helpHeight == 0)
                        {
                            System.out.println("M���P");
                        }
                        // add help element to retain stack if it is a right
                        // node
                        // and not stored in treehash
                        if ((index[helpHeight] - 3) % 2 == 0
                            && index[helpHeight] >= 3)
                        // TODO: check it
                        {
                            retain[helpHeight - (heightOfTree - K)]
                                .insertElementAt(help, 0);
                        }
                    }
                    else
                    {
                        // if element is third in his line add it to treehash
                        if (index[helpHeight] == 3)
                        {
                            treehash[helpHeight].setFirstNode(help);
                        }
                    }
                }
            }
            // push help element to the stack
            tailStack.addElement(help);
            heightOfNodes.addElement(Integers.valueOf(helpHeight));

            // is the root calculation finished?
            if (helpHeight == heightOfTree)
            {
                isFinished = true;
                isInitialized = false;
                root = (byte[])tailStack.lastElement();
            }
        }

    }

    /**
     * initializes the seeds for the treehashs of the tree precomputed by this
     * class
     *
     * @param seed  the initial seed for treehash: seedNext
     * @param index the height of the treehash
     */
    public void initializeTreehashSeed(byte[] seed, int index)
    {
        treehash[index].initializeSeed(seed);
    }

    /**
     * Method to check whether the instance has been initialized or not
     *
     * @return true if treehash was already initialized
     */
    public boolean wasInitialized()
    {
        return isInitialized;
    }

    /**
     * Method to check whether the instance has been finished or not
     *
     * @return true if tree has reached its maximum height
     */
    public boolean wasFinished()
    {
        return isFinished;
    }

    /**
     * returns the authentication path of the first leaf of the tree
     *
     * @return the authentication path of the first leaf of the tree
     */
    public byte[][] getAuthPath()
    {
        return GMSSUtils.clone(AuthPath);
    }

    /**
     * returns the initial treehash instances, storing value y_3(i)
     *
     * @return the initial treehash instances, storing value y_3(i)
     */
    public Treehash[] getTreehash()
    {
        return GMSSUtils.clone(treehash);
    }

    /**
     * returns the retain stacks storing all right nodes near to the root
     *
     * @return the retain stacks storing all right nodes near to the root
     */
    public Vector[] getRetain()
    {
        return GMSSUtils.clone(retain);
    }

    /**
     * returns the finished root value
     *
     * @return the finished root value
     */
    public byte[] getRoot()
    {
        return Arrays.clone(root);
    }

    /**
     * returns the shared stack
     *
     * @return the shared stack
     */
    public Vector getStack()
    {
        Vector copy = new Vector();
        for (Enumeration en = tailStack.elements(); en.hasMoreElements();)
        {
            copy.addElement(en.nextElement());
        }
        return copy;
    }

    /**
     * Returns the status byte array used by the GMSSPrivateKeyASN.1 class
     *
     * @return The status bytes
     */
    public byte[][] getStatByte()
    {

        int tailLength;
        if (tailStack == null)
        {
            tailLength = 0;
        }
        else
        {
            tailLength = tailStack.size();
        }
        byte[][] statByte = new byte[1 + heightOfTree + tailLength][64]; //FIXME: messDigestTree.getByteLength()
        statByte[0] = root;

        for (int i = 0; i < heightOfTree; i++)
        {
            statByte[1 + i] = AuthPath[i];
        }
        for (int i = 0; i < tailLength; i++)
        {
            statByte[1 + heightOfTree + i] = (byte[])tailStack.elementAt(i);
        }

        return statByte;
    }

    /**
     * Returns the status int array used by the GMSSPrivateKeyASN.1 class
     *
     * @return The status ints
     */
    public int[] getStatInt()
    {

        int tailLength;
        if (tailStack == null)
        {
            tailLength = 0;
        }
        else
        {
            tailLength = tailStack.size();
        }
        int[] statInt = new int[8 + heightOfTree + tailLength];
        statInt[0] = heightOfTree;
        statInt[1] = mdLength;
        statInt[2] = K;
        statInt[3] = indexForNextSeed;
        statInt[4] = heightOfNextSeed;
        if (isFinished)
        {
            statInt[5] = 1;
        }
        else
        {
            statInt[5] = 0;
        }
        if (isInitialized)
        {
            statInt[6] = 1;
        }
        else
        {
            statInt[6] = 0;
        }
        statInt[7] = tailLength;

        for (int i = 0; i < heightOfTree; i++)
        {
            statInt[8 + i] = index[i];
        }
        for (int i = 0; i < tailLength; i++)
        {
            statInt[8 + heightOfTree + i] = ((Integer)heightOfNodes
                .elementAt(i)).intValue();
        }

        return statInt;
    }

    /**
     * @return a human readable version of the structure
     */
    public String toString()
    {
        String out = "";
        int tailLength;
        if (tailStack == null)
        {
            tailLength = 0;
        }
        else
        {
            tailLength = tailStack.size();
        }

        for (int i = 0; i < 8 + heightOfTree + tailLength; i++)
        {
            out = out + getStatInt()[i] + " ";
        }
        for (int i = 0; i < 1 + heightOfTree + tailLength; i++)
        {
            out = out + new String(Hex.encode(getStatByte()[i])) + " ";
        }
        out = out + "  " + digestProvider.get().getDigestSize();
        return out;
    }
}
