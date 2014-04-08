package org.bouncycastle.pqc.crypto.gmss;

import java.util.Vector;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.crypto.gmss.util.GMSSRandom;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.encoders.Hex;


/**
 * This class implements a treehash instance for the Merkle tree traversal
 * algorithm. The first node of the stack is stored in this instance itself,
 * additional tail nodes are stored on a tailstack.
 */
public class Treehash
{

    /**
     * max height of current treehash instance.
     */
    private int maxHeight;

    /**
     * Vector element that stores the nodes on the stack
     */
    private Vector tailStack;

    /**
     * Vector element that stores the height of the nodes on the stack
     */
    private Vector heightOfNodes;

    /**
     * the first node is stored in the treehash instance itself, not on stack
     */
    private byte[] firstNode;

    /**
     * seedActive needed for the actual node
     */
    private byte[] seedActive;

    /**
     * the seed needed for the next re-initialization of the treehash instance
     */
    private byte[] seedNext;

    /**
     * number of nodes stored on the stack and belonging to this treehash
     * instance
     */
    private int tailLength;

    /**
     * the height in the tree of the first node stored in treehash
     */
    private int firstNodeHeight;

    /**
     * true if treehash instance was already initialized, false otherwise
     */
    private boolean isInitialized;

    /**
     * true if the first node's height equals the maxHeight of the treehash
     */
    private boolean isFinished;

    /**
     * true if the nextSeed has been initialized with index 3*2^h needed for the
     * seed scheduling
     */
    private boolean seedInitialized;

    /**
     * denotes the Message Digest used by the tree to create nodes
     */
    private Digest messDigestTree;

    /**
     * This constructor regenerates a prior treehash object
     *
     * @param name     an array of strings, containing the name of the used hash
     *                 function and PRNG and the name of the corresponding provider
     * @param statByte status bytes
     * @param statInt  status ints
     */
    public Treehash(Digest name, byte[][] statByte, int[] statInt)
    {
        this.messDigestTree = name;

        // decode statInt
        this.maxHeight = statInt[0];
        this.tailLength = statInt[1];
        this.firstNodeHeight = statInt[2];

        if (statInt[3] == 1)
        {
            this.isFinished = true;
        }
        else
        {
            this.isFinished = false;
        }
        if (statInt[4] == 1)
        {
            this.isInitialized = true;
        }
        else
        {
            this.isInitialized = false;
        }
        if (statInt[5] == 1)
        {
            this.seedInitialized = true;
        }
        else
        {
            this.seedInitialized = false;
        }

        this.heightOfNodes = new Vector();
        for (int i = 0; i < tailLength; i++)
        {
            this.heightOfNodes.addElement(Integers.valueOf(statInt[6 + i]));
        }

        // decode statByte
        this.firstNode = statByte[0];
        this.seedActive = statByte[1];
        this.seedNext = statByte[2];

        this.tailStack = new Vector();
        for (int i = 0; i < tailLength; i++)
        {
            this.tailStack.addElement(statByte[3 + i]);
        }
    }

    /**
     * Constructor
     *
     * @param tailStack a vector element where the stack nodes are stored
     * @param maxHeight maximal height of the treehash instance
     * @param digest    an array of strings, containing the name of the used hash
     *                  function and PRNG and the name of the corresponding provider
     */
    public Treehash(Vector tailStack, int maxHeight, Digest digest)
    {
        this.tailStack = tailStack;
        this.maxHeight = maxHeight;
        this.firstNode = null;
        this.isInitialized = false;
        this.isFinished = false;
        this.seedInitialized = false;
        this.messDigestTree = digest;

        this.seedNext = new byte[messDigestTree.getDigestSize()];
        this.seedActive = new byte[messDigestTree.getDigestSize()];
    }

    /**
     * Method to initialize the seeds needed for the precomputation of right
     * nodes. Should be initialized with index 3*2^i for treehash_i
     *
     * @param seedIn
     */
    public void initializeSeed(byte[] seedIn)
    {
        System.arraycopy(seedIn, 0, this.seedNext, 0, this.messDigestTree
            .getDigestSize());
        this.seedInitialized = true;
    }

    /**
     * initializes the treehash instance. The seeds must already have been
     * initialized to work correctly.
     */
    public void initialize()
    {
        if (!this.seedInitialized)
        {
            System.err.println("Seed " + this.maxHeight + " not initialized");
            return;
        }

        this.heightOfNodes = new Vector();
        this.tailLength = 0;
        this.firstNode = null;
        this.firstNodeHeight = -1;
        this.isInitialized = true;
        System.arraycopy(this.seedNext, 0, this.seedActive, 0, messDigestTree
            .getDigestSize());
    }

    /**
     * Calculates one update of the treehash instance, i.e. creates a new leaf
     * and hashes if possible
     *
     * @param gmssRandom an instance of the PRNG
     * @param leaf       The byte value of the leaf needed for the update
     */
    public void update(GMSSRandom gmssRandom, byte[] leaf)
    {

        if (this.isFinished)
        {
            System.err
                .println("No more update possible for treehash instance!");
            return;
        }
        if (!this.isInitialized)
        {
            System.err
                .println("Treehash instance not initialized before update");
            return;
        }

        byte[] help = new byte[this.messDigestTree.getDigestSize()];
        int helpHeight = -1;

        gmssRandom.nextSeed(this.seedActive);

        // if treehash gets first update
        if (this.firstNode == null)
        {
            this.firstNode = leaf;
            this.firstNodeHeight = 0;
        }
        else
        {
            // store the new node in help array, do not push it on the stack
            help = leaf;
            helpHeight = 0;

            // hash the nodes on the stack if possible
            while (this.tailLength > 0
                && helpHeight == ((Integer)heightOfNodes.lastElement())
                .intValue())
            {
                // put top element of the stack and help node in array
                // 'tobehashed'
                // and hash them together, put result again in help array
                byte[] toBeHashed = new byte[this.messDigestTree
                    .getDigestSize() << 1];

                // pop element from stack
                System.arraycopy(this.tailStack.lastElement(), 0, toBeHashed,
                    0, this.messDigestTree.getDigestSize());
                this.tailStack.removeElementAt(this.tailStack.size() - 1);
                this.heightOfNodes
                    .removeElementAt(this.heightOfNodes.size() - 1);

                System.arraycopy(help, 0, toBeHashed, this.messDigestTree
                    .getDigestSize(), this.messDigestTree
                    .getDigestSize());
                messDigestTree.update(toBeHashed, 0, toBeHashed.length);
                help = new byte[messDigestTree.getDigestSize()];
                messDigestTree.doFinal(help, 0);

                // increase help height, stack was reduced by one element
                helpHeight++;
                this.tailLength--;
            }

            // push the new node on the stack
            this.tailStack.addElement(help);
            this.heightOfNodes.addElement(Integers.valueOf(helpHeight));
            this.tailLength++;

            // finally check whether the top node on stack and the first node
            // in treehash have same height. If so hash them together
            // and store them in treehash
            if (((Integer)heightOfNodes.lastElement()).intValue() == this.firstNodeHeight)
            {
                byte[] toBeHashed = new byte[this.messDigestTree
                    .getDigestSize() << 1];
                System.arraycopy(this.firstNode, 0, toBeHashed, 0,
                    this.messDigestTree.getDigestSize());

                // pop element from tailStack and copy it into help2 array
                System.arraycopy(this.tailStack.lastElement(), 0, toBeHashed,
                    this.messDigestTree.getDigestSize(),
                    this.messDigestTree.getDigestSize());
                this.tailStack.removeElementAt(this.tailStack.size() - 1);
                this.heightOfNodes
                    .removeElementAt(this.heightOfNodes.size() - 1);

                // store new element in firstNode, stack is then empty
                messDigestTree.update(toBeHashed, 0, toBeHashed.length);
                this.firstNode = new byte[messDigestTree.getDigestSize()];
                messDigestTree.doFinal(this.firstNode, 0);
                this.firstNodeHeight++;

                // empty the stack
                this.tailLength = 0;
            }
        }

        // check if treehash instance is completed
        if (this.firstNodeHeight == this.maxHeight)
        {
            this.isFinished = true;
        }
    }

    /**
     * Destroys a treehash instance after the top node was taken for
     * authentication path.
     */
    public void destroy()
    {
        this.isInitialized = false;
        this.isFinished = false;
        this.firstNode = null;
        this.tailLength = 0;
        this.firstNodeHeight = -1;
    }

    /**
     * Returns the height of the lowest node stored either in treehash or on the
     * stack. It must not be set to infinity (as mentioned in the paper) because
     * this cases are considered in the computeAuthPaths method of
     * JDKGMSSPrivateKey
     *
     * @return Height of the lowest node
     */
    public int getLowestNodeHeight()
    {
        if (this.firstNode == null)
        {
            return this.maxHeight;
        }
        else if (this.tailLength == 0)
        {
            return this.firstNodeHeight;
        }
        else
        {
            return Math.min(this.firstNodeHeight, ((Integer)heightOfNodes
                .lastElement()).intValue());
        }
    }

    /**
     * Returns the top node height
     *
     * @return Height of the first node, the top node
     */
    public int getFirstNodeHeight()
    {
        if (firstNode == null)
        {
            return maxHeight;
        }
        return firstNodeHeight;
    }

    /**
     * Method to check whether the instance has been initialized or not
     *
     * @return true if treehash was already initialized
     */
    public boolean wasInitialized()
    {
        return this.isInitialized;
    }

    /**
     * Method to check whether the instance has been finished or not
     *
     * @return true if treehash has reached its maximum height
     */
    public boolean wasFinished()
    {
        return this.isFinished;
    }

    /**
     * returns the first node stored in treehash instance itself
     *
     * @return the first node stored in treehash instance itself
     */
    public byte[] getFirstNode()
    {
        return this.firstNode;
    }

    /**
     * returns the active seed
     *
     * @return the active seed
     */
    public byte[] getSeedActive()
    {
        return this.seedActive;
    }

    /**
     * This method sets the first node stored in the treehash instance itself
     *
     * @param hash
     */
    public void setFirstNode(byte[] hash)
    {
        if (!this.isInitialized)
        {
            this.initialize();
        }
        this.firstNode = hash;
        this.firstNodeHeight = this.maxHeight;
        this.isFinished = true;
    }

    /**
     * updates the nextSeed of this treehash instance one step needed for the
     * schedulng of the seeds
     *
     * @param gmssRandom the prng used for the seeds
     */
    public void updateNextSeed(GMSSRandom gmssRandom)
    {
        gmssRandom.nextSeed(seedNext);
    }

    /**
     * Returns the tailstack
     *
     * @return the tailstack
     */
    public Vector getTailStack()
    {
        return this.tailStack;
    }

    /**
     * Returns the status byte array used by the GMSSPrivateKeyASN.1 class
     *
     * @return The status bytes
     */
    public byte[][] getStatByte()
    {

        byte[][] statByte = new byte[3 + tailLength][this.messDigestTree
            .getDigestSize()];
        statByte[0] = firstNode;
        statByte[1] = seedActive;
        statByte[2] = seedNext;
        for (int i = 0; i < tailLength; i++)
        {
            statByte[3 + i] = (byte[])tailStack.elementAt(i);
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

        int[] statInt = new int[6 + tailLength];
        statInt[0] = maxHeight;
        statInt[1] = tailLength;
        statInt[2] = firstNodeHeight;
        if (this.isFinished)
        {
            statInt[3] = 1;
        }
        else
        {
            statInt[3] = 0;
        }
        if (this.isInitialized)
        {
            statInt[4] = 1;
        }
        else
        {
            statInt[4] = 0;
        }
        if (this.seedInitialized)
        {
            statInt[5] = 1;
        }
        else
        {
            statInt[5] = 0;
        }
        for (int i = 0; i < tailLength; i++)
        {
            statInt[6 + i] = ((Integer)heightOfNodes.elementAt(i)).intValue();
        }
        return statInt;
    }

    /**
     * returns a String representation of the treehash instance
     */
    public String toString()
    {
        String out = "Treehash    : ";
        for (int i = 0; i < 6 + tailLength; i++)
        {
            out = out + this.getStatInt()[i] + " ";
        }
        for (int i = 0; i < 3 + tailLength; i++)
        {
            if (this.getStatByte()[i] != null)
            {
                out = out + new String(Hex.encode((this.getStatByte()[i]))) + " ";
            }
            else
            {
                out = out + "null ";
            }
        }
        out = out + "  " + this.messDigestTree.getDigestSize();
        return out;
    }

}