package org.bouncycastle.pqc.crypto.gmss;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.gmss.util.GMSSRandom;
import org.bouncycastle.pqc.crypto.gmss.util.GMSSUtil;
import org.bouncycastle.pqc.crypto.gmss.util.WinternitzOTSVerify;
import org.bouncycastle.pqc.crypto.gmss.util.WinternitzOTSignature;
import org.bouncycastle.util.Arrays;

/**
 * This class implements the GMSS signature scheme.
 */
public class GMSSSigner
    implements MessageSigner
{

    /**
     * Instance of GMSSParameterSpec
     */
    //private GMSSParameterSpec gmssParameterSpec;

    /**
     * Instance of GMSSUtilities
     */
    private GMSSUtil gmssUtil = new GMSSUtil();


    /**
     * The raw GMSS public key
     */
    private byte[] pubKeyBytes;

    /**
     * Hash function for the construction of the authentication trees
     */
    private Digest messDigestTrees;

    /**
     * The length of the hash function output
     */
    private int mdLength;

    /**
     * The number of tree layers
     */
    private int numLayer;

    /**
     * The hash function used by the OTS
     */
    private Digest messDigestOTS;

    /**
     * An instance of the Winternitz one-time signature
     */
    private WinternitzOTSignature ots;

    /**
     * Array of strings containing the name of the hash function used by the OTS
     * and the corresponding provider name
     */
    private GMSSDigestProvider digestProvider;

    /**
     * The current main tree and subtree indices
     */
    private int[] index;

    /**
     * Array of the authentication paths for the current trees of all layers
     */
    private byte[][][] currentAuthPaths;

    /**
     * The one-time signature of the roots of the current subtrees
     */
    private byte[][] subtreeRootSig;


    /**
     * The GMSSParameterset
     */
    private GMSSParameters gmssPS;

    /**
     * The PRNG
     */
    private GMSSRandom gmssRandom;

    GMSSKeyParameters key;

    // XXX needed? Source of randomness
    private SecureRandom random;


    /**
     * The standard constructor tries to generate the MerkleTree Algorithm
     * identifier with the corresponding OID.
     *
     * @param digest     the digest to use
     */
    // TODO
    public GMSSSigner(GMSSDigestProvider digest)
    {
        digestProvider = digest;
        messDigestTrees = digest.get();
        messDigestOTS = messDigestTrees;
        mdLength = messDigestTrees.getDigestSize();
        gmssRandom = new GMSSRandom(messDigestTrees);
    }

    public void init(boolean forSigning,
                     CipherParameters param)
    {

        if (forSigning)
        {
            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom rParam = (ParametersWithRandom)param;

                // XXX random needed?
                this.random = rParam.getRandom();
                this.key = (GMSSPrivateKeyParameters)rParam.getParameters();
                initSign();

            }
            else
            {

                this.random = new SecureRandom();
                this.key = (GMSSPrivateKeyParameters)param;
                initSign();
            }
        }
        else
        {
            this.key = (GMSSPublicKeyParameters)param;
            initVerify();

        }

    }


    /**
     * Initializes the signature algorithm for signing a message.
     */
    private void initSign()
    {
        messDigestTrees.reset();
        // set private key and take from it ots key, auth, tree and key
        // counter, rootSign
        GMSSPrivateKeyParameters gmssPrivateKey = (GMSSPrivateKeyParameters)key;

        if (gmssPrivateKey.isUsed())
        {
            throw new IllegalStateException("Private key already used");
        }

        // check if last signature has been generated
        if (gmssPrivateKey.getIndex(0) >= gmssPrivateKey.getNumLeafs(0))
        {
            throw new IllegalStateException("No more signatures can be generated");
        }

        // get Parameterset
        this.gmssPS = gmssPrivateKey.getParameters();
        // get numLayer
        this.numLayer = gmssPS.getNumOfLayers();

        // get OTS Instance of lowest layer
        byte[] seed = gmssPrivateKey.getCurrentSeeds()[numLayer - 1];
        byte[] OTSSeed = new byte[mdLength];
        byte[] dummy = new byte[mdLength];
        System.arraycopy(seed, 0, dummy, 0, mdLength);
        OTSSeed = gmssRandom.nextSeed(dummy); // secureRandom.nextBytes(currentSeeds[currentSeeds.length-1]);secureRandom.nextBytes(OTSseed);
        this.ots = new WinternitzOTSignature(OTSSeed, digestProvider.get(), gmssPS.getWinternitzParameter()[numLayer - 1]);

        byte[][][] helpCurrentAuthPaths = gmssPrivateKey.getCurrentAuthPaths();
        currentAuthPaths = new byte[numLayer][][];

        // copy the main tree authentication path
        for (int j = 0; j < numLayer; j++)
        {
            currentAuthPaths[j] = new byte[helpCurrentAuthPaths[j].length][mdLength];
            for (int i = 0; i < helpCurrentAuthPaths[j].length; i++)
            {
                System.arraycopy(helpCurrentAuthPaths[j][i], 0, currentAuthPaths[j][i], 0, mdLength);
            }
        }

        // copy index
        index = new int[numLayer];
        System.arraycopy(gmssPrivateKey.getIndex(), 0, index, 0, numLayer);

        // copy subtreeRootSig
        byte[] helpSubtreeRootSig;
        subtreeRootSig = new byte[numLayer - 1][];
        for (int i = 0; i < numLayer - 1; i++)
        {
            helpSubtreeRootSig = gmssPrivateKey.getSubtreeRootSig(i);
            subtreeRootSig[i] = new byte[helpSubtreeRootSig.length];
            System.arraycopy(helpSubtreeRootSig, 0, subtreeRootSig[i], 0, helpSubtreeRootSig.length);
        }

        gmssPrivateKey.markUsed();
    }

    /**
     * Signs a message.
     *
     * @return the signature.
     */
    public byte[] generateSignature(byte[] message)
    {

        byte[] otsSig = new byte[mdLength];
        byte[] authPathBytes;
        byte[] indexBytes;

        otsSig = ots.getSignature(message);

        // get concatenated lowest layer tree authentication path
        authPathBytes = gmssUtil.concatenateArray(currentAuthPaths[numLayer - 1]);

        // put lowest layer index into a byte array
        indexBytes = gmssUtil.intToBytesLittleEndian(index[numLayer - 1]);

        // create first part of GMSS signature
        byte[] gmssSigFirstPart = new byte[indexBytes.length + otsSig.length + authPathBytes.length];
        System.arraycopy(indexBytes, 0, gmssSigFirstPart, 0, indexBytes.length);
        System.arraycopy(otsSig, 0, gmssSigFirstPart, indexBytes.length, otsSig.length);
        System.arraycopy(authPathBytes, 0, gmssSigFirstPart, (indexBytes.length + otsSig.length), authPathBytes.length);
        // --- end first part

        // --- next parts of the signature
        // create initial array with length 0 for iteration
        byte[] gmssSigNextPart = new byte[0];

        for (int i = numLayer - 1 - 1; i >= 0; i--)
        {

            // get concatenated next tree authentication path
            authPathBytes = gmssUtil.concatenateArray(currentAuthPaths[i]);

            // put next tree index into a byte array
            indexBytes = gmssUtil.intToBytesLittleEndian(index[i]);

            // create next part of GMSS signature

            // create help array and copy actual gmssSig into it
            byte[] helpGmssSig = new byte[gmssSigNextPart.length];
            System.arraycopy(gmssSigNextPart, 0, helpGmssSig, 0, gmssSigNextPart.length);
            // adjust length of gmssSigNextPart for adding next part
            gmssSigNextPart = new byte[helpGmssSig.length + indexBytes.length + subtreeRootSig[i].length + authPathBytes.length];

            // copy old data (help array) and new data in gmssSigNextPart
            System.arraycopy(helpGmssSig, 0, gmssSigNextPart, 0, helpGmssSig.length);
            System.arraycopy(indexBytes, 0, gmssSigNextPart, helpGmssSig.length, indexBytes.length);
            System.arraycopy(subtreeRootSig[i], 0, gmssSigNextPart, (helpGmssSig.length + indexBytes.length), subtreeRootSig[i].length);
            System.arraycopy(authPathBytes, 0, gmssSigNextPart, (helpGmssSig.length + indexBytes.length + subtreeRootSig[i].length), authPathBytes.length);

        }
        // --- end next parts

        // concatenate the two parts of the GMSS signature
        byte[] gmssSig = new byte[gmssSigFirstPart.length + gmssSigNextPart.length];
        System.arraycopy(gmssSigFirstPart, 0, gmssSig, 0, gmssSigFirstPart.length);
        System.arraycopy(gmssSigNextPart, 0, gmssSig, gmssSigFirstPart.length, gmssSigNextPart.length);

        // return the GMSS signature
        return gmssSig;
    }

    /**
     * Initializes the signature algorithm for verifying a signature.
     */
    private void initVerify()
    {
        messDigestTrees.reset();

        GMSSPublicKeyParameters gmssPublicKey = (GMSSPublicKeyParameters)key;
        pubKeyBytes = gmssPublicKey.getPublicKey();
        gmssPS = gmssPublicKey.getParameters();
        // get numLayer
        this.numLayer = gmssPS.getNumOfLayers();


    }

    /**
     * This function verifies the signature of the message that has been
     * updated, with the aid of the public key.
     *
     * @param message the message
     * @param signature the signature associated with the message
     * @return true if the signature has been verified, false otherwise.
     */
    public boolean verifySignature(byte[] message, byte[] signature)
    {

        boolean success = false;
        // int halfSigLength = signature.length >>> 1;
        messDigestOTS.reset();
        WinternitzOTSVerify otsVerify;
        int otsSigLength;

        byte[] help = message;

        byte[] otsSig;
        byte[] otsPublicKey;
        byte[][] authPath;
        byte[] dest;
        int nextEntry = 0;
        int index;
        // Verify signature

        // --- begin with message = 'message that was signed'
        // and then in each step message = subtree root
        for (int j = numLayer - 1; j >= 0; j--)
        {
            otsVerify = new WinternitzOTSVerify(digestProvider.get(), gmssPS.getWinternitzParameter()[j]);
            otsSigLength = otsVerify.getSignatureLength();

            message = help;
            // get the subtree index
            index = gmssUtil.bytesToIntLittleEndian(signature, nextEntry);

            // 4 is the number of bytes in integer
            nextEntry += 4;

            // get one-time signature
            otsSig = new byte[otsSigLength];
            System.arraycopy(signature, nextEntry, otsSig, 0, otsSigLength);
            nextEntry += otsSigLength;

            // compute public OTS key from the one-time signature
            otsPublicKey = otsVerify.Verify(message, otsSig);

            // test if OTSsignature is correct
            if (otsPublicKey == null)
            {
                System.err.println("OTS Public Key is null in GMSSSignature.verify");
                return false;
            }

            // get authentication path from the signature
            authPath = new byte[gmssPS.getHeightOfTrees()[j]][mdLength];
            for (int i = 0; i < authPath.length; i++)
            {
                System.arraycopy(signature, nextEntry, authPath[i], 0, mdLength);
                nextEntry = nextEntry + mdLength;
            }

            // compute the root of the subtree from the authentication path
            help = new byte[mdLength];

            help = otsPublicKey;

            int count = 1 << authPath.length;
            count = count + index;

            for (int i = 0; i < authPath.length; i++)
            {
                dest = new byte[mdLength << 1];

                if ((count % 2) == 0)
                {
                    System.arraycopy(help, 0, dest, 0, mdLength);
                    System.arraycopy(authPath[i], 0, dest, mdLength, mdLength);
                    count = count / 2;
                }
                else
                {
                    System.arraycopy(authPath[i], 0, dest, 0, mdLength);
                    System.arraycopy(help, 0, dest, mdLength, help.length);
                    count = (count - 1) / 2;
                }
                messDigestTrees.update(dest, 0, dest.length);
                help = new byte[messDigestTrees.getDigestSize()];
                messDigestTrees.doFinal(help, 0);
            }
        }

        // now help contains the root of the maintree

        // test if help is equal to the GMSS public key
        if (Arrays.areEqual(pubKeyBytes, help))
        {
            success = true;
        }

        return success;
    }


}