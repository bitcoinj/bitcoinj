package org.bouncycastle.pqc.crypto.gmss;

import org.bouncycastle.util.Arrays;

/**
 * This class provides a specification for the GMSS parameters that are used by
 * the GMSSKeyPairGenerator and GMSSSignature classes.
 *
 * @see org.bouncycastle.pqc.crypto.gmss.GMSSKeyPairGenerator
 */
public class GMSSParameters
{
    /**
     * The number of authentication tree layers.
     */
    private int numOfLayers;

    /**
     * The height of the authentication trees of each layer.
     */
    private int[] heightOfTrees;

    /**
     * The Winternitz Parameter 'w' of each layer.
     */
    private int[] winternitzParameter;

    /**
     * The parameter K needed for the authentication path computation
     */
    private int[] K;

    /**
     * The constructor for the parameters of the GMSSKeyPairGenerator.
     *
     * @param layers              the number of authentication tree layers
     * @param heightOfTrees       the height of the authentication trees
     * @param winternitzParameter the Winternitz Parameter 'w' of each layer
     * @param K                   parameter for authpath computation
     */
    public GMSSParameters(int layers, int[] heightOfTrees, int[] winternitzParameter, int[] K)
        throws IllegalArgumentException
    {
        init(layers, heightOfTrees, winternitzParameter, K);
    }

    private void init(int layers, int[] heightOfTrees,
                      int[] winternitzParameter, int[] K)
        throws IllegalArgumentException
    {
        boolean valid = true;
        String errMsg = "";
        this.numOfLayers = layers;
        if ((numOfLayers != winternitzParameter.length)
            || (numOfLayers != heightOfTrees.length)
            || (numOfLayers != K.length))
        {
            valid = false;
            errMsg = "Unexpected parameterset format";
        }
        for (int i = 0; i < numOfLayers; i++)
        {
            if ((K[i] < 2) || ((heightOfTrees[i] - K[i]) % 2 != 0))
            {
                valid = false;
                errMsg = "Wrong parameter K (K >= 2 and H-K even required)!";
            }

            if ((heightOfTrees[i] < 4) || (winternitzParameter[i] < 2))
            {
                valid = false;
                errMsg = "Wrong parameter H or w (H > 3 and w > 1 required)!";
            }
        }

        if (valid)
        {
            this.heightOfTrees = Arrays.clone(heightOfTrees);
            this.winternitzParameter = Arrays.clone(winternitzParameter);
            this.K = Arrays.clone(K);
        }
        else
        {
            throw new IllegalArgumentException(errMsg);
        }
    }

    public GMSSParameters(int keySize)
        throws IllegalArgumentException
    {
        if (keySize <= 10)
        { // create 2^10 keys
            int[] defh = {10};
            int[] defw = {3};
            int[] defk = {2};
            this.init(defh.length, defh, defw, defk);
        }
        else if (keySize <= 20)
        { // create 2^20 keys
            int[] defh = {10, 10};
            int[] defw = {5, 4};
            int[] defk = {2, 2};
            this.init(defh.length, defh, defw, defk);
        }
        else
        { // create 2^40 keys, keygen lasts around 80 seconds
            int[] defh = {10, 10, 10, 10};
            int[] defw = {9, 9, 9, 3};
            int[] defk = {2, 2, 2, 2};
            this.init(defh.length, defh, defw, defk);
        }
    }

    /**
     * Returns the number of levels of the authentication trees.
     *
     * @return The number of levels of the authentication trees.
     */
    public int getNumOfLayers()
    {
        return numOfLayers;
    }

    /**
     * Returns the array of height (for each layer) of the authentication trees
     *
     * @return The array of height (for each layer) of the authentication trees
     */
    public int[] getHeightOfTrees()
    {
        return Arrays.clone(heightOfTrees);
    }

    /**
     * Returns the array of WinternitzParameter (for each layer) of the
     * authentication trees
     *
     * @return The array of WinternitzParameter (for each layer) of the
     *         authentication trees
     */
    public int[] getWinternitzParameter()
    {
        return Arrays.clone(winternitzParameter);
    }

    /**
     * Returns the parameter K needed for authentication path computation
     *
     * @return The parameter K needed for authentication path computation
     */
    public int[] getK()
    {
        return Arrays.clone(K);
    }
}
