package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.crypto.CipherParameters;

public class RainbowParameters
    implements CipherParameters
{

    /**
     * DEFAULT PARAMS
     */
    /*
      * Vi = vinegars per layer whereas n is vu (vu = 33 = n) such that
      *
      * v1 = 6; o1 = 12-6 = 6
      *
      * v2 = 12; o2 = 17-12 = 5
      *
      * v3 = 17; o3 = 22-17 = 5
      *
      * v4 = 22; o4 = 33-22 = 11
      *
      * v5 = 33; (o5 = 0)
      */
    private final int[] DEFAULT_VI = {6, 12, 17, 22, 33};

    private int[] vi;// set of vinegar vars per layer.

    /**
     * Default Constructor The elements of the array containing the number of
     * Vinegar variables in each layer are set to the default values here.
     */
    public RainbowParameters()
    {
        this.vi = this.DEFAULT_VI;
    }

    /**
     * Constructor with parameters
     *
     * @param vi The elements of the array containing the number of Vinegar
     *           variables per layer are set to the values of the input array.
     */
    public RainbowParameters(int[] vi)
    {
        this.vi = vi;
        try
        {
            checkParams();
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    private void checkParams()
        throws Exception
    {
        if (vi == null)
        {
            throw new Exception("no layers defined.");
        }
        if (vi.length > 1)
        {
            for (int i = 0; i < vi.length - 1; i++)
            {
                if (vi[i] >= vi[i + 1])
                {
                    throw new Exception(
                        "v[i] has to be smaller than v[i+1]");
                }
            }
        }
        else
        {
            throw new Exception(
                "Rainbow needs at least 1 layer, such that v1 < v2.");
        }
    }

    /**
     * Getter for the number of layers
     *
     * @return the number of layers
     */
    public int getNumOfLayers()
    {
        return this.vi.length - 1;
    }

    /**
     * Getter for the number of all the polynomials in Rainbow
     *
     * @return the number of the polynomials
     */
    public int getDocLength()
    {
        return vi[vi.length - 1] - vi[0];
    }

    /**
     * Getter for the array containing the number of Vinegar-variables per layer
     *
     * @return the numbers of vinegars per layer
     */
    public int[] getVi()
    {
        return this.vi;
    }
}
