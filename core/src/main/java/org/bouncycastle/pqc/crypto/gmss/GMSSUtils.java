package org.bouncycastle.pqc.crypto.gmss;

import java.util.Enumeration;
import java.util.Vector;

import org.bouncycastle.util.Arrays;

class GMSSUtils
{
    static GMSSLeaf[] clone(GMSSLeaf[] data)
    {
        if (data == null)
        {
            return null;
        }
        GMSSLeaf[] copy = new GMSSLeaf[data.length];

        System.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    static GMSSRootCalc[] clone(GMSSRootCalc[] data)
    {
        if (data == null)
        {
            return null;
        }
        GMSSRootCalc[] copy = new GMSSRootCalc[data.length];

        System.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    static GMSSRootSig[] clone(GMSSRootSig[] data)
    {
        if (data == null)
        {
            return null;
        }
        GMSSRootSig[] copy = new GMSSRootSig[data.length];

        System.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    static byte[][] clone(byte[][] data)
    {
        if (data == null)
        {
            return null;
        }
        byte[][] copy = new byte[data.length][];

        for (int i = 0; i != data.length; i++)
        {
            copy[i] = Arrays.clone(data[i]);
        }

        return copy;
    }

    static byte[][][] clone(byte[][][] data)
    {
        if (data == null)
        {
            return null;
        }
        byte[][][] copy = new byte[data.length][][];

        for (int i = 0; i != data.length; i++)
        {
            copy[i] = clone(data[i]);
        }

        return copy;
    }

    static Treehash[] clone(Treehash[] data)
    {
        if (data == null)
        {
            return null;
        }
        Treehash[] copy = new Treehash[data.length];

        System.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    static Treehash[][] clone(Treehash[][] data)
    {
        if (data == null)
        {
            return null;
        }
        Treehash[][] copy = new Treehash[data.length][];

        for (int i = 0; i != data.length; i++)
        {
            copy[i] = clone(data[i]);
        }

        return copy;
    }

    static Vector[] clone(Vector[] data)
    {
        if (data == null)
        {
            return null;
        }
        Vector[] copy = new Vector[data.length];

        for (int i = 0; i != data.length; i++)
        {
            copy[i] = new Vector();
            for (Enumeration en = data[i].elements(); en.hasMoreElements();)
            {
                copy[i].addElement(en.nextElement());
            }
        }

        return copy;
    }

    static Vector[][] clone(Vector[][] data)
    {
        if (data == null)
        {
            return null;
        }
        Vector[][] copy = new Vector[data.length][];

        for (int i = 0; i != data.length; i++)
        {
            copy[i] = clone(data[i]);
        }

        return copy;
    }
}
