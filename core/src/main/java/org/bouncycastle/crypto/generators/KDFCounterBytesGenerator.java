package org.bouncycastle.crypto.generators;

import java.math.BigInteger;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.MacDerivationFunction;
import org.bouncycastle.crypto.params.KDFCounterParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * This KDF has been defined by the publicly available NIST SP 800-108 specification.
 */
public class KDFCounterBytesGenerator
    implements MacDerivationFunction
{

    private static final BigInteger INTEGER_MAX = BigInteger.valueOf(Integer.MAX_VALUE);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    // please refer to the standard for the meaning of the variable names
    // all field lengths are in bytes, not in bits as specified by the standard

    // fields set by the constructor
    private final Mac prf;
    private final int h;

    // fields set by init
    private byte[] fixedInputData;
    private int maxSizeExcl;
    // ios is i defined as an octet string (the binary representation)
    private byte[] ios;

    // operational
    private int generatedBytes;
    // k is used as buffer for all K(i) values
    private byte[] k;


    public KDFCounterBytesGenerator(Mac prf)
    {
        this.prf = prf;
        this.h = prf.getMacSize();
        this.k = new byte[h];
    }


    public void init(DerivationParameters param)
    {
        if (!(param instanceof KDFCounterParameters))
        {
            throw new IllegalArgumentException("Wrong type of arguments given");
        }

        KDFCounterParameters kdfParams = (KDFCounterParameters)param;

        // --- init mac based PRF ---

        this.prf.init(new KeyParameter(kdfParams.getKI()));

        // --- set arguments ---

        this.fixedInputData = kdfParams.getFixedInputData();

        int r = kdfParams.getR();
        this.ios = new byte[r / 8];

        BigInteger maxSize = TWO.pow(r).multiply(BigInteger.valueOf(h));
        this.maxSizeExcl = maxSize.compareTo(INTEGER_MAX) == 1 ?
            Integer.MAX_VALUE : maxSize.intValue();

        // --- set operational state ---

        generatedBytes = 0;
    }


    public Mac getMac()
    {
        return prf;
    }

    public int generateBytes(byte[] out, int outOff, int len)
        throws DataLengthException, IllegalArgumentException
    {

        int generatedBytesAfter = generatedBytes + len;
        if (generatedBytesAfter < 0 || generatedBytesAfter >= maxSizeExcl)
        {
            throw new DataLengthException(
                "Current KDFCTR may only be used for " + maxSizeExcl + " bytes");
        }

        if (generatedBytes % h == 0)
        {
            generateNext();
        }

        // copy what is left in the currentT (1..hash
        int toGenerate = len;
        int posInK = generatedBytes % h;
        int leftInK = h - generatedBytes % h;
        int toCopy = Math.min(leftInK, toGenerate);
        System.arraycopy(k, posInK, out, outOff, toCopy);
        generatedBytes += toCopy;
        toGenerate -= toCopy;
        outOff += toCopy;

        while (toGenerate > 0)
        {
            generateNext();
            toCopy = Math.min(h, toGenerate);
            System.arraycopy(k, 0, out, outOff, toCopy);
            generatedBytes += toCopy;
            toGenerate -= toCopy;
            outOff += toCopy;
        }

        return len;
    }

    private void generateNext()
    {
        int i = generatedBytes / h + 1;

        // encode i into counter buffer
        switch (ios.length)
        {
        case 4:
            ios[0] = (byte)(i >>> 24);
            // fall through
        case 3:
            ios[ios.length - 3] = (byte)(i >>> 16);
            // fall through
        case 2:
            ios[ios.length - 2] = (byte)(i >>> 8);
            // fall through
        case 1:
            ios[ios.length - 1] = (byte)i;
            break;
        default:
            throw new IllegalStateException("Unsupported size of counter i");
        }


        // special case for K(0): K(0) is empty, so no update
        prf.update(ios, 0, ios.length);
        prf.update(fixedInputData, 0, fixedInputData.length);
        prf.doFinal(k, 0);
    }
}
