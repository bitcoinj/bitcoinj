package org.bouncycastle.crypto.generators;

import java.math.BigInteger;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.MacDerivationFunction;
import org.bouncycastle.crypto.params.KDFFeedbackParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * This KDF has been defined by the publicly available NIST SP 800-108 specification.
 */
public class KDFFeedbackBytesGenerator
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
    private byte[] iv;
    private boolean useCounter;

    // operational
    private int generatedBytes;
    // k is used as buffer for all K(i) values
    private byte[] k;


    public KDFFeedbackBytesGenerator(Mac prf)
    {
        this.prf = prf;
        this.h = prf.getMacSize();
        this.k = new byte[h];
    }

    public void init(DerivationParameters params)
    {
        if (!(params instanceof KDFFeedbackParameters))
        {
            throw new IllegalArgumentException("Wrong type of arguments given");
        }

        KDFFeedbackParameters feedbackParams = (KDFFeedbackParameters)params;

        // --- init mac based PRF ---

        this.prf.init(new KeyParameter(feedbackParams.getKI()));

        // --- set arguments ---

        this.fixedInputData = feedbackParams.getFixedInputData();

        int r = feedbackParams.getR();
        this.ios = new byte[r / 8];

        if (feedbackParams.useCounter())
        {
            // this is more conservative than the spec
            BigInteger maxSize = TWO.pow(r).multiply(BigInteger.valueOf(h));
            this.maxSizeExcl = maxSize.compareTo(INTEGER_MAX) == 1 ?
                Integer.MAX_VALUE : maxSize.intValue();
        }
        else
        {
            this.maxSizeExcl = Integer.MAX_VALUE;
        }

        this.iv = feedbackParams.getIV();
        this.useCounter = feedbackParams.useCounter();

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

        // TODO enable IV
        if (generatedBytes == 0)
        {
            prf.update(iv, 0, iv.length);
        }
        else
        {
            prf.update(k, 0, k.length);
        }

        if (useCounter)
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
            prf.update(ios, 0, ios.length);
        }

        prf.update(fixedInputData, 0, fixedInputData.length);
        prf.doFinal(k, 0);
    }
}
