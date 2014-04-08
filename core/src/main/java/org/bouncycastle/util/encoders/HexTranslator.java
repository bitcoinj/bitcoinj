package org.bouncycastle.util.encoders;

/**
 * Converters for going from hex to binary and back. Note: this class assumes ASCII processing.
 */
public class HexTranslator
    implements Translator
{
    private static final byte[]   hexTable = 
        { 
            (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7',
            (byte)'8', (byte)'9', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f'
        };

    /**
     * size of the output block on encoding produced by getDecodedBlockSize()
     * bytes.
     */
    public int getEncodedBlockSize()
    {
        return 2;
    }

    public int encode(
        byte[]  in,
        int     inOff,
        int     length,
        byte[]  out,
        int     outOff)
    {
        for (int i = 0, j = 0; i < length; i++, j += 2)
        {
            out[outOff + j] = hexTable[(in[inOff] >> 4) & 0x0f];
            out[outOff + j + 1] = hexTable[in[inOff] & 0x0f];

            inOff++;
        }

        return length * 2;
    }

    /**
     * size of the output block on decoding produced by getEncodedBlockSize()
     * bytes.
     */
    public int getDecodedBlockSize()
    {
        return 1;
    }

    public int decode(
        byte[]  in,
        int     inOff,
        int     length,
        byte[]  out,
        int     outOff)
    {
        int halfLength = length / 2;
        byte left, right;
        for (int i = 0; i < halfLength; i++)
        {
            left  = in[inOff + i * 2];
            right = in[inOff + i * 2 + 1];
            
            if (left < (byte)'a')
            {
                out[outOff] = (byte)((left - '0') << 4);
            }
            else
            {
                out[outOff] = (byte)((left - 'a' + 10) << 4);
            }
            if (right < (byte)'a')
            {
                out[outOff] += (byte)(right - '0');
            }
            else
            {
                out[outOff] += (byte)(right - 'a' + 10);
            }

            outOff++;
        }

        return halfLength;
    }
}
