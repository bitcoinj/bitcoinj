package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Block cipher Shacal2, designed by Helena Handschuh and David Naccache,
 * based on hash function SHA-256,
 * using SHA-256-Initialization-Values as data and SHA-256-Data as key.
 * <p>
 * A description of Shacal can be found at:
 *    http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.3.4066
 * Best known cryptanalytic (Wikipedia 11.2013):
 *    Related-key rectangle attack on 44-rounds (Jiqiang Lu, Jongsung Kim).
 * Comments are related to SHA-256-Naming as described in FIPS PUB 180-2
 * </p>
 */
public class Shacal2Engine 
	implements BlockCipher 
{
	private final static int[] K = { // SHA-256-Constants
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
			0x983e5152,	0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,	0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 
	}; 
	
	private static final int BLOCK_SIZE = 32;
	private boolean forEncryption = false;
	private static final int ROUNDS = 64;
	
	private int[] workingKey = null; // expanded key: corresponds to the message block W in FIPS PUB 180-2
	
	public Shacal2Engine()
	{		
	}
	
	public void reset()
	{
	}
	
	public String getAlgorithmName()
	{
		return "Shacal2";
	}

	public int getBlockSize()
	{
	    return BLOCK_SIZE;
	}

	public void init(boolean _forEncryption, CipherParameters  params)
		throws IllegalArgumentException
	{
		if (!(params instanceof KeyParameter))
		{
			throw new IllegalArgumentException("only simple KeyParameter expected.");
		}
		this.forEncryption = _forEncryption;
		workingKey = new int[64];
		setKey( ((KeyParameter)params).getKey() );
	}

	public void setKey(byte[] kb) 
	{
		if (kb.length == 0 || kb.length > 64 || kb.length < 16 || kb.length % 8 != 0)
		{
			throw new IllegalArgumentException("Shacal2-key must be 16 - 64 bytes and multiple of 8");
		}

		bytes2ints(kb, workingKey, 0, 0);

		for ( int i = 16; i < 64; i++) 
		{ // Key-Expansion, implicitly Zero-Padding for 16 > i > kb.length/4
			workingKey[i] = 
									( (workingKey[i-2] >>> 17 | workingKey[i-2] << -17) // corresponds to ROTL n(x) of FIPS PUB 180-2
										^ (workingKey[i-2] >>> 19 | workingKey[i-2] << -19)
										^ (workingKey[i-2] >>> 10) ) // corresponds to sigma1(x)-Function of FIPS PUB 180-2	    	  
									+ workingKey[i-7] 		    				
									+ ( (workingKey[i-15] >>> 7 | workingKey[i-15] << -7) 
										^ (workingKey[i-15] >>> 18 | workingKey[i-15] << -18) 
										^ (workingKey[i-15] >>> 3) ) // corresponds to sigma0(x)-Function of FIPS PUB 180-2	    
									+ workingKey[i-16];
		}
	}
	
	public void encryptBlock(byte[] in, int inOffset, byte[] out, int outOffset) 
	{
		int[] block = new int[BLOCK_SIZE / 4];// corresponds to working variables a,b,c,d,e,f,g,h of FIPS PUB 180-2
		bytes2ints(in, block, inOffset, 0);
		
		for (int i = 0; i < ROUNDS; i++) 
		{			
			int tmp =
                (((block[4] >>> 6) | (block[4] << -6))
                    ^ ((block[4] >>> 11) | (block[4] << -11))
                    ^ ((block[4] >>> 25) | (block[4] << -25)))
                    + ((block[4] & block[5]) ^ ((~block[4]) & block[6]))
                    + block[7] + K[i] + workingKey[i];  // corresponds to T1 of FIPS PUB 180-2
			block[7] = block[6];
			block[6] = block[5];
			block[5] = block[4];			
			block[4] = block[3] + tmp;
			block[3] = block[2];
			block[2] = block[1];
			block[1] = block[0];
			block[0] = tmp
                + (((block[0] >>> 2) | (block[0] << -2))
                ^ ((block[0] >>> 13) | (block[0] << -13))
                ^ ((block[0] >>> 22) | (block[0] << -22)))
                + ((block[0] & block[2]) ^ (block[0] & block[3]) ^ (block[2] & block[3]));
			//corresponds to T2 of FIPS PUB 180-2, block[1] and block[2] replaced
		}		
		ints2bytes(block, out, outOffset);
	}
	
	public void decryptBlock(byte[] in, int inOffset, byte[] out, int outOffset) 
	{		
		int[] block = new int[BLOCK_SIZE / 4];
		bytes2ints(in, block, inOffset, 0);		
		for (int i = ROUNDS - 1; i >-1; i--) 
		{
            int tmp = block[0] - (((block[1] >>> 2) | (block[1] << -2))
                ^ ((block[1] >>> 13) | (block[1] << -13))
                ^ ((block[1] >>> 22) | (block[1] << -22)))
                - ((block[1] & block[2]) ^ (block[1] & block[3]) ^ (block[2] & block[3]));    // T2
            block[0] = block[1];
            block[1] = block[2];
            block[2] = block[3];
            block[3] = block[4] - tmp;
            block[4] = block[5];
            block[5] = block[6];
            block[6] = block[7];
            block[7] = tmp - K[i] - workingKey[i]
                - (((block[4] >>> 6) | (block[4] << -6))
                ^ ((block[4] >>> 11) | (block[4] << -11))
                ^ ((block[4] >>> 25) | (block[4] << -25)))
                - ((block[4] & block[5]) ^ ((~block[4]) & block[6])); // T1
        }
		ints2bytes(block, out, outOffset);
	}

	public int processBlock(byte[] in, int inOffset, byte[] out, int outOffset)	    
			throws DataLengthException, IllegalStateException 
	{
		if (workingKey == null)
		{
			throw new IllegalStateException("Shacal2 not initialised");
		}

		if ((inOffset + BLOCK_SIZE) > in.length)
		{
			throw new DataLengthException("input buffer too short");
		}

		if ((outOffset + BLOCK_SIZE) > out.length)
		{
			throw new OutputLengthException("output buffer too short");
		}

		if (forEncryption)
		{
			encryptBlock(in, inOffset, out, outOffset);
		}
		else
		{    
			decryptBlock(in, inOffset, out, outOffset);
		}

		return BLOCK_SIZE;
	}

    private void bytes2ints(byte[] bytes, int[] block, int bytesPos, int blockPos)
    {
        for (int i = blockPos; i < bytes.length / 4; i++)
        {
            block[i] = ((bytes[bytesPos++] & 0xFF) << 24)
                | ((bytes[bytesPos++] & 0xFF) << 16)
                | ((bytes[bytesPos++] & 0xFF) << 8)
                | (bytes[bytesPos++] & 0xFF);
        }
    }

    private void ints2bytes(int[] block, byte[] out, int pos)
    {
        for (int i = 0; i < block.length; i++)
        {
            out[pos++] = (byte)(block[i] >>> 24);
            out[pos++] = (byte)(block[i] >>> 16);
            out[pos++] = (byte)(block[i] >>> 8);
            out[pos++] = (byte)block[i];
        }
    }
}
