package org.bouncycastle.pqc.crypto.gmss.util;

import org.bouncycastle.crypto.Digest;

/**
 * This class implements signature verification of the Winternitz one-time
 * signature scheme (OTSS), described in C.Dods, N.P. Smart, and M. Stam, "Hash
 * Based Digital Signature Schemes", LNCS 3796, pages 96&#8211;115, 2005. The
 * class is used by the GMSS classes.
 */
public class WinternitzOTSVerify
{

    private Digest messDigestOTS;

    /**
     * The Winternitz parameter
     */
    private int w;

    /**
     * The constructor
     *
     * @param digest the name of the hash function used by the OTS and the provider
     *               name of the hash function
     * @param w      the Winternitz parameter
     */
    public WinternitzOTSVerify(Digest digest, int w)
    {
        this.w = w;

        messDigestOTS = digest;
    }

    /**
     * @return The length of the one-time signature
     */
    public int getSignatureLength()
    {
        int mdsize = messDigestOTS.getDigestSize();
        int size = ((mdsize << 3) + (w - 1)) / w;
        int logs = getLog((size << w) + 1);
        size += (logs + w - 1) / w;

        return mdsize * size;
    }

    /**
     * This method computes the public OTS key from the one-time signature of a
     * message. This is *NOT* a complete OTS signature verification, but it
     * suffices for usage with CMSS.
     *
     * @param message   the message
     * @param signature the one-time signature
     * @return The public OTS key
     */
    public byte[] Verify(byte[] message, byte[] signature)
    {

        int mdsize = messDigestOTS.getDigestSize();
        byte[] hash = new byte[mdsize]; // hash of message m

        // create hash of message m
        messDigestOTS.update(message, 0, message.length);
        hash = new byte[messDigestOTS.getDigestSize()];
        messDigestOTS.doFinal(hash, 0);

        int size = ((mdsize << 3) + (w - 1)) / w;
        int logs = getLog((size << w) + 1);
        int keysize = size + (logs + w - 1) / w;

        int testKeySize = mdsize * keysize;

        if (testKeySize != signature.length)
        {
            return null;
        }

        byte[] testKey = new byte[testKeySize];

        int c = 0;
        int counter = 0;
        int test;

        if (8 % w == 0)
        {
            int d = 8 / w;
            int k = (1 << w) - 1;
            byte[] hlp = new byte[mdsize];

            // verify signature
            for (int i = 0; i < hash.length; i++)
            {
                for (int j = 0; j < d; j++)
                {
                    test = hash[i] & k;
                    c += test;

                    System.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

                    while (test < k)
                    {
                        messDigestOTS.update(hlp, 0, hlp.length);
                        hlp = new byte[messDigestOTS.getDigestSize()];
                        messDigestOTS.doFinal(hlp, 0);
                        test++;
                    }

                    System.arraycopy(hlp, 0, testKey, counter * mdsize, mdsize);
                    hash[i] = (byte)(hash[i] >>> w);
                    counter++;
                }
            }

            c = (size << w) - c;
            for (int i = 0; i < logs; i += w)
            {
                test = c & k;

                System.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

                while (test < k)
                {
                    messDigestOTS.update(hlp, 0, hlp.length);
                    hlp = new byte[messDigestOTS.getDigestSize()];
                    messDigestOTS.doFinal(hlp, 0);
                    test++;
                }
                System.arraycopy(hlp, 0, testKey, counter * mdsize, mdsize);
                c >>>= w;
                counter++;
            }
        }
        else if (w < 8)
        {
            int d = mdsize / w;
            int k = (1 << w) - 1;
            byte[] hlp = new byte[mdsize];
            long big8;
            int ii = 0;
            // create signature
            // first d*w bytes of hash
            for (int i = 0; i < d; i++)
            {
                big8 = 0;
                for (int j = 0; j < w; j++)
                {
                    big8 ^= (hash[ii] & 0xff) << (j << 3);
                    ii++;
                }
                for (int j = 0; j < 8; j++)
                {
                    test = (int)(big8 & k);
                    c += test;

                    System.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

                    while (test < k)
                    {
                        messDigestOTS.update(hlp, 0, hlp.length);
                        hlp = new byte[messDigestOTS.getDigestSize()];
                        messDigestOTS.doFinal(hlp, 0);
                        test++;
                    }

                    System.arraycopy(hlp, 0, testKey, counter * mdsize, mdsize);
                    big8 >>>= w;
                    counter++;
                }
            }
            // rest of hash
            d = mdsize % w;
            big8 = 0;
            for (int j = 0; j < d; j++)
            {
                big8 ^= (hash[ii] & 0xff) << (j << 3);
                ii++;
            }
            d <<= 3;
            for (int j = 0; j < d; j += w)
            {
                test = (int)(big8 & k);
                c += test;

                System.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

                while (test < k)
                {
                    messDigestOTS.update(hlp, 0, hlp.length);
                    hlp = new byte[messDigestOTS.getDigestSize()];
                    messDigestOTS.doFinal(hlp, 0);
                    test++;
                }

                System.arraycopy(hlp, 0, testKey, counter * mdsize, mdsize);
                big8 >>>= w;
                counter++;
            }

            // check bytes
            c = (size << w) - c;
            for (int i = 0; i < logs; i += w)
            {
                test = c & k;

                System.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

                while (test < k)
                {
                    messDigestOTS.update(hlp, 0, hlp.length);
                    hlp = new byte[messDigestOTS.getDigestSize()];
                    messDigestOTS.doFinal(hlp, 0);
                    test++;
                }

                System.arraycopy(hlp, 0, testKey, counter * mdsize, mdsize);
                c >>>= w;
                counter++;
            }
        }// end if(w<8)
        else if (w < 57)
        {
            int d = (mdsize << 3) - w;
            int k = (1 << w) - 1;
            byte[] hlp = new byte[mdsize];
            long big8, test8;
            int r = 0;
            int s, f, rest, ii;
            // create signature
            // first a*w bits of hash where a*w <= 8*mdsize < (a+1)*w
            while (r <= d)
            {
                s = r >>> 3;
                rest = r % 8;
                r += w;
                f = (r + 7) >>> 3;
                big8 = 0;
                ii = 0;
                for (int j = s; j < f; j++)
                {
                    big8 ^= (hash[j] & 0xff) << (ii << 3);
                    ii++;
                }

                big8 >>>= rest;
                test8 = (big8 & k);
                c += test8;

                System.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

                while (test8 < k)
                {
                    messDigestOTS.update(hlp, 0, hlp.length);
                    hlp = new byte[messDigestOTS.getDigestSize()];
                    messDigestOTS.doFinal(hlp, 0);
                    test8++;
                }

                System.arraycopy(hlp, 0, testKey, counter * mdsize, mdsize);
                counter++;

            }
            // rest of hash
            s = r >>> 3;
            if (s < mdsize)
            {
                rest = r % 8;
                big8 = 0;
                ii = 0;
                for (int j = s; j < mdsize; j++)
                {
                    big8 ^= (hash[j] & 0xff) << (ii << 3);
                    ii++;
                }

                big8 >>>= rest;
                test8 = (big8 & k);
                c += test8;

                System.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

                while (test8 < k)
                {
                    messDigestOTS.update(hlp, 0, hlp.length);
                    hlp = new byte[messDigestOTS.getDigestSize()];
                    messDigestOTS.doFinal(hlp, 0);
                    test8++;
                }

                System.arraycopy(hlp, 0, testKey, counter * mdsize, mdsize);
                counter++;
            }
            // check bytes
            c = (size << w) - c;
            for (int i = 0; i < logs; i += w)
            {
                test8 = (c & k);

                System.arraycopy(signature, counter * mdsize, hlp, 0, mdsize);

                while (test8 < k)
                {
                    messDigestOTS.update(hlp, 0, hlp.length);
                    hlp = new byte[messDigestOTS.getDigestSize()];
                    messDigestOTS.doFinal(hlp, 0);
                    test8++;
                }

                System.arraycopy(hlp, 0, testKey, counter * mdsize, mdsize);
                c >>>= w;
                counter++;
            }
        }// end if(w<57)

        byte[] TKey = new byte[mdsize];
        messDigestOTS.update(testKey, 0, testKey.length);
        TKey = new byte[messDigestOTS.getDigestSize()];
        messDigestOTS.doFinal(TKey, 0);

        return TKey;

    }

    /**
     * This method returns the least integer that is greater or equal to the
     * logarithm to the base 2 of an integer <code>intValue</code>.
     *
     * @param intValue an integer
     * @return The least integer greater or equal to the logarithm to the base
     *         256 of <code>intValue</code>
     */
    public int getLog(int intValue)
    {
        int log = 1;
        int i = 2;
        while (i < intValue)
        {
            i <<= 1;
            log++;
        }
        return log;
    }

}
