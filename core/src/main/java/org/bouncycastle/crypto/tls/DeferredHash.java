package org.bouncycastle.crypto.tls;

import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Shorts;

/**
 * Buffers input until the hash algorithm is determined.
 */
class DeferredHash
    implements TlsHandshakeHash
{
    protected static final int BUFFERING_HASH_LIMIT = 4;

    protected TlsContext context;

    private DigestInputBuffer buf;
    private Hashtable hashes;
    private Short prfHashAlgorithm;

    DeferredHash()
    {
        this.buf = new DigestInputBuffer();
        this.hashes = new Hashtable();
        this.prfHashAlgorithm = null;
    }

    private DeferredHash(Short prfHashAlgorithm, Digest prfHash)
    {
        this.buf = null;
        this.hashes = new Hashtable();
        this.prfHashAlgorithm = prfHashAlgorithm;
        hashes.put(prfHashAlgorithm, prfHash);
    }

    public void init(TlsContext context)
    {
        this.context = context;
    }

    public TlsHandshakeHash notifyPRFDetermined()
    {
        int prfAlgorithm = context.getSecurityParameters().getPrfAlgorithm();
        if (prfAlgorithm == PRFAlgorithm.tls_prf_legacy)
        {
            CombinedHash legacyHash = new CombinedHash();
            legacyHash.init(context);
            buf.updateDigest(legacyHash);
            return legacyHash.notifyPRFDetermined();
        }

        this.prfHashAlgorithm = Shorts.valueOf(TlsUtils.getHashAlgorithmForPRFAlgorithm(prfAlgorithm));

        checkTrackingHash(prfHashAlgorithm);

        return this;
    }

    public void trackHashAlgorithm(short hashAlgorithm)
    {
        if (buf == null)
        {
            throw new IllegalStateException("Too late to track more hash algorithms");
        }

        checkTrackingHash(Shorts.valueOf(hashAlgorithm));
    }

    public void sealHashAlgorithms()
    {
        checkStopBuffering();
    }

    public TlsHandshakeHash stopTracking()
    {
        Digest prfHash = TlsUtils.cloneHash(prfHashAlgorithm.shortValue(), (Digest)hashes.get(prfHashAlgorithm));
        if (buf != null)
        {
            buf.updateDigest(prfHash);
        }
        DeferredHash result = new DeferredHash(prfHashAlgorithm, prfHash);
        result.init(context);
        return result;
    }

    public Digest forkPRFHash()
    {
        checkStopBuffering();

        if (buf != null)
        {
            Digest prfHash = TlsUtils.createHash(prfHashAlgorithm.shortValue());
            buf.updateDigest(prfHash);
            return prfHash;
        }

        return TlsUtils.cloneHash(prfHashAlgorithm.shortValue(), (Digest)hashes.get(prfHashAlgorithm));
    }

    public byte[] getFinalHash(short hashAlgorithm)
    {
        Digest d = (Digest)hashes.get(Shorts.valueOf(hashAlgorithm));
        if (d == null)
        {
            throw new IllegalStateException("HashAlgorithm " + hashAlgorithm + " is not being tracked");
        }

        d = TlsUtils.cloneHash(hashAlgorithm, d);
        if (buf != null)
        {
            buf.updateDigest(d);
        }

        byte[] bs = new byte[d.getDigestSize()];
        d.doFinal(bs, 0);
        return bs;
    }

    public String getAlgorithmName()
    {
        throw new IllegalStateException("Use fork() to get a definite Digest");
    }

    public int getDigestSize()
    {
        throw new IllegalStateException("Use fork() to get a definite Digest");
    }

    public void update(byte input)
    {
        if (buf != null)
        {
            buf.write(input);
            return;
        }

        Enumeration e = hashes.elements();
        while (e.hasMoreElements())
        {
            Digest hash = (Digest)e.nextElement();
            hash.update(input);
        }
    }

    public void update(byte[] input, int inOff, int len)
    {
        if (buf != null)
        {
            buf.write(input, inOff, len);
            return;
        }

        Enumeration e = hashes.elements();
        while (e.hasMoreElements())
        {
            Digest hash = (Digest)e.nextElement();
            hash.update(input, inOff, len);
        }
    }

    public int doFinal(byte[] output, int outOff)
    {
        throw new IllegalStateException("Use fork() to get a definite Digest");
    }

    public void reset()
    {
        if (buf != null)
        {
            buf.reset();
            return;
        }

        Enumeration e = hashes.elements();
        while (e.hasMoreElements())
        {
            Digest hash = (Digest)e.nextElement();
            hash.reset();
        }
    }

    protected void checkStopBuffering()
    {
        if (buf != null && hashes.size() <= BUFFERING_HASH_LIMIT)
        {
            Enumeration e = hashes.elements();
            while (e.hasMoreElements())
            {
                Digest hash = (Digest)e.nextElement();
                buf.updateDigest(hash);
            }

            this.buf = null;
        }
    }

    protected void checkTrackingHash(Short hashAlgorithm)
    {
        if (!hashes.containsKey(hashAlgorithm))
        {
            Digest hash = TlsUtils.createHash(hashAlgorithm.shortValue());
            hashes.put(hashAlgorithm, hash);
        }
    }
}
