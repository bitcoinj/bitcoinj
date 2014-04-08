package org.bouncycastle.crypto.tls;

class DTLSEpoch
{
    private final DTLSReplayWindow replayWindow = new DTLSReplayWindow();

    private final int epoch;
    private final TlsCipher cipher;

    private long sequence_number = 0;

    DTLSEpoch(int epoch, TlsCipher cipher)
    {
        if (epoch < 0)
        {
            throw new IllegalArgumentException("'epoch' must be >= 0");
        }
        if (cipher == null)
        {
            throw new IllegalArgumentException("'cipher' cannot be null");
        }

        this.epoch = epoch;
        this.cipher = cipher;
    }

    long allocateSequenceNumber()
    {
        // TODO Check for overflow
        return sequence_number++;
    }

    TlsCipher getCipher()
    {
        return cipher;
    }

    int getEpoch()
    {
        return epoch;
    }

    DTLSReplayWindow getReplayWindow()
    {
        return replayWindow;
    }

    long getSequence_number()
    {
        return sequence_number;
    }
}
