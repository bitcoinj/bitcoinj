package org.bouncycastle.crypto.tls;

public class SupplementalDataEntry
{
    protected int dataType;
    protected byte[] data;

    public SupplementalDataEntry(int dataType, byte[] data)
    {
        this.dataType = dataType;
        this.data = data;
    }

    public int getDataType()
    {
        return dataType;
    }

    public byte[] getData()
    {
        return data;
    }
}
