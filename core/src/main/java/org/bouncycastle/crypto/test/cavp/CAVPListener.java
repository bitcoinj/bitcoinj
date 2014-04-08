package org.bouncycastle.crypto.test.cavp;

import java.util.Properties;

public interface CAVPListener
{
    public void setup();

    public void receiveStart(String name);

    public void receiveCAVPVectors(String name, Properties config, Properties vectors);

    public void receiveCommentLine(String commentLine);

    public void receiveEnd();

    public void tearDown();
}
