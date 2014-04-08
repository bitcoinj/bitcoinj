package org.bouncycastle.crypto.test.cavp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.HMac;

public class CAVPReader
{

    private static final Pattern COMMENT_PATTERN = Pattern.compile("^\\s*\\#\\s*(.*)$");
    private static final Pattern CONFIG_PATTERN = Pattern.compile("^\\s*+\\[\\s*+(.*?)\\s*+=\\s*+(.*?)\\s*+\\]\\s*+$");
    private static final Pattern VECTOR_PATTERN = Pattern.compile("^\\s*+(.*?)\\s*+=\\s*+(.*?)\\s*+$");
    private static final Pattern EMPTY_PATTERN = Pattern.compile("^\\s*+$");
    static final Pattern PATTERN_FOR_R = Pattern.compile("(\\d+)_BITS");
    private final CAVPListener listener;
    private String name;
    private BufferedReader lineReader;


    public CAVPReader(CAVPListener listener)
    {
        this.listener = listener;
    }

    public void setInput(String name, Reader reader)
    {
        this.name = name;
        this.lineReader = new BufferedReader(reader);
    }

    public void readAll()
        throws IOException
    {

        listener.setup();

        Properties config = new Properties();

        boolean startNewVector = true;

        Properties vectors = new Properties();

        while (true)
        {
            final String line = lineReader.readLine();
            if (line == null)
            {
                listener.receiveEnd();
                break;
            }

            final Matcher commentMatcher = COMMENT_PATTERN.matcher(line);
            if (commentMatcher.matches())
            {
                listener.receiveCommentLine(commentMatcher.group(1));
                continue;
            }

            final Matcher configMatcher = CONFIG_PATTERN.matcher(line);
            if (configMatcher.matches())
            {
                config.put(configMatcher.group(1), configMatcher.group(2));
                continue;
            }

            final Matcher vectorMatcher = VECTOR_PATTERN.matcher(line);
            if (vectorMatcher.matches())
            {
                vectors.put(vectorMatcher.group(1), vectorMatcher.group(2));
                startNewVector = false;
                continue;
            }

            final Matcher emptyMatcher = EMPTY_PATTERN.matcher(line);
            if (emptyMatcher.matches())
            {
                if (startNewVector)
                {
                    continue;
                }

                listener.receiveCAVPVectors(name, config, vectors);
                vectors = new Properties();
                startNewVector = true;
            }
        }

        listener.tearDown();
    }

    static Mac createPRF(Properties config)
    {
        final Mac prf;
        if (config.getProperty("PRF").matches("CMAC_AES\\d\\d\\d"))
        {
            BlockCipher blockCipher = new AESFastEngine();
            prf = new CMac(blockCipher);
        }
        else if (config.getProperty("PRF").matches("CMAC_TDES\\d"))
        {
            BlockCipher blockCipher = new DESedeEngine();
            prf = new CMac(blockCipher);
        }
        else if (config.getProperty("PRF").matches("HMAC_SHA1"))
        {
            Digest digest = new SHA1Digest();
            prf = new HMac(digest);
        }
        else if (config.getProperty("PRF").matches("HMAC_SHA224"))
        {
            Digest digest = new SHA224Digest();
            prf = new HMac(digest);
        }
        else if (config.getProperty("PRF").matches("HMAC_SHA256"))
        {
            Digest digest = new SHA256Digest();
            prf = new HMac(digest);
        }
        else if (config.getProperty("PRF").matches("HMAC_SHA384"))
        {
            Digest digest = new SHA384Digest();
            prf = new HMac(digest);
        }
        else if (config.getProperty("PRF").matches("HMAC_SHA512"))
        {
            Digest digest = new SHA512Digest();
            prf = new HMac(digest);
        }
        else
        {
            throw new IllegalStateException("Unknown Mac for PRF");
        }
        return prf;
    }

}
