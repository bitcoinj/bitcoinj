package org.bouncycastle.pqc.asn1;

import java.math.BigInteger;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.pqc.crypto.gmss.GMSSLeaf;
import org.bouncycastle.pqc.crypto.gmss.GMSSParameters;
import org.bouncycastle.pqc.crypto.gmss.GMSSRootCalc;
import org.bouncycastle.pqc.crypto.gmss.GMSSRootSig;
import org.bouncycastle.pqc.crypto.gmss.Treehash;

public class GMSSPrivateKey
    extends ASN1Object
{
    private ASN1Primitive primitive;

    private GMSSPrivateKey(ASN1Sequence mtsPrivateKey)
    {
        // --- Decode <index>.
        ASN1Sequence indexPart = (ASN1Sequence)mtsPrivateKey.getObjectAt(0);
        int[] index = new int[indexPart.size()];
        for (int i = 0; i < indexPart.size(); i++)
        {
            index[i] = checkBigIntegerInIntRange(indexPart.getObjectAt(i));
        }

        // --- Decode <curSeeds>.
        ASN1Sequence curSeedsPart = (ASN1Sequence)mtsPrivateKey.getObjectAt(1);
        byte[][] curSeeds = new byte[curSeedsPart.size()][];
        for (int i = 0; i < curSeeds.length; i++)
        {
            curSeeds[i] = ((DEROctetString)curSeedsPart.getObjectAt(i)).getOctets();
        }

        // --- Decode <nextNextSeeds>.
        ASN1Sequence nextNextSeedsPart = (ASN1Sequence)mtsPrivateKey.getObjectAt(2);
        byte[][] nextNextSeeds = new byte[nextNextSeedsPart.size()][];
        for (int i = 0; i < nextNextSeeds.length; i++)
        {
            nextNextSeeds[i] = ((DEROctetString)nextNextSeedsPart.getObjectAt(i)).getOctets();
        }

        // --- Decode <curAuth>.
        ASN1Sequence curAuthPart0 = (ASN1Sequence)mtsPrivateKey.getObjectAt(3);
        ASN1Sequence curAuthPart1;

        byte[][][] curAuth = new byte[curAuthPart0.size()][][];
        for (int i = 0; i < curAuth.length; i++)
        {
            curAuthPart1 = (ASN1Sequence)curAuthPart0.getObjectAt(i);
            curAuth[i] = new byte[curAuthPart1.size()][];
            for (int j = 0; j < curAuth[i].length; j++)
            {
                curAuth[i][j] = ((DEROctetString)curAuthPart1.getObjectAt(j)).getOctets();
            }
        }

        // --- Decode <nextAuth>.
        ASN1Sequence nextAuthPart0 = (ASN1Sequence)mtsPrivateKey.getObjectAt(4);
        ASN1Sequence nextAuthPart1;

        byte[][][] nextAuth = new byte[nextAuthPart0.size()][][];
        for (int i = 0; i < nextAuth.length; i++)
        {
            nextAuthPart1 = (ASN1Sequence)nextAuthPart0.getObjectAt(i);
            nextAuth[i] = new byte[nextAuthPart1.size()][];
            for (int j = 0; j < nextAuth[i].length; j++)
            {
                nextAuth[i][j] = ((DEROctetString)nextAuthPart1.getObjectAt(j)).getOctets();
            }
        }

        // --- Decode <curTreehash>.
        ASN1Sequence seqOfcurTreehash0 = (ASN1Sequence)mtsPrivateKey.getObjectAt(5);
        ASN1Sequence seqOfcurTreehash1;
        ASN1Sequence seqOfcurTreehashStat;
        ASN1Sequence seqOfcurTreehashBytes;
        ASN1Sequence seqOfcurTreehashInts;
        ASN1Sequence seqOfcurTreehashString;

        Treehash[][] curTreehash = new Treehash[seqOfcurTreehash0.size()][];
        /*
        for (int i = 0; i < curTreehash.length; i++)
        {
            seqOfcurTreehash1 = (ASN1Sequence)seqOfcurTreehash0.getObjectAt(i);
            curTreehash[i] = new Treehash[seqOfcurTreehash1.size()];
            for (int j = 0; j < curTreehash[i].length; j++)
            {
                seqOfcurTreehashStat = (ASN1Sequence)seqOfcurTreehash1.getObjectAt(j);
                seqOfcurTreehashString = (ASN1Sequence)seqOfcurTreehashStat
                    .getObjectAt(0);
                seqOfcurTreehashBytes = (ASN1Sequence)seqOfcurTreehashStat
                    .getObjectAt(1);
                seqOfcurTreehashInts = (ASN1Sequence)seqOfcurTreehashStat
                    .getObjectAt(2);

                String[] name = new String[2];
                name[0] = ((DERIA5String)seqOfcurTreehashString.getObjectAt(0)).getString();
                name[1] = ((DERIA5String)seqOfcurTreehashString.getObjectAt(1)).getString();

                int tailLength = checkBigIntegerInIntRange(seqOfcurTreehashInts.getObjectAt(1));
                byte[][] statByte = new byte[3 + tailLength][];
                statByte[0] = ((DEROctetString)seqOfcurTreehashBytes.getObjectAt(0)).getOctets();

                if (statByte[0].length == 0)
                { // if null was encoded
                    statByte[0] = null;
                }

                statByte[1] = ((DEROctetString)seqOfcurTreehashBytes.getObjectAt(1)).getOctets();
                statByte[2] = ((DEROctetString)seqOfcurTreehashBytes.getObjectAt(2)).getOctets();
                for (int k = 0; k < tailLength; k++)
                {
                    statByte[3 + k] = ((DEROctetString)seqOfcurTreehashBytes
                        .getObjectAt(3 + k)).getOctets();
                }
                int[] statInt = new int[6 + tailLength];
                statInt[0] = checkBigIntegerInIntRange(seqOfcurTreehashInts.getObjectAt(0));
                statInt[1] = tailLength;
                statInt[2] = checkBigIntegerInIntRange(seqOfcurTreehashInts.getObjectAt(2));
                statInt[3] = checkBigIntegerInIntRange(seqOfcurTreehashInts.getObjectAt(3));
                statInt[4] = checkBigIntegerInIntRange(seqOfcurTreehashInts.getObjectAt(4));
                statInt[5] = checkBigIntegerInIntRange(seqOfcurTreehashInts.getObjectAt(5));
                for (int k = 0; k < tailLength; k++)
                {
                    statInt[6 + k] = checkBigIntegerInIntRange(seqOfcurTreehashInts.getObjectAt(6 + k));
                }

                // TODO: Check if we can do better than throwing away name[1] !!!
                curTreehash[i][j] = new Treehash(DigestFactory.getDigest(name[0]).getClass(), statByte, statInt);
            }
        }


        // --- Decode <nextTreehash>.
        ASN1Sequence seqOfNextTreehash0 = (ASN1Sequence)mtsPrivateKey.getObjectAt(6);
        ASN1Sequence seqOfNextTreehash1;
        ASN1Sequence seqOfNextTreehashStat;
        ASN1Sequence seqOfNextTreehashBytes;
        ASN1Sequence seqOfNextTreehashInts;
        ASN1Sequence seqOfNextTreehashString;

        Treehash[][] nextTreehash = new Treehash[seqOfNextTreehash0.size()][];

        for (int i = 0; i < nextTreehash.length; i++)
        {
            seqOfNextTreehash1 = (ASN1Sequence)seqOfNextTreehash0.getObjectAt(i);
            nextTreehash[i] = new Treehash[seqOfNextTreehash1.size()];
            for (int j = 0; j < nextTreehash[i].length; j++)
            {
                seqOfNextTreehashStat = (ASN1Sequence)seqOfNextTreehash1
                    .getObjectAt(j);
                seqOfNextTreehashString = (ASN1Sequence)seqOfNextTreehashStat
                    .getObjectAt(0);
                seqOfNextTreehashBytes = (ASN1Sequence)seqOfNextTreehashStat
                    .getObjectAt(1);
                seqOfNextTreehashInts = (ASN1Sequence)seqOfNextTreehashStat
                    .getObjectAt(2);

                String[] name = new String[2];
                name[0] = ((DERIA5String)seqOfNextTreehashString.getObjectAt(0))
                    .getString();
                name[1] = ((DERIA5String)seqOfNextTreehashString.getObjectAt(1))
                    .getString();

                int tailLength = checkBigIntegerInIntRange(seqOfNextTreehashInts.getObjectAt(1));

                byte[][] statByte = new byte[3 + tailLength][];
                statByte[0] = ((DEROctetString)seqOfNextTreehashBytes.getObjectAt(0)).getOctets();
                if (statByte[0].length == 0)
                { // if null was encoded
                    statByte[0] = null;
                }

                statByte[1] = ((DEROctetString)seqOfNextTreehashBytes.getObjectAt(1)).getOctets();
                statByte[2] = ((DEROctetString)seqOfNextTreehashBytes.getObjectAt(2)).getOctets();
                for (int k = 0; k < tailLength; k++)
                {
                    statByte[3 + k] = ((DEROctetString)seqOfNextTreehashBytes
                        .getObjectAt(3 + k)).getOctets();
                }
                int[] statInt = new int[6 + tailLength];
                statInt[0] = checkBigIntegerInIntRange(seqOfNextTreehashInts.getObjectAt(0));

                statInt[1] = tailLength;
                statInt[2] = checkBigIntegerInIntRange(seqOfNextTreehashInts.getObjectAt(2));

                statInt[3] = checkBigIntegerInIntRange(seqOfNextTreehashInts.getObjectAt(3));

                statInt[4] = checkBigIntegerInIntRange(seqOfNextTreehashInts.getObjectAt(4));

                statInt[5] = checkBigIntegerInIntRange(seqOfNextTreehashInts.getObjectAt(5));

                for (int k = 0; k < tailLength; k++)
                {
                    statInt[6 + k] = checkBigIntegerInIntRange(seqOfNextTreehashInts.getObjectAt(6 + k));

                }
                nextTreehash[i][j] = new Treehash(DigestFactory.getDigest(name[0]).getClass(), statByte, statInt);
            }
        }


        // --- Decode <keep>.
        ASN1Sequence keepPart0 = (ASN1Sequence)mtsPrivateKey.getObjectAt(7);
        ASN1Sequence keepPart1;

        byte[][][] keep = new byte[keepPart0.size()][][];
        for (int i = 0; i < keep.length; i++)
        {
            keepPart1 = (ASN1Sequence)keepPart0.getObjectAt(i);
            keep[i] = new byte[keepPart1.size()][];
            for (int j = 0; j < keep[i].length; j++)
            {
                keep[i][j] = ((DEROctetString)keepPart1.getObjectAt(j)).getOctets();
            }
        }

        // --- Decode <curStack>.
        ASN1Sequence curStackPart0 = (ASN1Sequence)mtsPrivateKey.getObjectAt(8);
        ASN1Sequence curStackPart1;

        Vector[] curStack = new Vector[curStackPart0.size()];
        for (int i = 0; i < curStack.length; i++)
        {
            curStackPart1 = (ASN1Sequence)curStackPart0.getObjectAt(i);
            curStack[i] = new Vector();
            for (int j = 0; j < curStackPart1.size(); j++)
            {
                curStack[i].addElement(((DEROctetString)curStackPart1.getObjectAt(j)).getOctets());
            }
        }

        // --- Decode <nextStack>.
        ASN1Sequence nextStackPart0 = (ASN1Sequence)mtsPrivateKey.getObjectAt(9);
        ASN1Sequence nextStackPart1;

        Vector[] nextStack = new Vector[nextStackPart0.size()];
        for (int i = 0; i < nextStack.length; i++)
        {
            nextStackPart1 = (ASN1Sequence)nextStackPart0.getObjectAt(i);
            nextStack[i] = new Vector();
            for (int j = 0; j < nextStackPart1.size(); j++)
            {
                nextStack[i].addElement(((DEROctetString)nextStackPart1
                    .getObjectAt(j)).getOctets());
            }
        }

        // --- Decode <curRetain>.
        ASN1Sequence curRetainPart0 = (ASN1Sequence)mtsPrivateKey.getObjectAt(10);
        ASN1Sequence curRetainPart1;
        ASN1Sequence curRetainPart2;

        Vector[][] curRetain = new Vector[curRetainPart0.size()][];
        for (int i = 0; i < curRetain.length; i++)
        {
            curRetainPart1 = (ASN1Sequence)curRetainPart0.getObjectAt(i);
            curRetain[i] = new Vector[curRetainPart1.size()];
            for (int j = 0; j < curRetain[i].length; j++)
            {
                curRetainPart2 = (ASN1Sequence)curRetainPart1.getObjectAt(j);
                curRetain[i][j] = new Vector();
                for (int k = 0; k < curRetainPart2.size(); k++)
                {
                    curRetain[i][j]
                        .addElement(((DEROctetString)curRetainPart2
                            .getObjectAt(k)).getOctets());
                }
            }
        }

        // --- Decode <nextRetain>.
        ASN1Sequence nextRetainPart0 = (ASN1Sequence)mtsPrivateKey.getObjectAt(11);
        ASN1Sequence nextRetainPart1;
        ASN1Sequence nextRetainPart2;

        Vector[][] nextRetain = new Vector[nextRetainPart0.size()][];
        for (int i = 0; i < nextRetain.length; i++)
        {
            nextRetainPart1 = (ASN1Sequence)nextRetainPart0.getObjectAt(i);
            nextRetain[i] = new Vector[nextRetainPart1.size()];
            for (int j = 0; j < nextRetain[i].length; j++)
            {
                nextRetainPart2 = (ASN1Sequence)nextRetainPart1.getObjectAt(j);
                nextRetain[i][j] = new Vector();
                for (int k = 0; k < nextRetainPart2.size(); k++)
                {
                    nextRetain[i][j]
                        .addElement(((DEROctetString)nextRetainPart2
                            .getObjectAt(k)).getOctets());
                }
            }
        }

        // --- Decode <nextNextLeaf>.
        ASN1Sequence seqOfLeafs = (ASN1Sequence)mtsPrivateKey.getObjectAt(12);
        ASN1Sequence seqOfLeafStat;
        ASN1Sequence seqOfLeafBytes;
        ASN1Sequence seqOfLeafInts;
        ASN1Sequence seqOfLeafString;

        GMSSLeaf[] nextNextLeaf = new GMSSLeaf[seqOfLeafs.size()];

        for (int i = 0; i < nextNextLeaf.length; i++)
        {
            seqOfLeafStat = (ASN1Sequence)seqOfLeafs.getObjectAt(i);
            // nextNextAuth[i]= new byte[nextNextAuthPart1.size()][];
            seqOfLeafString = (ASN1Sequence)seqOfLeafStat.getObjectAt(0);
            seqOfLeafBytes = (ASN1Sequence)seqOfLeafStat.getObjectAt(1);
            seqOfLeafInts = (ASN1Sequence)seqOfLeafStat.getObjectAt(2);

            String[] name = new String[2];
            name[0] = ((DERIA5String)seqOfLeafString.getObjectAt(0)).getString();
            name[1] = ((DERIA5String)seqOfLeafString.getObjectAt(1)).getString();
            byte[][] statByte = new byte[4][];
            statByte[0] = ((DEROctetString)seqOfLeafBytes.getObjectAt(0))
                .getOctets();
            statByte[1] = ((DEROctetString)seqOfLeafBytes.getObjectAt(1))
                .getOctets();
            statByte[2] = ((DEROctetString)seqOfLeafBytes.getObjectAt(2))
                .getOctets();
            statByte[3] = ((DEROctetString)seqOfLeafBytes.getObjectAt(3))
                .getOctets();
            int[] statInt = new int[4];
            statInt[0] = checkBigIntegerInIntRange(seqOfLeafInts.getObjectAt(0));
            statInt[1] = checkBigIntegerInIntRange(seqOfLeafInts.getObjectAt(1));
            statInt[2] = checkBigIntegerInIntRange(seqOfLeafInts.getObjectAt(2));
            statInt[3] = checkBigIntegerInIntRange(seqOfLeafInts.getObjectAt(3));
            nextNextLeaf[i] = new GMSSLeaf(DigestFactory.getDigest(name[0]).getClass(), statByte, statInt);
        }

        // --- Decode <upperLeaf>.
        ASN1Sequence seqOfUpperLeafs = (ASN1Sequence)mtsPrivateKey.getObjectAt(13);
        ASN1Sequence seqOfUpperLeafStat;
        ASN1Sequence seqOfUpperLeafBytes;
        ASN1Sequence seqOfUpperLeafInts;
        ASN1Sequence seqOfUpperLeafString;

        GMSSLeaf[] upperLeaf = new GMSSLeaf[seqOfUpperLeafs.size()];

        for (int i = 0; i < upperLeaf.length; i++)
        {
            seqOfUpperLeafStat = (ASN1Sequence)seqOfUpperLeafs.getObjectAt(i);
            seqOfUpperLeafString = (ASN1Sequence)seqOfUpperLeafStat.getObjectAt(0);
            seqOfUpperLeafBytes = (ASN1Sequence)seqOfUpperLeafStat.getObjectAt(1);
            seqOfUpperLeafInts = (ASN1Sequence)seqOfUpperLeafStat.getObjectAt(2);

            String[] name = new String[2];
            name[0] = ((DERIA5String)seqOfUpperLeafString.getObjectAt(0)).getString();
            name[1] = ((DERIA5String)seqOfUpperLeafString.getObjectAt(1)).getString();
            byte[][] statByte = new byte[4][];
            statByte[0] = ((DEROctetString)seqOfUpperLeafBytes.getObjectAt(0))
                .getOctets();
            statByte[1] = ((DEROctetString)seqOfUpperLeafBytes.getObjectAt(1))
                .getOctets();
            statByte[2] = ((DEROctetString)seqOfUpperLeafBytes.getObjectAt(2))
                .getOctets();
            statByte[3] = ((DEROctetString)seqOfUpperLeafBytes.getObjectAt(3))
                .getOctets();
            int[] statInt = new int[4];
            statInt[0] = checkBigIntegerInIntRange(seqOfUpperLeafInts.getObjectAt(0));
            statInt[1] = checkBigIntegerInIntRange(seqOfUpperLeafInts.getObjectAt(1));
            statInt[2] = checkBigIntegerInIntRange(seqOfUpperLeafInts.getObjectAt(2));
            statInt[3] = checkBigIntegerInIntRange(seqOfUpperLeafInts.getObjectAt(3));
            upperLeaf[i] = new GMSSLeaf(DigestFactory.getDigest(name[0]).getClass(), statByte, statInt);
        }

        // --- Decode <upperTreehashLeaf>.
        ASN1Sequence seqOfUpperTHLeafs = (ASN1Sequence)mtsPrivateKey.getObjectAt(14);
        ASN1Sequence seqOfUpperTHLeafStat;
        ASN1Sequence seqOfUpperTHLeafBytes;
        ASN1Sequence seqOfUpperTHLeafInts;
        ASN1Sequence seqOfUpperTHLeafString;

        GMSSLeaf[] upperTHLeaf = new GMSSLeaf[seqOfUpperTHLeafs.size()];

        for (int i = 0; i < upperTHLeaf.length; i++)
        {
            seqOfUpperTHLeafStat = (ASN1Sequence)seqOfUpperTHLeafs.getObjectAt(i);
            seqOfUpperTHLeafString = (ASN1Sequence)seqOfUpperTHLeafStat.getObjectAt(0);
            seqOfUpperTHLeafBytes = (ASN1Sequence)seqOfUpperTHLeafStat.getObjectAt(1);
            seqOfUpperTHLeafInts = (ASN1Sequence)seqOfUpperTHLeafStat.getObjectAt(2);

            String[] name = new String[2];
            name[0] = ((DERIA5String)seqOfUpperTHLeafString.getObjectAt(0))
                .getString();
            name[1] = ((DERIA5String)seqOfUpperTHLeafString.getObjectAt(1))
                .getString();
            byte[][] statByte = new byte[4][];
            statByte[0] = ((DEROctetString)seqOfUpperTHLeafBytes.getObjectAt(0))
                .getOctets();
            statByte[1] = ((DEROctetString)seqOfUpperTHLeafBytes.getObjectAt(1))
                .getOctets();
            statByte[2] = ((DEROctetString)seqOfUpperTHLeafBytes.getObjectAt(2))
                .getOctets();
            statByte[3] = ((DEROctetString)seqOfUpperTHLeafBytes.getObjectAt(3))
                .getOctets();
            int[] statInt = new int[4];
            statInt[0] = checkBigIntegerInIntRange(seqOfUpperTHLeafInts.getObjectAt(0));
            statInt[1] = checkBigIntegerInIntRange(seqOfUpperTHLeafInts.getObjectAt(1));
            statInt[2] = checkBigIntegerInIntRange(seqOfUpperTHLeafInts.getObjectAt(2));
            statInt[3] = checkBigIntegerInIntRange(seqOfUpperTHLeafInts.getObjectAt(3));
            upperTHLeaf[i] = new GMSSLeaf(DigestFactory.getDigest(name[0]).getClass(), statByte, statInt);
        }

        // --- Decode <minTreehash>.
        ASN1Sequence minTreehashPart = (ASN1Sequence)mtsPrivateKey.getObjectAt(15);
        int[] minTreehash = new int[minTreehashPart.size()];
        for (int i = 0; i < minTreehashPart.size(); i++)
        {
            minTreehash[i] = checkBigIntegerInIntRange(minTreehashPart.getObjectAt(i));
        }

        // --- Decode <nextRoot>.
        ASN1Sequence seqOfnextRoots = (ASN1Sequence)mtsPrivateKey.getObjectAt(16);
        byte[][] nextRoot = new byte[seqOfnextRoots.size()][];
        for (int i = 0; i < nextRoot.length; i++)
        {
            nextRoot[i] = ((DEROctetString)seqOfnextRoots.getObjectAt(i))
                .getOctets();
        }

        // --- Decode <nextNextRoot>.
        ASN1Sequence seqOfnextNextRoot = (ASN1Sequence)mtsPrivateKey.getObjectAt(17);
        ASN1Sequence seqOfnextNextRootStat;
        ASN1Sequence seqOfnextNextRootBytes;
        ASN1Sequence seqOfnextNextRootInts;
        ASN1Sequence seqOfnextNextRootString;
        ASN1Sequence seqOfnextNextRootTreeH;
        ASN1Sequence seqOfnextNextRootRetain;

        GMSSRootCalc[] nextNextRoot = new GMSSRootCalc[seqOfnextNextRoot.size()];

        for (int i = 0; i < nextNextRoot.length; i++)
        {
            seqOfnextNextRootStat = (ASN1Sequence)seqOfnextNextRoot.getObjectAt(i);
            seqOfnextNextRootString = (ASN1Sequence)seqOfnextNextRootStat
                .getObjectAt(0);
            seqOfnextNextRootBytes = (ASN1Sequence)seqOfnextNextRootStat
                .getObjectAt(1);
            seqOfnextNextRootInts = (ASN1Sequence)seqOfnextNextRootStat.getObjectAt(2);
            seqOfnextNextRootTreeH = (ASN1Sequence)seqOfnextNextRootStat
                .getObjectAt(3);
            seqOfnextNextRootRetain = (ASN1Sequence)seqOfnextNextRootStat
                .getObjectAt(4);

            // decode treehash of nextNextRoot
            // ---------------------------------
            ASN1Sequence seqOfnextNextRootTreeHStat;
            ASN1Sequence seqOfnextNextRootTreeHBytes;
            ASN1Sequence seqOfnextNextRootTreeHInts;
            ASN1Sequence seqOfnextNextRootTreeHString;

            Treehash[] nnRTreehash = new Treehash[seqOfnextNextRootTreeH.size()];

            for (int k = 0; k < nnRTreehash.length; k++)
            {
                seqOfnextNextRootTreeHStat = (ASN1Sequence)seqOfnextNextRootTreeH
                    .getObjectAt(k);
                seqOfnextNextRootTreeHString = (ASN1Sequence)seqOfnextNextRootTreeHStat
                    .getObjectAt(0);
                seqOfnextNextRootTreeHBytes = (ASN1Sequence)seqOfnextNextRootTreeHStat
                    .getObjectAt(1);
                seqOfnextNextRootTreeHInts = (ASN1Sequence)seqOfnextNextRootTreeHStat
                    .getObjectAt(2);

                String[] name = new String[2];
                name[0] = ((DERIA5String)seqOfnextNextRootTreeHString.getObjectAt(0))
                    .getString();
                name[1] = ((DERIA5String)seqOfnextNextRootTreeHString.getObjectAt(1))
                    .getString();

                int tailLength = checkBigIntegerInIntRange(seqOfnextNextRootTreeHInts.getObjectAt(1));

                byte[][] statByte = new byte[3 + tailLength][];
                statByte[0] = ((DEROctetString)seqOfnextNextRootTreeHBytes
                    .getObjectAt(0)).getOctets();
                if (statByte[0].length == 0)
                { // if null was encoded
                    statByte[0] = null;
                }

                statByte[1] = ((DEROctetString)seqOfnextNextRootTreeHBytes
                    .getObjectAt(1)).getOctets();
                statByte[2] = ((DEROctetString)seqOfnextNextRootTreeHBytes
                    .getObjectAt(2)).getOctets();
                for (int j = 0; j < tailLength; j++)
                {
                    statByte[3 + j] = ((DEROctetString)seqOfnextNextRootTreeHBytes
                        .getObjectAt(3 + j)).getOctets();
                }
                int[] statInt = new int[6 + tailLength];
                statInt[0] = checkBigIntegerInIntRange(seqOfnextNextRootTreeHInts.getObjectAt(0));

                statInt[1] = tailLength;
                statInt[2] = checkBigIntegerInIntRange(seqOfnextNextRootTreeHInts.getObjectAt(2));

                statInt[3] = checkBigIntegerInIntRange(seqOfnextNextRootTreeHInts.getObjectAt(3));

                statInt[4] = checkBigIntegerInIntRange(seqOfnextNextRootTreeHInts.getObjectAt(4));

                statInt[5] = checkBigIntegerInIntRange(seqOfnextNextRootTreeHInts.getObjectAt(5));

                for (int j = 0; j < tailLength; j++)
                {
                    statInt[6 + j] = checkBigIntegerInIntRange(seqOfnextNextRootTreeHInts
                        .getObjectAt(6 + j));
                }
                nnRTreehash[k] = new Treehash(DigestFactory.getDigest(name[0]).getClass(), statByte, statInt);
            }
            // ---------------------------------

            // decode retain of nextNextRoot
            // ---------------------------------
            // ASN1Sequence seqOfnextNextRootRetainPart0 =
            // (ASN1Sequence)seqOfnextNextRootRetain.get(0);
            ASN1Sequence seqOfnextNextRootRetainPart1;

            Vector[] nnRRetain = new Vector[seqOfnextNextRootRetain.size()];
            for (int j = 0; j < nnRRetain.length; j++)
            {
                seqOfnextNextRootRetainPart1 = (ASN1Sequence)seqOfnextNextRootRetain
                    .getObjectAt(j);
                nnRRetain[j] = new Vector();
                for (int k = 0; k < seqOfnextNextRootRetainPart1.size(); k++)
                {
                    nnRRetain[j]
                        .addElement(((DEROctetString)seqOfnextNextRootRetainPart1
                            .getObjectAt(k)).getOctets());
                }
            }
            // ---------------------------------

            String[] name = new String[2];
            name[0] = ((DERIA5String)seqOfnextNextRootString.getObjectAt(0))
                .getString();
            name[1] = ((DERIA5String)seqOfnextNextRootString.getObjectAt(1))
                .getString();

            int heightOfTree = checkBigIntegerInIntRange(seqOfnextNextRootInts.getObjectAt(0));
            int tailLength = checkBigIntegerInIntRange(seqOfnextNextRootInts.getObjectAt(7));
            byte[][] statByte = new byte[1 + heightOfTree + tailLength][];
            statByte[0] = ((DEROctetString)seqOfnextNextRootBytes.getObjectAt(0))
                .getOctets();
            for (int j = 0; j < heightOfTree; j++)
            {
                statByte[1 + j] = ((DEROctetString)seqOfnextNextRootBytes
                    .getObjectAt(1 + j)).getOctets();
            }
            for (int j = 0; j < tailLength; j++)
            {
                statByte[1 + heightOfTree + j] = ((DEROctetString)seqOfnextNextRootBytes
                    .getObjectAt(1 + heightOfTree + j)).getOctets();
            }
            int[] statInt = new int[8 + heightOfTree + tailLength];
            statInt[0] = heightOfTree;
            statInt[1] = checkBigIntegerInIntRange(seqOfnextNextRootInts.getObjectAt(1));
            statInt[2] = checkBigIntegerInIntRange(seqOfnextNextRootInts.getObjectAt(2));
            statInt[3] = checkBigIntegerInIntRange(seqOfnextNextRootInts.getObjectAt(3));
            statInt[4] = checkBigIntegerInIntRange(seqOfnextNextRootInts.getObjectAt(4));
            statInt[5] = checkBigIntegerInIntRange(seqOfnextNextRootInts.getObjectAt(5));
            statInt[6] = checkBigIntegerInIntRange(seqOfnextNextRootInts.getObjectAt(6));
            statInt[7] = tailLength;
            for (int j = 0; j < heightOfTree; j++)
            {
                statInt[8 + j] = checkBigIntegerInIntRange(seqOfnextNextRootInts.getObjectAt(8 + j));
            }
            for (int j = 0; j < tailLength; j++)
            {
                statInt[8 + heightOfTree + j] = checkBigIntegerInIntRange(seqOfnextNextRootInts.getObjectAt(8
                    + heightOfTree + j));
            }
            nextNextRoot[i] = new GMSSRootCalc(DigestFactory.getDigest(name[0]).getClass(), statByte, statInt,
                nnRTreehash, nnRRetain);
        }

        // --- Decode <curRootSig>.
        ASN1Sequence seqOfcurRootSig = (ASN1Sequence)mtsPrivateKey.getObjectAt(18);
        byte[][] curRootSig = new byte[seqOfcurRootSig.size()][];
        for (int i = 0; i < curRootSig.length; i++)
        {
            curRootSig[i] = ((DEROctetString)seqOfcurRootSig.getObjectAt(i))
                .getOctets();
        }

        // --- Decode <nextRootSig>.
        ASN1Sequence seqOfnextRootSigs = (ASN1Sequence)mtsPrivateKey.getObjectAt(19);
        ASN1Sequence seqOfnRSStats;
        ASN1Sequence seqOfnRSStrings;
        ASN1Sequence seqOfnRSInts;
        ASN1Sequence seqOfnRSBytes;

        GMSSRootSig[] nextRootSig = new GMSSRootSig[seqOfnextRootSigs.size()];

        for (int i = 0; i < nextRootSig.length; i++)
        {
            seqOfnRSStats = (ASN1Sequence)seqOfnextRootSigs.getObjectAt(i);
            // nextNextAuth[i]= new byte[nextNextAuthPart1.size()][];
            seqOfnRSStrings = (ASN1Sequence)seqOfnRSStats.getObjectAt(0);
            seqOfnRSBytes = (ASN1Sequence)seqOfnRSStats.getObjectAt(1);
            seqOfnRSInts = (ASN1Sequence)seqOfnRSStats.getObjectAt(2);

            String[] name = new String[2];
            name[0] = ((DERIA5String)seqOfnRSStrings.getObjectAt(0)).getString();
            name[1] = ((DERIA5String)seqOfnRSStrings.getObjectAt(1)).getString();
            byte[][] statByte = new byte[5][];
            statByte[0] = ((DEROctetString)seqOfnRSBytes.getObjectAt(0))
                .getOctets();
            statByte[1] = ((DEROctetString)seqOfnRSBytes.getObjectAt(1))
                .getOctets();
            statByte[2] = ((DEROctetString)seqOfnRSBytes.getObjectAt(2))
                .getOctets();
            statByte[3] = ((DEROctetString)seqOfnRSBytes.getObjectAt(3))
                .getOctets();
            statByte[4] = ((DEROctetString)seqOfnRSBytes.getObjectAt(4))
                .getOctets();
            int[] statInt = new int[9];
            statInt[0] = checkBigIntegerInIntRange(seqOfnRSInts.getObjectAt(0));
            statInt[1] = checkBigIntegerInIntRange(seqOfnRSInts.getObjectAt(1));
            statInt[2] = checkBigIntegerInIntRange(seqOfnRSInts.getObjectAt(2));
            statInt[3] = checkBigIntegerInIntRange(seqOfnRSInts.getObjectAt(3));
            statInt[4] = checkBigIntegerInIntRange(seqOfnRSInts.getObjectAt(4));
            statInt[5] = checkBigIntegerInIntRange(seqOfnRSInts.getObjectAt(5));
            statInt[6] = checkBigIntegerInIntRange(seqOfnRSInts.getObjectAt(6));
            statInt[7] = checkBigIntegerInIntRange(seqOfnRSInts.getObjectAt(7));
            statInt[8] = checkBigIntegerInIntRange(seqOfnRSInts.getObjectAt(8));
            nextRootSig[i] = new GMSSRootSig(DigestFactory.getDigest(name[0]).getClass(), statByte, statInt);
        }

        // --- Decode <name>.

        // TODO: Really check, why there are multiple algorithms, we only
        //       use the first one!!!
        ASN1Sequence namePart = (ASN1Sequence)mtsPrivateKey.getObjectAt(20);
        String[] name = new String[namePart.size()];
        for (int i = 0; i < name.length; i++)
        {
            name[i] = ((DERIA5String)namePart.getObjectAt(i)).getString();
        }
        */
    }

    public GMSSPrivateKey(int[] index, byte[][] currentSeed,
                          byte[][] nextNextSeed, byte[][][] currentAuthPath,
                          byte[][][] nextAuthPath, Treehash[][] currentTreehash,
                          Treehash[][] nextTreehash, Vector[] currentStack,
                          Vector[] nextStack, Vector[][] currentRetain,
                          Vector[][] nextRetain, byte[][][] keep, GMSSLeaf[] nextNextLeaf,
                          GMSSLeaf[] upperLeaf, GMSSLeaf[] upperTreehashLeaf,
                          int[] minTreehash, byte[][] nextRoot, GMSSRootCalc[] nextNextRoot,
                          byte[][] currentRootSig, GMSSRootSig[] nextRootSig,
                          GMSSParameters gmssParameterset, AlgorithmIdentifier digestAlg)
    {
        AlgorithmIdentifier[] names = new AlgorithmIdentifier[] { digestAlg };
        this.primitive = encode(index, currentSeed, nextNextSeed, currentAuthPath, nextAuthPath, keep, currentTreehash, nextTreehash, currentStack, nextStack, currentRetain, nextRetain, nextNextLeaf, upperLeaf, upperTreehashLeaf, minTreehash, nextRoot, nextNextRoot, currentRootSig, nextRootSig, gmssParameterset, names);
    }


    // TODO: change method signature to something more integrated into BouncyCastle

    /**
     * @param index             tree indices
     * @param currentSeeds      seed for the generation of private OTS keys for the
     *                          current subtrees (TREE)
     * @param nextNextSeeds     seed for the generation of private OTS keys for the
     *                          subtrees after next (TREE++)
     * @param currentAuthPaths  array of current authentication paths (AUTHPATH)
     * @param nextAuthPaths     array of next authentication paths (AUTHPATH+)
     * @param keep              keep array for the authPath algorithm
     * @param currentTreehash   treehash for authPath algorithm of current tree
     * @param nextTreehash      treehash for authPath algorithm of next tree (TREE+)
     * @param currentStack      shared stack for authPath algorithm of current tree
     * @param nextStack         shared stack for authPath algorithm of next tree (TREE+)
     * @param currentRetain     retain stack for authPath algorithm of current tree
     * @param nextRetain        retain stack for authPath algorithm of next tree (TREE+)
     * @param nextNextLeaf      array of upcoming leafs of the tree after next (LEAF++) of
     *                          each layer
     * @param upperLeaf         needed for precomputation of upper nodes
     * @param upperTreehashLeaf needed for precomputation of upper treehash nodes
     * @param minTreehash       index of next treehash instance to receive an update
     * @param nextRoot          the roots of the next trees (ROOT+)
     * @param nextNextRoot      the roots of the tree after next (ROOT++)
     * @param currentRootSig    array of signatures of the roots of the current subtrees
     *                          (SIG)
     * @param nextRootSig       array of signatures of the roots of the next subtree
     *                          (SIG+)
     * @param gmssParameterset  the GMSS Parameterset
     * @param algorithms        An array of algorithm identifiers, containing the hash function details
     */
    private ASN1Primitive encode(int[] index, byte[][] currentSeeds,
                                byte[][] nextNextSeeds, byte[][][] currentAuthPaths,
                                byte[][][] nextAuthPaths, byte[][][] keep,
                                Treehash[][] currentTreehash, Treehash[][] nextTreehash,
                                Vector[] currentStack, Vector[] nextStack,
                                Vector[][] currentRetain, Vector[][] nextRetain,
                                GMSSLeaf[] nextNextLeaf, GMSSLeaf[] upperLeaf,
                                GMSSLeaf[] upperTreehashLeaf, int[] minTreehash, byte[][] nextRoot,
                                GMSSRootCalc[] nextNextRoot, byte[][] currentRootSig,
                                GMSSRootSig[] nextRootSig, GMSSParameters gmssParameterset,
                                AlgorithmIdentifier[] algorithms)
    {

        ASN1EncodableVector result = new ASN1EncodableVector();

        // --- Encode <index>.
        ASN1EncodableVector indexPart = new ASN1EncodableVector();
        for (int i = 0; i < index.length; i++)
        {
            indexPart.add(new ASN1Integer(index[i]));
        }
        result.add(new DERSequence(indexPart));

        // --- Encode <curSeeds>.
        ASN1EncodableVector curSeedsPart = new ASN1EncodableVector();
        for (int i = 0; i < currentSeeds.length; i++)
        {
            curSeedsPart.add(new DEROctetString(currentSeeds[i]));
        }
        result.add(new DERSequence(curSeedsPart));

        // --- Encode <nextNextSeeds>.
        ASN1EncodableVector nextNextSeedsPart = new ASN1EncodableVector();
        for (int i = 0; i < nextNextSeeds.length; i++)
        {
            nextNextSeedsPart.add(new DEROctetString(nextNextSeeds[i]));
        }
        result.add(new DERSequence(nextNextSeedsPart));

        // --- Encode <curAuth>.
        ASN1EncodableVector curAuthPart0 = new ASN1EncodableVector();
        ASN1EncodableVector curAuthPart1 = new ASN1EncodableVector();
        for (int i = 0; i < currentAuthPaths.length; i++)
        {
            for (int j = 0; j < currentAuthPaths[i].length; j++)
            {
                curAuthPart0.add(new DEROctetString(currentAuthPaths[i][j]));
            }
            curAuthPart1.add(new DERSequence(curAuthPart0));
            curAuthPart0 = new ASN1EncodableVector();
        }
        result.add(new DERSequence(curAuthPart1));

        // --- Encode <nextAuth>.
        ASN1EncodableVector nextAuthPart0 = new ASN1EncodableVector();
        ASN1EncodableVector nextAuthPart1 = new ASN1EncodableVector();
        for (int i = 0; i < nextAuthPaths.length; i++)
        {
            for (int j = 0; j < nextAuthPaths[i].length; j++)
            {
                nextAuthPart0.add(new DEROctetString(nextAuthPaths[i][j]));
            }
            nextAuthPart1.add(new DERSequence(nextAuthPart0));
            nextAuthPart0 = new ASN1EncodableVector();
        }
        result.add(new DERSequence(nextAuthPart1));

        // --- Encode <curTreehash>.
        ASN1EncodableVector seqOfTreehash0 = new ASN1EncodableVector();
        ASN1EncodableVector seqOfTreehash1 = new ASN1EncodableVector();
        ASN1EncodableVector seqOfStat = new ASN1EncodableVector();
        ASN1EncodableVector seqOfByte = new ASN1EncodableVector();
        ASN1EncodableVector seqOfInt = new ASN1EncodableVector();

        for (int i = 0; i < currentTreehash.length; i++)
        {
            for (int j = 0; j < currentTreehash[i].length; j++)
            {
                seqOfStat.add(new DERSequence(algorithms[0]));

                int tailLength = currentTreehash[i][j].getStatInt()[1];

                seqOfByte.add(new DEROctetString(currentTreehash[i][j]
                    .getStatByte()[0]));
                seqOfByte.add(new DEROctetString(currentTreehash[i][j]
                    .getStatByte()[1]));
                seqOfByte.add(new DEROctetString(currentTreehash[i][j]
                    .getStatByte()[2]));
                for (int k = 0; k < tailLength; k++)
                {
                    seqOfByte.add(new DEROctetString(currentTreehash[i][j]
                        .getStatByte()[3 + k]));
                }
                seqOfStat.add(new DERSequence(seqOfByte));
                seqOfByte = new ASN1EncodableVector();

                seqOfInt.add(new ASN1Integer(
                    currentTreehash[i][j].getStatInt()[0]));
                seqOfInt.add(new ASN1Integer(tailLength));
                seqOfInt.add(new ASN1Integer(
                    currentTreehash[i][j].getStatInt()[2]));
                seqOfInt.add(new ASN1Integer(
                    currentTreehash[i][j].getStatInt()[3]));
                seqOfInt.add(new ASN1Integer(
                    currentTreehash[i][j].getStatInt()[4]));
                seqOfInt.add(new ASN1Integer(
                    currentTreehash[i][j].getStatInt()[5]));
                for (int k = 0; k < tailLength; k++)
                {
                    seqOfInt.add(new ASN1Integer(currentTreehash[i][j]
                        .getStatInt()[6 + k]));
                }
                seqOfStat.add(new DERSequence(seqOfInt));
                seqOfInt = new ASN1EncodableVector();

                seqOfTreehash1.add(new DERSequence(seqOfStat));
                seqOfStat = new ASN1EncodableVector();
            }
            seqOfTreehash0.add(new DERSequence(seqOfTreehash1));
            seqOfTreehash1 = new ASN1EncodableVector();
        }
        result.add(new DERSequence(seqOfTreehash0));

        // --- Encode <nextTreehash>.
        seqOfTreehash0 = new ASN1EncodableVector();
        seqOfTreehash1 = new ASN1EncodableVector();
        seqOfStat = new ASN1EncodableVector();
        seqOfByte = new ASN1EncodableVector();
        seqOfInt = new ASN1EncodableVector();

        for (int i = 0; i < nextTreehash.length; i++)
        {
            for (int j = 0; j < nextTreehash[i].length; j++)
            {
                seqOfStat.add(new DERSequence(algorithms[0]));

                int tailLength = nextTreehash[i][j].getStatInt()[1];

                seqOfByte.add(new DEROctetString(nextTreehash[i][j]
                    .getStatByte()[0]));
                seqOfByte.add(new DEROctetString(nextTreehash[i][j]
                    .getStatByte()[1]));
                seqOfByte.add(new DEROctetString(nextTreehash[i][j]
                    .getStatByte()[2]));
                for (int k = 0; k < tailLength; k++)
                {
                    seqOfByte.add(new DEROctetString(nextTreehash[i][j]
                        .getStatByte()[3 + k]));
                }
                seqOfStat.add(new DERSequence(seqOfByte));
                seqOfByte = new ASN1EncodableVector();

                seqOfInt
                    .add(new ASN1Integer(nextTreehash[i][j].getStatInt()[0]));
                seqOfInt.add(new ASN1Integer(tailLength));
                seqOfInt
                    .add(new ASN1Integer(nextTreehash[i][j].getStatInt()[2]));
                seqOfInt
                    .add(new ASN1Integer(nextTreehash[i][j].getStatInt()[3]));
                seqOfInt
                    .add(new ASN1Integer(nextTreehash[i][j].getStatInt()[4]));
                seqOfInt
                    .add(new ASN1Integer(nextTreehash[i][j].getStatInt()[5]));
                for (int k = 0; k < tailLength; k++)
                {
                    seqOfInt.add(new ASN1Integer(nextTreehash[i][j]
                        .getStatInt()[6 + k]));
                }
                seqOfStat.add(new DERSequence(seqOfInt));
                seqOfInt = new ASN1EncodableVector();

                seqOfTreehash1.add(new DERSequence(seqOfStat));
                seqOfStat = new ASN1EncodableVector();
            }
            seqOfTreehash0.add(new DERSequence(new DERSequence(seqOfTreehash1)));
            seqOfTreehash1 = new ASN1EncodableVector();
        }
        result.add(new DERSequence(seqOfTreehash0));

        // --- Encode <keep>.
        ASN1EncodableVector keepPart0 = new ASN1EncodableVector();
        ASN1EncodableVector keepPart1 = new ASN1EncodableVector();
        for (int i = 0; i < keep.length; i++)
        {
            for (int j = 0; j < keep[i].length; j++)
            {
                keepPart0.add(new DEROctetString(keep[i][j]));
            }
            keepPart1.add(new DERSequence(keepPart0));
            keepPart0 = new ASN1EncodableVector();
        }
        result.add(new DERSequence(keepPart1));

        // --- Encode <curStack>.
        ASN1EncodableVector curStackPart0 = new ASN1EncodableVector();
        ASN1EncodableVector curStackPart1 = new ASN1EncodableVector();
        for (int i = 0; i < currentStack.length; i++)
        {
            for (int j = 0; j < currentStack[i].size(); j++)
            {
                curStackPart0.add(new DEROctetString((byte[])currentStack[i]
                    .elementAt(j)));
            }
            curStackPart1.add(new DERSequence(curStackPart0));
            curStackPart0 = new ASN1EncodableVector();
        }
        result.add(new DERSequence(curStackPart1));

        // --- Encode <nextStack>.
        ASN1EncodableVector nextStackPart0 = new ASN1EncodableVector();
        ASN1EncodableVector nextStackPart1 = new ASN1EncodableVector();
        for (int i = 0; i < nextStack.length; i++)
        {
            for (int j = 0; j < nextStack[i].size(); j++)
            {
                nextStackPart0.add(new DEROctetString((byte[])nextStack[i]
                    .elementAt(j)));
            }
            nextStackPart1.add(new DERSequence(nextStackPart0));
            nextStackPart0 = new ASN1EncodableVector();
        }
        result.add(new DERSequence(nextStackPart1));

        // --- Encode <curRetain>.
        ASN1EncodableVector currentRetainPart0 = new ASN1EncodableVector();
        ASN1EncodableVector currentRetainPart1 = new ASN1EncodableVector();
        ASN1EncodableVector currentRetainPart2 = new ASN1EncodableVector();
        for (int i = 0; i < currentRetain.length; i++)
        {
            for (int j = 0; j < currentRetain[i].length; j++)
            {
                for (int k = 0; k < currentRetain[i][j].size(); k++)
                {
                    currentRetainPart0.add(new DEROctetString(
                        (byte[])currentRetain[i][j].elementAt(k)));
                }
                currentRetainPart1.add(new DERSequence(currentRetainPart0));
                currentRetainPart0 = new ASN1EncodableVector();
            }
            currentRetainPart2.add(new DERSequence(currentRetainPart1));
            currentRetainPart1 = new ASN1EncodableVector();
        }
        result.add(new DERSequence(currentRetainPart2));

        // --- Encode <nextRetain>.
        ASN1EncodableVector nextRetainPart0 = new ASN1EncodableVector();
        ASN1EncodableVector nextRetainPart1 = new ASN1EncodableVector();
        ASN1EncodableVector nextRetainPart2 = new ASN1EncodableVector();
        for (int i = 0; i < nextRetain.length; i++)
        {
            for (int j = 0; j < nextRetain[i].length; j++)
            {
                for (int k = 0; k < nextRetain[i][j].size(); k++)
                {
                    nextRetainPart0.add(new DEROctetString(
                        (byte[])nextRetain[i][j].elementAt(k)));
                }
                nextRetainPart1.add(new DERSequence(nextRetainPart0));
                nextRetainPart0 = new ASN1EncodableVector();
            }
            nextRetainPart2.add(new DERSequence(nextRetainPart1));
            nextRetainPart1 = new ASN1EncodableVector();
        }
        result.add(new DERSequence(nextRetainPart2));

        // --- Encode <nextNextLeaf>.
        ASN1EncodableVector seqOfLeaf = new ASN1EncodableVector();
        seqOfStat = new ASN1EncodableVector();
        seqOfByte = new ASN1EncodableVector();
        seqOfInt = new ASN1EncodableVector();

        for (int i = 0; i < nextNextLeaf.length; i++)
        {
            seqOfStat.add(new DERSequence(algorithms[0]));

            byte[][] tempByte = nextNextLeaf[i].getStatByte();
            seqOfByte.add(new DEROctetString(tempByte[0]));
            seqOfByte.add(new DEROctetString(tempByte[1]));
            seqOfByte.add(new DEROctetString(tempByte[2]));
            seqOfByte.add(new DEROctetString(tempByte[3]));
            seqOfStat.add(new DERSequence(seqOfByte));
            seqOfByte = new ASN1EncodableVector();

            int[] tempInt = nextNextLeaf[i].getStatInt();
            seqOfInt.add(new ASN1Integer(tempInt[0]));
            seqOfInt.add(new ASN1Integer(tempInt[1]));
            seqOfInt.add(new ASN1Integer(tempInt[2]));
            seqOfInt.add(new ASN1Integer(tempInt[3]));
            seqOfStat.add(new DERSequence(seqOfInt));
            seqOfInt = new ASN1EncodableVector();

            seqOfLeaf.add(new DERSequence(seqOfStat));
            seqOfStat = new ASN1EncodableVector();
        }
        result.add(new DERSequence(seqOfLeaf));

        // --- Encode <upperLEAF>.
        ASN1EncodableVector seqOfUpperLeaf = new ASN1EncodableVector();
        seqOfStat = new ASN1EncodableVector();
        seqOfByte = new ASN1EncodableVector();
        seqOfInt = new ASN1EncodableVector();

        for (int i = 0; i < upperLeaf.length; i++)
        {
            seqOfStat.add(new DERSequence(algorithms[0]));

            byte[][] tempByte = upperLeaf[i].getStatByte();
            seqOfByte.add(new DEROctetString(tempByte[0]));
            seqOfByte.add(new DEROctetString(tempByte[1]));
            seqOfByte.add(new DEROctetString(tempByte[2]));
            seqOfByte.add(new DEROctetString(tempByte[3]));
            seqOfStat.add(new DERSequence(seqOfByte));
            seqOfByte = new ASN1EncodableVector();

            int[] tempInt = upperLeaf[i].getStatInt();
            seqOfInt.add(new ASN1Integer(tempInt[0]));
            seqOfInt.add(new ASN1Integer(tempInt[1]));
            seqOfInt.add(new ASN1Integer(tempInt[2]));
            seqOfInt.add(new ASN1Integer(tempInt[3]));
            seqOfStat.add(new DERSequence(seqOfInt));
            seqOfInt = new ASN1EncodableVector();

            seqOfUpperLeaf.add(new DERSequence(seqOfStat));
            seqOfStat = new ASN1EncodableVector();
        }
        result.add(new DERSequence(seqOfUpperLeaf));

        // encode <upperTreehashLeaf>
        ASN1EncodableVector seqOfUpperTreehashLeaf = new ASN1EncodableVector();
        seqOfStat = new ASN1EncodableVector();
        seqOfByte = new ASN1EncodableVector();
        seqOfInt = new ASN1EncodableVector();

        for (int i = 0; i < upperTreehashLeaf.length; i++)
        {
            seqOfStat.add(new DERSequence(algorithms[0]));

            byte[][] tempByte = upperTreehashLeaf[i].getStatByte();
            seqOfByte.add(new DEROctetString(tempByte[0]));
            seqOfByte.add(new DEROctetString(tempByte[1]));
            seqOfByte.add(new DEROctetString(tempByte[2]));
            seqOfByte.add(new DEROctetString(tempByte[3]));
            seqOfStat.add(new DERSequence(seqOfByte));
            seqOfByte = new ASN1EncodableVector();

            int[] tempInt = upperTreehashLeaf[i].getStatInt();
            seqOfInt.add(new ASN1Integer(tempInt[0]));
            seqOfInt.add(new ASN1Integer(tempInt[1]));
            seqOfInt.add(new ASN1Integer(tempInt[2]));
            seqOfInt.add(new ASN1Integer(tempInt[3]));
            seqOfStat.add(new DERSequence(seqOfInt));
            seqOfInt = new ASN1EncodableVector();

            seqOfUpperTreehashLeaf.add(new DERSequence(seqOfStat));
            seqOfStat = new ASN1EncodableVector();
        }
        result.add(new DERSequence(seqOfUpperTreehashLeaf));

        // --- Encode <minTreehash>.
        ASN1EncodableVector minTreehashPart = new ASN1EncodableVector();
        for (int i = 0; i < minTreehash.length; i++)
        {
            minTreehashPart.add(new ASN1Integer(minTreehash[i]));
        }
        result.add(new DERSequence(minTreehashPart));

        // --- Encode <nextRoot>.
        ASN1EncodableVector nextRootPart = new ASN1EncodableVector();
        for (int i = 0; i < nextRoot.length; i++)
        {
            nextRootPart.add(new DEROctetString(nextRoot[i]));
        }
        result.add(new DERSequence(nextRootPart));

        // --- Encode <nextNextRoot>.
        ASN1EncodableVector seqOfnextNextRoot = new ASN1EncodableVector();
        ASN1EncodableVector seqOfnnRStats = new ASN1EncodableVector();
        ASN1EncodableVector seqOfnnRStrings = new ASN1EncodableVector();
        ASN1EncodableVector seqOfnnRBytes = new ASN1EncodableVector();
        ASN1EncodableVector seqOfnnRInts = new ASN1EncodableVector();
        ASN1EncodableVector seqOfnnRTreehash = new ASN1EncodableVector();
        ASN1EncodableVector seqOfnnRRetain = new ASN1EncodableVector();

        for (int i = 0; i < nextNextRoot.length; i++)
        {
            seqOfnnRStats.add(new DERSequence(algorithms[0]));
            seqOfnnRStrings = new ASN1EncodableVector();

            int heightOfTree = nextNextRoot[i].getStatInt()[0];
            int tailLength = nextNextRoot[i].getStatInt()[7];

            seqOfnnRBytes.add(new DEROctetString(
                nextNextRoot[i].getStatByte()[0]));
            for (int j = 0; j < heightOfTree; j++)
            {
                seqOfnnRBytes.add(new DEROctetString(nextNextRoot[i]
                    .getStatByte()[1 + j]));
            }
            for (int j = 0; j < tailLength; j++)
            {
                seqOfnnRBytes.add(new DEROctetString(nextNextRoot[i]
                    .getStatByte()[1 + heightOfTree + j]));
            }

            seqOfnnRStats.add(new DERSequence(seqOfnnRBytes));
            seqOfnnRBytes = new ASN1EncodableVector();

            seqOfnnRInts.add(new ASN1Integer(heightOfTree));
            seqOfnnRInts.add(new ASN1Integer(nextNextRoot[i].getStatInt()[1]));
            seqOfnnRInts.add(new ASN1Integer(nextNextRoot[i].getStatInt()[2]));
            seqOfnnRInts.add(new ASN1Integer(nextNextRoot[i].getStatInt()[3]));
            seqOfnnRInts.add(new ASN1Integer(nextNextRoot[i].getStatInt()[4]));
            seqOfnnRInts.add(new ASN1Integer(nextNextRoot[i].getStatInt()[5]));
            seqOfnnRInts.add(new ASN1Integer(nextNextRoot[i].getStatInt()[6]));
            seqOfnnRInts.add(new ASN1Integer(tailLength));
            for (int j = 0; j < heightOfTree; j++)
            {
                seqOfnnRInts.add(new ASN1Integer(
                    nextNextRoot[i].getStatInt()[8 + j]));
            }
            for (int j = 0; j < tailLength; j++)
            {
                seqOfnnRInts.add(new ASN1Integer(nextNextRoot[i].getStatInt()[8
                    + heightOfTree + j]));
            }

            seqOfnnRStats.add(new DERSequence(seqOfnnRInts));
            seqOfnnRInts = new ASN1EncodableVector();

            // add treehash of nextNextRoot object
            // ----------------------------
            seqOfStat = new ASN1EncodableVector();
            seqOfByte = new ASN1EncodableVector();
            seqOfInt = new ASN1EncodableVector();

            if (nextNextRoot[i].getTreehash() != null)
            {
                for (int j = 0; j < nextNextRoot[i].getTreehash().length; j++)
                {
                    seqOfStat.add(new DERSequence(algorithms[0]));

                    tailLength = nextNextRoot[i].getTreehash()[j].getStatInt()[1];

                    seqOfByte.add(new DEROctetString(nextNextRoot[i]
                        .getTreehash()[j].getStatByte()[0]));
                    seqOfByte.add(new DEROctetString(nextNextRoot[i]
                        .getTreehash()[j].getStatByte()[1]));
                    seqOfByte.add(new DEROctetString(nextNextRoot[i]
                        .getTreehash()[j].getStatByte()[2]));
                    for (int k = 0; k < tailLength; k++)
                    {
                        seqOfByte.add(new DEROctetString(nextNextRoot[i]
                            .getTreehash()[j].getStatByte()[3 + k]));
                    }
                    seqOfStat.add(new DERSequence(seqOfByte));
                    seqOfByte = new ASN1EncodableVector();

                    seqOfInt.add(new ASN1Integer(
                        nextNextRoot[i].getTreehash()[j].getStatInt()[0]));
                    seqOfInt.add(new ASN1Integer(tailLength));
                    seqOfInt.add(new ASN1Integer(
                        nextNextRoot[i].getTreehash()[j].getStatInt()[2]));
                    seqOfInt.add(new ASN1Integer(
                        nextNextRoot[i].getTreehash()[j].getStatInt()[3]));
                    seqOfInt.add(new ASN1Integer(
                        nextNextRoot[i].getTreehash()[j].getStatInt()[4]));
                    seqOfInt.add(new ASN1Integer(
                        nextNextRoot[i].getTreehash()[j].getStatInt()[5]));
                    for (int k = 0; k < tailLength; k++)
                    {
                        seqOfInt.add(new ASN1Integer(nextNextRoot[i]
                            .getTreehash()[j].getStatInt()[6 + k]));
                    }
                    seqOfStat.add(new DERSequence(seqOfInt));
                    seqOfInt = new ASN1EncodableVector();

                    seqOfnnRTreehash.add(new DERSequence(seqOfStat));
                    seqOfStat = new ASN1EncodableVector();
                }
            }
            // ----------------------------
            seqOfnnRStats.add(new DERSequence(seqOfnnRTreehash));
            seqOfnnRTreehash = new ASN1EncodableVector();

            // encode retain of nextNextRoot
            // ----------------------------
            // --- Encode <curRetain>.
            currentRetainPart0 = new ASN1EncodableVector();
            if (nextNextRoot[i].getRetain() != null)
            {
                for (int j = 0; j < nextNextRoot[i].getRetain().length; j++)
                {
                    for (int k = 0; k < nextNextRoot[i].getRetain()[j].size(); k++)
                    {
                        currentRetainPart0.add(new DEROctetString(
                            (byte[])nextNextRoot[i].getRetain()[j]
                                .elementAt(k)));
                    }
                    seqOfnnRRetain.add(new DERSequence(currentRetainPart0));
                    currentRetainPart0 = new ASN1EncodableVector();
                }
            }
            // ----------------------------
            seqOfnnRStats.add(new DERSequence(seqOfnnRRetain));
            seqOfnnRRetain = new ASN1EncodableVector();

            seqOfnextNextRoot.add(new DERSequence(seqOfnnRStats));
            seqOfnnRStats = new ASN1EncodableVector();
        }
        result.add(new DERSequence(seqOfnextNextRoot));

        // --- Encode <curRootSig>.
        ASN1EncodableVector curRootSigPart = new ASN1EncodableVector();
        for (int i = 0; i < currentRootSig.length; i++)
        {
            curRootSigPart.add(new DEROctetString(currentRootSig[i]));
        }
        result.add(new DERSequence(curRootSigPart));

        // --- Encode <nextRootSig>.
        ASN1EncodableVector seqOfnextRootSigs = new ASN1EncodableVector();
        ASN1EncodableVector seqOfnRSStats = new ASN1EncodableVector();
        ASN1EncodableVector seqOfnRSStrings = new ASN1EncodableVector();
        ASN1EncodableVector seqOfnRSBytes = new ASN1EncodableVector();
        ASN1EncodableVector seqOfnRSInts = new ASN1EncodableVector();

        for (int i = 0; i < nextRootSig.length; i++)
        {
            seqOfnRSStats.add(new DERSequence(algorithms[0]));
            seqOfnRSStrings = new ASN1EncodableVector();

            seqOfnRSBytes.add(new DEROctetString(
                nextRootSig[i].getStatByte()[0]));
            seqOfnRSBytes.add(new DEROctetString(
                nextRootSig[i].getStatByte()[1]));
            seqOfnRSBytes.add(new DEROctetString(
                nextRootSig[i].getStatByte()[2]));
            seqOfnRSBytes.add(new DEROctetString(
                nextRootSig[i].getStatByte()[3]));
            seqOfnRSBytes.add(new DEROctetString(
                nextRootSig[i].getStatByte()[4]));

            seqOfnRSStats.add(new DERSequence(seqOfnRSBytes));
            seqOfnRSBytes = new ASN1EncodableVector();

            seqOfnRSInts.add(new ASN1Integer(nextRootSig[i].getStatInt()[0]));
            seqOfnRSInts.add(new ASN1Integer(nextRootSig[i].getStatInt()[1]));
            seqOfnRSInts.add(new ASN1Integer(nextRootSig[i].getStatInt()[2]));
            seqOfnRSInts.add(new ASN1Integer(nextRootSig[i].getStatInt()[3]));
            seqOfnRSInts.add(new ASN1Integer(nextRootSig[i].getStatInt()[4]));
            seqOfnRSInts.add(new ASN1Integer(nextRootSig[i].getStatInt()[5]));
            seqOfnRSInts.add(new ASN1Integer(nextRootSig[i].getStatInt()[6]));
            seqOfnRSInts.add(new ASN1Integer(nextRootSig[i].getStatInt()[7]));
            seqOfnRSInts.add(new ASN1Integer(nextRootSig[i].getStatInt()[8]));

            seqOfnRSStats.add(new DERSequence(seqOfnRSInts));
            seqOfnRSInts = new ASN1EncodableVector();

            seqOfnextRootSigs.add(new DERSequence(seqOfnRSStats));
            seqOfnRSStats = new ASN1EncodableVector();
        }
        result.add(new DERSequence(seqOfnextRootSigs));

        // --- Encode <parameterset>.
        ASN1EncodableVector parSetPart0 = new ASN1EncodableVector();
        ASN1EncodableVector parSetPart1 = new ASN1EncodableVector();
        ASN1EncodableVector parSetPart2 = new ASN1EncodableVector();
        ASN1EncodableVector parSetPart3 = new ASN1EncodableVector();

        for (int i = 0; i < gmssParameterset.getHeightOfTrees().length; i++)
        {
            parSetPart1.add(new ASN1Integer(
                gmssParameterset.getHeightOfTrees()[i]));
            parSetPart2.add(new ASN1Integer(gmssParameterset
                .getWinternitzParameter()[i]));
            parSetPart3.add(new ASN1Integer(gmssParameterset.getK()[i]));
        }
        parSetPart0.add(new ASN1Integer(gmssParameterset.getNumOfLayers()));
        parSetPart0.add(new DERSequence(parSetPart1));
        parSetPart0.add(new DERSequence(parSetPart2));
        parSetPart0.add(new DERSequence(parSetPart3));
        result.add(new DERSequence(parSetPart0));

        // --- Encode <names>.
        ASN1EncodableVector namesPart = new ASN1EncodableVector();

        for (int i = 0; i < algorithms.length; i++)
        {
            namesPart.add(algorithms[i]);
        }

        result.add(new DERSequence(namesPart));
        return new DERSequence(result);

    }

    private static int checkBigIntegerInIntRange(ASN1Encodable a)
    {
        BigInteger b = ((ASN1Integer)a).getValue();
        if ((b.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) > 0) ||
            (b.compareTo(BigInteger.valueOf(Integer.MIN_VALUE)) < 0))
        {
            throw new IllegalArgumentException("BigInteger not in Range: " + b.toString());
        }
        return b.intValue();
    }


    public ASN1Primitive toASN1Primitive()
    {
        return this.primitive;
    }
}
