package org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.pqc.crypto.rainbow.Layer;
import org.bouncycastle.pqc.crypto.rainbow.util.RainbowUtil;

/**
 * Return the key data to encode in the PrivateKeyInfo structure.
 * <p>
 * The ASN.1 definition of the key structure is
 * <pre>
 *   RainbowPrivateKey ::= SEQUENCE {
 *         CHOICE
 *         {
 *         oid        OBJECT IDENTIFIER         -- OID identifying the algorithm
 *         version    INTEGER                    -- 0
 *         }
 *     A1inv      SEQUENCE OF OCTET STRING  -- inversed matrix of L1
 *     b1         OCTET STRING              -- translation vector of L1
 *     A2inv      SEQUENCE OF OCTET STRING  -- inversed matrix of L2
 *     b2         OCTET STRING              -- translation vector of L2
 *     vi         OCTET STRING              -- num of elmts in each Set S
 *     layers     SEQUENCE OF Layer         -- layers of F
 *   }
 *
 *   Layer             ::= SEQUENCE OF Poly
 *
 *   Poly              ::= SEQUENCE {
 *     alpha      SEQUENCE OF OCTET STRING
 *     beta       SEQUENCE OF OCTET STRING
 *     gamma      OCTET STRING
 *     eta        INTEGER
 *   }
 * </pre>
 */
public class RainbowPrivateKey
    extends ASN1Object
{
    private ASN1Integer  version;
    private ASN1ObjectIdentifier oid;

    private byte[][] invA1;
    private byte[] b1;
    private byte[][] invA2;
    private byte[] b2;
    private byte[] vi;
    private Layer[] layers;

    private RainbowPrivateKey(ASN1Sequence seq)
    {
        // <oidString>  or version
        if (seq.getObjectAt(0) instanceof ASN1Integer)
        {
            version = ASN1Integer.getInstance(seq.getObjectAt(0));
        }
        else
        {
            oid = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        }

        // <A1inv>
        ASN1Sequence asnA1 = (ASN1Sequence)seq.getObjectAt(1);
        invA1 = new byte[asnA1.size()][];
        for (int i = 0; i < asnA1.size(); i++)
        {
            invA1[i] = ((ASN1OctetString)asnA1.getObjectAt(i)).getOctets();
        }

        // <b1>
        ASN1Sequence asnb1 = (ASN1Sequence)seq.getObjectAt(2);
        b1 = ((ASN1OctetString)asnb1.getObjectAt(0)).getOctets();

        // <A2inv>
        ASN1Sequence asnA2 = (ASN1Sequence)seq.getObjectAt(3);
        invA2 = new byte[asnA2.size()][];
        for (int j = 0; j < asnA2.size(); j++)
        {
            invA2[j] = ((ASN1OctetString)asnA2.getObjectAt(j)).getOctets();
        }

        // <b2>
        ASN1Sequence asnb2 = (ASN1Sequence)seq.getObjectAt(4);
        b2 = ((ASN1OctetString)asnb2.getObjectAt(0)).getOctets();

        // <vi>
        ASN1Sequence asnvi = (ASN1Sequence)seq.getObjectAt(5);
        vi = ((ASN1OctetString)asnvi.getObjectAt(0)).getOctets();

        // <layers>
        ASN1Sequence asnLayers = (ASN1Sequence)seq.getObjectAt(6);

        byte[][][][] alphas = new byte[asnLayers.size()][][][];
        byte[][][][] betas = new byte[asnLayers.size()][][][];
        byte[][][] gammas = new byte[asnLayers.size()][][];
        byte[][] etas = new byte[asnLayers.size()][];
        // a layer:
        for (int l = 0; l < asnLayers.size(); l++)
        {
            ASN1Sequence asnLayer = (ASN1Sequence)asnLayers.getObjectAt(l);

            // alphas (num of alpha-2d-array = oi)
            ASN1Sequence alphas3d = (ASN1Sequence)asnLayer.getObjectAt(0);
            alphas[l] = new byte[alphas3d.size()][][];
            for (int m = 0; m < alphas3d.size(); m++)
            {
                ASN1Sequence alphas2d = (ASN1Sequence)alphas3d.getObjectAt(m);
                alphas[l][m] = new byte[alphas2d.size()][];
                for (int n = 0; n < alphas2d.size(); n++)
                {
                    alphas[l][m][n] = ((ASN1OctetString)alphas2d.getObjectAt(n)).getOctets();
                }
            }

            // betas ....
            ASN1Sequence betas3d = (ASN1Sequence)asnLayer.getObjectAt(1);
            betas[l] = new byte[betas3d.size()][][];
            for (int mb = 0; mb < betas3d.size(); mb++)
            {
                ASN1Sequence betas2d = (ASN1Sequence)betas3d.getObjectAt(mb);
                betas[l][mb] = new byte[betas2d.size()][];
                for (int nb = 0; nb < betas2d.size(); nb++)
                {
                    betas[l][mb][nb] = ((ASN1OctetString)betas2d.getObjectAt(nb)).getOctets();
                }
            }

            // gammas ...
            ASN1Sequence gammas2d = (ASN1Sequence)asnLayer.getObjectAt(2);
            gammas[l] = new byte[gammas2d.size()][];
            for (int mg = 0; mg < gammas2d.size(); mg++)
            {
                gammas[l][mg] = ((ASN1OctetString)gammas2d.getObjectAt(mg)).getOctets();
            }

            // eta ...
            etas[l] = ((ASN1OctetString)asnLayer.getObjectAt(3)).getOctets();
        }

        int numOfLayers = vi.length - 1;
        this.layers = new Layer[numOfLayers];
        for (int i = 0; i < numOfLayers; i++)
        {
            Layer l = new Layer(vi[i], vi[i + 1], RainbowUtil.convertArray(alphas[i]),
                RainbowUtil.convertArray(betas[i]), RainbowUtil.convertArray(gammas[i]), RainbowUtil.convertArray(etas[i]));
            this.layers[i] = l;

        }
    }

    public RainbowPrivateKey(short[][] invA1, short[] b1, short[][] invA2,
                                   short[] b2, int[] vi, Layer[] layers)
    {
        this.version = new ASN1Integer(1);
        this.invA1 = RainbowUtil.convertArray(invA1);
        this.b1 = RainbowUtil.convertArray(b1);
        this.invA2 = RainbowUtil.convertArray(invA2);
        this.b2 = RainbowUtil.convertArray(b2);
        this.vi = RainbowUtil.convertIntArray(vi);
        this.layers = layers;
    }
    
    public static RainbowPrivateKey getInstance(Object o)
    {
        if (o instanceof RainbowPrivateKey)
        {
            return (RainbowPrivateKey)o;
        }
        else if (o != null)
        {
            return new RainbowPrivateKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1Integer getVersion()
    {
        return version;
    }

    /**
     * Getter for the inverse matrix of A1.
     *
     * @return the A1inv inverse
     */
    public short[][] getInvA1()
    {
        return RainbowUtil.convertArray(invA1);
    }

    /**
     * Getter for the translation part of the private quadratic map L1.
     *
     * @return b1 the translation part of L1
     */
    public short[] getB1()
    {
        return RainbowUtil.convertArray(b1);
    }

    /**
     * Getter for the translation part of the private quadratic map L2.
     *
     * @return b2 the translation part of L2
     */
    public short[] getB2()
    {
        return RainbowUtil.convertArray(b2);
    }

    /**
     * Getter for the inverse matrix of A2
     *
     * @return the A2inv
     */
    public short[][] getInvA2()
    {
        return RainbowUtil.convertArray(invA2);
    }

    /**
     * Returns the layers contained in the private key
     *
     * @return layers
     */
    public Layer[] getLayers()
    {
        return this.layers;
    }

    /**
     * Returns the array of vi-s
     *
     * @return the vi
     */
    public int[] getVi()
    {
        return RainbowUtil.convertArraytoInt(vi);
    }
    
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        // encode <oidString>  or version
        if (version != null)
        {
            v.add(version);
        }
        else
        {
            v.add(oid);
        }

        // encode <A1inv>
        ASN1EncodableVector asnA1 = new ASN1EncodableVector();
        for (int i = 0; i < invA1.length; i++)
        {
            asnA1.add(new DEROctetString(invA1[i]));
        }
        v.add(new DERSequence(asnA1));

        // encode <b1>
        ASN1EncodableVector asnb1 = new ASN1EncodableVector();
        asnb1.add(new DEROctetString(b1));
        v.add(new DERSequence(asnb1));

        // encode <A2inv>
        ASN1EncodableVector asnA2 = new ASN1EncodableVector();
        for (int i = 0; i < invA2.length; i++)
        {
            asnA2.add(new DEROctetString(invA2[i]));
        }
        v.add(new DERSequence(asnA2));

        // encode <b2>
        ASN1EncodableVector asnb2 = new ASN1EncodableVector();
        asnb2.add(new DEROctetString(b2));
        v.add(new DERSequence(asnb2));

        // encode <vi>
        ASN1EncodableVector asnvi = new ASN1EncodableVector();
        asnvi.add(new DEROctetString(vi));
        v.add(new DERSequence(asnvi));

        // encode <layers>
        ASN1EncodableVector asnLayers = new ASN1EncodableVector();
        // a layer:
        for (int l = 0; l < layers.length; l++)
        {
            ASN1EncodableVector aLayer = new ASN1EncodableVector();

            // alphas (num of alpha-2d-array = oi)
            byte[][][] alphas = RainbowUtil.convertArray(layers[l].getCoeffAlpha());
            ASN1EncodableVector alphas3d = new ASN1EncodableVector();
            for (int i = 0; i < alphas.length; i++)
            {
                ASN1EncodableVector alphas2d = new ASN1EncodableVector();
                for (int j = 0; j < alphas[i].length; j++)
                {
                    alphas2d.add(new DEROctetString(alphas[i][j]));
                }
                alphas3d.add(new DERSequence(alphas2d));
            }
            aLayer.add(new DERSequence(alphas3d));

            // betas ....
            byte[][][] betas = RainbowUtil.convertArray(layers[l].getCoeffBeta());
            ASN1EncodableVector betas3d = new ASN1EncodableVector();
            for (int i = 0; i < betas.length; i++)
            {
                ASN1EncodableVector betas2d = new ASN1EncodableVector();
                for (int j = 0; j < betas[i].length; j++)
                {
                    betas2d.add(new DEROctetString(betas[i][j]));
                }
                betas3d.add(new DERSequence(betas2d));
            }
            aLayer.add(new DERSequence(betas3d));

            // gammas ...
            byte[][] gammas = RainbowUtil.convertArray(layers[l].getCoeffGamma());
            ASN1EncodableVector asnG = new ASN1EncodableVector();
            for (int i = 0; i < gammas.length; i++)
            {
                asnG.add(new DEROctetString(gammas[i]));
            }
            aLayer.add(new DERSequence(asnG));

            // eta
            aLayer.add(new DEROctetString(RainbowUtil.convertArray(layers[l].getCoeffEta())));

            // now, layer built up. add it!
            asnLayers.add(new DERSequence(aLayer));
        }

        v.add(new DERSequence(asnLayers));

        return new DERSequence(v);
    }
}
