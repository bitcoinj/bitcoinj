package org.bouncycastle.math.ec.test;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.Properties;
import java.util.Set;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

public class F2mProofer
{
    private static final int NUM_SAMPLES = 1000;

    private static final String PATH = "crypto/test/src/org/bouncycastle/math/ec/test/samples/";

    private static final String INPUT_FILE_NAME_PREFIX = "Input_";

    private static final String RESULT_FILE_NAME_PREFIX = "Output_";

    /**
     * The standard curves on which the tests are done
     */
    public static final String[] CURVES = { "sect163r2", "sect233r1",
        "sect283r1", "sect409r1", "sect571r1" };

    private String pointToString(ECPoint.F2m p)
    {
        ECFieldElement.F2m x = (ECFieldElement.F2m) p.getAffineXCoord();
        ECFieldElement.F2m y = (ECFieldElement.F2m) p.getAffineYCoord();

        int m = x.getM();
        int len = m / 2 + 5;

        StringBuffer sb = new StringBuffer(len);
        sb.append('(');
        sb.append(x.toBigInteger().toString(16));
        sb.append(", ");
        sb.append(y.toBigInteger().toString(16));
        sb.append(')');

        return sb.toString();
    }

    private void generateRandomInput(X9ECParameters x9ECParameters)
        throws NoSuchAlgorithmException, IOException
    {
        ECPoint.F2m g = (ECPoint.F2m) x9ECParameters.getG();
        int m = ((ECFieldElement.F2m) (g.getAffineXCoord())).getM();

        SecureRandom secRand = SecureRandom.getInstance("SHA1PRNG");
        Properties inputProps = new Properties();
        for (int i = 0; i < NUM_SAMPLES; i++)
        {
            BigInteger rand = new BigInteger(m, secRand);
            inputProps.put(Integer.toString(i), rand.toString(16));
        }
        String bits = Integer.toString(m);
        FileOutputStream fos = new FileOutputStream(PATH
            + INPUT_FILE_NAME_PREFIX + bits + ".properties");
        inputProps.store(fos, "Input Samples of length" + bits);
    }

    private void multiplyPoints(X9ECParameters x9ECParameters,
        String classPrefix) throws IOException
    {
        ECPoint.F2m g = (ECPoint.F2m) x9ECParameters.getG();
        int m = ((ECFieldElement.F2m) (g.getAffineXCoord())).getM();

        String inputFileName = PATH + INPUT_FILE_NAME_PREFIX + m
            + ".properties";
        Properties inputProps = new Properties();
        inputProps.load(new FileInputStream(inputFileName));

        Properties outputProps = new Properties();

        for (int i = 0; i < NUM_SAMPLES; i++)
        {
            BigInteger rand = new BigInteger(inputProps.getProperty(Integer
                .toString(i)), 16);
            ECPoint.F2m result = (ECPoint.F2m) g.multiply(rand).normalize();
            String resultStr = pointToString(result);
            outputProps.setProperty(Integer.toString(i), resultStr);
        }

        String outputFileName = PATH + RESULT_FILE_NAME_PREFIX + classPrefix
            + "_" + m + ".properties";
        FileOutputStream fos = new FileOutputStream(outputFileName);
        outputProps.store(fos, "Output Samples of length" + m);
    }

    private Properties loadResults(String classPrefix, int m)
        throws IOException
    {
        FileInputStream fis = new FileInputStream(PATH
            + RESULT_FILE_NAME_PREFIX + classPrefix + "_" + m + ".properties");
        Properties res = new Properties();
        res.load(fis);
        return res;

    }

    private void compareResult(X9ECParameters x9ECParameters,
        String classPrefix1, String classPrefix2) throws IOException
    {
        ECPoint.F2m g = (ECPoint.F2m) x9ECParameters.getG();
        int m = ((ECFieldElement.F2m) (g.getAffineXCoord())).getM();

        Properties res1 = loadResults(classPrefix1, m);
        Properties res2 = loadResults(classPrefix2, m);

        Set keys = res1.keySet();
        Iterator iter = keys.iterator();
        while (iter.hasNext())
        {
            String key = (String) iter.next();
            String result1 = res1.getProperty(key);
            String result2 = res2.getProperty(key);
            if (!(result1.equals(result2)))
            {
                System.err.println("Difference found: m = " + m + ", "
                    + result1 + " does not equal " + result2);
            }
        }

    }

    private static void usage()
    {
        System.err.println("Usage: F2mProofer [-init | -multiply <className> "
            + "| -compare <className1> <className2>]");
    }

    public static void main(String[] args) throws Exception
    {
        if (args.length == 0)
        {
            usage();
            return;
        }
        F2mProofer proofer = new F2mProofer();
        if (args[0].equals("-init"))
        {
            System.out.println("Generating random input...");
            for (int i = 0; i < CURVES.length; i++)
            {
                X9ECParameters x9ECParameters = SECNamedCurves
                    .getByName(CURVES[i]);
                proofer.generateRandomInput(x9ECParameters);
            }
            System.out
                .println("Successfully generated random input in " + PATH);
        }
        else if (args[0].equals("-compare"))
        {
            if (args.length < 3)
            {
                usage();
                return;
            }
            String classPrefix1 = args[1];
            String classPrefix2 = args[2];
            System.out.println("Comparing results...");
            for (int i = 0; i < CURVES.length; i++)
            {
                X9ECParameters x9ECParameters = SECNamedCurves
                    .getByName(CURVES[i]);
                proofer.compareResult(x9ECParameters, classPrefix1,
                    classPrefix2);
            }
            System.out.println("Successfully compared results in " + PATH);
        }
        else if (args[0].equals("-multiply"))
        {
            if (args.length < 2)
            {
                usage();
                return;
            }
            String classPrefix = args[1];
            System.out.println("Multiplying points...");
            for (int i = 0; i < CURVES.length; i++)
            {
                X9ECParameters x9ECParameters = SECNamedCurves
                    .getByName(CURVES[i]);
                proofer.multiplyPoints(x9ECParameters, classPrefix);
            }
            System.out.println("Successfully generated multiplied points in "
                + PATH);
        }
        else
        {
            usage();
        }
    }
}
