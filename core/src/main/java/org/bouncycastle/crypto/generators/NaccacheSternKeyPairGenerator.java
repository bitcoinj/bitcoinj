package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.NaccacheSternKeyGenerationParameters;
import org.bouncycastle.crypto.params.NaccacheSternKeyParameters;
import org.bouncycastle.crypto.params.NaccacheSternPrivateKeyParameters;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Vector;

/**
 * Key generation parameters for NaccacheStern cipher. For details on this cipher, please see
 * 
 * http://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf
 */
public class NaccacheSternKeyPairGenerator 
    implements AsymmetricCipherKeyPairGenerator 
{

    private static int[] smallPrimes =
    {
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
        71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
        151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
        239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331,
        337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431,
        433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523,
        541, 547, 557
    };
    
    private NaccacheSternKeyGenerationParameters param;

    private static final BigInteger ONE = BigInteger.valueOf(1); // JDK 1.1 compatibility

    /*
     * (non-Javadoc)
     * 
     * @see org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator#init(org.bouncycastle.crypto.KeyGenerationParameters)
     */
    public void init(KeyGenerationParameters param)
    {
        this.param = (NaccacheSternKeyGenerationParameters)param;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator#generateKeyPair()
     */
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        int strength = param.getStrength();
        SecureRandom rand = param.getRandom();
        int certainty = param.getCertainty();
        boolean debug = param.isDebug();

        if (debug)
        {
            System.out.println("Fetching first " + param.getCntSmallPrimes() + " primes.");
        }

        Vector smallPrimes = findFirstPrimes(param.getCntSmallPrimes());
        smallPrimes = permuteList(smallPrimes, rand);

        BigInteger u = ONE;
        BigInteger v = ONE;

        for (int i = 0; i < smallPrimes.size() / 2; i++)
        {
            u = u.multiply((BigInteger)smallPrimes.elementAt(i));
        }
        for (int i = smallPrimes.size() / 2; i < smallPrimes.size(); i++)
        {
            v = v.multiply((BigInteger)smallPrimes.elementAt(i));
        }

        BigInteger sigma = u.multiply(v);

        // n = (2 a u p_ + 1 ) ( 2 b v q_ + 1)
        // -> |n| = strength
        // |2| = 1 in bits
        // -> |a| * |b| = |n| - |u| - |v| - |p_| - |q_| - |2| -|2|
        // remainingStrength = strength - sigma.bitLength() - p_.bitLength() -
        // q_.bitLength() - 1 -1
        int remainingStrength = strength - sigma.bitLength() - 48;
        BigInteger a = generatePrime(remainingStrength / 2 + 1, certainty, rand);
        BigInteger b = generatePrime(remainingStrength / 2 + 1, certainty, rand);

        BigInteger p_;
        BigInteger q_;
        BigInteger p;
        BigInteger q;
        long tries = 0;
        if (debug)
        {
            System.out.println("generating p and q");
        }

        BigInteger _2au = a.multiply(u).shiftLeft(1);
        BigInteger _2bv = b.multiply(v).shiftLeft(1);

        for (;;)
        {
            tries++;

            p_ = generatePrime(24, certainty, rand);
   
            p = p_.multiply(_2au).add(ONE);

            if (!p.isProbablePrime(certainty))
            {
                continue;
            }

            for (;;)
            {
                q_ = generatePrime(24, certainty, rand);

                if (p_.equals(q_))
                {
                    continue;
                }

                q = q_.multiply(_2bv).add(ONE);

                if (q.isProbablePrime(certainty))
                {
                    break;
                }
            }

            if (!sigma.gcd(p_.multiply(q_)).equals(ONE))
            {
                // System.out.println("sigma.gcd(p_.mult(q_)) != 1!\n p_: " + p_
                // +"\n q_: "+ q_ );
                continue;
            }

            if (p.multiply(q).bitLength() < strength)
            {
                if (debug)
                {
                    System.out.println("key size too small. Should be " + strength + " but is actually "
                                    + p.multiply(q).bitLength());
                }
                continue;
            }
            break;
        }

        if (debug)
        {
            System.out.println("needed " + tries + " tries to generate p and q.");
        }

        BigInteger n = p.multiply(q);
        BigInteger phi_n = p.subtract(ONE).multiply(q.subtract(ONE));
        BigInteger g;
        tries = 0;
        if (debug)
        {
            System.out.println("generating g");
        }
        for (;;)
        {

            Vector gParts = new Vector();
            for (int ind = 0; ind != smallPrimes.size(); ind++)
            {
                BigInteger i = (BigInteger)smallPrimes.elementAt(ind);
                BigInteger e = phi_n.divide(i);

                for (;;)
                {
                    tries++;
                    g = new BigInteger(strength, certainty, rand);
                    if (g.modPow(e, n).equals(ONE))
                    {
                        continue;
                    }
                    gParts.addElement(g);
                    break;
                }
            }
            g = ONE;
            for (int i = 0; i < smallPrimes.size(); i++)
            {
                g = g.multiply(((BigInteger)gParts.elementAt(i)).modPow(sigma.divide((BigInteger)smallPrimes.elementAt(i)), n)).mod(n);
            }

            // make sure that g is not divisible by p_i or q_i
            boolean divisible = false;
            for (int i = 0; i < smallPrimes.size(); i++)
            {
                if (g.modPow(phi_n.divide((BigInteger)smallPrimes.elementAt(i)), n).equals(ONE))
                {
                    if (debug)
                    {
                        System.out.println("g has order phi(n)/" + smallPrimes.elementAt(i) + "\n g: " + g);
                    }
                    divisible = true;
                    break;
                }
            }
            
            if (divisible)
            {
                continue;
            }

            // make sure that g has order > phi_n/4

            if (g.modPow(phi_n.divide(BigInteger.valueOf(4)), n).equals(ONE))
            {
                if (debug)
                {
                    System.out.println("g has order phi(n)/4\n g:" + g);
                }
                continue;
            }

            if (g.modPow(phi_n.divide(p_), n).equals(ONE))
            {
                if (debug)
                {
                    System.out.println("g has order phi(n)/p'\n g: " + g);
                }
                continue;
            }
            if (g.modPow(phi_n.divide(q_), n).equals(ONE))
            {
                if (debug)
                {
                    System.out.println("g has order phi(n)/q'\n g: " + g);
                }
                continue;
            }
            if (g.modPow(phi_n.divide(a), n).equals(ONE))
            {
                if (debug)
                {
                    System.out.println("g has order phi(n)/a\n g: " + g);
                }
                continue;
            }
            if (g.modPow(phi_n.divide(b), n).equals(ONE))
            {
                if (debug)
                {
                    System.out.println("g has order phi(n)/b\n g: " + g);
                }
                continue;
            }
            break;
        }
        if (debug)
        {
            System.out.println("needed " + tries + " tries to generate g");
            System.out.println();
            System.out.println("found new NaccacheStern cipher variables:");
            System.out.println("smallPrimes: " + smallPrimes);
            System.out.println("sigma:...... " + sigma + " (" + sigma.bitLength() + " bits)");
            System.out.println("a:.......... " + a);
            System.out.println("b:.......... " + b);
            System.out.println("p':......... " + p_);
            System.out.println("q':......... " + q_);
            System.out.println("p:.......... " + p);
            System.out.println("q:.......... " + q);
            System.out.println("n:.......... " + n);
            System.out.println("phi(n):..... " + phi_n);
            System.out.println("g:.......... " + g);
            System.out.println();
        }

        return new AsymmetricCipherKeyPair(new NaccacheSternKeyParameters(false, g, n, sigma.bitLength()),
                        new NaccacheSternPrivateKeyParameters(g, n, sigma.bitLength(), smallPrimes, phi_n));
    }

    private static BigInteger generatePrime(
            int bitLength, 
            int certainty,
            SecureRandom rand)
    {
        BigInteger p_ = new BigInteger(bitLength, certainty, rand);
        while (p_.bitLength() != bitLength)
        {
            p_ = new BigInteger(bitLength, certainty, rand);
        }
        return p_;
    }

    /**
     * Generates a permuted ArrayList from the original one. The original List
     * is not modified
     * 
     * @param arr
     *            the ArrayList to be permuted
     * @param rand
     *            the source of Randomness for permutation
     * @return a new ArrayList with the permuted elements.
     */
    private static Vector permuteList(
        Vector arr, 
        SecureRandom rand) 
    {
        Vector retval = new Vector();
        Vector tmp = new Vector();
        for (int i = 0; i < arr.size(); i++) 
        {
            tmp.addElement(arr.elementAt(i));
        }
        retval.addElement(tmp.elementAt(0));
        tmp.removeElementAt(0);
        while (tmp.size() != 0) 
        {
            retval.insertElementAt(tmp.elementAt(0), getInt(rand, retval.size() + 1));
            tmp.removeElementAt(0);
        }
        return retval;
    }

    private static int getInt(
        SecureRandom rand,
        int n)
    {
        if ((n & -n) == n) 
        {
            return (int)((n * (long)(rand.nextInt() & 0x7fffffff)) >> 31);
        }

        int bits, val;
        do
        {
            bits = rand.nextInt() & 0x7fffffff;
            val = bits % n;
        }
        while (bits - val + (n-1) < 0);

        return val;
    }

    /**
     * Finds the first 'count' primes starting with 3
     * 
     * @param count
     *            the number of primes to find
     * @return a vector containing the found primes as Integer
     */
    private static Vector findFirstPrimes(
        int count) 
    {
        Vector primes = new Vector(count);

        for (int i = 0; i != count; i++)
        {
            primes.addElement(BigInteger.valueOf(smallPrimes[i]));
        }
        
        return primes;
    }

}
