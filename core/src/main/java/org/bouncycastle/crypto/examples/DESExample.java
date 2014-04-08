package org.bouncycastle.crypto.examples;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.generators.DESedeKeyGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

/**
 * DESExample is a simple DES based encryptor/decryptor.
 * <p>
 * The program is command line driven, with the input
 * and output files specified on the command line.
 * <pre>
 * java org.bouncycastle.crypto.examples.DESExample infile outfile [keyfile]
 * </pre>
 * A new key is generated for each encryption, if key is not specified,
 * then the example will assume encryption is required, and as output
 * create deskey.dat in the current directory.  This key is a hex
 * encoded byte-stream that is used for the decryption.  The output
 * file is Hex encoded, 60 characters wide text file.
 * <p>
 * When encrypting;
 * <ul>
 *  <li>the infile is expected to be a byte stream (text or binary)
 *  <li>there is no keyfile specified on the input line
 * </ul>
 * <p>
 * When decrypting;
 * <ul>
 *  <li>the infile is expected to be the 60 character wide base64 
 *    encoded file
 *  <li>the keyfile is expected to be a base64 encoded file
 * </ul>
 * <p>
 * This example shows how to use the light-weight API, DES and
 * the filesystem for message encryption and decryption.
 *
 */
public class DESExample extends Object
{
    // Encrypting or decrypting ?
    private boolean encrypt = true;

    // To hold the initialised DESede cipher
    private PaddedBufferedBlockCipher cipher = null;

    // The input stream of bytes to be processed for encryption
    private BufferedInputStream in = null;

    // The output stream of bytes to be procssed
    private BufferedOutputStream out = null;

    // The key
    private byte[] key = null;

    /*
     * start the application
     */
    public static void main(String[] args)
    {
        boolean encrypt = true;
        String infile = null;
        String outfile = null;
        String keyfile = null;

        if (args.length < 2)
        {
            DESExample de = new DESExample();
            System.err.println("Usage: java "+de.getClass().getName()+
                                " infile outfile [keyfile]");
            System.exit(1);
        }

        keyfile = "deskey.dat";
        infile = args[0];
        outfile = args[1];

        if (args.length > 2)
        {
            encrypt = false;
            keyfile = args[2];
        }

        DESExample de = new DESExample(infile, outfile, keyfile, encrypt);
        de.process();
    }

    // Default constructor, used for the usage message
    public DESExample()
    {
    }

    /*
     * Constructor, that takes the arguments appropriate for
     * processing the command line directives.
     */
    public DESExample(
                String infile,
                String outfile,
                String keyfile,
                boolean encrypt)
    {
        /* 
         * First, determine that infile & keyfile exist as appropriate.
         *
         * This will also create the BufferedInputStream as required
         * for reading the input file.  All input files are treated
         * as if they are binary, even if they contain text, it's the
         * bytes that are encrypted.
         */
        this.encrypt = encrypt;
        try
        {
            in = new BufferedInputStream(new FileInputStream(infile));
        }
        catch (FileNotFoundException fnf)
        {
            System.err.println("Input file not found ["+infile+"]");
            System.exit(1);
        }

        try
        {
            out = new BufferedOutputStream(new FileOutputStream(outfile));
        }
        catch (IOException fnf)
        {
            System.err.println("Output file not created ["+outfile+"]");
            System.exit(1);
        }

        if (encrypt)
        {
            try
            {
                /*
                 * The process of creating a new key requires a 
                 * number of steps.
                 *
                 * First, create the parameters for the key generator
                 * which are a secure random number generator, and
                 * the length of the key (in bits).
                 */
                SecureRandom sr = null;
                try
                {
                    sr = new SecureRandom();
                    /*
                     * This following call to setSeed() makes the
                     * initialisation of the SecureRandom object
                     * _very_ fast, but not secure AT ALL.  
                     *
                     * Remove the line, recreate the class file and 
                     * then run DESExample again to see the difference.
                     *
                     * The initialisation of a SecureRandom object
                     * can take 5 or more seconds depending on the
                     * CPU that the program is running on.  That can
                     * be annoying during unit testing.
                     *     -- jon
                     */
                    sr.setSeed("www.bouncycastle.org".getBytes());
                }
                catch (Exception nsa)
                {
                    System.err.println("Hmmm, no SHA1PRNG, you need the "+
                                        "Sun implementation");
                    System.exit(1);
                }
                KeyGenerationParameters kgp = new KeyGenerationParameters(
                                    sr, 
                                    DESedeParameters.DES_EDE_KEY_LENGTH*8);

                /*
                 * Second, initialise the key generator with the parameters
                 */
                DESedeKeyGenerator kg = new DESedeKeyGenerator();
                kg.init(kgp);

                /*
                 * Third, and finally, generate the key
                 */
                key = kg.generateKey();

                /*
                 * We can now output the key to the file, but first
                 * hex encode the key so that we can have a look
                 * at it with a text editor if we so desire
                 */
                BufferedOutputStream keystream = 
                    new BufferedOutputStream(new FileOutputStream(keyfile));
                byte[] keyhex = Hex.encode(key);
                keystream.write(keyhex, 0, keyhex.length);
                keystream.flush();
                keystream.close();
            }
            catch (IOException createKey)
            {
                System.err.println("Could not decryption create key file "+
                                    "["+keyfile+"]");
                System.exit(1);
            }
        }
        else
        {
            try
            {
                // read the key, and decode from hex encoding
                BufferedInputStream keystream = 
                    new BufferedInputStream(new FileInputStream(keyfile));
                int len = keystream.available();
                byte[] keyhex = new byte[len];
                keystream.read(keyhex, 0, len);
                key = Hex.decode(keyhex);
            }
            catch (IOException ioe)
            {
                System.err.println("Decryption key file not found, "+
                                    "or not valid ["+keyfile+"]");
                System.exit(1);
            }
        }
    }

    private void process()
    {
        /* 
         * Setup the DESede cipher engine, create a PaddedBufferedBlockCipher
         * in CBC mode.
         */
        cipher = new PaddedBufferedBlockCipher(
                                    new CBCBlockCipher(new DESedeEngine()));

        /*
         * The input and output streams are currently set up
         * appropriately, and the key bytes are ready to be
         * used.
         *
         */

        if (encrypt)
        {
            performEncrypt(key);
        }
        else
        {
            performDecrypt(key);
        }

        // after processing clean up the files
        try
        {
            in.close();
            out.flush();
            out.close();
        }
        catch (IOException closing)
        {

        }
    }
        
    /*
     * This method performs all the encryption and writes
     * the cipher text to the buffered output stream created
     * previously.
     */
    private void performEncrypt(byte[] key)
    {
        // initialise the cipher with the key bytes, for encryption
        cipher.init(true, new KeyParameter(key));

        /*
         * Create some temporary byte arrays for use in
         * encryption, make them a reasonable size so that
         * we don't spend forever reading small chunks from
         * a file.
         *
         * There is no particular reason for using getBlockSize()
         * to determine the size of the input chunk.  It just
         * was a convenient number for the example.  
         */
        // int inBlockSize = cipher.getBlockSize() * 5;
        int inBlockSize = 47;
        int outBlockSize = cipher.getOutputSize(inBlockSize);

        byte[] inblock = new byte[inBlockSize];
        byte[] outblock = new byte[outBlockSize];

        /* 
         * now, read the file, and output the chunks
         */
        try
        {
            int inL;
            int outL;
            byte[] rv = null;
            while ((inL=in.read(inblock, 0, inBlockSize)) > 0)
            {
                outL = cipher.processBytes(inblock, 0, inL, outblock, 0);
                /*
                 * Before we write anything out, we need to make sure
                 * that we've got something to write out. 
                 */
                if (outL > 0)
                {
                    rv = Hex.encode(outblock, 0, outL);
                    out.write(rv, 0, rv.length);
                    out.write('\n');
                }
            }

            try
            {
                /*
                 * Now, process the bytes that are still buffered
                 * within the cipher.
                 */
                outL = cipher.doFinal(outblock, 0);
                if (outL > 0)
                {
                    rv = Hex.encode(outblock, 0, outL);
                    out.write(rv, 0, rv.length);
                    out.write('\n');
                }
            }
            catch (CryptoException ce)
            {

            }
        }
        catch (IOException ioeread)
        {
            ioeread.printStackTrace();
        }
    }

    /*
     * This method performs all the decryption and writes
     * the plain text to the buffered output stream created
     * previously.
     */
    private void performDecrypt(byte[] key)
    {    
        // initialise the cipher for decryption
        cipher.init(false, new KeyParameter(key));

        /* 
         * As the decryption is from our preformatted file,
         * and we know that it's a hex encoded format, then
         * we wrap the InputStream with a BufferedReader
         * so that we can read it easily.
         */
        BufferedReader br = new BufferedReader(new InputStreamReader(in));

        /* 
         * now, read the file, and output the chunks
         */
        try
        {
            int outL;
            byte[] inblock = null;
            byte[] outblock = null;
            String rv = null;
            while ((rv = br.readLine()) != null)
            {
                inblock = Hex.decode(rv);
                outblock = new byte[cipher.getOutputSize(inblock.length)];

                outL = cipher.processBytes(inblock, 0, inblock.length, 
                                            outblock, 0);
                /*
                 * Before we write anything out, we need to make sure
                 * that we've got something to write out. 
                 */
                if (outL > 0)
                {
                    out.write(outblock, 0, outL);
                }
            }

            try
            {
                /*
                 * Now, process the bytes that are still buffered
                 * within the cipher.
                 */
                outL = cipher.doFinal(outblock, 0);
                if (outL > 0)
                {
                    out.write(outblock, 0, outL);
                }
            }
            catch (CryptoException ce)
            {

            }
        }
        catch (IOException ioeread)
        {
            ioeread.printStackTrace();
        }
    }

}

