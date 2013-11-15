/*
 * Copyright 2013 Ken Sedgwick
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.bitcoin.crypto;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.spongycastle.crypto.engines.RijndaelEngine;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.util.encoders.Hex;

import com.google.bitcoin.core.Sha256Hash;

/**
 * A MnemonicCode object may be used to convert between binary seed values and
 * lists of words per <a href="https://en.bitcoin.it/wiki/BIP_0039">the BIP 39
 * specification</a>
 *
 * NOTE - as of 15 Oct 2013 the spec at
 * https://en.bitcoin.it/wiki/BIP_0039 is out-of-date.  The correct
 * spec can be found at https://github.com/trezor/python-mnemonic
 */

public class MnemonicCode {

    private ArrayList<String>	wordList;

    public static String BIP0039_ENGLISH_SHA256 =
        "ad90bf3beb7b0eb7e5acd74727dc0da96e0a280a258354e7293fb7e211ac03db";

    /**
     * Creates an MnemonicCode object, initializing with words read
     * from the supplied input stream.  If a wordListDigest is
     * supplied the digest of the words will be checked.
     */
    public MnemonicCode(InputStream wordstream, String wordListDigest)
        throws IOException, IllegalArgumentException {
        BufferedReader br = new BufferedReader(new InputStreamReader(wordstream, "UTF-8"));
        String word;
        this.wordList = new ArrayList<String>();
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);		// Can't happen.
        }
        while ((word = br.readLine()) != null) {
            md.update(word.getBytes());
            this.wordList.add(word);
        }
        br.close();

        if (this.wordList.size() != 2048)
            throw new IllegalArgumentException("input stream did not contain 2048 words");

        // If a wordListDigest is supplied check to make sure it matches.
        if (wordListDigest != null) {
            byte[] digest = md.digest();
            String hexdigest = new String(Hex.encode(digest));
            if (!hexdigest.equals(wordListDigest))
                throw new IllegalArgumentException("wordlist digest mismatch");
        }
    }

    /**
     * Encodes a 128, 192 or 256 bit seed into a list of words.
     */
    public List<String> encode(byte[] seed) throws IllegalArgumentException {
        
        // 2. Make sure its length (L) is 128, 192 or 256 bits.
        int len = seed.length * 8;
        if (len != 128 && len != 192 && len != 256)
            throw new IllegalArgumentException("seed not 128, 192 or 256 bits");

        // 3. Encrypt input data 10000x with Rijndael (ECB mode).
        //    Set key to SHA256 hash of string ("mnemonic" + user_password).
        //    Set block size to input size (that's why Rijndael is used, not AES).
        byte[] indata = stretch(len, seed);

        // Convert binary data to array of boolean for processing.
        boolean[] inarray = new boolean[indata.length * 8];
        for (int ii = 0; ii < indata.length; ++ii)
            for (int kk = 0; kk < 8; ++kk)
                inarray[(ii * 8) + kk] = (indata[ii] & (1 << (7 - kk))) != 0;

        // 4-6 Compute checksum.
        boolean[] chksum = checksum(inarray);

        // 7. Concatenate I and C into encoded data (E). Length of E is divisable by 33 bits.
        boolean[] ee = new boolean[inarray.length + chksum.length];
        for (int ii = 0; ii < inarray.length; ++ii)
            ee[ii] = inarray[ii];
        for (int ii = 0; ii < chksum.length; ++ii)
            ee[inarray.length + ii] = chksum[ii];

        // 8. Keep taking 11 bits from E until there are none left.
        // 9. Treat them as integer W, add word with index W to the output.
        ArrayList<String> words = new ArrayList<String>();
        int nwords = ee.length / 11;
        for (int ii = 0; ii < nwords; ++ii) {
            int ndx = 0;
            for (int kk = 0; kk < 11; ++kk) {
                ndx <<= 1;
                if (ee[(ii * 11) + kk])
                    ndx |= 0x1;
            }
            words.add(this.wordList.get(ndx));
        }
            
        return words;
    }

    /**
     * Decodes a list of words into a seed value.
     */
    public byte[] decode(List<String> words) throws IllegalArgumentException {
        int nwords = words.size();

        // 2. Make sure the number of words is 12, 18 or 24.
        if (nwords != 12 && nwords != 18 && nwords != 24)
            throw new IllegalArgumentException("Mnemonic code not 12, 18 or 24 words");

        // 3. Figure out word indexes in a dictionary and output them as binary stream E.
        int len = nwords * 11;
        boolean[] ee = new boolean[len];
        int wordindex = 0;
        for (String word : words) {
            // Find the words index in the wordlist.
            int ndx = Collections.binarySearch(this.wordList, word);
            if (ndx < 0)
                throw new IllegalArgumentException("\"" + word + "\" invalid");

            // Set the next 11 bits to the value of the index.
            for (int ii = 0; ii < 11; ++ii)
                ee[(wordindex * 11) + ii] = (ndx & (1 << (10 - ii))) != 0;
            ++wordindex;
        }

        // 5. Split E into two parts: B and C, where B are first L/33*32 bits, C are last L/33 bits.
        int bblen = (len / 33) * 32;
        int cclen = len - bblen;

        boolean[] bb = new boolean[bblen];
        for (int ii = 0; ii < bblen; ++ii)
            bb[ii] = ee[ii];

        boolean[] cc = new boolean[cclen];
        for (int ii = 0; ii < cclen; ++ii)
            cc[ii] = ee[bblen + ii];

        // 6. Make sure C is the checksum of B (using the step 5 from the above paragraph).
        boolean[] chksum = checksum(bb);
        if (!Arrays.equals(chksum, cc))
            throw new IllegalArgumentException("checksum error");

        // 8. Treat B as binary data.
        byte[] outdata = new byte[bblen / 8];
        for (int ii = 0; ii < outdata.length; ++ii)
            for (int jj = 0; jj < 8; ++jj)
                if (bb[(ii * 8) + jj])
                    outdata[ii] |= 1 << (7 - jj);

        // 9. Decrypt this data 10000x with Rijndael (ECB mode),
        //    use the same parameters as used in step 3 of encryption.
        byte[] seed = unstretch(bblen, outdata);

        return seed;
    }

    private byte[] stretch(int len, byte[] data) {
        // 3. Encrypt input data 10000x with Rijndael (ECB mode).
        //    Set key to SHA256 hash of string ("mnemonic" + user_password).
        //    Set block size to input size (that's why Rijndael is used, not AES).
        byte[] mnemonic = {'m', 'n', 'e', 'm', 'o', 'n', 'i', 'c'};
        byte[] key = Sha256Hash.create(mnemonic).getBytes();
        RijndaelEngine cipher = new RijndaelEngine(len);
        cipher.init(true, new KeyParameter(key));
        for (int ii = 0; ii < 10000; ++ii)
            cipher.processBlock(data, 0, data, 0);
        return data;
    }

    private byte[] unstretch(int len, byte[] data) {
        // 9. Decrypt this data 10000x with Rijndael (ECB mode),
        //    use the same parameters as used in step 3 of encryption.
        byte[] mnemonic = {'m', 'n', 'e', 'm', 'o', 'n', 'i', 'c'};
        byte[] key = Sha256Hash.create(mnemonic).getBytes();
        RijndaelEngine cipher = new RijndaelEngine(len);
        cipher.init(false, new KeyParameter(key));
        for (int ii = 0; ii < 10000; ++ii)
            cipher.processBlock(data, 0, data, 0);
        return data;
    }

    private boolean[] checksum(boolean[] bits) {
        // 4. Compute the length of the checkum (LC). LC = L/32
        int lc = bits.length / 32;

        // 5. Split I into chunks of LC bits (I1, I2, I3, ...).
        // 6. XOR them altogether and produce the checksum C. C = I1 xor I2 xor I3 ... xor In.
        boolean[] cc = new boolean[lc];
        for (int ii = 0; ii < 32; ++ii)
            for (int jj = 0; jj < lc; ++jj)
                cc[jj] ^= bits[(ii * lc) + jj];
        return cc;
    }
}
