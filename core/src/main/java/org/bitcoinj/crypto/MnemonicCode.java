/*
 * Copyright 2013 Ken Sedgwick
 * Copyright 2014 Andreas Schildbach
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

package org.bitcoinj.crypto;

import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Utils;
import com.google.common.base.Joiner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.bitcoinj.core.Utils.HEX;

/**
 * A MnemonicCode object may be used to convert between binary seed values and
 * lists of words per <a href="https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki">the BIP 39
 * specification</a>
 */

public class MnemonicCode {
    private static final Logger log = LoggerFactory.getLogger(MnemonicCode.class);

    private ArrayList<String> wordList;

    private static final String BIP39_ENGLISH_RESOURCE_NAME = "mnemonic/wordlist/english.txt";
    private static String BIP39_ENGLISH_SHA256 = "ad90bf3beb7b0eb7e5acd74727dc0da96e0a280a258354e7293fb7e211ac03db";

    /** UNIX time for when the BIP39 standard was finalised. This can be used as a default seed birthday. */
    public static long BIP39_STANDARDISATION_TIME_SECS = 1381276800;

    private static final int PBKDF2_ROUNDS = 2048;

    public static MnemonicCode INSTANCE;

    static {
        try {
            INSTANCE = new MnemonicCode();
        } catch (FileNotFoundException e) {
            // We expect failure on Android. The developer has to set INSTANCE themselves.
            if (!Utils.isAndroidRuntime())
                log.error("Could not find word list", e);
        } catch (IOException e) {
            log.error("Failed to load word list", e);
        }
    }

    /** Initialise from the included word list. Won't work on Android. */
    public MnemonicCode() throws IOException {
        this(openDefaultWords(), BIP39_ENGLISH_SHA256);
    }

    private static InputStream openDefaultWords() throws IOException {
        InputStream stream = MnemonicCode.class.getResourceAsStream(BIP39_ENGLISH_RESOURCE_NAME);
        if (stream == null)
            throw new FileNotFoundException(BIP39_ENGLISH_RESOURCE_NAME);
        return stream;
    }

    /**
     * Creates an MnemonicCode object, initializing with words read from the supplied input stream.  If a wordListDigest
     * is supplied the digest of the words will be checked.
     */
    public MnemonicCode(InputStream wordstream, String wordListDigest) throws IOException, IllegalArgumentException {
        BufferedReader br = new BufferedReader(new InputStreamReader(wordstream, "UTF-8"));
        this.wordList = new ArrayList<String>(2048);
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);		// Can't happen.
        }
        String word;
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
            String hexdigest = HEX.encode(digest);
            if (!hexdigest.equals(wordListDigest))
                throw new IllegalArgumentException("wordlist digest mismatch");
        }
    }

    /**
     * Gets the word list this code uses.
     */
    public List<String> getWordList() {
        return wordList;
    }

    /**
     * Convert mnemonic word list to seed.
     */
    public static byte[] toSeed(List<String> words, String passphrase) {

        // To create binary seed from mnemonic, we use PBKDF2 function
        // with mnemonic sentence (in UTF-8) used as a password and
        // string "mnemonic" + passphrase (again in UTF-8) used as a
        // salt. Iteration count is set to 4096 and HMAC-SHA512 is
        // used as a pseudo-random function. Desired length of the
        // derived key is 512 bits (= 64 bytes).
        //
        String pass = Joiner.on(' ').join(words);
        String salt = "mnemonic" + passphrase;

        long start = System.currentTimeMillis();
        byte[] seed = PBKDF2SHA512.derive(pass, salt, PBKDF2_ROUNDS, 64);
        log.info("PBKDF2 took {}ms", System.currentTimeMillis() - start);
        return seed;
    }

    /**
     * Convert mnemonic word list to original entropy value.
     */
    public byte[] toEntropy(List<String> words) throws MnemonicException.MnemonicLengthException, MnemonicException.MnemonicWordException, MnemonicException.MnemonicChecksumException {
        if (words.size() % 3 > 0)
            throw new MnemonicException.MnemonicLengthException("Word list size must be multiple of three words.");

        if (words.size() == 0)
            throw new MnemonicException.MnemonicLengthException("Word list is empty.");

        // Look up all the words in the list and construct the
        // concatenation of the original entropy and the checksum.
        //
        int concatLenBits = words.size() * 11;
        boolean[] concatBits = new boolean[concatLenBits];
        int wordindex = 0;
        for (String word : words) {
            // Find the words index in the wordlist.
            int ndx = Collections.binarySearch(this.wordList, word);
            if (ndx < 0)
                throw new MnemonicException.MnemonicWordException(word);

            // Set the next 11 bits to the value of the index.
            for (int ii = 0; ii < 11; ++ii)
                concatBits[(wordindex * 11) + ii] = (ndx & (1 << (10 - ii))) != 0;
            ++wordindex;
        }        

        int checksumLengthBits = concatLenBits / 33;
        int entropyLengthBits = concatLenBits - checksumLengthBits;

        // Extract original entropy as bytes.
        byte[] entropy = new byte[entropyLengthBits / 8];
        for (int ii = 0; ii < entropy.length; ++ii)
            for (int jj = 0; jj < 8; ++jj)
                if (concatBits[(ii * 8) + jj])
                    entropy[ii] |= 1 << (7 - jj);

        // Take the digest of the entropy.
        byte[] hash = Sha256Hash.create(entropy).getBytes();
        boolean[] hashBits = bytesToBits(hash);

        // Check all the checksum bits.
        for (int i = 0; i < checksumLengthBits; ++i)
            if (concatBits[entropyLengthBits + i] != hashBits[i])
                throw new MnemonicException.MnemonicChecksumException();

        return entropy;
    }

    /**
     * Convert entropy data to mnemonic word list.
     */
    public List<String> toMnemonic(byte[] entropy) throws MnemonicException.MnemonicLengthException {
        if (entropy.length % 4 > 0)
            throw new MnemonicException.MnemonicLengthException("Entropy length not multiple of 32 bits.");

        if (entropy.length == 0)
            throw new MnemonicException.MnemonicLengthException("Entropy is empty.");

        // We take initial entropy of ENT bits and compute its
        // checksum by taking first ENT / 32 bits of its SHA256 hash.

        byte[] hash = Sha256Hash.create(entropy).getBytes();
        boolean[] hashBits = bytesToBits(hash);
        
        boolean[] entropyBits = bytesToBits(entropy);
        int checksumLengthBits = entropyBits.length / 32;

        // We append these bits to the end of the initial entropy. 
        boolean[] concatBits = new boolean[entropyBits.length + checksumLengthBits];
        System.arraycopy(entropyBits, 0, concatBits, 0, entropyBits.length);
        System.arraycopy(hashBits, 0, concatBits, entropyBits.length, checksumLengthBits);

        // Next we take these concatenated bits and split them into
        // groups of 11 bits. Each group encodes number from 0-2047
        // which is a position in a wordlist.  We convert numbers into
        // words and use joined words as mnemonic sentence.

        ArrayList<String> words = new ArrayList<String>();
        int nwords = concatBits.length / 11;
        for (int i = 0; i < nwords; ++i) {
            int index = 0;
            for (int j = 0; j < 11; ++j) {
                index <<= 1;
                if (concatBits[(i * 11) + j])
                    index |= 0x1;
            }
            words.add(this.wordList.get(index));
        }
            
        return words;        
    }

    /**
     * Check to see if a mnemonic word list is valid.
     */
    public void check(List<String> words) throws MnemonicException {
        toEntropy(words);
    }

    private static boolean[] bytesToBits(byte[] data) {
        boolean[] bits = new boolean[data.length * 8];
        for (int i = 0; i < data.length; ++i)
            for (int j = 0; j < 8; ++j)
                bits[(i * 8) + j] = (data[i] & (1 << (7 - j))) != 0;
        return bits;
    }
}
