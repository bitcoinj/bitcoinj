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

import org.junit.Test;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.spongycastle.util.encoders.Hex;

import static org.junit.Assert.assertEquals;

public class MnemonicCodeTest {

    // These vectors are from https://raw.github.com/trezor/python-mnemonic/master/vectors.json
    String vectors[] = {
    
        "00000000000000000000000000000000", 
        "risk tiger venture dinner age assume float denial penalty hello game wing",

        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", 
        "truth chase learn pretty right casual acoustic frozen betray main slogan method",

        "80808080808080808080808080808080", 
        "olive garment twenty drill people finish hat own usual level milk usage",

        "ffffffffffffffffffffffffffffffff", 
        "laundry faint system client frog vanish plug shell slot cable large embrace",

        "000000000000000000000000000000000000000000000000", 
        "giant twelve seat embark ostrich jazz leader lunch budget hover much weapon vendor build truth garden year list",

        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", 
        "awful faint gun mean fuel side slogan marine glad donkey velvet oyster movie real type digital dress federal",

        "808080808080808080808080808080808080808080808080", 
        "bless carpet daughter animal hospital pave faculty escape fortune song sign twin unknown bread mobile normal agent use",

        "ffffffffffffffffffffffffffffffffffffffffffffffff", 
        "saddle curve flight drama client resemble venture arch will ordinary enrich clutch razor shallow trophy tumble dice outer",

        "0000000000000000000000000000000000000000000000000000000000000000", 
        "supreme army trim onion neglect coach squirrel spider device glass cabbage giant web digital floor able social magnet only fork fuel embrace salt fence",

        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", 
        "cloth video uncle switch year captain artist country adjust edit inherit ocean tennis soda baby express hospital forest panel actual profit boy spice elite",

        "8080808080808080808080808080808080808080808080808080808080808080", 
        "fence twin prize extra choose mask twist deny cereal quarter can power term ostrich leg staff nature nut swift sausage amateur aim script wisdom",

        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 
        "moon fiscal evidence exile rifle series neglect giant exclude banana glance frown kangaroo globe turtle hat fitness casual sudden select idle arctic best unlock",

        "449ea2d7249c6e0d8d295424fb8894cf", 
        "choice barrel artefact cram increase sell veteran matrix mirror hollow walk pave",

        "75fc3f44a7ff8e2b8af05aa18bded3827a3796df406763dd", 
        "crack outside teach chat praise client manual scorpion predict chalk decrease casino lunch garbage enable ball when bamboo",

        "1cce2f8c2c6a7f2d8473ebf1c32ce13b36737835d7a8768f44dcf96d64782c0e", 
        "muffin evoke all fiber night guard black quote neck expire dial tenant leisure have dragon neck notable peace captain insane nice uphold shine angry",

        "3daa82dd08bd144ec9fb9f77c6ece3d2", 
        "foil dawn net enroll turtle bird vault trumpet service fun immune unveil",

        "9720239c0039f8446d44334daec325f3c24b3a490315d6d9", 
        "damp all desert dash insane pear debate easily soup enough goddess make friend plug violin pact wealth insect",

        "fe58c6644bc3fad95832d4400cea0cce208c8b19bb4734a26995440b7fae7600", 
        "wet sniff asthma once gap enrich pumpkin define trust rude gesture keen grass fine emerge census immense smooth ritual spirit rescue problem beef choice",

        "99fe82c94edadffe75e1cc64cbd7ada7", 
        "thing real emerge verify domain cloud lens teach travel radio effort glad",

        "4fd6e8d06d55b4700130f8f462f7f9bfc6188da83e3faadb", 
        "diary opinion lobster code orange odor insane permit spirit evolve upset final antique grant friend dutch say enroll",

        "7a547fb59606e89ba88188013712946f6cb31c3e0ca606a7ee1ff23f57272c63", 
        "layer owner legal stadium glance oyster element spell episode eager wagon stand pride old defense black print junior fade easy topic ready galaxy debris",

        "e5fc62d20e0e5d9b2756e8d4d91cbb80", 
        "flat make unit discover rifle armed unit acquire group panel nerve want",

        "d29be791a9e4b6a48ff79003dbf31d6afabdc4290a273765", 
        "absurd valve party disorder basket injury make blanket vintage ancient please random theory cart retire odor borrow belt",

        "c87c135433c16f1ecbf9919dc53dd9f30f85824dc7264d4e1bd644826c902be2", 
        "upper will wisdom term once bean blur inquiry used bamboo frequent hamster amazing cake attack any author mimic leopard day token joy install company",
    };

    @Test
    public void testEncodeVectors() throws Exception {
        InputStream wordstream = getClass().getResourceAsStream("mnemonic/wordlist/english.txt");
        MnemonicCode mc = new MnemonicCode(wordstream, MnemonicCode.BIP0039_ENGLISH_SHA256);

        for (int ii = 0; ii < vectors.length; ii += 2) {
            List<String> words = mc.encode(Hex.decode(vectors[ii]));
            assertEquals(vectors[ii+1], join(words));
        }
    }

    @Test
    public void testDecodeVectors() throws Exception {
        InputStream wordstream = getClass().getResourceAsStream("mnemonic/wordlist/english.txt");
        MnemonicCode mc = new MnemonicCode(wordstream, MnemonicCode.BIP0039_ENGLISH_SHA256);

        for (int ii = 0; ii < vectors.length; ii += 2) {
            byte[] seed = mc.decode(split(vectors[ii+1]));
            assertEquals(vectors[ii], new String(Hex.encode(seed)));
        }
    }

    @Test
    public void testBadSeedLength() throws Exception {
        InputStream wordstream = getClass().getResourceAsStream("mnemonic/wordlist/english.txt");
        MnemonicCode mc = new MnemonicCode(wordstream, MnemonicCode.BIP0039_ENGLISH_SHA256);

        boolean sawException = false;
        try {
            byte[] seed = Hex.decode("7f7f7f7f7f7f7f7f7f7f7f7f7f7f");
            List<String> words = mc.encode(seed);
        } catch (IllegalArgumentException ex) {
            sawException = true;
        }
        assertEquals(true, sawException);
    }    

    @Test
    public void testBadWordsLength() throws Exception {
        InputStream wordstream = getClass().getResourceAsStream("mnemonic/wordlist/english.txt");
        MnemonicCode mc = new MnemonicCode(wordstream, MnemonicCode.BIP0039_ENGLISH_SHA256);

        boolean sawException = false;
        try {
            List<String> words = split("risk tiger venture dinner age assume float denial penalty");
            byte[] seed = mc.decode(words);
        } catch (IllegalArgumentException ex) {
            sawException = true;
        }
        assertEquals(true, sawException);
    }    

    static public String join(List<String> list) {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (String item : list)
        {
            if (first)
                first = false;
            else
                sb.append(" ");
            sb.append(item);
        }
        return sb.toString();
    }

    static public List<String> split(String words) {
        return new ArrayList<String>(Arrays.asList(words.split("\\s+")));
    }
}
