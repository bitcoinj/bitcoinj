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

import com.google.common.base.Joiner;
import org.junit.Before;
import org.junit.Test;
import org.spongycastle.util.encoders.Hex;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class MnemonicCodeTest {
    // These vectors are from https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    String vectors[] = {
        "00000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "3d39670caaa237f5fb2999474413733b59d9dfe12b2cccfe878069a2f605ae467a669619a0a45c7b3378c4c812b80be677c1b8f8f60db9383f1ed265c45eb41c",

        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "34eb04e0d4d60d00217f1c0150d8b0d6ffc6086e365a8a94fcceae8614e38274e719ebe7a693356426d1c62fdf90c84eaaac3d920743f3e79e0970a295886a08",

        "80808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "acd45eb0b06e53d2e0fa6d1b3e8b3c33f200d2be6013fc5f8796c8c1d238552a615a01f325d78a10e633991d92f1236e21c24afe7c679fa1ecbc67fe71a5337d",

        "ffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "d20f4e7902c3fd2f7716a533b131042036e6df2e44b14c8d65eb57403d002e4a12fa9be5325b257637ad1209e850188ffb061b3033a315b236ffc70c4ab4ea96",

        "000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        "55fb6d9683e16f71025b73efa1a297d522010e37a4fc5b54770b09173e4f7fed85f83b075142965015d17c8f7a365e589ac943ed83cfbf76dcaf301c6c53b9d6",

        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        "a2455beee8e73686d56f92979ed8a69011772f68e8329a437f47e55d79eaeec25afc2ac5ff636ac8578161a09a2ea690747575653f9d91016b09b71227a53791",

        "808080808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        "dd53ab268c524bad304e3decf4298ba1413a785bc866c2118988d1634bddf5a1301718191b247761060bc6dce3c62f833b22c062e51e7508fc04201cd7f8515b",

        "ffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        "f0747118b52dcd33d383e5f3d6dddc94f66accd38b6d48f8a07fed9752fa8457dcb40bba5f40399814dcbd1a3f5cfaead1cf26c72268d1aa71561611421d4aaf",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "681088fbeaf5e4c29de23f55967a942bcb3400dc5b6e507477dfdcb493d921902352e015cd1235279c61ddf26b9536e6cf87fccb3cf2e142db44689f78ccad12",

        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "0881d39ee42046f433bff48ae0520128b79c0b9ff376c805b384340bd73767cdd8d1583606bafe2879be99ff44847e83057dbe521415a6067e8e4d7334e35a6c",

        "8080808080808080808080808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "63362d97a394e67674c5e337b8b8221f242cdf84eac057e08e8d522ac458e0c8b577c487bf82255d41e2ecfaf9326be2b3b31534a990608950b05a5d849e0603",

        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "3c22432ca0b5c9572a631b1068749bb6b663a78390322ab4b763c3ee21d81a7774f8ecdbc6ec73932b961c7374c7d14156cd61f81e433de3953fad23ea407e58",

        "b71edfa823c78c5f8d6cade654e298b4",
        "require want tube elegant juice cool cup noble town poem plate harsh",
        "b424ec5ee4eb4127c3ce0722572c456a47084cda617a26fb647f9a02f43fcc3d11a84dadb6e892ec2641d8592149018a39c8bd9c1cadc969188da4b820bf3371",

        "8ffd2ff2b2fa4dd7c61f019698893918dfd72c0ea37d0027",
        "morning truly witness grass pill typical blur then notable session exact coyote word noodle dentist hurry ability dignity",
        "d20f3879eebf9858443a6ca0f04f568aac06e74fb542475824101855133ed5f54d0805d0fc9bc0e6f03c1f820ee01a462b291caeba7cbf659b670afd00e0db42",

        "9b655bc7d4e380bad6148df1cf8d8a6b023b781b05c2e823c5b5dd05139d30f6",
        "opinion client vehicle prefer day frost flame museum vault ladder glad stock casual rose hire reunion trial bullet hope ring eye soldier sense stereo",
        "3c6d3843502c73e29d7e9ddc3e81354d3467121244e0b713cdb8e0e76c357d6db2f738c43bc2550bb85c9d5c900fbd7fbba10c76e7a8b920e0d450ef5a6750eb",

        "bdc823540d4ff8d372d29f4265fe5cf8",
        "saddle donate steak box zebra have slender fault draw copper now various",
        "0c960d7d54415e5d3ae41ea805bc961f14d7031ea0b92058c19cecab7b7e51f82a4d987dbe63dfaed30805bd746d93e645fd5dffea8354b90688711d6fa570bd",

        "53de16bcad3ea92c691f5d069de6f1870a9adfe764b1aa33",
        "fatigue vague quality foil tunnel normal piece two alley upset round asthma predict husband outside normal pretty oppose",
        "fa384e2775768bc4905a5f7a014cdb62bbf77f751a039d5a124191099970dafc02e679232aeab769cb1582038907829baa3995255be01fe042b462539b26f1af",

        "29932ac2fbba5682ef711bd7429068ac7f90fe6132c9f1a722e8441240cb9a96",
        "civil off radar wash pistol door saddle casino struggle behind boss flight weekend left luggage float vast decorate ring market catch grape heart sport",
        "777122f7b4e1dd21d385e71b9811d7d8d2adffcb8d0cebb667c93346156d4baec6b23adc519515742a4f6a712cbbef3e03e528f912498a3104206f33259d8823",

        "498e5f6f8039399a5e307406f448f846",
        "end indicate swim about near snake juice attend alone pelican dignity mimic",
        "551e36122e37276b2840ab5c71b2a33888a6efa501a47b8323b313bf03f6dec1fb3d2ef11bfb35ec41580c5c0be3f881907fe2a3154b6e0ba8e05177b8e928a6",

        "7d205696a272051f60c14f146808a2c83bb0f7ef95037b4e",
        "large actor pizza eager cake moral loan clarify behave doctor chunk motor roast know salad parrot kitten item",
        "d8bb3b18a5b9844ae1117b680986d93074efc691d9084dc5ef9d3570d9f9bcaffc9c319fb53d6c728564ee0e4494953245607688adb2efbbe77b912835f40e8c",

        "d10c1c341f19c89a5c8c505cabfa027422ea6cb4cb6c28003898676ef7611cd2",
        "speed genius artist dilemma orient essay impulse meat frequent garlic letter tribe concert curve spring horn chimney achieve champion solution urge rack infant furnace",
        "a2f0b91b238ca1df0c4ac89eaa628701800f70732a1952982f3021e94bf7c3aafa0bb51bbdcc210f1e433d3e740660d1e4053c12edfdc1eb77ceafbe6a32723e",

        "719ddb2a59b10066c74d26954da2dc2e",
        "immense uphold skin recall avoid cricket brush pill next home require friend",
        "9be5826432f915ace1f77827028a0ab7098dd3776304aa17e03698b09e5e93914e3e3f0d3d38c9b265ec2cc4bba1da8c9d9a97c8a3b1ec05add8e34a1c676490",

        "5746a7704cd3b9dc0a022f2a9025618d813c8ca873b8008c",
        "firm cry swing often describe unlock chimney echo clever license flash brand because edge peace jacket above gentle",
        "06f5b2d7af46c2e7b7b99c87aa52d17c27925ba685ba5e572b4e978da2adee44fe7d5726966cd2ee1ae47b65790baa4b3f7952505b0b45d9c8673a29e6a57ffc",

        "8fdda21cc1b39a6fb264ab3c007995cf9ed9efcfebc07652951e769b6bcbfad4",
        "more unfair mango lock defy daughter sister nice despair adult grace palace unique wave distance job iron net elegant unfold repeat tourist twice number",
        "c37ae2956e1396b03a722d647dbcf2672cb8db1493c2c136ab9370a62c19c8f45023a635b7c2646a9748ff28c7ef64d93d089c315d390c50cee19cb46a01927f"
    };
    private MnemonicCode mc;

    @Before
    public void setup() throws IOException {
        mc = new MnemonicCode();
    }

    @Test
    public void testVectors() throws Exception {
        for (int ii = 0; ii < vectors.length; ii += 3) {
            String vecData = vectors[ii];
            String vecCode = vectors[ii+1];
            String vecSeed = vectors[ii+2];

            List<String> code = mc.toMnemonic(Hex.decode(vecData));
            byte[] seed = MnemonicCode.toSeed(code, "TREZOR");
            byte[] entropy = mc.toEntropy(split(vecCode));

            assertEquals(vecCode, Joiner.on(' ').join(code));
            assertEquals(vecSeed, new String(Hex.encode(seed)));
            assertEquals(vecData, new String(Hex.encode(entropy)));
        }
    }

    @Test(expected = MnemonicException.MnemonicLengthException.class)
    public void testBadEntropyLength() throws Exception {
        byte[] entropy = Hex.decode("7f7f7f7f7f7f7f7f7f7f7f7f7f7f");
        mc.toMnemonic(entropy);
    }    

    @Test(expected = MnemonicException.MnemonicLengthException.class)
    public void testBadLength() throws Exception {
        List<String> words = split("risk tiger venture dinner age assume float denial penalty hello");
        mc.check(words);
    }

    @Test(expected = MnemonicException.MnemonicWordException.class)
    public void testBadWord() throws Exception {
        List<String> words = split("risk tiger venture dinner xyzzy assume float denial penalty hello game wing");
        mc.check(words);
    }

    @Test(expected = MnemonicException.MnemonicChecksumException.class)
    public void testBadChecksum() throws Exception {
        List<String> words = split("bless cloud wheel regular tiny venue bird web grief security dignity zoo");
        mc.check(words);
    }

    static public List<String> split(String words) {
        return new ArrayList<String>(Arrays.asList(words.split("\\s+")));
    }
}
