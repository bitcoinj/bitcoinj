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
            "cb5e7230ce8229de990674f6aa4288325fd4d8181f761734bd8b5cc944fedc2a4300e64422864b565352de7ffbc5ad0fafdf5344489f3a83e4a4bb5271cafaae",

            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", 
            "legal winner thank year wave sausage worth useful legal winner thank yellow", 
            "de1277934939d6969519f44b7b3757a905d7f635be41e1e88022c346bc52ad26c0a3e9578e73e9b89066873266f285a5891d27d28cb27fccfe26d92bbd7ee364",

            "80808080808080808080808080808080", 
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above", 
            "8863bccef9cfffeacef1e4c6fc97bba8227ab0fc7e8e162be7467282689a13521ea364d7c4bc8cd241b59f53c5147a89c18a47248a96592ab9a2c1f1870b026c",

            "ffffffffffffffffffffffffffffffff", 
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong", 
            "7a29e57c7a1532af1bddb7e02b892cfccc6a57b74fe9784324ea89fab8a66dc64fde79c31166b159685116f4e93c1795496f20ffdc2d3a69d3439931dabde86e",

            "000000000000000000000000000000000000000000000000", 
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent", 
            "c3e382025b6a22a901505cf393faea450eb6c4a5f2a8c8f0596285b2bd84688877a6cc7231420e2bbdd2428e62ed549a78fa215b3adafd8dea075dabfc704d5e",

            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", 
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will", 
            "c82666e40eb097bf6eb05fecd7dc2ddfb6bbdc6071900f4b3fd3c3e635db69aa2094f1f450c98e8dc6103aa72df635abdfcc3b6d6ec5261a9208a07a35a3f1c8",

            "808080808080808080808080808080808080808080808080", 
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always", 
            "e90681c67c55504afadca009ce4042819341fa0e90300b6d32b4f2e8e8a6678ff7e7fc1da663ae194dc7a2ef7ec7b50112d1a5efce47bfd00c66eec82f2265b5",

            "ffffffffffffffffffffffffffffffffffffffffffffffff", 
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when", 
            "2a372547df962742942674170a7cef495ea0b97f4864de16d0f3ee82eb577ca1eca345e601cc2df7c626c5bc51c52c28a3b4294224b685c958c7450bee6769e6",

            "0000000000000000000000000000000000000000000000000000000000000000", 
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", 
            "58cb9c5555d67ecc7b32305a78d1a2fcf0c9b22f1af761cfafc65eb1d3909f63ee2cab84996a7478cfd3e864cda5efb0caf580d56cf49739c6b3638d94e758c1",

            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", 
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title", 
            "0093cb3ed6d1302d3cf498017f8cb1c7dc2fdbd62ec57fc49e4b2a4dd47a23e44e0b309517d5a3e7b0f4f0ef0ed132818cf120a098a92e572ad086f1a90ccb7f",

            "8080808080808080808080808080808080808080808080808080808080808080", 
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless", 
            "8a21e46b9d264328c63e707e3d38ed4eb21508deda309fa2ef57cc8eca8b351ca3018758844ba9fb5851bab15d026a61cabace53a9a39bc91dc2c51407542cf5",

            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote", 
            "5c8a1a284ab2844daf02cab322df3996574c9d53cbd36159c493441990f0d2a6bc9bc1502e3a067943d8ec67324663cbfb9667b57fed220e3f28335e26a90f93",

            "1083fa24dbb0afa4e7b327d23f666567", 
            "awesome cabin matrix resist april sponsor paddle gossip split will off soon", 
            "467406b36a0176e40e013393e5ecef1f5b4019980b502eda9db1db06f7786e088b206f045f2bfcf93bd3b17a598335b078fcc5890115857ff741bd154b54f049",

            "d8cbcd1ac2153ecd74048480c2732f637d642b21f0dd40df", 
            "sugar fury effort loud fault grit source mountain liar bean slim shoulder stone better march brick dolphin zero", 
            "f60180ea5047659cbb17ed6ef79c974de86c0170c7a1962b205329eb8fe9dcdd148615d35c515c4ec8da25f4cf54d5b7cd8cd5bf8dc4059df3a7900ca25f8306",

            "2952f95cefe041616f6f379ab649cf8b702ecf8e4acceaebdda4cc50e2bf1d7b", 
            "citizen oak fire thank advice radar sad tragic one rather initial black actual guitar decrease flower turtle galaxy hard obvious athlete garbage invest have", 
            "eff4b6a15bb55fcf4bbfa2b3b9e24e7dc4bed8319ef7703f1786d472c73666922925778eaa5a06f8a26d2c7e7240be746fd69edfaf197e0dae12d7e0b550cfc8",

            "f5e82717078a6ddc538a03e825f91bed", 
            "vote donkey shift audit plug until evolve document trial cool eight swarm", 
            "83dad22293225780a914083fc1a69bfe1d910f5b5962b0364820132a42ae1bd567a1fb4d5a19ad3d64539e38a7ee3d6429fac2b74e72b020913131c5eadb7db4",

            "16b59b6a426f2f302f73049a32ab8572394278982212357a", 
            "birth proud surround luggage very object saddle gauge olive next throw tongue neither detail gauge drastic cube strategy", 
            "38ceb07e0dad221f612631843be6ae44a650aaf789c8ebea9313e07498d7864385227d25c7a8268a5b850367eef31639632e9218acadead20980b864b1cd477e",

            "95b6cb48c7bc9c2a54496ae3eea790824b57e52b9637058f084555bc1b809b2f", 
            "noble rent split month six benefit eye coil token inside tomorrow afraid rely verb purity shoulder airport joke bacon problem script scare hole trumpet", 
            "e33e3d32e467877596a18ac60050488a0ec1557fda6bf95bad3d33d964c5e99dcd97d378403cc2723ed1c85c12b42bc59f15458d970d7a9d015f556109c146b0",

            "7f93397f750f70a26513de2732ed95ee", 
            "legend oil garlic tube warfare eye nephew knock cheese number grace tackle", 
            "7f92ad63e4cdf4f15c23740556ad81e7f8cbd67cc672c93894c9c0d4fb171539eed5ab29f366570ed9940b816f45a539c3816f7ac19511794b752c5c1ec0e732",

            "14c29fe840dd1c9f05d392ba13e4e1466b32ed0726a15f89", 
            "below belt wheel like spike exhibit blanket inch ring palace debate mimic rebel isolate broken stage garbage enhance", 
            "7bae6e54f8bad645f18f574b310bd3e6fde126dabcaf63a889940380e4798810e48c8151fc56bb2389c07498deacef025f03cbf8fc57ea3ec68f6421b0fcb649",

            "cb30610d175ffeab8357d5190d31923997752a7f9815087bfcad5eb0b43f6468", 
            "sleep loan drive concert zoo fiction ask wide boil hat goose industry jar news wrist actor anchor that clip runway area cabbage museum abuse", 
            "b922030609e7626696b9cf5ca4c06cd99290be30b1052770f6a60c5f26532d178f287a4285d7a2add2845dc89a816b26fdba1c830067d130740f64c0ab5cfbe1",

            "a30b50a5439dcd1774f412ea5ec33403", 
            "perfect fold citizen mango system merry stable liquid tumble voyage snack alter", 
            "aae175f26848370c4d5d3d0640597e2bf1b28e95908dd877259b3eac5d71ffe3140739a3ed80180f88159571df84441985620e6b2fb0696e5cba1aa7b8d10b98",

            "70044da2175ad681d0ebbf2da83cf407eb9c8fd91fc0a8c9", 
            "hybrid carbon hammer concert pulp domain dry jewel color draft dial average right elevator good way potato energy", 
            "a3dffe3a31a2e949d1b04af7495a5b59db17e41d93b985feeaaae89260a9c86c6dcdf7cb32eaba61c2f4f0340f0f17d1ebb67af11657286b2ffd66ec4e05a8b7",

            "0e0bab4df9669b97ba3f75a50b2e92423bbe6e91a1b01dbbf3ba200a917c9106", 
            "asthma front square version have slim trophy upgrade pink floor pig love room dance educate current buffalo test update divorce poverty salad dune scheme", 
            "2eb4d85fbd8deaf9b06bf9cdb3e5f36e8da040d110312075eb32e776fc8e505b94be3e63c1525ad41f5e5968a263853001dc7c40ea3af8e8b0cfb7effd5f408c",
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

            assertEquals(vecCode, Joiner.on(' ').join(code));
            assertEquals(vecSeed, new String(Hex.encode(seed)));
        }
    }

    @Test(expected = MnemonicLengthException.class)
    public void testBadEntropyLength() throws Exception {
        byte[] entropy = Hex.decode("7f7f7f7f7f7f7f7f7f7f7f7f7f7f");
        mc.toMnemonic(entropy);
    }    

    @Test(expected = MnemonicLengthException.class)
    public void testBadLength() throws Exception {
        List<String> words = split("risk tiger venture dinner age assume float denial penalty hello");
        mc.check(words);
    }

    @Test(expected = MnemonicWordException.class)
    public void testBadWord() throws Exception {
        List<String> words = split("risk tiger venture dinner xyzzy assume float denial penalty hello game wing");
        mc.check(words);
    }

    @Test(expected = MnemonicChecksumException.class)
    public void testBadChecksum() throws Exception {
        List<String> words = split("bless cloud wheel regular tiny venue bird web grief security dignity zoo");
        mc.check(words);
    }

    static public List<String> split(String words) {
        return new ArrayList<String>(Arrays.asList(words.split("\\s+")));
    }
}
