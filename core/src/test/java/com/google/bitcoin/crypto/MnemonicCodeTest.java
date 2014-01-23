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
    String vectors_v0_6[] = {
        "00000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",

        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",


        "80808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",


        "ffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",


        "000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",


        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",


        "808080808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",


        "ffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",


        "0000000000000000000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",


        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",


        "8080808080808080808080808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",


        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",


        "77c2b00716cec7213839159e404db50d",
        "jelly better achieve collect unaware mountain thought cargo oxygen act hood bridge",
        "b5b6d0127db1a9d2226af0c3346031d77af31e918dba64287a1b44b8ebf63cdd52676f672a290aae502472cf2d602c051f3e6f18055e84e4c43897fc4e51a6ff",


        "b63a9c59a6e641f288ebc103017f1da9f8290b3da6bdef7b",
        "renew stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
        "9248d83e06f4cd98debf5b6f010542760df925ce46cf38a1bdb4e4de7d21f5c39366941c69e1bdbf2966e0f6e6dbece898a0e2f0a4c2b3e640953dfe8b7bbdc5",


        "3e141609b97933b66a060dcddc71fad1d91677db872031e85f4c015c5e7e8982",
        "dignity pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
        "ff7f3184df8696d8bef94b6c03114dbee0ef89ff938712301d27ed8336ca89ef9635da20af07d4175f2bf5f3de130f39c9d9e8dd0472489c19b1a020a940da67",


        "0460ef47585604c5660618db2e6a7e7f",
        "afford alter spike radar gate glance object seek swamp infant panel yellow",
        "65f93a9f36b6c85cbe634ffc1f99f2b82cbb10b31edc7f087b4f6cb9e976e9faf76ff41f8f27c99afdf38f7a303ba1136ee48a4c1e7fcd3dba7aa876113a36e4",


        "72f60ebac5dd8add8d2a25a797102c3ce21bc029c200076f",
        "indicate race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
        "3bbf9daa0dfad8229786ace5ddb4e00fa98a044ae4c4975ffd5e094dba9e0bb289349dbe2091761f30f382d4e35c4a670ee8ab50758d2c55881be69e327117ba",


        "2c85efc7f24ee4573d2b81a6ec66cee209b2dcbd09d8eddc51e0215b0b68e416",
        "clutch control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
        "fe908f96f46668b2d5b37d82f558c77ed0d69dd0e7e043a5b0511c48c2f1064694a956f86360c93dd04052a8899497ce9e985ebe0c8c52b955e6ae86d4ff4449",


        "eaebabb2383351fd31d703840b32e9e2",
        "turtle front uncle idea crush write shrug there lottery flower risk shell",
        "bdfb76a0759f301b0b899a1e3985227e53b3f51e67e3f2a65363caedf3e32fde42a66c404f18d7b05818c95ef3ca1e5146646856c461c073169467511680876c",


        "7ac45cfe7722ee6c7ba84fbc2d5bd61b45cb2fe5eb65aa78",
        "kiss carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
        "ed56ff6c833c07982eb7119a8f48fd363c4a9b1601cd2de736b01045c5eb8ab4f57b079403485d1c4924f0790dc10a971763337cb9f9c62226f64fff26397c79",


        "4fa1a8bc3e6d80ee1316050e862c1812031493212b7ec3f3bb1b08f168cabeef",
        "exile ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
        "095ee6f817b4c2cb30a5a797360a81a40ab0f9a4e25ecd672a3f58a0b5ba0687c096a6b14d2c0deb3bdefce4f61d01ae07417d502429352e27695163f7447a8c",


        "18ab19a9f54a9274f03e5209a2ac8a91",
        "board flee heavy tunnel powder denial science ski answer betray cargo cat",
        "6eff1bb21562918509c73cb990260db07c0ce34ff0e3cc4a8cb3276129fbcb300bddfe005831350efd633909f476c45c88253276d9fd0df6ef48609e8bb7dca8",


        "18a2e1d81b8ecfb2a333adcb0c17a5b9eb76cc5d05db91a4",
        "board blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
        "f84521c777a13b61564234bf8f8b62b3afce27fc4062b51bb5e62bdfecb23864ee6ecf07c1d5a97c0834307c5c852d8ceb88e7c97923c0a3b496bedd4e5f88a9",


        "15da872c95a13dd738fbf50e427583ad61f18fd99f628c417a61cf8343c90419",
        "beyond stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
        "b15509eaa2d09d3efd3e006ef42151b30367dc6e3aa5e44caba3fe4d3e352e65101fbdb86a96776b91946ff06f8eac594dc6ee1d3e82a42dfe1b40fef6bcc3fd"
    };

    String vectors_v0_5[] = {
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
        for (int ii = 0; ii < vectors_v0_6.length; ii += 3) {
            String vecData = vectors_v0_6[ii];
            String vecCode = vectors_v0_6[ii+1];
            String vecSeed = vectors_v0_6[ii+2];

            List<String> code = mc.toMnemonic(Hex.decode(vecData));
            byte[] seed = MnemonicCode.toSeed(code, "TREZOR");
            byte[] entropy = mc.toEntropy(split(vecCode));

            assertEquals(vecData, new String(Hex.encode(entropy)));
            assertEquals(vecCode, Joiner.on(' ').join(code));
            assertEquals(vecSeed, new String(Hex.encode(seed)));
        }

        for (int ii = 0; ii < vectors_v0_5.length; ii += 3) {
            String vecData = vectors_v0_5[ii];
            String vecCode = vectors_v0_5[ii+1];
            String vecSeed = vectors_v0_5[ii+2];

            List<String> code = mc.toMnemonic(Hex.decode(vecData));
            byte[] seed = MnemonicCode.toSeed(code, "TREZOR", MnemonicCode.Version.V0_5);
            byte[] entropy = mc.toEntropy(split(vecCode));

            assertEquals(vecData, new String(Hex.encode(entropy)));
            assertEquals(vecCode, Joiner.on(' ').join(code));
            assertEquals(vecSeed, new String(Hex.encode(seed)));
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
