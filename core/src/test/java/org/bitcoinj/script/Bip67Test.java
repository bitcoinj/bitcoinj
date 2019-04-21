package org.bitcoinj.script;

import com.google.common.collect.ImmutableList;
import org.bitcoinj.core.ECKey;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.bitcoinj.core.Utils.HEX;
import static org.junit.Assert.assertEquals;

/**
 *
 * Test vectors from
 * <a href="https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki">BIP 67</a>.
 */
@RunWith(Parameterized.class)
public class Bip67Test {

    private static final int THRESHOLD = 2;

    @Parameterized.Parameters
    public static Collection<Bip67TestVector> data() {
        Bip67TestVector test1 = new Bip67TestVector(
                ImmutableList.of("02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8",
                        "02fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f"),
                ImmutableList.of("02fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f",
                        "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8"),
                "522102fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f2102ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f852ae",
                "39bgKC7RFbpoCRbtD5KEdkYKtNyhpsNa3Z"
        );

        Bip67TestVector test2 = new Bip67TestVector(
                ImmutableList.of("02632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0",
                        "027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e77",
                        "02e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b404"),
                ImmutableList.of("02632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0",
                        "027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e77",
                        "02e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b404"),
                "522102632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed021027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e772102e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b40453ae",
                "3CKHTjBKxCARLzwABMu9yD85kvtm7WnMfH"
        );

        Bip67TestVector test3 = new Bip67TestVector(
                ImmutableList.of("030000000000000000000000000000000000004141414141414141414141414141",
                        "020000000000000000000000000000000000004141414141414141414141414141",
                        "020000000000000000000000000000000000004141414141414141414141414140",
                        "030000000000000000000000000000000000004141414141414141414141414140"),
                ImmutableList.of("020000000000000000000000000000000000004141414141414141414141414140",
                        "020000000000000000000000000000000000004141414141414141414141414141",
                        "030000000000000000000000000000000000004141414141414141414141414140",
                        "030000000000000000000000000000000000004141414141414141414141414141"),
                "522102000000000000000000000000000000000000414141414141414141414141414021020000000000000000000000000000000000004141414141414141414141414141210300000000000000000000000000000000000041414141414141414141414141402103000000000000000000000000000000000000414141414141414141414141414154ae",
                "32V85igBri9zcfBRVupVvwK18NFtS37FuD"
        );

        Bip67TestVector test4 = new Bip67TestVector(
                ImmutableList.of("022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da",
                        "03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9",
                        "021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18"),
                ImmutableList.of("021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18",
                        "022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da",
                        "03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9"),
                "5221021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc1821022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da2103e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e953ae",
                "3Q4sF6tv9wsdqu2NtARzNCpQgwifm2rAba"

        );

        return ImmutableList.of(test1, test2, test3, test4);
    }

    private final ImmutableList<ECKey> list;
    private final ImmutableList<ECKey> sorted;
    private final String script;
    private final String address;

    public Bip67Test(Bip67TestVector testVector) {
        this.list = pubkeysFromHex(testVector.list);
        this.sorted = pubkeysFromHex(testVector.sorted);
        this.script = testVector.script;
        this.address = testVector.address;
    }

    @Test
    public void sorting() {
        ImmutableList<ECKey> result = ScriptBuilder.sortMultisigPubkeys(list);
        assertEquals(sorted, result);
    }

    @Test
    public void createMultiSigOutputScript() {
        Script outScript = ScriptBuilder.createMultiSigOutputScript(THRESHOLD, sorted);
        String outScriptHex = HEX.encode(outScript.getProgram());
        assertEquals(script, outScriptHex);
    }

    private static ImmutableList<ECKey> pubkeysFromHex(Collection<String> publicKeys) {
        ImmutableList.Builder<ECKey> serialized = new ImmutableList.Builder<>();
        for (String publicKeyHex : publicKeys) {
            serialized.add(ECKey.fromPublicOnly(HEX.decode(publicKeyHex)));
        }
        return serialized.build();
    }

    private final static class Bip67TestVector {
        private final ImmutableList<String> list;
        private final ImmutableList<String> sorted;
        private final String script;
        private final String address;

        private Bip67TestVector(List<String> list, List<String> sorted, String script, String address) {
            this.list = ImmutableList.copyOf(list);
            this.sorted = ImmutableList.copyOf(sorted);
            this.script = script;
            this.address = address;
        }
    }
}
