package com.google.bitcoin.crypto;

import com.google.bitcoin.crypto.HDUtils;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

/**
 * @author Matija Mazi <br/>
 */
public class HDUtilsTest {
    private static final Logger log = LoggerFactory.getLogger(HDUtilsTest.class);

    @Test
    public void testHmac() throws Exception {
        String tv[] = {
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" +
                        "0b0b0b0b",
                "4869205468657265",
                "87aa7cdea5ef619d4ff0b4241a1d6cb0" +
                        "2379f4e2ce4ec2787ad0b30545e17cde" +
                        "daa833b7d6b8a702038b274eaea3f4e4" +
                        "be9d914eeb61f1702e696c203a126854",

                "4a656665",
                "7768617420646f2079612077616e7420" +
                        "666f72206e6f7468696e673f",
                "164b7a7bfcf819e2e395fbe73b56e0a3" +
                        "87bd64222e831fd610270cd7ea250554" +
                        "9758bf75c05a994a6d034f65f8f0e6fd" +
                        "caeab1a34d4a6b4b636e070a38bce737",

                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                        "aaaaaaaa",
                "dddddddddddddddddddddddddddddddd" +
                        "dddddddddddddddddddddddddddddddd" +
                        "dddddddddddddddddddddddddddddddd" +
                        "dddd",
                "fa73b0089d56a284efb0f0756c890be9" +
                        "b1b5dbdd8ee81a3655f83e33b2279d39" +
                        "bf3e848279a722c806b485a47e67c807" +
                        "b946a337bee8942674278859e13292fb",

                "0102030405060708090a0b0c0d0e0f10" +
                        "111213141516171819",
                "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" +
                        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" +
                        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" +
                        "cdcd",
                "b0ba465637458c6990e5a8c5f61d4af7" +
                        "e576d97ff94b872de76f8050361ee3db" +
                        "a91ca5c11aa25eb4d679275cc5788063" +
                        "a5f19741120c4f2de2adebeb10a298dd",

                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                        "aaaaaa",
                "54657374205573696e67204c61726765" +
                        "72205468616e20426c6f636b2d53697a" +
                        "65204b6579202d2048617368204b6579" +
                        "204669727374",
                "80b24263c7c1a3ebb71493c1dd7be8b4" +
                        "9b46d1f41b4aeec1121b013783f8f352" +
                        "6b56d037e05f2598bd0fd2215d6a1e52" +
                        "95e64f73f63f0aec8b915a985d786598",

                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                        "aaaaaa",
                "54686973206973206120746573742075" +
                        "73696e672061206c6172676572207468" +
                        "616e20626c6f636b2d73697a65206b65" +
                        "7920616e642061206c61726765722074" +
                        "68616e20626c6f636b2d73697a652064" +
                        "6174612e20546865206b6579206e6565" +
                        "647320746f2062652068617368656420" +
                        "6265666f7265206265696e6720757365" +
                        "642062792074686520484d414320616c" +
                        "676f726974686d2e",
                "e37b6a775dc87dbaa4dfa9f96e5e3ffd" +
                        "debd71f8867289865df5a32d20cdc944" +
                        "b6022cac3c4982b10d5eeb55c3e4de15" +
                        "134676fb6de0446065c97440fa8c6a58"
        };

        for (int i = 0; i < tv.length; i += 3) {
            Assert.assertArrayEquals("Case " + i, getBytes(tv, i + 2), HDUtils.hmacSha256(getBytes(tv, i), getBytes(tv, i + 1)));
        }
    }

    private static byte[] getBytes(String[] hmacTestVectors, int i) {
        return Hex.decode(hmacTestVectors[i]);
    }

    @Test
    public void testPointCompression() {
        List<String> testPubKey = Arrays.asList(
                "044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1",
                "04ed83704c95d829046f1ac27806211132102c34e9ac7ffa1b71110658e5b9d1bdedc416f5cefc1db0625cd0c75de8192d2b592d7e3b00bcfb4a0e860d880fd1fc",
                "042596957532fc37e40486b910802ff45eeaa924548c0e1c080ef804e523ec3ed3ed0a9004acf927666eee18b7f5e8ad72ff100a3bb710a577256fd7ec81eb1cb3");

        ECDomainParameters ecp = HDUtils.getEcParams();
        ECCurve curve = ecp.getCurve();

        for (String testpkStr : testPubKey) {
            byte[] testpk = Hex.decode(testpkStr);

            BigInteger pubX = HDUtils.toBigInteger(Arrays.copyOfRange(testpk, 1, 33));
            BigInteger pubY = HDUtils.toBigInteger(Arrays.copyOfRange(testpk, 33, 65));

            ECPoint ptFlat = curve.createPoint(pubX, pubY, false); // 65
            ECPoint ptComp = curve.createPoint(pubX, pubY, true);  // 33
            ECPoint uncompressed = HDUtils.toUncompressed(ptComp);
            ECPoint recompressed = HDUtils.compressedCopy(uncompressed);
            ECPoint orig = curve.decodePoint(testpk);

            log.info("====================");
            log.info("Flat:              {}", asHexStr(ptFlat));
            log.info("Compressed:        {}", asHexStr(ptComp));
            log.info("Uncompressed:      {}", asHexStr(uncompressed));
            log.info("Recompressed:      {}", asHexStr(recompressed));
            log.info("Original (uncomp): {}", asHexStr(orig));

            // assert point equality:
            Assert.assertEquals(ptFlat, uncompressed);
            Assert.assertEquals(ptFlat, ptComp);
            Assert.assertEquals(ptComp, recompressed);
            Assert.assertEquals(ptComp, orig);

            // assert bytes equality:
            Assert.assertArrayEquals(ptFlat.getEncoded(), uncompressed.getEncoded());
            Assert.assertArrayEquals(ptComp.getEncoded(), recompressed.getEncoded());
            Assert.assertArrayEquals(ptFlat.getEncoded(), orig.getEncoded());
            Assert.assertFalse(Arrays.equals(ptFlat.getEncoded(), ptComp.getEncoded()));

            // todo: assert header byte
        }
    }

    private String asHexStr(ECPoint ptFlat) {
        return new String(Hex.encode(ptFlat.getEncoded()));
    }

    @Test
    public void testLongToByteArray() throws Exception {
        byte[] bytes = HDUtils.longTo4ByteArray(1026);
        Assert.assertEquals("00000402", new String(Hex.encode(bytes)));
    }
}
