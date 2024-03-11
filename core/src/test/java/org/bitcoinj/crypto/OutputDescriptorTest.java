package org.bitcoinj.crypto;

import org.bitcoinj.base.ScriptType;
import org.bitcoinj.crypto.HDPath;
import org.bitcoinj.crypto.OutputDescriptor;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * Simple test of Descriptor using test vector (see the integration test for more detail)
 */
public class OutputDescriptorTest {
    static final String
            vectorDescriptor         = "pkh([37b5eed4/44H/0H/0H]xpub6CnQkivUEH9bSbWVWfDLCtigKKgnSWGaVSRyCbN2QNBJzuvHT1vUQpgSpY1NiVvoeNEuVwk748Cn9G3NtbQB1aGGsEL7aYEnjVWgjj9tefu)";

    @Test
    public void testDescriptor() {
        String xpub = "xpub6CnQkivUEH9bSbWVWfDLCtigKKgnSWGaVSRyCbN2QNBJzuvHT1vUQpgSpY1NiVvoeNEuVwk748Cn9G3NtbQB1aGGsEL7aYEnjVWgjj9tefu";
        OutputDescriptor descriptor = OutputDescriptor.HDKeychainOutputDescriptor.of(ScriptType.P2PKH, xpub, HDPath.parsePath("/44H/0H/0H") , 0x37b5eed4);
        assertEquals("unexpected descriptor", vectorDescriptor,          descriptor.toString());
    }

    @Test
    public void testParse() {
        String descString = "pkh(xpub6CnQkivUEH9bSbWVWfDLCtigKKgnSWGaVSRyCbN2QNBJzuvHT1vUQpgSpY1NiVvoeNEuVwk748Cn9G3NtbQB1aGGsEL7aYEnjVWgjj9tefu)";
        OutputDescriptor descriptor = OutputDescriptor.HDKeychainOutputDescriptor.parse(descString);

        assertEquals(descString, descriptor.toString());
    }

    @Test
    public void testParse2() {
        String descString = "pkh([37b5eed4/44H/0H/0H]xpub6CnQkivUEH9bSbWVWfDLCtigKKgnSWGaVSRyCbN2QNBJzuvHT1vUQpgSpY1NiVvoeNEuVwk748Cn9G3NtbQB1aGGsEL7aYEnjVWgjj9tefu)";
        OutputDescriptor descriptor = OutputDescriptor.HDKeychainOutputDescriptor.parse(descString);

        assertEquals(descString, descriptor.toString());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testParseInvalid() {
        String descString = "foo";
        OutputDescriptor result = OutputDescriptor.HDKeychainOutputDescriptor.parse(descString);
    }
}
