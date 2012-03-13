/**
 * Copyright John Sample
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

package com.google.bitcoin.discovery;

import org.junit.Test;

import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;

import static org.junit.Assert.assertEquals;

public class IrcDiscoveryTest {
    // TODO: Inject a mock IRC server and more thoroughly exercise this class.

    @Test
    public void testParseUserList() throws UnknownHostException {
        // Test some random addresses grabbed from the channel.
        String[] userList = new String[]{ "x201500200","u4stwEBjT6FYyVV", "u5BKEqDApa8SbA7"};
        
        ArrayList<InetSocketAddress> addresses = IrcDiscovery.parseUserList(userList);
        
        // Make sure the "x" address is excluded.
        assertEquals("Too many addresses.", 2, addresses.size());
        
        String[] ips = new String[]{"69.4.98.82:8333","74.92.222.129:8333"};
        InetSocketAddress[] decoded = addresses.toArray(new InetSocketAddress[]{});
        
        for (int i = 0; i < decoded.length; i++) {
            String formattedIP = decoded[i].getAddress().getHostAddress() + ":" + ((Integer)decoded[i].getPort())
                    .toString();
            assertEquals("IPs decoded improperly", ips[i], formattedIP);
        }        
    }

}
