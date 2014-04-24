package com.subgraph.orchid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.Before;
import org.junit.Test;

import com.subgraph.orchid.circuits.hs.HSDescriptorCookie;
import com.subgraph.orchid.config.TorConfigBridgeLine;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.IPv4Address;
import com.subgraph.orchid.encoders.Hex;

public class TorConfigTest {

	private TorConfig config;
	
	@Before
	public void setup() {
		config = Tor.createConfig();
	}


	@Test
	public void testCircuitBuildTimeout() {
		final long timeout = config.getCircuitBuildTimeout();
		assertEquals(TimeUnit.MILLISECONDS.convert(60, TimeUnit.SECONDS), timeout);
		config.setCircuitBuildTimeout(2, TimeUnit.MINUTES);
		assertTrue(config.getCircuitBuildTimeout() > timeout);
	}
	
	@Test
	public void testDataDirectory() {
		final File dd = config.getDataDirectory();
		assertTrue(dd.getPath().charAt(0) != '~');
		final String testPath = "/foo/dir";
		config.setDataDirectory(new File(testPath));
		assertEquals(new File(testPath), config.getDataDirectory());
	}
	
	@Test
	public void testMaxCircuitsPending() {
		assertEquals(32, config.getMaxClientCircuitsPending());
		config.setMaxClientCircuitsPending(23);
		assertEquals(23, config.getMaxClientCircuitsPending());
	}
	
	@Test
	public void testEnforceDistinctSubnets() {
		assertEquals(true, config.getEnforceDistinctSubnets());
		config.setEnforceDistinctSubnets(false);
		assertEquals(false, config.getEnforceDistinctSubnets());
	}
	
	@Test
	public void testCircuitStreamTimeout() {
		assertEquals(0, config.getCircuitStreamTimeout());
		config.setCircuitStreamTimeout(30, TimeUnit.SECONDS);
		assertEquals(30 * 1000, config.getCircuitStreamTimeout());
	}
	
	@Test
	public void testHidServAuth() {
		final String address = "3t43tfluce4qcxbo";
		final String onion = address + ".onion";
		
		final String hex = "022b99d1d272285c80f7214bd6c07c27";
		final String descriptor = "AiuZ0dJyKFyA9yFL1sB8Jw";
		
		assertNull(config.getHidServAuth(onion));
		
		config.addHidServAuth(onion, descriptor);
		
		HSDescriptorCookie cookie = config.getHidServAuth(onion);
		assertNotNull(cookie);
		assertEquals(hex, new String(Hex.encode(cookie.getValue())));
		assertSame(cookie, config.getHidServAuth(address));
	}
	
	@Test
	public void testAutoBool() {
		assertEquals(TorConfig.AutoBoolValue.AUTO, config.getUseNTorHandshake());
		config.setUseNTorHandshake(TorConfig.AutoBoolValue.TRUE);
		assertEquals(TorConfig.AutoBoolValue.TRUE, config.getUseNTorHandshake());
		config.setUseNTorHandshake(TorConfig.AutoBoolValue.AUTO);
		assertEquals(TorConfig.AutoBoolValue.AUTO, config.getUseNTorHandshake());
	}
	
	@Test
	public void testBridges() {
		final IPv4Address a1 = IPv4Address.createFromString("1.2.3.4");
		final IPv4Address a2 = IPv4Address.createFromString("4.4.4.4");
		final HexDigest fp = HexDigest.createFromString("0EA20CAA3CE696E561BC08B15E00106700E8F682");
		config.addBridge(a1, 88);
		config.addBridge(a2, 101, fp);
		List<TorConfigBridgeLine> bs = config.getBridges();
		assertEquals(2, bs.size());
		final TorConfigBridgeLine b1 = bs.get(0);
		final TorConfigBridgeLine b2 = bs.get(1);
		
		assertEquals(a1, b1.getAddress());
		assertEquals(a2, b2.getAddress());
		assertEquals(88, b1.getPort());
		assertEquals(101, b2.getPort());
		assertNull(b1.getFingerprint());
		assertSame(b2.getFingerprint(), fp);
	}
}
