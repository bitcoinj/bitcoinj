package com.subgraph.orchid.circuits.path;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import com.subgraph.orchid.Router;
import com.subgraph.orchid.circuits.path.ConfigNodeFilter;
import com.subgraph.orchid.circuits.path.RouterFilter;
import com.subgraph.orchid.data.IPv4Address;

public class ConfigNodeFilterTest {

	@Test
	public void testIsAddressString() {
		final List<String> validStrings = Arrays.asList(
				"1.2.3.4/16",
				"0.0.0.0/1",
				"255.0.255.0/16");
		
		final List<String> invalidStrings = Arrays.asList(
				"1.2.3.256/16",
				"1.2.3.4/61",
				"1.2.3.4/0",
				"1.2.3.4/22x",
				"1.2.3.4/",
				"1.2.3.4");

		for(String s: validStrings) {
			assertTrue(s, ConfigNodeFilter.isAddressString(s));
		}
		for(String s: invalidStrings) {
			assertFalse(s, ConfigNodeFilter.isAddressString(s));
		}

	}
	
	@Test
	public void testIsCountryCode() {
		final List<String> validStrings = Arrays.asList("{CC}", "{xx}");
		final List<String> invalidStrings = Arrays.asList("US", "{xxx}");
		for(String s: validStrings) { assertTrue(s, ConfigNodeFilter.isCountryCodeString(s)); }
		for(String s: invalidStrings) { assertFalse(s, ConfigNodeFilter.isCountryCodeString(s)); }
	}
	
	private Router createRouterMockWithAddress(String ip) {
		final IPv4Address address = IPv4Address.createFromString(ip);
		final Router router = createMock("mockRouter", Router.class);
		expect(router.getAddress()).andReturn(address);
		replay(router);
		return router;
	}
	
	@Test
	public void testMaskFilter() {
		final Router r1 = createRouterMockWithAddress("1.2.3.4");
		final Router r2 = createRouterMockWithAddress("1.7.3.4");
		final RouterFilter f = ConfigNodeFilter.createFilterFor("1.2.3.0/16");
		assertTrue(f.filter(r1));
		assertFalse(f.filter(r2));
		verify(r1, r2);
	}
	
	
}
