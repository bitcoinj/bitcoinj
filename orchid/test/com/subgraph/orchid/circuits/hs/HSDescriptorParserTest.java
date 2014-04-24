package com.subgraph.orchid.circuits.hs;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.util.List;

import org.junit.Test;

import com.subgraph.orchid.Tor;
import com.subgraph.orchid.directory.DocumentFieldParserImpl;
import com.subgraph.orchid.directory.parsing.DocumentFieldParser;
import com.subgraph.orchid.directory.parsing.DocumentParsingResult;

public class HSDescriptorParserTest {
	private final static String TEST_DESCRIPTOR =
	"rendezvous-service-descriptor apue4vh2fduecfztrrwczoo7cprlki4s\n"+
	"version 2\n"+
	"permanent-key\n"+
	"-----BEGIN RSA PUBLIC KEY-----\n"+
	"MIGJAoGBAMNTmy7L/isS+XTkCf1B1aik0ApE9sxcNpLwNR2JOZyy5puEGPuVY1FW\n"+
	"nw+CnMmTWXchTTRfboFmIv4F3i8ZTLHdWJ7wqRGyc0aabvkDZBSRWVHby3oDf/uQ\n"+
	"abtrJxXzYjy/dP29v5bLkb7a2zaAeP1ojX8ZwpxgJ9BCI+2fvBArAgMBAAE=\n"+
	"-----END RSA PUBLIC KEY-----\n"+
	"secret-id-part xaib3au35yqklp5txmncxbi2uic6jqor\n"+
	"publication-time 2013-07-07 23:20:40\n"+
	"protocol-versions 2,3\n"+
	"introduction-points\n"+
	"-----BEGIN MESSAGE-----\n"+
	"aW50cm9kdWN0aW9uLXBvaW50IGpla2tubHY0dWh2cGNoajVpcnZtd3I0Ym5rb2Ry\n"+
	"N3ZkCmlwLWFkZHJlc3MgMTczLjI1NS4yNDkuMjIyCm9uaW9uLXBvcnQgNDQzCm9u\n"+
	"aW9uLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JB\n"+
	"TG9OeXdIeW1QRGo2c2NvdUsvbGJZR01MRllGRGxDOVJyN2Jjc0MxQW12MWp0MjBH\n"+
	"WlBOdGFHMgorbjdDdHhMK3JWM3g5eFRQSDZBWUlDQmxycnA3TngzRlJQMWorQ3JI\n"+
	"WWk3WkNrTWhDUmg3NXNadmhIV01GT3liClM1QUUyWlhCMTA4cUVucGJnSFdrWmFX\n"+
	"SXdZZXdGZUZxdU5JV3ZjYVgxTU1lc3BONTJ2c0JBZ01CQUFFPQotLS0tLUVORCBS\n"+
	"U0EgUFVCTElDIEtFWS0tLS0tCnNlcnZpY2Uta2V5Ci0tLS0tQkVHSU4gUlNBIFBV\n"+
	"QkxJQyBLRVktLS0tLQpNSUdKQW9HQkFMZDJqYVk0a3oydVBlS05MRnBVMW80MUFV\n"+
	"UmpiQW42bWdzWGtFNm15TTFhcDczS09FUGFQaUFwCmpib1pZSFdCV29QVVZFUFhu\n"+
	"ZE9XcU92ZmFEVGJsbndGU1F1NU54VWVPVkNELzdOYnd6Y0l0c2ZkQ1RBMzVzcHIK\n"+
	"ZGFUK3ZwWmFRWGgxbWt0NlFMN1dKeHZLaXI2bDFuMitwdXFwZ201ZUJhSXRCOEt4\n"+
	"cnVLaEFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0KaW50cm9k\n"+
	"dWN0aW9uLXBvaW50IDcyb3R1Mnl4ZXJoNGZocHAybjNpMnBwNmo3Z2ZrNWZzCmlw\n"+
	"LWFkZHJlc3MgMTk4LjI3LjY0LjI5Cm9uaW9uLXBvcnQgNDQzCm9uaW9uLWtleQot\n"+
	"LS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBT0pLc2UzQmdv\n"+
	"TzhKdytFMURHUXhVbTV6UGQwcjFscHl3U25IamFKb2ZIbitDaUdSTHRnS2JNNQpN\n"+
	"R01UUnRhNVZKWTRUNjFpUFdmN05Ma0FiVnZuSllMcXVHZjdScnh4MCtnNm5jdTVG\n"+
	"blJRMTQwOVkwVXRpNDFmCmVMeGI2YWJlMkorQTRLN2ZGdkMzVjVBSnhtZDIrV2xt\n"+
	"dFhQbGV4aHlYN21SWGhBVzZ1UXpBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElD\n"+
	"IEtFWS0tLS0tCnNlcnZpY2Uta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVkt\n"+
	"LS0tLQpNSUdKQW9HQkFOa0I3eTVaN2FhVUs3R3ZTUWdKVHl6aU43anhlNXlvcEpU\n"+
	"LzBIRURCSGN3cVBqMkdZMytTZ2VJCjRpUWFCRG1SL1V0Y3FuU1JLaGNyMFBSRFBy\n"+
	"T2wxa3lSRmhLWTdqNWttSGRiMko3aEZ2eER1emRTNE43RWdCVVQKbHEvaFdZa2po\n"+
	"QzVDck9uVTNIY1h5Q3RlU1p0bk5qRlkxVHJnSUx4Z1NwcXA0SU5ZZ1NpcEFnTUJB\n"+
	"QUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0KaW50cm9kdWN0aW9uLXBv\n"+
	"aW50IHNzNTR1amRlcWJ6a3RzbnBibzJwZXV5eDJpem1wbmZhCmlwLWFkZHJlc3Mg\n"+
	"MzcuMTU3LjE5NS40OApvbmlvbi1wb3J0IDkwMDEKb25pb24ta2V5Ci0tLS0tQkVH\n"+
	"SU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFKaUZhRE05Nm1acWQ0QTRj\n"+
	"L3lkallpQjRXbGx5b0J5NGt2WXhYZUNnRHA4VGpNVmFzcUFRQUYzCjE5UnJUL01v\n"+
	"TzE4SHVnWjMrUkticFptK2xLeHZlRkpIdGpmTUZQL0NEbDVFOUZ3VFcrdEVUdXMy\n"+
	"RmVYcHJrVGMKbDc3YjIzSkpYd0FtQ3lYMFgyQWNUVVBoVkg4YXdGZU43T0xkRnk0\n"+
	"ZzF3UjZhVzA1SFpIRkFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0t\n"+
	"LS0Kc2VydmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1J\n"+
	"R0pBb0dCQUtSTVVIUTdWaWxRZ1l6c3ZJVEJuZko1QXVSOUNZQWc5eGFUQzNmVWZ1\n"+
	"T21udkZlNHZzZTFJeWsKUkNRSzZHOTVPbGxOd3B5akU4WXRCSlIxUlZLUFBqcHNI\n"+
	"YUxJTmszVmROM3Z5NWxlL0VVQXY2c0dEUnRZODNDLwo3MFhGN1h6YjFGUVBNcm5a\n"+
	"d1o2N3A4Wkc2KzNub1JSUFZLbFJzQU9wa2YwMWJOb3ZpR09iQWdNQkFBRT0KLS0t\n"+
	"LS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQoK\n"+
	"-----END MESSAGE-----\n"+
	"signature\n"+
	"-----BEGIN SIGNATURE-----\n"+
	"p1yxzPiIWpS0m+MTQW9LdJmgiOgaUTbwTz9GyoInPi5lC/WvX8/AnccsLoOUWjKs\n"+
	"3q8xV/8Gtz3qyigsWSggFuXyc3mRGM28tpdCNNkFovKAQgiZ0KjLky9BaQPEFOpr\n"+
	"v4Yo65ZbYvujPyc9xpqbtPNRf7LBe6GaqHvzP4kWqr8=\n"+
	"-----END SIGNATURE-----\n";
	
	private final static String[] TEST_IPS = { 
			"introduction-point mjxsa2bywdvbft6kltuqfwwyru4ggo7o\n"
			+ "ip-address 86.59.119.82\n"
			+ "onion-port 443\n"
			+ "onion-key\n"
			+ "-----BEGIN RSA PUBLIC KEY-----\n"
			+ "MIGJAoGBAKIXLeVl4ut60oNnXeZtxJk7DMKFmklF/zeD+TqB1oW/QALt5wMVmO8u\n"
			+ "RBK7BfSxXG6IWQ0O5vBVSM25qss7+Nv/brS61VcB7IZKDaEd4n3f6Tlu4G8vxjNm\n"
			+ "zX0S1iYLqMOY1vcvuBIN2T43khkO5uyKjgF7EkAXLaH6hJgMSW9bAgMBAAE=\n"
			+ "-----END RSA PUBLIC KEY-----\n"
			+ "service-key\n"
			+ "-----BEGIN RSA PUBLIC KEY-----\n"
			+ "MIGJAoGBAL3FbGOkQ8cjlB70Fy1gv4178MwdNZrBPXwySubW206S0WILGePcXrZX\n"
			+ "4yVCNb4V4i4l9XisSAzyYS2D3CSAtYkinnSlafV3tCvt+QCKeGgtALT42oLt5UOn\n"
			+ "v494xZHVYKCiAwBScjqi7f+/BeclDPqBnm9af8p+cIkeCNrLt0WRAgMBAAE=\n"
			+ "-----END RSA PUBLIC KEY-----\n"
			+ "introduction-point 3ju2px3yec7ylznlwr2fyflabz5nq5kq\n"
			+ "ip-address 209.236.66.136\n"
			+ "onion-port 443\n"
			+ "onion-key\n"
			+ "-----BEGIN RSA PUBLIC KEY-----\n"
			+ "MIGJAoGBAKQLOS9Z5oKUE3EkYgXf5M086S/iJ6YzPB8wPsPRNCNgnGDFYXCLHtw8\n"
			+ "9mfm3jEG7/I5ab3+9hShMfls3uk0kIuOvD7b2VxNpsf5+z7RhZIpkCdby7etR3VL\n"
			+ "RlQO41EIujAfoVFKMk0WmmtpMp7FzPZc8pg3jAfvkwN/wkCeONcBAgMBAAE=\n"
			+ "-----END RSA PUBLIC KEY-----\n"
			+ "service-key\n"
			+ "-----BEGIN RSA PUBLIC KEY-----\n"
			+ "MIGJAoGBALGabFwhhBa5P8br8SScwAK7qJIJlirf95pKASeY4phORZaZFo9qOy7B\n"
			+ "qcIHQNGt3XIbW3MGMvOgIBklus97Bti8KDSTapWvmL4G3uF/XUoP8aPxUO56F+Gv\n"
			+ "RqDQEuf/sk6MbMLPLipG7xWLnn5wYzwsCxutcv2RJdA4mCDcQJYlAgMBAAE=\n"
			+ "-----END RSA PUBLIC KEY-----\n",
			
			"introduction-point f6b7o3f7hh7eudpc4cjocmew6kmnacsy\n"
			+ "ip-address 37.157.192.150\n"
			+ "onion-port 443\n"
			+ "onion-key\n"
			+ "-----BEGIN RSA PUBLIC KEY-----\n"
			+ "MIGJAoGBALoaGfBx/MWM4yVrYO4jxKiVfyTVtvgXlk523ifA2beO6yfeDVKR+4u0\n"
			+ "S/ABa9/kdQFXw4s9Ahz6vI0imdMPyUgYTXp+mP7pa45xp2uLi8kPgZLYzsJZc1Lm\n"
			+ "pyS5CA4Fzq7jblR3R7rGJyRBm1h8Pa8p9xE3RI6oRJnjAoCW+3LBAgMBAAE=\n"
			+ "-----END RSA PUBLIC KEY-----\n"
			+ "service-key\n"
			+ "-----BEGIN RSA PUBLIC KEY-----\n"
			+ "MIGJAoGBAK4GlIJ95emUzWG3zfWGemJbR7UZU+Ufysrgn8VZh2oH01jvTXj14qwD\n"
			+ "8PxI5R8CDlgfzCMMsUwp4tDZHd1IQZSyxRtonprq+j1ACDYm1hvYzwB1kjwlbp5g\n"
			+ "OYl2PtveH5zu2pkvCjknZxW8TCKry5jL8RqY23zLwe+AZWU9BZJdAgMBAAE=\n"
			+ "-----END RSA PUBLIC KEY-----\n"};
	
	
	@Test
	public void testDescriptorParser() {
		final HSDescriptorParser parser = createDescriptorParserFromString(TEST_DESCRIPTOR);
		DocumentParsingResult<HSDescriptor> result = parser.parse();
		assertTrue(result.isOkay());
		HSDescriptor descriptor = result.getDocument();
		List<IntroductionPoint> ips = descriptor.getIntroductionPoints();
		assertEquals(3, ips.size());
		for(IntroductionPoint ip: ips) {
			assertTrue(ip.isValidDocument());
		}
	}
	
	@Test
	public void testIntroductionPointParser() {
		final IntroductionPointParser parser = createIntroductionPointParserFromString(TEST_IPS[0]);
		DocumentParsingResult<IntroductionPoint> result = parser.parse();
		assertTrue(result.isOkay());
		final List<IntroductionPoint> ips = result.getParsedDocuments();
		assertEquals(2, ips.size());
		for(IntroductionPoint ip: result.getParsedDocuments()) {
			assertTrue(ip.isValidDocument());
		}
		
	}
	
	
	private HSDescriptorParser createDescriptorParserFromString(String s) {
		return new HSDescriptorParser(null, createFieldParser(s));
	}
	
	private IntroductionPointParser createIntroductionPointParserFromString(String s) {
		return new IntroductionPointParser(createFieldParser(s)); 
	}
	
	private DocumentFieldParser createFieldParser(String s) {
		ByteBuffer buffer = ByteBuffer.wrap(s.getBytes(Tor.getDefaultCharset()));
		return new DocumentFieldParserImpl(buffer);
	}
}
