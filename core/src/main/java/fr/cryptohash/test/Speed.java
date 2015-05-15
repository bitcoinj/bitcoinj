// $Id: Speed.java 229 2010-06-16 20:22:27Z tp $

package fr.cryptohash.test;

import fr.cryptohash.Digest;

import java.util.Hashtable;
import java.util.Vector;

/**
 * <p>This class implements some speed tests for hash functions.</p>
 *
 * <pre>
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 * </pre>
 *
 * @version   $Revision: 229 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

public class Speed {

	/*
	 * Each entry in the FUNS and FUNS_SHA3 arrays consists in two
	 * consecutive names. The first name is the one which is matched
	 * with the command-line arguments. The second name is the
	 * corresponding class name. If the second name contains a comma,
	 * then this is a SHA-3-like class with four acceptable output
	 * sizes (224, 256, 384 and 512 bits); the comma separated list
	 * of suffixes indicates those sizes which are relevant.
	 *
	 * Matched functions should be benchmarked in array order (FUNS
	 * first, then FUNS_SHA3).
	 */

	private static final String[] FUNS = {
		"haval3",        "HAVAL256_3",
		"haval4",        "HAVAL256_4",
		"haval5",        "HAVAL256_5",
		"md2",           "MD2",
		"md4",           "MD4",
		"md5",           "MD5",
		"panama",        "PANAMA",
		"radiogatun32",  "RadioGatun32",
		"radiogatun64",  "RadioGatun64",
		"ripemd",        "RIPEMD",
		"ripemd128",     "RIPEMD128",
		"ripemd160",     "RIPEMD160",
		"sha0",          "SHA0",
		"sha1",          "SHA1",
		"sha",           "SHA,256,512",
		"tiger",         "Tiger",
		"whirlpool",     "Whirlpool"
	};

	private static final String[] FUNS_SHA3 = {
		"blake",      "BLAKE,256,512",
		"bmw",        "BMW,256,512",
		"cubehash",   "CubeHash,512",
		"echo",       "ECHO,256,512",
		"fugue",      "Fugue,256,384,512",
		"groestl",    "Groestl,256,512",
		"hamsi",      "Hamsi,256,512",
		"jh",         "JH,512",
		"keccak",     "Keccak,224,256,384,512",
		"luffa",      "Luffa,256,384,512",
		"shabal",     "Shabal,512",
		"shavite",    "SHAvite,256,512",
		"simd",       "SIMD,256,512",
		"skein",      "Skein,256,512"
	};

	private static final Hashtable NAME_TO_CLASSNAMES = new Hashtable();
	private static final Vector ORDERED_CLASSNAMES = new Vector();

	private static void addFun(String name, String cspec,
		Vector sha3classes)
	{
		int n = cspec.indexOf(',');
		if (n < 0) {
			NAME_TO_CLASSNAMES.put(name, cspec);
			ORDERED_CLASSNAMES.addElement(cspec);
		} else {
			String base = cspec.substring(0, n);
			NAME_TO_CLASSNAMES.put(name + "224", base + "224");
			ORDERED_CLASSNAMES.addElement(base + "224");
			NAME_TO_CLASSNAMES.put(name + "256", base + "256");
			ORDERED_CLASSNAMES.addElement(base + "256");
			NAME_TO_CLASSNAMES.put(name + "384", base + "384");
			ORDERED_CLASSNAMES.addElement(base + "384");
			NAME_TO_CLASSNAMES.put(name + "512", base + "512");
			ORDERED_CLASSNAMES.addElement(base + "512");
			int len = cspec.length();
			StringBuffer sb = new StringBuffer();
			n ++;
			while (n < len) {
				int p = cspec.indexOf(',', n);
				if (p < 0)
					p = len;
				String suffix = cspec.substring(n, p);
				if (sb.length() > 0)
					sb.append(',');
				String cname = base + suffix;
				sb.append(cname);
				if (sha3classes != null)
					sha3classes.addElement(cname);
				n = p + 1;
			}
			String ac = sb.toString();
			NAME_TO_CLASSNAMES.put(name, ac);
		}
	}

	private static final Vector SHA3_CLASSES = new Vector();

	static {
		for (int i = 0; i < FUNS.length; i += 2)
			addFun(FUNS[i], FUNS[i + 1], null);
		for (int i = 0; i < FUNS_SHA3.length; i += 2)
			addFun(FUNS_SHA3[i], FUNS_SHA3[i + 1], SHA3_CLASSES);
	}

	/*
	 * FUNS_ALIAS contains mappings from alternate command-line names
	 * to one of the matched names defined in FUNS and FUNS_SHA3.
	 */

	private static final String[] FUNS_ALIAS = {
		"rmd",        "ripemd",
		"rmd128",     "ripemd128",
		"rmd160",     "ripemd160",
		"sha2",       "sha",
		"shavite3",   "shavite"
	};

	private static final Hashtable ALIASES = new Hashtable();
	static {
		for (int i = 0; i < FUNS_ALIAS.length; i += 2)
			ALIASES.put(FUNS_ALIAS[i], FUNS_ALIAS[i + 1]);
	}

	/**
	 * Program entry point. The arguments should be function names,
	 * for which speed is measured. If no argument is given, then
	 * all implemented functions are benchmarked.
	 *
	 * @param args   the program arguments
	 * @throws Exception  on (internal) error
	 */
	public static void main(String[] args)
		throws Exception
	{
		Hashtable todo = new Hashtable();
		for (int i = 0; i < args.length; i ++) {
			String s = normalize(args[i]);
			String t = (String)ALIASES.get(s);
			if (t != null)
				s = t;
			if (s.equals("sha3")) {
				int n = SHA3_CLASSES.size();
				for (int j = 0; j < n; j ++)
					todo.put(SHA3_CLASSES.elementAt(j), "");
			} else {
				String cns = (String)NAME_TO_CLASSNAMES.get(s);
				if (cns == null)
					usage(args[i]);
				int n = 0;
				for (;;) {
					int p = cns.indexOf(',', n);
					String cn = cns.substring(n,
						(p < 0) ? cns.length() : p);
					todo.put(cn, "");
					if (p < 0) 
						break;
					n = p + 1;
				}
			}
		}

		boolean all = (todo.size() == 0);

		int n = ORDERED_CLASSNAMES.size();
		for (int i = 0; i < n; i ++) {
			String cn = (String)ORDERED_CLASSNAMES.elementAt(i);
			if (!all && !todo.containsKey(cn))
				continue;
			Digest d = (Digest)Class.forName(
				"fr.cryptohash." + cn).newInstance();
			speed(d.toString(), d);
		}
	}

	private static String normalize(String name)
	{
		name = name.toLowerCase();
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < name.length(); i ++) {
			char c = name.charAt(i);
			if (c != '-' && c != '/')
				sb.append(c);
		}
		return sb.toString();
	}

	private static void usage(String name)
	{
		System.err.println("unknown hash function name: '"
			+ name + "'");
		System.exit(1);
	}

	private static void speed(String name, Digest dig)
	{
		System.out.println("Speed test: " + name);
		byte[] buf = new byte[8192];
		for (int i = 0; i < buf.length; i ++)
			buf[i] = 'a';
		int dlen = dig.getDigestLength();
		int j = 0;
		long num = 2L;
		for (int clen = 16;; clen <<= 2) {
			if (clen == 4096) {
				clen = 8192;
				if (num > 1L)
					num >>= 1;
			}
			long tt;
			for (;;) {
				tt = speedUnit(dig, j, buf, clen, num);
				j += dlen;
				if (j > (buf.length - dlen))
					j = 0;
				if (tt > 6000L) {
					if (num <= 1L)
						break;
					num >>= 1L;
				} else if (tt < 2000L) {
					num += num;
				} else {
					break;
				}
			}
			long tlen = (long)clen * num;
			long div = 10L * tt;
			long rate = (tlen + (div - 1) / 2) / div;
			System.out.println("message length = "
				+ formatLong((long)clen, 5)
				+ " -> "
				+ prependSpaces(Long.toString(rate / 100L), 4)
				+ "."
				+ prependZeroes(Long.toString(rate % 100L), 2)
				+ " MBytes/s");
			if (clen == 8192) {
				tt = speedLong(dig, buf, clen, num);
				tlen = (long)clen * num;
				div = 10L * tt;
				rate = (tlen + (div - 1) / 2) / div;
				System.out.println("long messages          -> "
					+ prependSpaces(
						Long.toString(rate / 100L), 4)
					+ "."
					+ prependZeroes(
						Long.toString(rate % 100L), 2)
					+ " MBytes/s");
				break;
			}
			if (num > 4L)
				num >>= 2;
		}
	}

	private static long speedUnit(Digest dig, int j,
		byte[] buf, int len, long num)
	{
		int dlen = dig.getDigestLength();
		long orig = System.currentTimeMillis();
		while (num -- > 0) {
			dig.update(buf, 0, len);
			dig.digest(buf, j, dlen);
			if ((j += dlen) > (buf.length - dlen))
				j = 0;
		}
		long end = System.currentTimeMillis();
		return end - orig;
	}

	private static long speedLong(Digest dig, byte[] buf, int len, long num)
	{
		byte[] out = new byte[dig.getDigestLength()];
		long orig = System.currentTimeMillis();
		while (num -- > 0) {
			dig.update(buf, 0, len);
		}
		long end = System.currentTimeMillis();
		dig.digest(out, 0, out.length);
		return end - orig;
	}

	private static String formatLong(long num, int len)
	{
		return prependSpaces(Long.toString(num), len);
	}

	private static String prependSpaces(String s, int len)
	{
		return prependChar(s, ' ', len);
	}

	private static String prependZeroes(String s, int len)
	{
		return prependChar(s, '0', len);
	}

	private static String prependChar(String s, char c, int len)
	{
		int slen = s.length();
		if (slen >= len)
			return s;
		StringBuffer sb = new StringBuffer();
		while (len -- > slen)
			sb.append(c);
		sb.append(s);
		return sb.toString();
	}
}
