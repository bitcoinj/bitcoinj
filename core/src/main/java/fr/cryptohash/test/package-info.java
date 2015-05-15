// $Id: package-info.java 157 2010-04-26 19:03:44Z tp $

/**
 * <p>The {@code fr.cryptohash.test} package contains some test code
 * which can be used to verify that the hash function implementations
 * run correctly, and to measure their speed.</p>
 *
 * <p>There are two classes in this package. Each of them is a program
 * entry point (each contains a proper {@code main()} static method).
 * The {@link fr.cryptohash.test.TestDigest TestDigest} class runs
 * self-tests with hardcoded test vectors; it ignores its arguments. The
 * {@link fr.cryptohash.test.Speed Speed} class benchmarks the hash
 * function implementations for processing speed, over various message
 * lengths; the names of the functions to hash are given as argument. If
 * no argument is given then all implemented functions are benchmarked
 * (which takes a few minutes).</p>
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
 * @version   $Revision: 157 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

package fr.cryptohash.test;
