/*
 * A free Java implementation of Password Based Key Derivation Function 2 as
 * defined by RFC 2898. Copyright 2007, 2014, Matthias G&auml;rtner
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package de.rtner.security.auth.spi;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Unit Tests.
 */
public class SimplePBKDF2Test {

	@Test
	public void testVerifyOK() {
		boolean r = new SimplePBKDF2().verifyKeyFormatted("73616C74:1:0c60c80f961f0e71f3a9b524af6012062fe037a6", "password");
		assertTrue("Should verify OK", r);
	}

	@Test
	public void testVerifyBadKey() {
		boolean r = new SimplePBKDF2().verifyKeyFormatted("73616C74:1:0c60c80f961f0e71f3a9b524af6012062fe037a6", "pasSword");
		assertFalse("Verified? How?", r);
	}

	@Test
	public void testVerifyBadFormat() {
		boolean r = new SimplePBKDF2().verifyKeyFormatted("73616C74_1_0c60c80f961f0e71f3a9b524af6012062fe037a6", "password");
		assertFalse("Verified? How?", r);
	}

	@Test
	public void testDerive() {
		// CCD16F76AF3DE30A:1000:B53849A7E20883C77618D3AD16269F98BC4DCA19
		String s = new SimplePBKDF2().deriveKeyFormatted("password");
		assertEquals("Inaccurate result length", s.length(), 62);
		assertEquals("Formatting and Iteration count?", s.substring(16,22), ":1000:");
	}

	@Test
	public void testDerive_12_22() {
		// 85CD9C55749056369CF77873:22:411AFEAD6AB353670E1DCAC917EC52D17936626E
		SimplePBKDF2 e = new SimplePBKDF2(12, 22);
		String s = e.deriveKeyFormatted("password");
		assertEquals("Inaccurate result length", s.length(), 68);
		assertEquals("Formatting and Iteration count?", s.substring(24,28), ":22:");
		assertTrue("Should verify OK", e.verifyKeyFormatted(s, "password"));
	}

	@Test
	public void testDeriveNegativeIteration() {
		SimplePBKDF2 e = new SimplePBKDF2(1, -1);
		assertEquals("Effective iteration count should be zero.",
				e.getParameters().getIterationCount(), 0);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testBadSaltLength() {
		new SimplePBKDF2(0, 1);
	}
}
