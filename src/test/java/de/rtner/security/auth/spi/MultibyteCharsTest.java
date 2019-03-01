/*
 * A free Java implementation of Password Based Key Derivation Function 2 as
 * defined by RFC 2898. Copyright 2007, 2019, Matthias G&auml;rtner
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

import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Unit Tests.
 */
public class MultibyteCharsTest {

	@Test
	public void testPbkdf2mb() {
		String pwd = "santiagui\u00F1o"; // U+00F1 195 177 LATIN SMALL LETTER N WITH TILDE
		String hash = new SimplePBKDF2().deriveKeyFormatted(pwd);
		assertTrue(new SimplePBKDF2().verifyKeyFormatted(hash, pwd));
	}

	@Test
	public void testPbkdf2mbUTF8() {
		String pwd = "santiagui\u00F1o"; // U+00F1 195 177 LATIN SMALL LETTER N WITH TILDE
		SimplePBKDF2 kdf = new SimplePBKDF2();
		kdf.setParameters(new PBKDF2Parameters("HmacSHA1", "UTF-8", null, 1000));
		String hash = kdf.deriveKeyFormatted(pwd);
		assertTrue(kdf.verifyKeyFormatted(hash, pwd));
	}

	@Test
	public void testPbkdf2AumlUTF8() {
		String pwd = "Matthias G\u00E4rtner"; // Should have tested with my own name! (&auml;)
		SimplePBKDF2 kdf = new SimplePBKDF2();
		kdf.setParameters(new PBKDF2Parameters("HmacSHA1", "UTF-8", null, 1000));
		String hash = kdf.deriveKeyFormatted(pwd);
		assertTrue(kdf.verifyKeyFormatted(hash, pwd));
	}
}
