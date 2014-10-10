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

import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import org.junit.Test;

/**
 * Unit Tests.
 *
 * @see <a href="http://tools.ietf.org/html/rfc6070">RFC 6070</a> "PKCS #5: Password-Based Key Derivation Function 2 (PBKDF2) Test Vectors" (Jan 2011)
 */
public class PBKDF2EngineTest {

	@Test
	public void testRFC6070_1() {
		decodeAndCheck("password", "73616C74:1:0c60c80f961f0e71f3a9b524af6012062fe037a6");
	}

	@Test
	public void testRFC6070_2() {
		decodeAndCheck("password", "73616C74:2:ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
	}

	@Test
	public void testRFC6070_3() {
		decodeAndCheck("password", "73616C74:4096:4b007901b765489abead49d926f721d065a429c1");
	}

	@Test
	public void testRFC6070_4() {
		// Note: this takes multiple seconds. On my (cheap) machine, nearly 30 seconds.
		assumeTrue("true".equals(System.getProperty("pbkdf2.run.lengthy.test")));
		decodeAndCheck("password", "73616C74:16777216:eefe3d61cd4da4e4e9945b3d6ba2158c2634e984");
	}

	@Test
	public void testRFC6070_5() {
		decodeAndCheck("passwordPASSWORDpassword", "73616C7453414C5473616C7453414C5473616C7453414C5473616C7453414C5473616C74:4096:3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");
	}

	@Test
	public void testRFC6070_6() {
		decodeAndCheck("pass\0word", "7361006C74:4096:56fa6aa75548099dcc37d7f03425e0c3");
	}

	/**
	 * Run one check.
	 * @param pwd The password string
	 * @param saltIterDK Colon-separated salt, iteration count, Base64 derived key
	 */
	protected void decodeAndCheck(String pwd, String saltIterDK) {
		PBKDF2Parameters p = new PBKDF2Parameters("HmacSHA1","ISO-8859-1",null,0);
		new PBKDF2HexFormatter().fromString(p, saltIterDK);
		boolean verifyOK = new PBKDF2Engine(p).verifyKey(pwd);
		assertTrue(verifyOK);
	}
}
