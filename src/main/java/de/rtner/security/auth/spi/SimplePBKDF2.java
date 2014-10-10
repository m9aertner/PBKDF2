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

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * PBKDF2 convenience object that comes pre-configured.
 * <ul>
 * <li>Salt Generator: &quot;SHA1PRNG&quot;</li>
 * <li>Hash Algorithm: &quot;HmacSHA1&quot;</li>
 * <li>Iterations: 1000</li>
 * <li>Encoding: &quot;ISO-8859-1&quot;</li>
 * </ul>
 * Note: this class is <b>not thread-safe</b>. Create a new instance for each thread.
 *
 * @see <a href="http://tools.ietf.org/html/rfc2898">RFC 2898</a>
 * @author Matthias G&auml;rtner
 */
public class SimplePBKDF2 extends PBKDF2Engine {

	protected int saltSize = 8;

	protected SecureRandom sr;

	protected PBKDF2Formatter formatter;

	/**
	 * Constructor for PBKDF2 implementation object that uses defaults.
	 */
	public SimplePBKDF2() {
		this(8, 1000);
	}

	/**
	 * Extension point. Derived classes can call this, then initialize the other
	 * members as desired.
	 *
	 * @param saltSize
	 *            Salt size.
	 * @param parameters
	 *            Parameters object.
	 */
    protected SimplePBKDF2(int saltSize, PBKDF2Parameters parameters) {
    	super(parameters);
    	setSaltSize(saltSize);
    }

	/**
	 * Constructor for PBKDF2 implementation object.
	 *
	 * @param saltSize
	 *            Salt size.
	 * @param parameters
	 *            Parameters object.
	 */
	public SimplePBKDF2(int saltSize, int iterationCount) {
		this(saltSize, new PBKDF2Parameters("HmacSHA1", "ISO-8859-1",
					null, (iterationCount<0?0:iterationCount)));

		try {
			formatter = new PBKDF2HexFormatter();
			sr = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException ignore) {
			// Should not happen. Named algorithms are included in all JREs.
			// Otherwise, NPE below when the object is _used_.
		}
	}

	public PBKDF2Formatter getFormatter() {
		return formatter;
	}

	public void setFormatter(PBKDF2Formatter formatter) {
		this.formatter = formatter;
	}

	public int getSaltSize() {
		return saltSize;
	}

	public void setSaltSize(int saltSize) {
		if( saltSize <= 0 ) {
			throw new IllegalArgumentException("Salt size must be positive.");
		}
		this.saltSize = saltSize;
	}

	/**
	 * Derive key from password, then format.
	 *
	 * @param inputPassword The password to derive key from.
	 * @return &quot;salt:iteration-count:derived-key&quot; (depends on effective formatter)
	 */
	public String deriveKeyFormatted(String inputPassword) {
		PBKDF2Parameters p = getParameters();
		byte[] salt = generateSalt();
		p.setSalt(salt);
		p.setDerivedKey(deriveKey(inputPassword));
		String formatted = getFormatter().toString(p);
		return formatted;
	}

	/**
	 * Generate Salt. Default is 8 Bytes obtained from SecureRandom.
	 *
	 * @return Random Bytes
	 */
	protected byte[] generateSalt() {
		byte[] salt = new byte[getSaltSize()];
		sr.nextBytes(salt);
		return salt;
	}

	/**
	 * Verification function.
	 *
	 * @param formatted
	 *            &quot;salt:iteration-count:derived-key&quot; (depends on
	 *            effective formatter). This value should come from server-side
	 *            storage.
	 * @param candidatePassword
	 *            The password that is checked against the formatted reference
	 *            data. This value will usually be supplied by the
	 *            &quot;user&quot; or &quot;client&quot;.
	 * @return <code>true</code> verification OK. <code>false</code>
	 *         verification failed or formatter unable to decode input value as
	 *         PBKDF2 parameters.
	 */
	public boolean verifyKeyFormatted(String formatted, String candidatePassword) {
		// Parameter as member of Engine was not the smartest design decision back then...
		PBKDF2Parameters p = getParameters();
		PBKDF2Parameters q = new PBKDF2Parameters();
		q.hashAlgorithm = p.hashAlgorithm;
		boolean verifyOK = false;
		if (!getFormatter().fromString(q, formatted)) {
			try {
				setParameters(q);
				verifyOK = verifyKey(candidatePassword);
			} finally {
				setParameters(p);
			}
		}
		return verifyOK;
	}
}
