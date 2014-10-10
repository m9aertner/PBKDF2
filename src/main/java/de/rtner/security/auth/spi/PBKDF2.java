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

/**
 * Interface to <b>Password Based Key Derivation Function 2</b> implementations.
 *
 * @author Matthias G&auml;rtner
 * @since 1.0
 */
public interface PBKDF2
{
    /**
     * Convert String-based input to internal byte array, then invoke PBKDF2.
     * Desired key length defaults to Pseudo Random Function block size.
     *
     * @param inputPassword
     *            Candidate password to compute the derived key for.
     * @return internal byte array
     */
    public abstract byte[] deriveKey(String inputPassword);

    /**
     * Convert String-based input to internal byte array, then invoke PBKDF2.
     *
     * @param inputPassword
     *            Candidate password to compute the derived key for.
     * @param dkLen
     *            Specify desired key length
     * @return internal byte array
     */
    public abstract byte[] deriveKey(String inputPassword, int dkLen);

    /**
     * Convert String-based input to internal byte arrays, then invoke PBKDF2
     * and verify result against the reference data that is supplied in the
     * PBKDF2Parameters.
     *
     * @param inputPassword
     *            Candidate password to compute the derived key for.
     * @return <code>true</code> password match; <code>false</code>
     *         incorrect password
     */
    public abstract boolean verifyKey(String inputPassword);

    /**
     * Allow reading of configured parameters.
     *
     * @return Currently set parameters.
     */
    public abstract PBKDF2Parameters getParameters();

    /**
     * Allow setting of configured parameters.
     *
     * @param parameters The parameters object to set.
     */
    public abstract void setParameters(PBKDF2Parameters parameters);

    /**
     * Get currently set Pseudo Random Function.
     *
     * @return Currently set Pseudo Random Function
     */
    public abstract PRF getPseudoRandomFunction();

    /**
     * Set the Pseudo Random Function to use. Note that deriveKeys/getPRF does
     * init this object using the supplied candidate password. If this is
     * undesired, one has to override getPRF.
     *
     * @param prf
     *            Pseudo Random Function to set.
     */
    public abstract void setPseudoRandomFunction(PRF prf);
}
