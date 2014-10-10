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
 * Interface to objects that know how to encode/decode PBKDF2 parameters.
 *
 * @author Matthias G&auml;rtner
 */
public interface PBKDF2Formatter
{
    /**
     * Convert parameters to String.
     *
     * @param p
     *            Parameters object to output.
     * @return String representation
     */
    public abstract String toString(PBKDF2Parameters p);

    /**
     * Convert String to parameters. Depending on actual implementation, it may
     * be required to set further fields externally.
     *
     * @param p
     *            Decode input string <i>s</i> into this parameter object (output).
     * @param s
     *            String representation of parameters to decode.
     * @return <code>false</code> syntax OK, <code>true</code> some syntax
     *         issue.
     */
    public abstract boolean fromString(PBKDF2Parameters p, String s);
}
