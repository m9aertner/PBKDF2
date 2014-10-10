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
 * Interface to <b>Pseudorandom Function</b>.
 *
 * @see <a href="http://tools.ietf.org/html/rfc2898">RFC 2898</a>
 * @author Matthias G&auml;rtner
 */
public interface PRF
{
    /**
     * Initialize this instance with the user-supplied password.
     * 
     * @param P
     *            The password supplied as array of bytes. It is the caller's
     *            task to convert String passwords to bytes as appropriate.
     */
    public void init(byte[] P);

    /**
     * Pseudo Random Function
     * 
     * @param M
     *            Input data/message etc. Together with any data supplied during
     *            initilization.
     * @return Random bytes of hLen length.
     */
    public byte[] doFinal(byte[] M);

    /**
     * Query block size of underlying algorithm/mechanism.
     * 
     * @return block size
     */
    public int getHLen();
}
