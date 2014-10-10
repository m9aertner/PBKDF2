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

import de.rtner.misc.BinTools;

/**
 * Hexadecimal PBKDF2 parameter encoder/decoder.
 * <p>
 * This formatter encodes/decodes Strings that consist of
 * <ol>
 * <li>hex-encoded salt bytes</li>
 * <li>colon (':')</li>
 * <li>iteration count, positive decimal integer</li>
 * <li>colon (':')</li>
 * <li>derived key bytes</li>
 * </ol>
 *
 * @author Matthias G&auml;rtner
 */
public class PBKDF2HexFormatter implements PBKDF2Formatter
{
    public boolean fromString(PBKDF2Parameters p, String s)
    {
        if (p == null || s == null)
        {
            return true;
        }

        String[] p123 = s.split(":");
        if (p123 == null || p123.length != 3)
        {
            return true;
        }

        byte salt[] = BinTools.hex2bin(p123[0]);
        int iterationCount = Integer.parseInt(p123[1]);
        byte bDK[] = BinTools.hex2bin(p123[2]);

        p.setSalt(salt);
        p.setIterationCount(iterationCount);
        p.setDerivedKey(bDK);
        return false;
    }

    public String toString(PBKDF2Parameters p)
    {
        String s = BinTools.bin2hex(p.getSalt()) + ":"
                + String.valueOf(p.getIterationCount()) + ":"
                + BinTools.bin2hex(p.getDerivedKey());
        return s;
    }
}
