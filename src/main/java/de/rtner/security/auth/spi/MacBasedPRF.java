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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Default PRF implementation based on standard javax.crypt.Mac mechanisms.
 *
 * @author Matthias G&auml;rtner
 */
public class MacBasedPRF implements PRF
{
    protected Mac mac;

    protected int hLen;

    protected String macAlgorithm;

    /**
     * Create Mac-based Pseudo Random Function.
     *
     * @param macAlgorithm
     *            Mac algorithm to use, i.e. HMacSHA1 or HMacMD5.
     */
    public MacBasedPRF(String macAlgorithm)
    {
        this.macAlgorithm = macAlgorithm;
        try
        {
            mac = Mac.getInstance(macAlgorithm);
            hLen = mac.getMacLength();
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new RuntimeException(e);
        }
    }

    public MacBasedPRF(String macAlgorithm, String provider)
    {
        this.macAlgorithm = macAlgorithm;
        try
        {
            mac = Mac.getInstance(macAlgorithm, provider);
            hLen = mac.getMacLength();
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new RuntimeException(e);
        }
        catch (NoSuchProviderException e)
        {
            throw new RuntimeException(e);
        }
    }

    public byte[] doFinal(byte[] M)
    {
        byte[] r = mac.doFinal(M);
        return r;
    }

    public int getHLen()
    {
        return hLen;
    }

    public void init(byte[] P)
    {
        try
        {
            mac.init(new SecretKeySpec(P, macAlgorithm));
        }
        catch (InvalidKeyException e)
        {
            throw new RuntimeException(e);
        }
    }
}
