package de.rtner.security.auth.spi;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

import org.jboss.security.auth.spi.DatabaseServerLoginModule;

/**
 * A JBoss JDBC based login module that supports authentication, role mapping
 * and salted iterated password hashing. Database connection and SQL are
 * inherited from DatabaseServerLoginModule.
 * 
 * Actual check is deferred to pluggable cryptographic module.
 * 
 * Format of password depends on formatter. Default PBKDF2HexFormmater's format
 * is: Salt(Hex):Iteration Count(decimal):hashed password(Hex)
 * 
 * <hr />
 * <p>
 * A free Java implementation of Password Based Key Derivation Function 2 as
 * defined by RFC 2898. Copyright (c) 2007 Matthias G&auml;rtner
 * </p>
 * <p>
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 * </p>
 * <p>
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 * </p>
 * <p>
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 * </p>
 * <p>
 * For Details, see <a
 * href="http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html">http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html</a>.
 * </p>
 * 
 * @author Matthias G&auml;rtner
 * @see org.jboss.security.auth.spi.DatabaseServerLoginModule
 * @version 1.0.4
 */
public class SaltedDatabaseServerLoginModule extends DatabaseServerLoginModule
{
    /**
     * The default formatter to use if not specified as a property.
     */
    public final String DEFAULT_FORMATTER = "de.rtner.security.auth.spi.PBKDF2HexFormatter";

    /**
     * The default engine to use if not specified as a property.
     */
    public final String DEFAULT_ENGINE = "de.rtner.security.auth.spi.PBKDF2Engine";

    /**
     * The default engine parameter class to use if not specified as a property.
     */
    public final String DEFAULT_PARAMETER = "de.rtner.security.auth.spi.PBKDF2Parameters";

    /**
     * The message digest algorithm used to hash passwords (examples: HMacSHA1,
     * HMacMD5). Defaults to HMacSHA1 if unset.
     */
    protected String hashAlgorithm = null;

    /**
     * The name of the charset/encoding to use when converting the password
     * String to a byte array. Default is the platform's default encoding.
     */
    protected String hashCharset = null;

    /**
     * Class name of formatter to use.
     * 
     * @see de.rtner.security.auth.spi.PBKDF2Formatter
     * @see de.rtner.security.auth.spi.PBKDF2HexFormatter
     */
    protected String formatterClassName = null;

    /**
     * Instantiation of formatter class. Implementation should be multi-thread
     * safe as this object may be used concurrently by multiple threads inside
     * JBoss.
     */
    protected PBKDF2Formatter formatter = null;

    /**
     * Class name of PBKDF2 engine to use.
     * 
     * @see de.rtner.security.auth.spi.PBKDF2
     */
    protected String engineClassName = null;

    /**
     * Class name of PBKDF2 engine parameters to use.
     * 
     * @see de.rtner.security.auth.spi.PBKDF2Parameters
     */
    protected String parameterClassName = null;

    /**
     */
    public void initialize(Subject subject, CallbackHandler callbackHandler,
            Map sharedState, Map options)
    {
        super.initialize(subject, callbackHandler, sharedState, options);

        // Too bad that we have to duplicate code from
        // UsernamePasswordLoginModule:
        // base class members are private with no accessors (!#@&)
        hashAlgorithm = (String) options.get("hmacAlgorithm");
        if (hashAlgorithm == null)
        {
            hashAlgorithm = "HMacSHA1";
        }
        hashCharset = (String) options.get("hashCharset");

        formatterClassName = (String) options.get("formatter");
        if (formatterClassName == null)
        {
            formatterClassName = DEFAULT_FORMATTER;
        }

        engineClassName = (String) options.get("engine");
        if (engineClassName == null)
        {
            engineClassName = DEFAULT_ENGINE;
        }

        parameterClassName = (String) options.get("engine-parameters");
        if (parameterClassName == null)
        {
            parameterClassName = DEFAULT_PARAMETER;
        }

    }

    /**
     * We just return the password unchanged. It will be decoded/hashed in
     * validatePassword.
     * 
     * @param username
     *            ignored in default version
     * @param password
     *            the password string to be hashed
     */
    protected String createPasswordHash(String username, String password)
    {
        return password;
    }

    /**
     * Actual salt-enabled verification function. Get parameters from database
     * 'password', then compute candidate derived key from user-supplied
     * password and parameters, then compare database derived key and candidate
     * derived key. Login if match.
     * 
     * @param inputPassword
     *            Password that was supplied by user (candidate password)
     * @param expectedPassword
     *            Actually the encoded PBKDF2 string which contains the
     *            expected/reference password implicitly. Not a clear-text
     *            password. Parameter is named like this because of inherited
     *            method parameter name.
     * @return true if the inputPassword is valid, false otherwise.
     */
    protected boolean validatePassword(String inputPassword,
            String expectedPassword)
    {
        if (inputPassword == null || expectedPassword == null)
        {
            return false;
        }

        PBKDF2Parameters p = getEngineParameters();
        PBKDF2Formatter f = getFormatter();
        if (f.fromString(p, expectedPassword))
        {
            return false;
        }
        PBKDF2 pBKDF2Engine = getEngine(p);
        boolean verifyOK = pBKDF2Engine.verifyKey(inputPassword);
        return verifyOK;
    }

    /**
     * Factory method: instantiate the PBKDF2 engine parameters. Override or
     * change the class via attribute.
     * 
     * @return Engine parameter object, initialized.
     */
    protected PBKDF2Parameters getEngineParameters()
    {
        PBKDF2Parameters p = null;
        try
        {
            p = (PBKDF2Parameters) Class.forName(parameterClassName)
                    .newInstance();
        }
        catch (Exception e)
        {
            throw new IllegalArgumentException(
                    "Unable to instantiate implementation class ("
                            + parameterClassName + ")");
        }
        p.setHashAlgorithm(hashAlgorithm);
        if (hashCharset != null)
        {
            p.setHashCharset(hashCharset);
        }
        return p;
    }

    /**
     * Factory method: instantiate the PBKDF2 engine. Override or change the
     * class via attribute.
     * 
     * @param parameters
     * @return Engine object
     */
    protected PBKDF2 getEngine(PBKDF2Parameters parameters)
    {
        PBKDF2 engine = null;
        try
        {
            engine = (PBKDF2) Class.forName(engineClassName).newInstance();
        }
        catch (Exception e)
        {
            throw new IllegalArgumentException(
                    "Unable to instantiate implementation class ("
                            + engineClassName + ")");
        }
        engine.setParameters(parameters);
        return engine;
    }

    /**
     * Factory method: instantiate the PBKDF2 formatter. Override or change the
     * class via attribute.
     * 
     * @return Engine formatter
     */
    protected PBKDF2Formatter getFormatter()
    {
        if (formatter == null)
        {
            try
            {
                formatter = (PBKDF2Formatter) Class.forName(formatterClassName)
                        .newInstance();
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException(
                        "Unable to instantiate implementation class ("
                                + formatterClassName + ")");
            }
        }
        return formatter;
    }
}
