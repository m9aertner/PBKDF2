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

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

import org.jboss.security.PicketBoxMessages;
import org.jboss.security.auth.spi.DatabaseServerLoginModule;

/**
 * A JBoss JDBC based login module that supports authentication, role mapping
 * and salted iterated password hashing. Database connection and SQL are
 * inherited from DatabaseServerLoginModule.
 * <p>
 * Actual check is deferred to pluggable cryptographic module.
 * <p>
 * Format of password depends on formatter. Default PBKDF2HexFormatter's format
 * is: Salt(Hex):Iteration Count(decimal):hashed password(Hex)
 *
 * @author Matthias G&auml;rtner
 * @see org.jboss.security.auth.spi.DatabaseServerLoginModule
 */
public class SaltedDatabaseServerLoginModule extends DatabaseServerLoginModule {

	private static final String HMAC_ALGORITHM = "hmacAlgorithm";
	private static final String HASH_CHARSET = "hashCharset";
	private static final String FORMATTER = "formatter";
	private static final String ENGINE = "engine";
	private static final String ENGINE_PARAMETERS = "engine-parameters";

	private static final String[] ALL_VALID_OPTIONS = {
		HMAC_ALGORITHM, HASH_CHARSET, FORMATTER, ENGINE, ENGINE_PARAMETERS
	};

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


    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler,
    		Map<String,?> sharedState, Map<String,?> options) {
    	addValidOptions(ALL_VALID_OPTIONS);
        super.initialize(subject, callbackHandler, sharedState, options);

        // Too bad that we have to duplicate code from
        // UsernamePasswordLoginModule.hashCharset:
        // base class members are private with no accessors (!#@&)
        hashAlgorithm = (String) options.get(HMAC_ALGORITHM);
        if (hashAlgorithm == null) {
            hashAlgorithm = "HMacSHA1";
        }
        hashCharset = (String) options.get(HASH_CHARSET);

        formatterClassName = (String) options.get(FORMATTER);
        if (formatterClassName == null) {
            formatterClassName = DEFAULT_FORMATTER;
        }

        engineClassName = (String) options.get(ENGINE);
        if (engineClassName == null) {
            engineClassName = DEFAULT_ENGINE;
        }

        parameterClassName = (String) options.get(ENGINE_PARAMETERS);
        if (parameterClassName == null) {
            parameterClassName = DEFAULT_PARAMETER;
        }

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
     * @return <code>true</code> if the inputPassword is valid, <code>false</code> otherwise.
     */
    @Override
    protected boolean validatePassword(String inputPassword, String expectedPassword) {
    	boolean verifyOK = false;
    	for(;;) { // single point of exit
	        if (inputPassword == null || expectedPassword == null) {
	            break;
	        }
	
	        PBKDF2Parameters p = getEngineParameters();
	        if( p == null ) {
	            break;
	        }
	
	        PBKDF2Formatter f = getFormatter();
	        if( f == null ) {
	            break;
	        }

	        if (f.fromString(p, expectedPassword)) {
	            break;
	        }

	        PBKDF2 pBKDF2Engine = getEngine(p);
	        if( pBKDF2Engine == null ) {
	            break;
	        }
	        verifyOK = pBKDF2Engine.verifyKey(inputPassword);
	        break;
    	}
        return verifyOK;
    }

	/**
	 * Factory method: instantiate the PBKDF2 engine parameters. Override or
	 * change the class via attribute.
	 *
	 * @return Engine parameter object, initialized. On error/exception, this
	 *         method registers the exception via {
	 *         {@link #setValidateError(Throwable)} and returns
	 *         <code>null</code>.
	 */
    protected PBKDF2Parameters getEngineParameters() {
        PBKDF2Parameters p = newInstance(parameterClassName, PBKDF2Parameters.class);
        if( p != null ) {
        	p.setHashAlgorithm(hashAlgorithm);
       		p.setHashCharset(hashCharset);
        }
        return p;
    }

	/**
	 * Factory method: instantiate the PBKDF2 engine. Override or change the
	 * class via attribute.
	 *
	 * @param parameters Parameters
	 * @return Engine object. On error/exception, this method registers the
	 *         exception via {{@link #setValidateError(Throwable)} and returns
	 *         <code>null</code>.
	 */
    protected PBKDF2 getEngine(PBKDF2Parameters parameters) {
        PBKDF2 engine = newInstance(engineClassName, PBKDF2.class);
        if( engine != null ) {
        	engine.setParameters(parameters);
        }
        return engine;
    }

	/**
	 * Factory method: instantiate the PBKDF2 formatter. Override or change the
	 * class via attribute. The instance is cached.
	 *
	 * @return Engine formatter. On error/exception, this method registers the
	 *         exception via {{@link #setValidateError(Throwable)} and returns
	 *         <code>null</code>.
	 */
    protected PBKDF2Formatter getFormatter() {
        if (formatter == null) {
            formatter = newInstance(formatterClassName, PBKDF2Formatter.class);
        }
        return formatter;
    }

	/**
	 * Generic helper: Use JBoss SecurityActions to load a class, then create a new instance.
	 *
	 * @param <T> generic return type
	 * @param name FQCN of the class to instantiate.
	 * @param clazz Expected type, used for PicketBox logging.
	 * @return Insance. On error/exception, this method registers the
	 *         exception via {{@link #setValidateError(Throwable)} and returns
	 *         <code>null</code>.
	 */
	@SuppressWarnings("unchecked")
	protected <T> T newInstance(final String name, final Class<T> clazz) {
		T r = null;
		try {
		   Class<?> loadedClass = getClass().getClassLoader().loadClass(name);
		   r = (T) loadedClass.newInstance();
		} catch(Exception e) {
		    LoginException le = new LoginException(PicketBoxMessages.MESSAGES.failedToInstantiateClassMessage(clazz));
		    le.initCause(e);
		    setValidateError(le);
		}
		return r;
	}
}
