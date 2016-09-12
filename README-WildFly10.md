# PBKDF2 - SaltedDatabaseServerLoginModule

A free Java implementation of RFC 2898 / PKCS#5 PBKDF2

I have updated the `SaltedDatabaseServerLoginModule` to work with WildFly9 (JBoss) and later. This is a _Custom Login Module_ that extends the stock "Database" login module. All database interaction continues to be handled by that stock module, it is just the verification step that is done differently.

Instructions, code and configuration can be migrated _verbatim_ from WildFly 9 to WildFly 10, which appears to be fully backwards compatible in this area. Only the WildFly version number is updated. 

The required steps include

1. Making the PBKDF2 code available via a JBoss Module

1. Creating a "Security Domain" that references this module

1. Create required database table

  * For simplicity, we use the built-in H2 database

1. Create one or more user entries

1. Access a protected resource

To ease these last three steps, find a small Web Application provided [PBKDF2-Sample-1.1.0.war](http://www.rtner.de/software/PBKDF2-Sample-1.1.0.war).

Note that this Web Application is for demonstration only, you do _not_ need to deploy this to use the "SaltedDatabaseServerLoginModule" in your system.


# WildFly Setup

Do a clean WildFly install to some folder of your choice. Let's use `C:\Server\wildfly-10.1.0.Final`:

    unzip wildfly-10.1.0.Final.zip -d C:\Server

Test-run the server by calling `standalone.bat`. The log also shows the exact version that we're running here:

    C:\Server\wildfly-10.1.0.Final\bin\standalone.bat
    ...
    ... WFLYSRV0025: WildFly Full 10.1.0.Final (WildFly Core 2.2.0.Final) started in ...

Finally, call [http://localhost:8080](http://localhost:8080) for WildFly's welcome page. Stop the server again for below configuration amendments.

# Integration into WildFly10

## Module

As a first step, we need to make the `SaltedDatabaseServerLoginModule` and PBKDF2 classes known to WildFly. For this , we create a [JBoss Module](https://docs.jboss.org/author/display/MODULES/Module+descriptors).
This _module_ will be referenced from the Security Domain, below

1. Create a folder `C:\Server\wildfly-10.1.0.Final\modules\de\rtner\PBKDF2\main`.

1. Copy file [PBKDF2-1.1.2.jar](http://search.maven.org/remotecontent?filepath=de/rtner/PBKDF2/1.1.2/PBKDF2-1.1.2.jar) there.

1. Create a JBoss module descriptor file named `module.xml` there that references the JAR

 * Amend the version number as appropriate.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<module xmlns="urn:jboss:module:1.1" name="de.rtner.PBKDF2">
    <resources>
        <resource-root path="PBKDF2-1.1.2.jar"/>
    </resources>
    <dependencies>
        <module name="org.picketbox"/>
        <module name="javax.api"/>
    </dependencies>
</module>
```

# Create Security Domain

Edit `C:\Server\wildfly-10.1.0.Final\standalone\configuration\standalone.xml` and insert a new _Security Domain_ named "PBKDF2DatabaseDomain" in the `<security-domains>` section, i.e. before the "other" domain.

The name is arbitrary, of course, and will be referenced in below Web Application. The key points here are to state the _fully qualified class name_ and the _module_ that the class is to be loaded from.

Note that the SQL is for illustration only. To keep things simple, we'll use only a single "Users" table, with _no_ user-to-role table. All users will simply be put into the "manager" role, via that 2nd SQL statement.

```xml
...
<subsystem xmlns="urn:jboss:domain:security:1.2">
    <security-domains>

        <security-domain name="PBKDF2DatabaseDomain">
            <authentication>
                <login-module code="de.rtner.security.auth.spi.SaltedDatabaseServerLoginModule" flag="required" module="de.rtner.PBKDF2">
                    <module-option name="dsJndiName" value="java:jboss/datasources/ExampleDS" />
                    <module-option name="principalsQuery" value="SELECT password FROM Users WHERE username=?" />
                    <module-option name="rolesQuery" value="SELECT DISTINCT 'manager', 'Roles' FROM Users WHERE username=?" />
                </login-module>
            </authentication>
        </security-domain>

        <security-domain name="other" cache-type="default">
             ...
```

# Web Application Configuration

For demonstration, we use a simple JEE web application. Its main deployment descriptor is `WEB-INF/web.xml`:

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<web-app>
    <welcome-file-list>
        <welcome-file>index.jsp</welcome-file>
    </welcome-file-list>

    <security-constraint>
        <web-resource-collection>
            <url-pattern>/hello.jsp</url-pattern>
        </web-resource-collection>
        <auth-constraint>
            <role-name>manager</role-name>
        </auth-constraint>
    </security-constraint>

    <login-config>
        <auth-method>BASIC</auth-method>
    </login-config>

    <security-role>
        <role-name>manager</role-name>
    </security-role>

</web-app>
```

# Security Considerations

A key point here is to use "BASIC" authentication. The Login Module needs to have access to the _plaintext_ password. All of the standard authentication methods supported by browsers other than BASIC either supply certificates only or supply the password in a _digested_ form that is not suitable as an input to the PBKDF2 procedure.

It is best to provide access to your login pages via SSL/TLS **only**. It is generally believed that the risk of plaintext password transmission with BASIC authentication is sufficiently mitigated through the TLS-supplied outer encryption.

The key advantage when using PBKDF2 _to the server side_ is that your user/password database can hold _iterated_ password hashes, whereas DIGEST authentication only supports a _non-iterated_ hash. An attacker will find it much more difficult to brute-force user passwords in case of unauthorized retrieval of the user database.

The random salt will effectively thwart the use of pre-computed password hashes. The iteration will multiply the effort to brute-force single-user passwords.

The above system could further be improved:

1. The supplied user name itself could be subjected to PBKDF2. The database will then not contain cleartext user names. Only if you _know_ a user name can you determine if an entry for that user name exists in the database.

1. The password iterated hash could be made to depend on the user name. This prevents substitution of one known PBKDF2 password hash into the password record of another user.

1. The salt used in all computations could be further enhanced by concatenation with a random server _configuration value_ of sufficient length that would _not_ be stored in the database. This effectively works as another HMAC layer. Leaking the database without that configuration value would make brute-forcing infeasible even for weak user passwords.

1. Obviously, a web application that only has a single protected resource while at the same time failing to protect its password-entry mechanism is, well, _sub-optimal_. Ideally, the "Users" table will be made read-only on database level for your front-end system, with updates / new user registrations being done exclusively through an independent internal system.

# Connect the Web App to the Domain

Put a `WEB-INF/jboss-web.xml` file into the Web App. This links the Web App to the security domain. Note that earlier JBoss versions required a prefix to the domain name. WildFly9 and later does not use a prefix, just specify the domain name as defined above in "standalone.xml".

```xml
<?xml version="1.0" encoding="UTF-8"?>
<jboss-web>
    <security-domain>PBKDF2DatabaseDomain</security-domain>
</jboss-web>
```

# Trying it out

1. Deploy the Web Application by copying file [PBKDF2-Sample-1.1.0.war](http://www.rtner.de/software/PBKDF2-Sample-1.1.0.war) to `C:\Server\wildfly-10.1.0.Final\standalone\deployments`. Note: You may re-build the Web Application locally using the `build-web.gradle` script.

1. Re-start WildFly to make the deployment and changes to `standalone.xml` have effect.

1. Access the web application as [http://localhost:8080/PBKDF2-Sample-1.1.0/index.jsp](http://localhost:8080/PBKDF2-Sample-1.1.0/index.jsp)

1. Hit the "Create Users Table" button. Press "Back". After the WildFly restart, the H2 starts out empty. This creates the user table that we'll fill and use in the next steps.

2. Press the "Add User" button (you may keep the filled-in default password value). This puts a line into the "Users" table. Adding another value to an existing user replaces the entry. Adding an empty password removes the user. Press "Back".

3. Now we're all set. Click the "secured resource" [http://localhost:8080/PBKDF2-Sample-1.1.0/hello.jsp](http://localhost:8080/PBKDF2-Sample-1.1.0/hello.jsp). This should open you browser's "BASIC" password entry dialog. Enter "john" / "password" and enjoy the greeting presented by the "hello.jsp" page.

# Server Logging

Can't log in? Duh. Works, but you want to see what's going on? Cool. First thing you want to do is enable **logging** for the security subsystem. Enable TRACE logging for "org.jboss.security". Also make sure to bump the _appender level_ to TRACE to see something in the log file. Do this by editing logging section of `standalone.xml` and restarting the server:

```xml
<server xmlns="urn:jboss:domain:3.0">
    ...
    <profile>
        <subsystem xmlns="urn:jboss:domain:logging:3.0">
            ...
            <periodic-rotating-file-handler name="FILE" autoflush="true">
                <level name="TRACE"/>
                ...
            </periodic-rotating-file-handler>
            ...
            <logger category="org.jboss.security">
                <level name="TRACE"/>
            </logger>
```

Now check the log file (C:\Server\wildfly-10.1.0.Final\standalone\log\server.log) for Picketbox output ("PBOXxxxxx"), such as:

```
2016-09-12 22:34:31,794 TRACE [org.jboss.security] (default task-17) PBOX00224: End getAppConfigurationEntry(PBKDF2DatabaseDomain), AuthInfo: AppConfigurationEntry[]:
[0]
LoginModule Class: de.rtner.security.auth.spi.SaltedDatabaseServerLoginModule
ControlFlag: LoginModuleControlFlag: required
Options:
name=dsJndiName, value=java:jboss/datasources/ExampleDS
name=principalsQuery, value=SELECT password FROM Users WHERE username=?
name=rolesQuery, value=SELECT DISTINCT 'manager', 'Roles' FROM Users WHERE username=?
```

# Database Details

The "Users" table in the sample database has just two columns:

1. A clear text username column
 * Sample value: "john"

1. A String-valued holder of the PBKDF2-processed password. This token contains the entry-specific salt and the entry-specific iteration count.
 * Sample value: "7008119CDC9AD6D9:1000:D213E20E346F4A762350C530BBBAD375ABA3FEB6" ("your password")
 * The desired _encoding_ to use when converting that password string to bytes can be specified using security domain module options. See SaltedDatabaseServerLoginModule JavaDoc.

The sample configuration shown above does not make use of a second/further database table(s) to store user-to-role (-group) associations. See virtually all other examples on the 'net - they all use multiple database tables.

# References

[http://stackoverflow.com/questions/22291407/jboss-wildfly-database-login-module](http://stackoverflow.com/questions/22291407/jboss-wildfly-database-login-module)

[http://rtner.de/software/PBKDF2.html](http://rtner.de/software/PBKDF2.html)
