PBKDF2
======

A free Java implementation of RFC 2898 / PKCS#5 PBKDF2

[http://rtner.de/software/PBKDF2.html](http://rtner.de/software/PBKDF2.html)

Recent History
==============

## v1.1.4 01Mar2019
* Addressed Issue #7 Checking password is not constant time algorithm
* Addressed Issue #8 SimplePBKDF2 fails with multibyte chars

## v1.1.3 01Mar2019
* Travis complains about unit test characters. Not publishing this version.

## v1.1.2 12Sep2016
* Checked that `SaltedDatabaseServerLoginModule` continues to work with [WildFly10](http://www.wildfly.org/)
 * See [README-WildFly10.md](README-WildFly10.md), sample [Web Application](http://www.rtner.de/software/PBKDF2-Sample-1.1.0.war) remains unchanged.
* Minor code change to "main" function: option "-i <number>" added to specify _desired_ (create mode) or _minimal_ (verification mode) iteration count on the `PBKDF2Engine` command line. Default remains at 1000.

## v1.1.1 14Jun2015
* Issues resolved
 * [Unable to resolve dependencies due to + sign in version number](https://github.com/m9aertner/PBKDF2/issues/2)
 * Prevented undeclared dependency in Picketbox on "org.jboss.logging", required for clean compile, from appearing in our POM.
* Checked that `SaltedDatabaseServerLoginModule` continues to work with [WildFly9](http://www.wildfly.org/)
 * See [README-WildFly9.md](README-WildFly9.md), sample [Web Application](http://www.rtner.de/software/PBKDF2-Sample-1.1.0.war) remains unchanged.
* No code change.

## v1.1.0 14Oct2014
* Added `SimplePBKDF2` convenience class
* Updated `SaltedDatabaseServerLoginModule` to work with [WildFly8](http://www.wildfly.org/)
* See [README-WildFly8.md](README-WildFly8.md) for configuration instructions via provided sample Web Application `PBKDF2-Sample-1.1.0.war`.

## v1.0.7 10Oct2014
* Connected to [Travis CI](https://travis-ci.org)
* [![Build Status](https://travis-ci.org/m9aertner/PBKDF2.svg?branch=master)](https://travis-ci.org/m9aertner/PBKDF2)
* No non-comment code changes, not published.

## v1.0.6 08Oct2014
* Main code *unchanged*
* Checking RFC 6070 values via JUnit tests now
* Converted to Gradle
* Uploaded artefacts to Maven Central
* GPG-signed tags
* JBoss `SaltedDatabaseServerLoginModule` removed from artefacts
 * Need to get this working with WildFly 8.1 first...

## v1.0.5 30Jun2011
* Added test program for RFC 6070 test vector #6. No code change.

## v1.0.3
* Added JBoss `SaltedDatabaseServerLoginModule`

## v1.0.0
* Ant build

Sample Use
==========

## Simple API

```java
// Salt 8 bytes SHA1PRNG, HmacSHA1, 1000 iterations, ISO-8859-1
String s = new SimplePBKDF2().deriveKeyFormatted("password");
// s === "CCD16F76AF3DE30A:1000:B53849A7E20883C77618D3AD16269F98BC4DCA19"
boolean ok = new SimplePBKDF2().verifyKeyFormatted(s, "password");
```

## DIY

```java
byte[] salt = new byte[8];
SecureRandom.getInstance("SHA1PRNG").nextBytes(salt);
PBKDF2Parameters p = new PBKDF2Parameters("HmacSHA256", "UTF-8", salt, 2000);
byte[] dk = new PBKDF2Engine(p).deriveKey("Hello World");
System.out.println(BinTools.bin2hex(dk));
// Result is 64-character Base64 value. Note SHA256, different from RFC 6070.
```

## Command line

```
> java -jar PBKDF2-1.1.4.jar "Hello World!"
AA2C42862321D0A5:1000:296C7F0EA94D0E79D6771D74158860608E8C7F73

> java -jar PBKDF2-1.1.4.jar -i 12288 password
082EFFA9F93CE8BB:12288:C24AC4382DFF88284F1B8338C3CCD95E3221B900

> java -jar PBKDF2-1.1.4.jar -i 12288 password 082EFFA9F93CE8BB:12288:C24AC4382DFF88284F1B8338C3CCD95E3221B900
OK

> echo %ERRORLEVEL%
0

> java -jar PBKDF2-1.1.4.jar -i 12289 password 082EFFA9F93CE8BB:12288:C24AC4382DFF88284F1B8338C3CCD95E3221B900
FAIL

> java -jar PBKDF2-1.1.4.jar -i 12288 password 082EFFA9F93CE8BB:12288:C24AC4382DFF88284F1B8338C3CCD95E3221B999
FAIL

> echo %ERRORLEVEL%
1
```

Dependency References
=====================

## Maven

```xml
<dependency>
    <groupId>de.rtner</groupId>
    <artifactId>PBKDF2</artifactId>
    <version>1.1.4</version>
</dependency>
```

## Gradle

`'de.rtner:PBKDF2:1.1.4'`


Digital Signature
=================

The version tag is signed with GnuPG keypair [0x6FFA6075617898B7](https://pgp.mit.edu/pks/lookup?search=0x6FFA6075617898B7)

```
pub  2048R/617898B7 2014-09-24 Matthias Gaertner (2014/09) <mgaert@web.de>
     Fingerprint=E510 7F88 F901 EEAF 622A  F1DE 6FFA 6075 6178 98B7
```
