PBKDF2
======

A free Java implementation of RFC 2898 / PKCS#5 PBKDF2

[http://rtner.de/software/PBKDF2.html](http://rtner.de/software/PBKDF2.html)

Recent History
==============

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

Dependency References
=====================

## Maven

```xml
<dependency>
    <groupId>de.rtner</groupId>
    <artifactId>PBKDF2</artifactId>
    <version>1.1.0</version>
</dependency>
```

## Gradle

`'de.rtner:PBKDF2:1.1.0'`
