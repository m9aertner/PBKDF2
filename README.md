PBKDF2
======

A free Java implementation of RFC 2898 / PKCS#5 PBKDF2

[http://rtner.de/software/PBKDF2.html](http://rtner.de/software/PBKDF2.html)

Recent History
==============

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
    <version>1.0.6</version>
</dependency>
```

## Gradle

`'de.rtner:PBKDF2:1.0.6'`
