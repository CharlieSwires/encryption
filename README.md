# Encryption

A Java/Maven project by Charles Swires containing RSA encryption utilities,
AES stream encryption, a random passphrase generator, and a field-encryption
demonstration using Java's built-in cryptography APIs.

The repository contains both legacy examples and a newer hybrid-encryption
example. They use different formats and are not interchangeable.

## Components

| Class | Purpose |
| --- | --- |
| `encryption.Encryption` | RSA key generation, Base64/hex encryption, SHA-1 hashing and PBKDF2 derivation using Bouncy Castle |
| `encryption.AES_BC` | Legacy padded AES encryption/decryption of streams using Bouncy Castle |
| `encryption.RandomPassphraseGenerator` | Random word-based passphrases using an EFF-format word list and `SecureRandom` |
| `encryption.FieldCryptoDemo` | AES-256-GCM field encryption, RSA-3072 OAEP key wrapping, and passphrase-protected private keys |

## Requirements

- An **OpenJDK JDK 21 or later**.
- **Apache Maven 3.6.3 or later** for the configured Maven compiler plugin.
- Internet access for Maven's first dependency download.
- An EFF long word list to run the passphrase generator.
- Git to clone the repository; curl or a browser to download the word list.

Downloads: [OpenJDK](https://jdk.java.net/), [Maven](https://maven.apache.org/download.cgi),
[Git](https://git-scm.com/downloads).

Check your environment:

```bash
java -version
mvn -version
```

`mvn -version` should report the intended JDK. The compiler plugin explicitly
sets `release` to **21**, although the POM's source/target properties say **22**.
The release setting controls the current compilation target; aligning those
properties would make the configuration clearer.

## Get the project

```bash
git clone https://github.com/CharlieSwires/encryption.git
cd encryption
```

## Build and test

```bash
mvn clean verify
```

This compiles the source, runs the JUnit tests and builds:

```text
target/encryption-0.0.1-SNAPSHOT.jar
```

The JAR is a normal library JAR: it has no configured executable main-class
manifest and does not bundle Bouncy Castle. Use the commands below rather than
`java -jar`.

The configured dependencies are:

| Dependency | Version |
| --- | --- |
| Bouncy Castle `bcprov-debug-jdk15on` | 1.70 |
| JUnit Jupiter, test scope | 5.10.2 |

The existing tests cover legacy RSA round trips, derived/hash value differences,
key-pair differences and an AES stream round trip. They do not directly test
`FieldCryptoDemo` or `RandomPassphraseGenerator`.

## Run the field-encryption demonstration

From the repository root:

```bash
mvn compile org.codehaus.mojo:exec-maven-plugin:3.5.0:java -Dexec.mainClass=encryption.FieldCryptoDemo
```

The demo:

1. Generates a fresh RSA-3072 key pair.
2. Encrypts the private key using a key derived from a demonstration passphrase.
3. Unlocks that private key again.
4. Encrypts a sample text field using a fresh AES-256 data key.
5. Wraps the AES key with the RSA public key.
6. Unwraps the key and prints the decrypted field.

It prints the public key, encrypted private-key package, encrypted field package
and recovered plaintext. It does **not** connect to MongoDB or Atlas, persist
keys, or provide a complete database encryption service.

### Cryptographic parameters

| Operation | Implementation |
| --- | --- |
| RSA key pair | 3,072 bits, generated randomly |
| Field encryption | AES-256-GCM, fresh key per `encryptField` call |
| GCM IV and tag | 12-byte random IV; 128-bit authentication tag |
| Data-key wrapping | RSA-OAEP with SHA-256 and MGF1-SHA-256 |
| Private-key protection | AES-256-GCM |
| Passphrase derivation | PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random salt |
| Text encoding | UTF-8 |
| Binary value representation | Base64 |

The passphrase protects the private key; it does **not** deterministically
regenerate the RSA key pair. Retain the encrypted private-key package as well
as the passphrase if you need to decrypt stored fields later.

The `EncryptedPrivateKey` record contains `kdf`, `iterations`, `saltB64`, `ivB64`
and `ciphertextB64`. The `EncryptedField` record contains `alg`, `wrapAlg`,
`wrappedDataKeyB64`, `ivB64` and `ciphertextB64`. These are Java records, not JSON
serialization or database persistence code. The GCM tag is included in the
ciphertext returned by Java's cipher.

### Use the field API

```java
import encryption.FieldCryptoDemo;
import java.security.KeyPair;

KeyPair keys = FieldCryptoDemo.generateRsaKeyPair();

FieldCryptoDemo.EncryptedField encrypted =
        FieldCryptoDemo.encryptField(keys.getPublic(), "Example sensitive value");

String recovered =
        FieldCryptoDemo.decryptField(keys.getPrivate(), encrypted);
```

## Generate a random passphrase

The word list is not included in the repository. Download it into the project
root:

```bash
curl -fL -o eff_large_wordlist.txt https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
```

Alternatively, download the file through your browser. The included
`src/main/java/encryption/get-words.sh` downloads it into your current working
directory when run through Bash.

Then run:

```bash
mvn compile org.codehaus.mojo:exec-maven-plugin:3.5.0:java -Dexec.mainClass=encryption.RandomPassphraseGenerator -Dexec.args="eff_large_wordlist.txt"
```

The command prints a **16-word** passphrase. Always pass the word-list path:
without an argument, `main` uses the author's machine-specific Windows path.
For a path containing spaces, put it in double quotes inside `exec.args`;
using a simple relative filename avoids shell-quoting differences.

The loader expects lines such as `11111 abacus`, ignores empty/comment lines,
and requires at least 7,000 parsed entries. It does not verify that the supplied
list has exactly 7,776 distinct EFF words.

The API supports a configurable word count, with a minimum of eight:

```java
import encryption.RandomPassphraseGenerator;
import java.nio.file.Path;

RandomPassphraseGenerator generator =
        new RandomPassphraseGenerator(Path.of("eff_large_wordlist.txt"));

String passphrase = generator.generatePassphrase();     // 16 words
String shorter = generator.generatePassphrase(12);      // 12 words
```

Words are selected independently, so repeated words are possible. Supplying a
second command-line argument does not change the count: `main` always requests
16 words.

## Legacy RSA utilities

To run the key-generation example:

```bash
mvn compile org.codehaus.mojo:exec-maven-plugin:3.5.0:java -Dexec.mainClass=encryption.Encryption
```

It asks you to press Enter ten times at irregular intervals. Timing values
supplement a `SecureRandom` instance, then the program prints the generated
private and public keys. These are Base64-encoded key data, not filenames.
Keep any private-key output confidential.

For non-interactive use, `generateOld()` uses `SecureRandom.getInstanceStrong()`
with a fallback to `new SecureRandom()`.

```java
import encryption.Encryption;

String[] keys = Encryption.generateOld();
String encrypted = Encryption.encrypt(keys[Encryption.PUBLIC], "Hello Charlie");
String decrypted = Encryption.decrypt(keys[Encryption.PRIVATE], encrypted);

String hex = Encryption.encryptHex(keys[Encryption.PUBLIC], "Hello Charlie");
String fromHex = Encryption.decryptHex(keys[Encryption.PRIVATE], hex);
```

The legacy implementation uses **1,024-bit RSA with PKCS#1 v1.5 padding**.
It splits input into 102-byte chunks and separates encoded ciphertext blocks
with newlines. Preserve those line boundaries when storing or transferring it.
String/byte conversions use the JVM's default charset, so non-ASCII text can
behave differently across environments or at chunk boundaries.

Despite its name, `sha256(salt, input)` performs **PBKDF2-HMAC-SHA256** with
12,000 iterations and a 256-bit result, returned as Base64. It is not a plain
SHA-256 digest. The `sha1` overloads return a Base64-encoded SHA-1 digest.

The hex decoder uses `BigInteger`, which does not preserve leading zero bytes
as a general-purpose byte-array decoder would.

## Legacy AES streams

`AES_BC` accepts a supplied AES key and encrypts/decrypts streams:

```java
import encryption.AES_BC;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

byte[] key = new byte[32];
new SecureRandom().nextBytes(key);
AES_BC aes = new AES_BC(key);

ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
aes.encrypt(new ByteArrayInputStream("Hello".getBytes(StandardCharsets.UTF_8)),
            ciphertext);

ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
aes.decrypt(new ByteArrayInputStream(ciphertext.toByteArray()), plaintext);

String recovered = plaintext.toString(StandardCharsets.UTF_8);
```

The implementation uses the bare AES engine with padding: effectively **ECB
mode**, with no IV or authentication tag. The no-argument constructor contains
a fixed demonstration key. Its stream methods catch and print I/O errors
instead of propagating them; callers remain responsible for closing streams.

## Scope and limitations

This repository demonstrates several approaches rather than supplying a
production-ready cryptography framework. The legacy RSA/AES examples have
security limitations described above; the authenticated hybrid example is
`FieldCryptoDemo`.

The field demo contains a publicly visible, hard-coded demonstration passphrase.
Replace it with securely supplied input before adapting the demo for real data.
It also prints recovered plaintext. Algorithm labels in the package records
are descriptive: decryption uses fixed algorithms rather than dispatching or
validating those labels. Key storage, rotation, recovery, access controls and
application integration require additional implementation.

## Eclipse

Import using **File → Import → Maven → Existing Maven Projects**, select the
repository folder, and configure a JDK 21 or later. Run a class with `main` as a
Java Application. For `RandomPassphraseGenerator`, set its word-list path in
**Run Configurations → Arguments → Program arguments**.

## Project layout

```text
pom.xml
src/main/java/encryption/
    Encryption.java
    AES_BC.java
    FieldCryptoDemo.java
    RandomPassphraseGenerator.java
    get-words.sh
src/test/java/encryption/
    EncryptionTests.java
    AES_BC_Tests.java
```

## Copyright and licensing

`Encryption.java` carries a Charles Swires copyright notice stating
"All Rights Reserved". `AES_BC.java` includes an LGPL 2.1-or-later notice and
credits Catalin / itcsolutions.eu. No repository-wide LICENSE file was present
in the inspected revision. Preserve existing notices and establish the applicable
permissions before redistributing or incorporating the code elsewhere.

## Links

- [Repository](https://github.com/CharlieSwires/encryption)
- [OpenJDK downloads](https://jdk.java.net/)
- [Apache Maven](https://maven.apache.org/)
- [Bouncy Castle](https://www.bouncycastle.org/)
- [EFF long word list](https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt)
