package encryption;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;

import static java.security.spec.MGF1ParameterSpec.SHA256;

public class FieldCryptoDemo {

    private static final SecureRandom RNG = new SecureRandom();

    private static final int RSA_BITS = 3072;
    private static final int AES_BITS = 256;
    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;

    // Tune this on your machine. 600k is a reasonable PBKDF2 starting point in 2026,
    // but Argon2id/scrypt would be better if you add a library.
    private static final int PBKDF2_ITERATIONS = 600_000;
    private static final int PBKDF2_KEY_BITS = 256;
    private static final int SALT_BYTES = 16;

    public record EncryptedPrivateKey(
            String kdf,
            int iterations,
            String saltB64,
            String ivB64,
            String ciphertextB64
    ) {}

    public record EncryptedField(
            String alg,
            String wrapAlg,
            String wrappedDataKeyB64,
            String ivB64,
            String ciphertextB64
    ) {}

    public static void main(String[] args) throws Exception {
        char[] ownerPassphrase = "impish synopses grandson banknote remote devotion purging able rockiness viable food predator broadly plunging colonist peculiar".toCharArray();

        KeyPair rsa = generateRsaKeyPair();

        String publicKeyB64 = b64(rsa.getPublic().getEncoded());
        EncryptedPrivateKey encryptedPrivateKey =
                encryptPrivateKeyWithPassphrase(rsa.getPrivate(), ownerPassphrase);

        System.out.println("Public key, safe to store:");
        System.out.println(publicKeyB64);

        System.out.println("\nEncrypted private key package, safe to store if passphrase is offline:");
        System.out.println(encryptedPrivateKey);

        PrivateKey unlockedPrivateKey =
                decryptPrivateKeyWithPassphrase(encryptedPrivateKey, ownerPassphrase);

        String sensitiveValue = "This is a sensitive Atlas field";
        EncryptedField encryptedField = encryptField(rsa.getPublic(), sensitiveValue);

        System.out.println("\nEncrypted field package for MongoDB:");
        System.out.println(encryptedField);

        String decrypted = decryptField(unlockedPrivateKey, encryptedField);
        System.out.println("\nDecrypted field:");
        System.out.println(decrypted);

        Arrays.fill(ownerPassphrase, '\0');
    }

    public static KeyPair generateRsaKeyPair() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(RSA_BITS, RNG);
        return kpg.generateKeyPair();
    }

    public static EncryptedPrivateKey encryptPrivateKeyWithPassphrase(
            PrivateKey privateKey,
            char[] passphrase
    ) throws GeneralSecurityException {

        byte[] salt = randomBytes(SALT_BYTES);
        byte[] iv = randomBytes(GCM_IV_BYTES);

        SecretKey aesKey = deriveAesKeyFromPassphrase(passphrase, salt, PBKDF2_ITERATIONS);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));

        byte[] privateKeyPkcs8 = privateKey.getEncoded();
        byte[] ciphertext = cipher.doFinal(privateKeyPkcs8);

        Arrays.fill(privateKeyPkcs8, (byte) 0);

        return new EncryptedPrivateKey(
                "PBKDF2WithHmacSHA256",
                PBKDF2_ITERATIONS,
                b64(salt),
                b64(iv),
                b64(ciphertext)
        );
    }

    public static PrivateKey decryptPrivateKeyWithPassphrase(
            EncryptedPrivateKey encrypted,
            char[] passphrase
    ) throws GeneralSecurityException {

        byte[] salt = fromB64(encrypted.saltB64());
        byte[] iv = fromB64(encrypted.ivB64());
        byte[] ciphertext = fromB64(encrypted.ciphertextB64());

        SecretKey aesKey = deriveAesKeyFromPassphrase(
                passphrase,
                salt,
                encrypted.iterations()
        );

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));

        byte[] privateKeyPkcs8 = cipher.doFinal(ciphertext);

        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyPkcs8));
        } finally {
            Arrays.fill(privateKeyPkcs8, (byte) 0);
        }
    }

    public static EncryptedField encryptField(
            PublicKey rsaPublicKey,
            String plaintext
    ) throws GeneralSecurityException {

        SecretKey dataKey = generateAes256Key();
        byte[] iv = randomBytes(GCM_IV_BYTES);

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, dataKey, new GCMParameterSpec(GCM_TAG_BITS, iv));

        byte[] ciphertext = aes.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        byte[] wrappedDataKey = wrapAesKeyWithRsaOaep(rsaPublicKey, dataKey);

        return new EncryptedField(
                "AES-256-GCM",
                "RSA-OAEP-SHA256",
                b64(wrappedDataKey),
                b64(iv),
                b64(ciphertext)
        );
    }

    public static String decryptField(
            PrivateKey rsaPrivateKey,
            EncryptedField encrypted
    ) throws GeneralSecurityException {

        byte[] wrappedDataKey = fromB64(encrypted.wrappedDataKeyB64());
        byte[] iv = fromB64(encrypted.ivB64());
        byte[] ciphertext = fromB64(encrypted.ciphertextB64());

        SecretKey dataKey = unwrapAesKeyWithRsaOaep(rsaPrivateKey, wrappedDataKey);

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, dataKey, new GCMParameterSpec(GCM_TAG_BITS, iv));

        byte[] plaintext = aes.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    private static SecretKey generateAes256Key() throws GeneralSecurityException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_BITS, RNG);
        return kg.generateKey();
    }

    private static SecretKey deriveAesKeyFromPassphrase(
            char[] passphrase,
            byte[] salt,
            int iterations
    ) throws GeneralSecurityException {

        PBEKeySpec spec = new PBEKeySpec(
                passphrase,
                salt,
                iterations,
                PBKDF2_KEY_BITS
        );

        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] keyBytes = skf.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            spec.clearPassword();
        }
    }

    private static byte[] wrapAesKeyWithRsaOaep(
            PublicKey publicKey,
            SecretKey aesKey
    ) throws GeneralSecurityException {

        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsa.init(
                Cipher.ENCRYPT_MODE,
                publicKey,
                new OAEPParameterSpec(
                        "SHA-256",
                        "MGF1",
                        SHA256,
                        PSource.PSpecified.DEFAULT
                )
        );

        return rsa.doFinal(aesKey.getEncoded());
    }

    private static SecretKey unwrapAesKeyWithRsaOaep(
            PrivateKey privateKey,
            byte[] wrappedKey
    ) throws GeneralSecurityException {

        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsa.init(
                Cipher.DECRYPT_MODE,
                privateKey,
                new OAEPParameterSpec(
                        "SHA-256",
                        "MGF1",
                        SHA256,
                        PSource.PSpecified.DEFAULT
                )
        );

        byte[] aesKeyBytes = rsa.doFinal(wrappedKey);
        return new SecretKeySpec(aesKeyBytes, "AES");
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RNG.nextBytes(bytes);
        return bytes;
    }

    private static String b64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static byte[] fromB64(String value) {
        return Base64.getDecoder().decode(value);
    }
}