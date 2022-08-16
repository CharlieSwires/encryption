package encryption;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
/**
 * Copyright 2021 Charles Swires All Rights Reserved
 * @author charl
 *
 */
public class Encryption {

    public static final int PRIVATE = 1;
    public static final int PUBLIC = 0;


    public static String[] generate (){

        try {

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            // Create the public and private keys
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
            Base64.Encoder b64 = Base64.getEncoder();

            SecureRandom random = new SecureRandom();
            generator.initialize(1024, random);

            KeyPair pair = generator.generateKeyPair();
            Key pubKey = pair.getPublic();
            Key privKey = pair.getPrivate();

            String[] result = new String[2];
            result[PUBLIC] = b64.encodeToString(pubKey.getEncoded());
            result[PRIVATE] = b64.encodeToString(privKey.getEncoded());
            return result;
        }
        catch (Exception e) {
            System.out.println(e);
        }
        return null;

    }



    /**
     * SecureRandom random = new SecureRandom();
     * byte salt[] = new salt[20];
     * random.nextBytes(salt);
     * @param salt
     * @param input
     * @return
     */
    public static String sha256(byte[] salt, String input) {
        Security.addProvider(new BouncyCastleProvider());

        Base64.Encoder b64 = Base64.getEncoder();
        SecretKeyFactory factoryBC = null;
        try {
            factoryBC = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "BC");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
        KeySpec keyspecBC = new PBEKeySpec(input.toCharArray(), salt, 12000, 256);
        SecretKey keyBC = null;
        try {
            keyBC = factoryBC.generateSecret(keyspecBC);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

        return b64.encodeToString(keyBC.getEncoded());

    }
    public static String sha1(byte[] bs) {
        byte[] result = bs;
        Base64.Encoder b64 = Base64.getEncoder();
        SHA1Digest digester = new SHA1Digest();
        byte[] retValue  = null;
        digester = new SHA1Digest();
        retValue = new byte[digester.getDigestSize()];
        digester.update(result, 0, result.length);
        digester.doFinal(retValue, 0);
        return b64.encodeToString(retValue);

    }
    public static String sha1(String bs) {
        return sha1(bs.getBytes());
    }


    public static String encrypt (String publicKeyString, String inputData){

        String encryptedData = null;
        try {

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            Base64.Decoder b64d = Base64.getDecoder();
            String key = publicKeyString;
            AsymmetricKeyParameter publicKey = 
                    (AsymmetricKeyParameter) PublicKeyFactory.createKey(b64d.decode(key));
            AsymmetricBlockCipher e = new RSAEngine();
            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
            e.init(true, publicKey);

            byte[] messageBytes = inputData.getBytes();
            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);
            Base64.Encoder b64e = Base64.getEncoder();

            encryptedData = b64e.encodeToString(hexEncodedCipher);

        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }

        return encryptedData;
    }


    public static String decrypt (String privateKeyString, String encryptedData) {

        String outputData = null;
        try {

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            String key = privateKeyString;
            Base64.Decoder b64 = Base64.getDecoder();
            AsymmetricKeyParameter privateKey = 
                    (AsymmetricKeyParameter) PrivateKeyFactory.createKey(b64.decode(key));
            AsymmetricBlockCipher e = new RSAEngine();
            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
            e.init(false, privateKey);

            byte[] messageBytes = b64.decode(encryptedData);
            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);

            //System.out.println(new String(hexEncodedCipher));
            outputData = new String(hexEncodedCipher);

        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }

        return outputData;
    }

    public static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }


    public static void main(String [] args) {
        String [] result = Encryption.generate();
        System.out.println("Private="+result[Encryption.PRIVATE]);
        System.out.println("Public="+result[Encryption.PUBLIC]);
    }
}
