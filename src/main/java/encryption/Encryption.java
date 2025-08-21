package encryption;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
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
import java.util.Random;

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
    private static final int KEY_LENGTH = 1024;
    private static final int MAX_LENGTH = KEY_LENGTH/10;

    public static String[] generate (){

        try {

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            // Create the public and private keys
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
            Base64.Encoder b64 = Base64.getEncoder();

            SecureRandom random = new SecureRandom(gatherConsoleEntropy(10));
            generator.initialize(KEY_LENGTH, random);

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
    public static String[] generateOld (){

        try {

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            // Create the public and private keys
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
            Base64.Encoder b64 = Base64.getEncoder();

            SecureRandom sr;
            try {
                sr = SecureRandom.getInstanceStrong();   // may block on some systems
            } catch (NoSuchAlgorithmException e) {
                sr = new SecureRandom();                 // safe fallback
            }    
            
            generator.initialize(KEY_LENGTH, sr);

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


    private static byte[] gatherConsoleEntropy(int presses) throws Exception {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        System.out.println("Press Enter " + presses + " times, irregularly:");

        long last = System.nanoTime();
        for (int i = 0; i < presses; i++) {
            br.readLine();
            long now = System.nanoTime();
            long delta = now - last;
            last = now;

            ByteBuffer bb = ByteBuffer.allocate(16);
            bb.putLong(now).putLong(delta);
            md.update(bb.array());
        }
        return md.digest();
    }

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

        String encryptedData = "";
        try {

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            Base64.Decoder b64d = Base64.getDecoder();
            String key = publicKeyString;
            AsymmetricKeyParameter publicKey = 
                    (AsymmetricKeyParameter) PublicKeyFactory.createKey(b64d.decode(key));
            AsymmetricBlockCipher e = new RSAEngine();
            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
            e.init(true, publicKey);

            Base64.Encoder b64e = Base64.getEncoder();
            int modulus = inputData.getBytes().length% MAX_LENGTH;
            int pages = inputData.getBytes().length/ MAX_LENGTH +(modulus > 0? 1:0);

            for (int i = 0; i < pages;i++){
                byte[] buffer = new byte[((pages == 1 || i == pages-1) && modulus != 0) ? modulus : MAX_LENGTH];
                for (int j = 0; j < MAX_LENGTH && ((i * MAX_LENGTH + j) < inputData.getBytes().length); j++){
                    buffer[j] = inputData.getBytes()[i * MAX_LENGTH + j];
                }
                byte[] messageBytes = buffer;
                byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);

                encryptedData += b64e.encodeToString(hexEncodedCipher)+(pages == 1 || i == pages-1? "":"\n");

            }
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }

        return encryptedData;
    }


    public static String decrypt (String privateKeyString, String encryptedData) {

        String outputData = "";
        try {

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            String key = privateKeyString;
            Base64.Decoder b64 = Base64.getDecoder();
            AsymmetricKeyParameter privateKey = 
                    (AsymmetricKeyParameter) PrivateKeyFactory.createKey(b64.decode(key));
            AsymmetricBlockCipher e = new RSAEngine();
            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
            e.init(false, privateKey);

            for(String buffer: encryptedData.split("\n")){
                byte[] messageBytes = b64.decode(buffer);
                byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);
                outputData += new String(hexEncodedCipher);
            }
 
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

	public static byte[] hexStringToByteArray(String hexString) {
		// Remove any leading "0x" or "0X" prefix if present
		hexString = hexString.replaceFirst("0x", "").replaceFirst("0X", "");

		// Ensure that the hexadecimal string length is even
		if (hexString.length() % 2 != 0) {
			hexString = "0" + hexString;
		}

		// Parse the hexadecimal string to a BigInteger
		BigInteger bigInteger = new BigInteger(hexString, 16);

		// Get the byte array from the BigInteger
		byte[] byteArray = bigInteger.toByteArray();

		// If the most significant byte is 0, remove it
		if (byteArray[0] == 0) {
			byte[] result = new byte[byteArray.length - 1];
			System.arraycopy(byteArray, 1, result, 0, result.length);
			return result;
		}

		return byteArray;
	}
	public static String decryptHex(String privateKeyString, String encryptedData) {
		String outputData = "";
		try {

			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

			String key = privateKeyString;
			Base64.Decoder b64 = Base64.getDecoder();
			AsymmetricKeyParameter privateKey = 
					(AsymmetricKeyParameter) PrivateKeyFactory.createKey(b64.decode(key));
			AsymmetricBlockCipher e = new RSAEngine();
			e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
			e.init(false, privateKey);

			for(String buffer: encryptedData.split("\n")){
				byte[] messageBytes = hexStringToByteArray(buffer);
				byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);
				outputData += new String(hexEncodedCipher);
			}

		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}

		return outputData;
	}
	public static String encryptHex(String publicKeyString, String inputData) {

		String encryptedData = "";
		try {

			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

			Base64.Decoder b64d = Base64.getDecoder();
			String key = publicKeyString;
			AsymmetricKeyParameter publicKey = 
					(AsymmetricKeyParameter) PublicKeyFactory.createKey(b64d.decode(key));
			AsymmetricBlockCipher e = new RSAEngine();
			e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
			e.init(true, publicKey);

			int modulus = inputData.getBytes().length% MAX_LENGTH;
			int pages = inputData.getBytes().length/ MAX_LENGTH +(modulus > 0? 1:0);

			for (int i = 0; i < pages;i++){
				byte[] buffer = new byte[((pages == 1 || i == pages-1) && modulus != 0) ? modulus : MAX_LENGTH];
				for (int j = 0; j < MAX_LENGTH && ((i * MAX_LENGTH + j) < inputData.getBytes().length); j++){
					buffer[j] = inputData.getBytes()[i * MAX_LENGTH + j];
				}
				byte[] messageBytes = buffer;
				byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);

				encryptedData += byteArrayToHexString(hexEncodedCipher)+(pages == 1 || i == pages-1? "":"\n");

			}
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}

		return encryptedData;	
	}
    public static void main(String [] args) {
        String [] result = Encryption.generate();
        System.out.println("Private="+result[Encryption.PRIVATE]);
        System.out.println("Public="+result[Encryption.PUBLIC]);
    }
}
