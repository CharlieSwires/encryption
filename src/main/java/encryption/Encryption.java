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
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
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
    
    private enum OutputMode {
        B64,
        HEX
    }

    private enum EntropyMode {
        CONSOLE,
        STRONG
    }

    public static String[] generate() {
        return generateInternal(EntropyMode.CONSOLE);
    }

    public static String[] generateOld() {
        return generateInternal(EntropyMode.STRONG);
    }

    private static String[] generateInternal(EntropyMode mode) {

        try {
            Security.addProvider(new BouncyCastleProvider());

            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
            SecureRandom random;

            switch (mode) {
                case CONSOLE:
                    random = new SecureRandom();
                    random.setSeed(gatherConsoleEntropy(10));
                    break;

                case STRONG:
                    try {
                        random = SecureRandom.getInstanceStrong();   // may block
                    } catch (NoSuchAlgorithmException e) {
                        random = new SecureRandom();                 // fallback
                    }
                    break;

                default:
                    throw new IllegalArgumentException("Unknown entropy mode");
            }

            generator.initialize(KEY_LENGTH, random);

            KeyPair pair = generator.generateKeyPair();

            Base64.Encoder b64 = Base64.getEncoder();
            String pubKey = b64.encodeToString(pair.getPublic().getEncoded());
            String privKey = b64.encodeToString(pair.getPrivate().getEncoded());

            return new String[]{ pubKey, privKey };

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
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


    public static String encrypt(String publicKeyString, String inputData) {
        return encryptInternal(publicKeyString, inputData, OutputMode.B64);
    }

    public static String decrypt(String privateKeyString, String encryptedData) {
        return decryptInternal(privateKeyString, encryptedData, OutputMode.B64);
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
	
	public static String encryptHex(String publicKeyString, String inputData) {
	    return encryptInternal(publicKeyString, inputData, OutputMode.HEX);
	}

	public static String decryptHex(String privateKeyString, String encryptedData) {
	    return decryptInternal(privateKeyString, encryptedData, OutputMode.HEX);
	}
	
	private static String encryptInternal(String publicKeyString, String inputData, OutputMode mode) {

	    try {
	        Security.addProvider(new BouncyCastleProvider());

	        Base64.Decoder b64d = Base64.getDecoder();

	        AsymmetricKeyParameter publicKey =
	                PublicKeyFactory.createKey(b64d.decode(publicKeyString));

	        AsymmetricBlockCipher cipher = new PKCS1Encoding(new RSAEngine());
	        cipher.init(true, publicKey);

	        byte[] data = inputData.getBytes();
	        int modulus = data.length % MAX_LENGTH;
	        int pages = data.length / MAX_LENGTH + (modulus > 0 ? 1 : 0);

	        StringBuilder out = new StringBuilder();

	        for (int i = 0; i < pages; i++) {
	            int chunkSize = ((pages == 1 || i == pages - 1) && modulus != 0)
	                    ? modulus
	                    : MAX_LENGTH;

	            byte[] buffer = new byte[chunkSize];
	            System.arraycopy(data, i * MAX_LENGTH, buffer, 0, chunkSize);

	            byte[] encrypted = cipher.processBlock(buffer, 0, buffer.length);

	            if (mode == OutputMode.B64) {
	                out.append(Base64.getEncoder().encodeToString(encrypted));
	            } else {
	                out.append(byteArrayToHexString(encrypted));
	            }

	            if (i < pages - 1) out.append("\n");
	        }

	        return out.toString();

	    } catch (Exception e) {
	        throw new RuntimeException(e);
	    }
	}
	private static String decryptInternal(String privateKeyString, String encryptedData, OutputMode mode) {

	    try {
	        Security.addProvider(new BouncyCastleProvider());

	        Base64.Decoder b64 = Base64.getDecoder();
	        AsymmetricKeyParameter privateKey =
	                PrivateKeyFactory.createKey(b64.decode(privateKeyString));

	        AsymmetricBlockCipher cipher = new PKCS1Encoding(new RSAEngine());
	        cipher.init(false, privateKey);

	        StringBuilder out = new StringBuilder();

	        for (String line : encryptedData.split("\n")) {

	            byte[] input;

	            if (mode == OutputMode.B64) {
	                input = b64.decode(line);
	            } else {
	                input = hexStringToByteArray(line);
	            }

	            byte[] decrypted = cipher.processBlock(input, 0, input.length);
	            out.append(new String(decrypted));
	        }

	        return out.toString();

	    } catch (Exception e) {
	        throw new RuntimeException(e);
	    }
	}


    public static void main(String [] args) {
        String [] result = Encryption.generate();
        System.out.println("Private="+result[Encryption.PRIVATE]);
        System.out.println("Public="+result[Encryption.PUBLIC]);
    }
}
