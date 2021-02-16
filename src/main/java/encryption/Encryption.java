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

public class Encryption {

    public static final int PRIVATE = 1;
    public static final int PUBLIC = 0;


    public String[] generate (){

        try {

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            // Create the public and private keys
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
            Base64.Encoder b64 = Base64.getEncoder();

            SecureRandom random = createFixedRandom();
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

    public static SecureRandom createFixedRandom()
    {
        return new FixedRand();
    }

    private static class FixedRand extends SecureRandom {

        /**
         * 
         */
        private static final long serialVersionUID = 3601395921206427046L;
        MessageDigest sha;
        byte[] state;

        FixedRand() {
            try
            {
                this.sha = MessageDigest.getInstance("SHA-1");
                this.state = sha.digest();
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new RuntimeException("can't find SHA-1!");
            }
        }

        public void nextBytes(byte[] bytes){

            int    off = 0;

            sha.update(state);

            while (off < bytes.length)
            {                
                state = sha.digest();

                if (bytes.length - off > state.length)
                {
                    System.arraycopy(state, 0, bytes, off, state.length);
                }
                else
                {
                    System.arraycopy(state, 0, bytes, off, bytes.length - off);
                }

                off += state.length;

                sha.update(state);
            }
        }
    }


    public String sha256(byte[] salt, String input) {
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
    public String sha1(String input) {
        byte[] result = new String(input).getBytes();
        Base64.Encoder b64 = Base64.getEncoder();
        SHA1Digest digester = new SHA1Digest();
        byte[] retValue  = null;
        digester = new SHA1Digest();
        retValue = new byte[digester.getDigestSize()];
        digester.update(result, 0, result.length);
        digester.doFinal(retValue, 0);
        return b64.encodeToString(retValue);

    }


    public String encrypt (String publicKeyString, String inputData){

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


    public String decrypt (String privateKeyString, String encryptedData) {

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



}
