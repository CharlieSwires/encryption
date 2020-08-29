package encryption;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

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


    public String sha256(String input) {
        //setDigest
        byte[] result = new String(input).getBytes();
        System.out.println("result size: " + result.length);
        Base64.Encoder b64 = Base64.getEncoder();
        SHA256Digest digester = new SHA256Digest();
        byte[] retValue  = null;

        for (int i = 0; i < 10; i++) {
            digester = new SHA256Digest();
            retValue = new byte[digester.getDigestSize()];
            for (int j = 0; j < 10; j++) {
                digester.update(result, 0, result.length);
            }
            digester.doFinal(retValue, 0);
        }
        System.out.println("retValue size: " + retValue.length);
        return b64.encodeToString(retValue);
        //return new String(retValue, StandardCharsets.UTF_8);

    }
    public String sha1(String input) {
        //setDigest
        byte[] result = new String(input).getBytes();
        System.out.println("result size: " + result.length);
        Base64.Encoder b64 = Base64.getEncoder();
        SHA1Digest digester = new SHA1Digest();
        byte[] retValue  = null;
        digester = new SHA1Digest();
        retValue = new byte[digester.getDigestSize()];
        digester.update(result, 0, result.length);
        digester.doFinal(retValue, 0);
        System.out.println("retValue size: " + retValue.length);
        return b64.encodeToString(retValue);
        //return new String(retValue, StandardCharsets.UTF_8);

    }


    public String encrypt (String publicKeyFilename, String inputData){

        String encryptedData = null;
        try {

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            Base64.Decoder b64d = Base64.getDecoder();
            String key = publicKeyFilename;
            AsymmetricKeyParameter publicKey = 
                    (AsymmetricKeyParameter) PublicKeyFactory.createKey(b64d.decode(key));
            AsymmetricBlockCipher e = new RSAEngine();
            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
            e.init(true, publicKey);

            byte[] messageBytes = inputData.getBytes();
            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);
            Base64.Encoder b64e = Base64.getEncoder();

            //System.out.println(getHexString(hexEncodedCipher));
            encryptedData = b64e.encodeToString(hexEncodedCipher);

        }
        catch (Exception e) {
            System.out.println(e);
        }

        return encryptedData;
    }


    public String decrypt (String privateKeyFilename, String encryptedData) {

        String outputData = null;
        try {

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            String key = privateKeyFilename;
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
            //System.out.println(e);
        }

        return outputData;
    }



}
