package encryption;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

public class Encryption {

    public static final int PRIVATE = 1;
    public static final int PUBLIC = 0;
    private SHA256Digest digest = null;


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


    public String MySha256(String input) {
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

    private void encrypt (String publicKeyFilename, String inputFilename, String encryptedFilename){

        try {

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            String key = readFileAsString(publicKeyFilename);
            Base64.Decoder b64 = Base64.getDecoder();
            AsymmetricKeyParameter publicKey = 
                    (AsymmetricKeyParameter) PublicKeyFactory.createKey(b64.decode(key));
            AsymmetricBlockCipher e = new RSAEngine();
            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
            e.init(true, publicKey);

            String inputdata = readFileAsString(inputFilename);
            byte[] messageBytes = inputdata.getBytes();
            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);

            //System.out.println(getHexString(hexEncodedCipher));
            BufferedWriter out = new BufferedWriter(new FileWriter(encryptedFilename));
            out.write(getHexString(hexEncodedCipher));
            out.close();

        }
        catch (Exception e) {
            //System.out.println(e);
        }
    }

    public String encrypt (String publicKeyFilename, String inputData){

        String encryptedData = null;
        try {

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            Base64.Decoder b64 = Base64.getDecoder();
            String key = publicKeyFilename;
            AsymmetricKeyParameter publicKey = 
                    (AsymmetricKeyParameter) PublicKeyFactory.createKey(b64.decode(key));
            AsymmetricBlockCipher e = new RSAEngine();
            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
            e.init(true, publicKey);

            byte[] messageBytes = inputData.getBytes();
            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);

            //System.out.println(getHexString(hexEncodedCipher));
            encryptedData = getHexString(hexEncodedCipher);

        }
        catch (Exception e) {
            System.out.println(e);
        }

        return encryptedData;
    }



    private void decrypt (String privateKeyFilename, String encryptedFilename, String outputFilename){

        try {

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            String key = readFileAsString(privateKeyFilename);
            Base64.Decoder b64 = Base64.getDecoder();
            AsymmetricKeyParameter privateKey = 
                    (AsymmetricKeyParameter) PrivateKeyFactory.createKey(b64.decode(key));
            AsymmetricBlockCipher e = new RSAEngine();
            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
            e.init(false, privateKey);

            String inputdata = readFileAsString(encryptedFilename);
            byte[] messageBytes = hexStringToByteArray(inputdata);
            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);

            //System.out.println(new String(hexEncodedCipher));
            BufferedWriter out = new BufferedWriter(new FileWriter(outputFilename));
            out.write(new String(hexEncodedCipher));
            out.close();

        }
        catch (Exception e) {
            //System.out.println(e);
        }
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

            byte[] messageBytes = hexStringToByteArray(encryptedData);
            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);

            //System.out.println(new String(hexEncodedCipher));
            outputData = new String(hexEncodedCipher);

        }
        catch (Exception e) {
            //System.out.println(e);
        }

        return outputData;
    }

    public static String getHexString(byte[] b) throws Exception {
        String result = "";
        for (int i=0; i < b.length; i++) {
            result +=
                    Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
        }
        return result;
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static String readFileAsString(String filePath)
            throws java.io.IOException{
        StringBuffer fileData = new StringBuffer(1000);
        BufferedReader reader = new BufferedReader(
                new FileReader(filePath));
        char[] buf = new char[1024];
        int numRead=0;
        while((numRead=reader.read(buf)) != -1){
            String readData = String.valueOf(buf, 0, numRead);
            fileData.append(readData);
            buf = new char[1024];
        }
        reader.close();
        //System.out.println(fileData.toString());
        return fileData.toString();
    }

    public SHA256Digest getDigest() {
        return digest;
    }

    public void setDigest(SHA256Digest digest) {
        this.digest = digest;
    }


}
