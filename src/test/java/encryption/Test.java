package encryption;

import java.security.SecureRandom;

import org.junit.Assert;

class Test {

    //encryption/decryption
    @org.junit.jupiter.api.Test
    void test() {

        String[] result = Encryption.generate();
        String publicKeyFilename = result[Encryption.PUBLIC];
        String privateKeyFilename = result[Encryption.PRIVATE];

        String inputData = "Hello this is a test!! Charlie was ere!";
        String encryptedData = Encryption.encrypt(publicKeyFilename, inputData);

        Assert.assertEquals(inputData,Encryption.decrypt(privateKeyFilename, encryptedData));
    }
    
    //Signing
    @org.junit.jupiter.api.Test
    void test2() {


        String[] result = Encryption.generate();
        String publicKeyFilename = result[Encryption.PRIVATE];
        String privateKeyFilename = result[Encryption.PUBLIC];

        String inputData = "Hello this is a test!! Charlie was ere!";
        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[32];
        sr.nextBytes(salt);
        String digest = Encryption.sha256(salt, inputData);
        System.out.println("digest: " + digest);
        
        String encryptedData = Encryption.encrypt(privateKeyFilename, digest);

        Assert.assertEquals(digest,Encryption.decrypt(publicKeyFilename, encryptedData));
        inputData = "Hello this is a test!! Charlie was ere! "; //extra space
        
        digest = Encryption.sha256(salt, inputData);
        System.out.println("digest: " + digest);
 
        inputData = "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! ";
        
        digest = Encryption.sha256(salt, inputData);
        System.out.println("digest: " + digest);

        
    }
    //Signing
    @org.junit.jupiter.api.Test
    void test3() {


        String[] result = Encryption.generate();
        String publicKeyFilename = result[Encryption.PRIVATE];
        String privateKeyFilename = result[Encryption.PUBLIC];

        String inputData = "Hello this is a test!! Charlie was ere!";
        String digest = Encryption.sha1(inputData);
        System.out.println("digest: " + digest);
        
        String encryptedData = Encryption.encrypt(privateKeyFilename, digest);

        Assert.assertEquals(digest,Encryption.decrypt(publicKeyFilename, encryptedData));
        inputData = "Hello this is a test!! Charlie was ere! "; //extra space
        
        digest = Encryption.sha1(inputData);
        System.out.println("digest: " + digest);
 
        inputData = "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! ";
        
        digest = Encryption.sha1(inputData);
        System.out.println("digest: " + digest);

        
    }

}
