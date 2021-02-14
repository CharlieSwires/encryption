package encryption;

import java.security.SecureRandom;

import org.junit.Assert;

class Test {

    //encryption/decryption
    @org.junit.jupiter.api.Test
    void test() {

        Encryption generateRSAKeys = new Encryption();

        String[] result = generateRSAKeys.generate();
        String publicKeyFilename = result[Encryption.PUBLIC];
        String privateKeyFilename = result[Encryption.PRIVATE];

        String inputData = "Hello this is a test!! Charlie was ere!";
        String encryptedData = generateRSAKeys.encrypt(publicKeyFilename, inputData);

        Assert.assertEquals(inputData,generateRSAKeys.decrypt(privateKeyFilename, encryptedData));
    }
    
    //Signing
    @org.junit.jupiter.api.Test
    void test2() {

        Encryption generateRSAKeys = new Encryption();

        String[] result = generateRSAKeys.generate();
        String publicKeyFilename = result[Encryption.PRIVATE];
        String privateKeyFilename = result[Encryption.PUBLIC];

        String inputData = "Hello this is a test!! Charlie was ere!";
        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[32];
        sr.nextBytes(salt);
        String digest = generateRSAKeys.sha256(salt, inputData);
        System.out.println("digest: " + digest);
        
        String encryptedData = generateRSAKeys.encrypt(privateKeyFilename, digest);

        Assert.assertEquals(digest,generateRSAKeys.decrypt(publicKeyFilename, encryptedData));
        inputData = "Hello this is a test!! Charlie was ere! "; //extra space
        
        digest = generateRSAKeys.sha256(salt, inputData);
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
        
        digest = generateRSAKeys.sha256(salt, inputData);
        System.out.println("digest: " + digest);

        
    }
    //Signing
    @org.junit.jupiter.api.Test
    void test3() {

        Encryption generateRSAKeys = new Encryption();

        String[] result = generateRSAKeys.generate();
        String publicKeyFilename = result[Encryption.PRIVATE];
        String privateKeyFilename = result[Encryption.PUBLIC];

        String inputData = "Hello this is a test!! Charlie was ere!";
        String digest = generateRSAKeys.sha1(inputData);
        System.out.println("digest: " + digest);
        
        String encryptedData = generateRSAKeys.encrypt(privateKeyFilename, digest);

        Assert.assertEquals(digest,generateRSAKeys.decrypt(publicKeyFilename, encryptedData));
        inputData = "Hello this is a test!! Charlie was ere! "; //extra space
        
        digest = generateRSAKeys.sha1(inputData);
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
        
        digest = generateRSAKeys.sha1(inputData);
        System.out.println("digest: " + digest);

        
    }

}
