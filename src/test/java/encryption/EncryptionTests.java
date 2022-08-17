package encryption;

import java.security.SecureRandom;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EncryptionTests {
    @BeforeEach
    void setUp() throws Exception {
    }

    //encryption/decryption
    @Test
    void test() {

        String[] result = Encryption.generate();
        String publicKeyFilename = result[Encryption.PUBLIC];
        String privateKeyFilename = result[Encryption.PRIVATE];

        String inputData = "Hello this is a test!! Charlie was ere!";
        String encryptedData = Encryption.encrypt(publicKeyFilename, inputData);

        Assertions.assertEquals(inputData,Encryption.decrypt(privateKeyFilename, encryptedData));
    }
    
    //Signing
    @Test
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

        Assertions.assertEquals(digest,Encryption.decrypt(publicKeyFilename, encryptedData));
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
    @Test
    void test3() {


        String[] result = Encryption.generate();
        String publicKeyFilename = result[Encryption.PRIVATE];
        String privateKeyFilename = result[Encryption.PUBLIC];

        String inputData = "Hello this is a test!! Charlie was ere!";
        String digest = Encryption.sha1(inputData);
        System.out.println("digest: " + digest);
        
        String encryptedData = Encryption.encrypt(privateKeyFilename, digest);

        Assertions.assertEquals(digest,Encryption.decrypt(publicKeyFilename, encryptedData));
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
    @Test
    void test4() {
        String[] result = Encryption.generate();
        String publicKeyFilename = result[Encryption.PRIVATE];
        String privateKeyFilename = result[Encryption.PUBLIC];
        String[] result2 = Encryption.generate();
        String publicKeyFilename2 = result2[Encryption.PRIVATE];
        String privateKeyFilename2 = result2[Encryption.PUBLIC];
        Assertions.assertNotEquals(publicKeyFilename,publicKeyFilename2);
        Assertions.assertNotEquals(privateKeyFilename,privateKeyFilename2);
    }

}
