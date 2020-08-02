package encryption;

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
        
        String digest = generateRSAKeys.MySha256(inputData);
        System.out.println("digest: " + digest);
        
        String encryptedData = generateRSAKeys.encrypt(privateKeyFilename, digest);

        Assert.assertEquals(digest,generateRSAKeys.decrypt(publicKeyFilename, encryptedData));
        Assert.assertEquals("G3WWx7K5DuTIadI4YHc7qx4LetTPfxvgoKOB0X09u44=", digest);
        inputData = "Hello this is a test!! Charlie was ere! "; //extra space
        
        digest = generateRSAKeys.MySha256(inputData);
        System.out.println("digest: " + digest);
        Assert.assertFalse("G3WWx7K5DuTIadI4YHc7qx4LetTPfxvgoKOB0X09u44=".equals(digest));
 
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
        
        digest = generateRSAKeys.MySha256(inputData);
        System.out.println("digest: " + digest);
        Assert.assertFalse("G3WWx7K5DuTIadI4YHc7qx4LetTPfxvgoKOB0X09u44=".equals(digest));

        
    }

}
