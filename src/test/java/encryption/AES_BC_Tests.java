package encryption;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AES_BC_Tests {

    private AES_BC aes;
    @BeforeEach
    void setUp() throws Exception {
        aes = new AES_BC();
    }

    @Test
    void test() throws DataLengthException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, IllegalStateException, InvalidCipherTextException {
        String inputData = "Hello this is a test!! Charlie was ere! "
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
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! "
                + "Hello this is a test!! Charlie was ere! ";

        ByteArrayInputStream bais = new ByteArrayInputStream(inputData.getBytes());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        long start = System.nanoTime();
        aes.encrypt(bais, baos);
        long stop = System.nanoTime();
        Base64.Encoder b64e = Base64.getEncoder();
        String output = b64e.encodeToString(baos.toByteArray());
        System.out.println("Encoded("+((stop-start)/inputData.length())+"ns/char):"+output);
        Base64.Decoder b64d = Base64.getDecoder();
        bais = new ByteArrayInputStream(b64d.decode(output));
        baos = new ByteArrayOutputStream();
        start = System.nanoTime();
        aes.decrypt(bais, baos);
        stop = System.nanoTime();
        output = baos.toString();
        System.out.println("Decoded("+((stop-start)/output.length())+"ns/char):"+output);
        Assertions.assertEquals(inputData,output);
    }

}
