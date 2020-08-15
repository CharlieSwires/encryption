package encryption;

import java.io.IOException;

import org.junit.Assert;

class Test {

	@org.junit.jupiter.api.Test
	void test() throws IOException {

		Encryption generateRSAKeys = new Encryption();

		String[] result = generateRSAKeys.generate();
		String publicKeyFilename = result[Encryption.PUBLIC];
		String privateKeyFilename = result[Encryption.PRIVATE];

		Encryption rsaEncryption = new Encryption();

		String inputData = "Hello this is a test!! Charlie was ere!";
		String encryptedData = rsaEncryption.encrypt(publicKeyFilename, inputData);

		Encryption rsaDecryption = new Encryption();


		Assert.assertEquals(inputData,rsaDecryption.decrypt(privateKeyFilename, encryptedData));
	}

}
