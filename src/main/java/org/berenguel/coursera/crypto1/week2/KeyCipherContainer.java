package org.berenguel.coursera.crypto1.week2;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class KeyCipherContainer {

	private static final int IV_BYTES = 16;

	private IvParameterSpec iv;
	private SecretKey key;
	private byte[] cipherText;
	private String mode;
	
	private byte[] plainText;

	public KeyCipherContainer(String mode, String keyString, String cipherAndIvString)
			throws DecoderException {

		this.mode = mode;
		
		// decode the key
		byte[] keyBytes = Hex.decodeHex(keyString.toCharArray());
		this.key = new SecretKeySpec(keyBytes, "AES");

		// decode iv
		byte[] ivBytes = Hex.decodeHex(cipherAndIvString.substring(0,
				IV_BYTES * 2).toCharArray());
		this.iv = new IvParameterSpec(ivBytes);

		// decode cipher
		this.cipherText = Hex.decodeHex(cipherAndIvString.substring(
				IV_BYTES * 2).toCharArray());
	}

	public void solveWithLibrary() throws InvalidKeyException,
			InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException {

		Cipher cipher = Cipher.getInstance("AES/" + mode + "/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key, iv);

		this.plainText = cipher.doFinal(cipherText);
	}

	public IvParameterSpec getIv() {
		return iv;
	}

	public SecretKey getKey() {
		return key;
	}

	public byte[] getCipherText() {
		return cipherText;
	}

	public byte[] getPlainText() {
		return plainText;
	}

	public static void main(String[] args) throws Exception {

		List<KeyCipherContainer> containers = new ArrayList<>();
		
		KeyCipherContainer container;
		
		container = new KeyCipherContainer("CBC", "140b41b22a29beb4061bda66b6747e14", "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81");
		containers.add(container);
		
		container = new KeyCipherContainer("CBC","140b41b22a29beb4061bda66b6747e14", "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253");
		containers.add(container);
		
		container = new KeyCipherContainer("CTR","36f18357be4dbd77f050515c73fcf9f2", "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329");
		containers.add(container);
		
		container = new KeyCipherContainer("CTR","36f18357be4dbd77f050515c73fcf9f2", "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451");
		containers.add(container);
		
		
		for (KeyCipherContainer c : containers) {
			c.solveWithLibrary();
			System.out.println(new String(c.getPlainText()));
		}
		

	}
}
