package org.berenguel.coursera.crypto1.week3;

import static org.berenguel.util.CipherUtils.store;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class Sha256Block {

	private static final int HASH_SIZE = 32; // 256 bits = 32 bytes

	private List<byte[]> blocks = new ArrayList<>();

	private byte[] h0;

	public Sha256Block(int blockSize, String filePath) throws IOException {

		byte[] allBytes = Files.readAllBytes(Paths.get(filePath));

		for (int i = 0; i < allBytes.length; i += blockSize) {

			boolean last = i + blockSize > allBytes.length;
			byte[] block = new byte[last ? allBytes.length - i : blockSize
					+ HASH_SIZE];
			store(block, allBytes, 0, i, blockSize);
			blocks.add(block);
		}
	}

	public void calculateHashes() throws NoSuchAlgorithmException {

		MessageDigest md = MessageDigest.getInstance("SHA-256");

		for (int i = blocks.size() - 1; i >= 0; i--) {

			// compute the hash
			md.update(blocks.get(i));
			byte[] hash = md.digest();

			if (i - 1 >= 0) {
				byte[] previousBlock = blocks.get(i - 1);
				store(previousBlock, hash,
						previousBlock.length - HASH_SIZE, 0);
			} else {
				this.h0 = hash;
			}
		}
	}

	public byte[] getHash(int i) {

		if (i == 0) {
			return this.h0.clone();
		}

		if (i > blocks.size() - 2) {
			throw new IllegalArgumentException("Not valid index: " + i);
		}

		byte[] hash = new byte[HASH_SIZE];
		byte[] block = blocks.get(i);
		store(hash, block, 0, block.length - HASH_SIZE);

		return hash;
	}

}
