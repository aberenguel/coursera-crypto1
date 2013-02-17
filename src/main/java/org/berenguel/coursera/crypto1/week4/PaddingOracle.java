package org.berenguel.coursera.crypto1.week4;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;

public class PaddingOracle {

	private static final int BLOCK_SIZE = 16;
	private static final int BLOCK_SIZE_HEX = BLOCK_SIZE * 2;

	private static void padBlock(byte[] block, char[] guesses, int position) {
		int pad = block.length - position;

		for (int i = position; i < block.length; i++) {
			byte b = (byte) (block[i] ^ guesses[i] ^ pad);
			block[i] = b;
		}
	}

	private static byte[] joinBlocks(List<byte[]> blocks, int blockInList,
			byte[]... lastBlocks) {

		int size = 0;

		List<byte[]> list = new ArrayList<>();
		list.addAll(blocks.subList(0, blockInList));
		for (byte[] block : lastBlocks) {
			list.add(block);
		}

		// discover the size
		for (byte[] block : list) {
			size += block.length;
		}

		byte[] joined = new byte[size];
		int index = 0;

		for (byte[] block : list) {
			for (int j = 0; j < block.length; j++) {
				joined[index++] = block[j];
			}
		}
		return joined;
	}

	/**
	 * @param args
	 * @throws IOException
	 * @throws ClientProtocolException
	 * @throws DecoderException
	 * @throws URISyntaxException
	 */
	public static void main(String[] args) throws ClientProtocolException,
			IOException, DecoderException, URISyntaxException {

		HttpClient client = new DefaultHttpClient();
		String cipherHex = "f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4";

		URIBuilder builder = new URIBuilder(
				"http://crypto-class.appspot.com/po");

		String message = "";

		// decode hex blocks
		List<byte[]> blocks = new ArrayList<>();
		for (int i = 0; i < cipherHex.length(); i += BLOCK_SIZE_HEX) {
			String blockHex = cipherHex.substring(i, i + BLOCK_SIZE_HEX);
			blocks.add(Hex.decodeHex(blockHex.toCharArray()));
		}

		// for all blocks, in reverse
		for (int i = blocks.size() - 2; i >= 0; i--) {

			byte[] lastBlock = blocks.remove(blocks.size() - 1);
			byte[] block = blocks.get(i);
			char[] guesses = new char[block.length];

			// test all cipher bytes
			for (int j = block.length - 1; j >= 0; j--) {

				int pad = block.length - j;
				byte[] testBlock = block.clone();
				
				// pad the (j+1..n)'th bytes
				for (int k = j+1; k < testBlock.length; k++) {
					byte b = (byte) (testBlock[k] ^ guesses[k] ^ pad);
					testBlock[k] = b;
				}

				// guess all chars
				boolean found = false;
				for (char guess = 0; guess <= 255; guess++) {

					if (guess == pad) {
						continue;
					}
					
					// pad the j'th byte
					testBlock[j] = (byte) (block[j] ^ guess ^ pad);

					byte[] joined = joinBlocks(blocks, i, testBlock, lastBlock);
					String testHex = Hex.encodeHexString(joined);
					
					builder.setParameter("er", testHex);
					HttpGet get = new HttpGet(builder.build());
					HttpResponse response = client.execute(get);
					EntityUtils.consumeQuietly(response.getEntity());
					System.out
							.println(String
									.format("Testing... block=%d position=%d guess=%d => %s [%s]",
											i, j, (int) guess, testHex,
											response.getStatusLine()));

					if (response.getStatusLine().getStatusCode() == 404) {
						guesses[j] = guess;
						found = true;
						break;
					}
				}

				// did not found, so the guess is the pad
				if (!found) {
					guesses[j] = (char) pad;
				}
			}

			message = new String(guesses) + message;
		}
		System.out.println(message);
		client.getConnectionManager().shutdown();

	}

}
