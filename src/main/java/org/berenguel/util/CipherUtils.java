package org.berenguel.util;

public class CipherUtils {

	public static void store(byte[] dst, byte[] src, int beginDstIndex,
			int beginSrcIndex, int maxBytes) {

		for (//
		int i = 0, iDst = beginDstIndex, iSrc = beginSrcIndex; //
		(maxBytes < 0 || i < maxBytes) && iDst < dst.length && iSrc < src.length; //
		i++, iDst++, iSrc++) {

			dst[iDst] = src[iSrc];
		}
	}

	public static void store(byte[] dst, byte[] src, int beginDstIndex,
			int beginSrcIndex) {
		store(dst, src, beginDstIndex, beginSrcIndex, -1);
	}

	public static byte[] xor(byte[] a, byte[] b) {
		byte[] c = new byte[a.length];

		for (int i = 0; i < c.length; i++) {
			c[i] = (byte) (a[i] ^ b[i]);
		}

		return c;
	}

	public static byte[] extractBlock(byte[] input, int index) {
		byte[] block = new byte[16];
		for (int i = 0; i < 16; i++) {
			block[i] = input[index * 16 + i];
		}
		return block;
	}

	public static byte[] removePad(byte[] input) {
		byte paddingCount = input[input.length - 1];

		// just check!
		for (int i = input.length - 1; i > input.length - paddingCount; i--) {
			if (input[i] != paddingCount) {
				throw new IllegalArgumentException("Input padding is not valid");
			}
		}

		// output
		byte[] inputWithouPadding = new byte[input.length - paddingCount];
		for (int i = 0; i < inputWithouPadding.length; i++) {
			inputWithouPadding[i] = input[i];
		}

		return inputWithouPadding;
	}

	public static void increment(byte[] input) {

		for (int i = input.length - 1; i >= 0; i--) {

			if ((input[i] & 0xff) == 255) {
				input[i] = 0;
			} else {
				input[i]++;
				break;
			}
		}
	}

}
