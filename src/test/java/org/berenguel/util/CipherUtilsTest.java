package org.berenguel.util;

import static org.junit.Assert.assertArrayEquals;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.berenguel.util.CipherUtils;
import org.junit.Test;

public class CipherUtilsTest {
	
	private String PLAIN_1 = "00112233445566778899AABBCCDD0202";
	private String PLAIN_2 = "00112233445566778899AABBCC030303";
	private String PLAIN_3 = "00112233445566778899AABBCCDDEEFF10101010101010101010101010101010";

	@Test
	public void testStore() {
		
		byte[] dst = new byte[] { 0, 1, 2, 3, 4, 5 };
		byte[] src = new byte[] { 7, 8, 9 };
		byte[] expect = new byte[] { 0, 1, 7, 8, 9, 5 };
		
		CipherUtils.store(dst, src, 2, 0);
		
		assertArrayEquals(expect, dst);
	}

	@Test
	public void testXor() {
		byte[] a = new byte[] { 0, 1, 2, 3, 4, 5 };
		byte[] b = new byte[] { 0, 0, 0, 0, 4, 1 };
		byte[] expect = new byte[] { 0, 1, 2, 3, 0, 4 };
		
		byte[] c = CipherUtils.xor(a, b);
		
		assertArrayEquals(expect, c);
	}
	
	@Test
	public void testExtractBlock() throws DecoderException {
		
		byte[] input = Hex.decodeHex(PLAIN_3.toCharArray());
		
		byte[] block1 = CipherUtils.extractBlock(input, 0);
		assertArrayEquals("00112233445566778899AABBCCDDEEFF".toLowerCase().toCharArray(), Hex.encodeHex(block1));
		
		byte[] block2 = CipherUtils.extractBlock(input, 1);
		assertArrayEquals("10101010101010101010101010101010".toLowerCase().toCharArray(), Hex.encodeHex(block2));
	}

	@Test
	public void testRemovePadding() throws DecoderException {
		
		byte[] plain1 = CipherUtils.removePad(Hex.decodeHex(PLAIN_1.toCharArray()));
		assertArrayEquals("00112233445566778899AABBCCDD".toLowerCase().toCharArray(), Hex.encodeHex(plain1));
		
		byte[] plain2 = CipherUtils.removePad(Hex.decodeHex(PLAIN_2.toCharArray()));
		assertArrayEquals("00112233445566778899AABBCC".toLowerCase().toCharArray(), Hex.encodeHex(plain2));
		
		byte[] plain3 = CipherUtils.removePad(Hex.decodeHex(PLAIN_3.toCharArray()));
		assertArrayEquals("00112233445566778899AABBCCDDEEFF".toLowerCase().toCharArray(), Hex.encodeHex(plain3));
	}
	
	@Test
	public void testIncrement() throws DecoderException {
		byte[] input, expect;
		
		input = Hex.decodeHex("000102030405".toCharArray());
		expect = Hex.decodeHex("000102030406".toCharArray());
		CipherUtils.increment(input);
		assertArrayEquals(expect, input);
		
		input = Hex.decodeHex("0001020304FA".toCharArray());
		expect = Hex.decodeHex("0001020304FB".toCharArray());
		CipherUtils.increment(input);
		assertArrayEquals(expect, input);
		
		input = Hex.decodeHex( "000102BFFFFF".toCharArray());
		expect = Hex.decodeHex("000102C00000".toCharArray());
		CipherUtils.increment(input);
		assertArrayEquals(expect, input);
		
	}
	
}
