package org.berenguel.coursera.crypto1.week3;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

public class Sha256BlockTest {

	@Test
	public void testExample() throws IOException, NoSuchAlgorithmException {

		// calculate the hashes and obtain the suggested h0
		Sha256Block sha256Block = new Sha256Block(1024, getClass().getResource("/lecture-6-2.mp4").getPath());
		sha256Block.calculateHashes();
		String actualH0 = Hex.encodeHexString(sha256Block.getHash(0));
		
		// the given h0
		String expectedH0 = "03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8";
		
		// verify!
		assertEquals(expectedH0, actualH0);
	}
	
	@Test
	public void testProblem() throws IOException, NoSuchAlgorithmException {

		// calculate the hashes and obtain the suggested h0
		Sha256Block sha256Block = new Sha256Block(1024, getClass().getResource("/lecture-6-1.mp4").getPath());
		sha256Block.calculateHashes();
		String actualH0 = Hex.encodeHexString(sha256Block.getHash(0));
		
		// the given h0
		String expectedH0 = "5b96aece304a1422224f9a41b228416028f9ba26b0d1058f400200f06a589949";
		
		// verify!
		assertEquals(expectedH0, actualH0);
	}

}
