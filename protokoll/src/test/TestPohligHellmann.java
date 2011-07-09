package test;

import java.math.BigInteger;

import task9.PohligHellmann;

public class TestPohligHellmann {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		PohligHellmann polly1 = new PohligHellmann();
		BigInteger m = new BigInteger("hallo",36);
		System.out.println("Nachricht: " + m);
		
		polly1.makeKey();
		BigInteger[] key = polly1.getChipherKey();
		
		BigInteger c = PohligHellmann.encipher(m, key);
		System.out.println("cipher:   " + c);
		
		BigInteger d = polly1.decipher(c);
		System.out.println("decipher: " + d);
		System.out.println("m==d = " + m.equals(d));
	}

}
