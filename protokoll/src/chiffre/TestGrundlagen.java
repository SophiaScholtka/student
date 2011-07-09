package chiffre;

import java.math.BigInteger;

public class TestGrundlagen {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		String path = "../protokoll/vertrag.txt";
		BigInteger[] bigs = Grundlagen.readFile(path, 3);
		for (int i = 0; i < bigs.length; i++) {
			System.out.print(enhance(bigs[i].toString(2),8));
			System.out.print("\t Länge=" + bigs[i].bitLength());
			System.out.println();
		}
	}

	private static String enhance(String s, int mod) {
		
		while(s.length() % mod != 0) {
			s = " " + s;
		}
		
		return s;
	}
}
