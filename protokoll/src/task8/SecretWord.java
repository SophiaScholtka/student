package task8;

import java.math.BigInteger;

public abstract class SecretWord {

	private final BigInteger TWO = new BigInteger("2");

	private BigInteger secret;        // Echtes Geheimnis
	private BigInteger guessedSecret; // Geratenes Geheimnis
	

	/**
	 * Das echte Geheimnis
	 * 
	 * @return
	 */
	public abstract BigInteger getSecret();
	
	/**
	 * Das geratene Geheimnis
	 * @return
	 */
	public abstract BigInteger getGuessedSecret();

	/**
	 * Ist binary2 ein Präfix von binary1?
	 * @param binary1
	 * @param prefix
	 * @return
	 */
	public static boolean isPrefix(BigInteger binary1, BigInteger prefix) {
		boolean b = false;
	
		int m = Math.max(prefix.bitLength(),binary1.bitLength());
		int shift;
		if (prefix.bitLength() != 0) {
			shift = m - prefix.bitLength();
		} else {
			shift = m - 1;
		}
		if (shift <= 0) {
			shift = 0;
		}
		b = prefix.equals(binary1.shiftRight(shift));
	
		return b;
	}
	
}
