package task8;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;

import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;

public class SecretWordSend extends SecretWord {

	private final BigInteger TWO = new BigInteger("2");

	private BigInteger secret; // Geheimnis
	private ArrayList<BigInteger> possiblePrefix; // Mögliche Präfixverwaltung
	private ArrayList<BigInteger> sendPrefix; // Gesendete falsche Präfixe
	private ArrayList<BigInteger> sendedNumbers; // Gesammelte falsche Präfixe
	
	
	/**
	 * Konstruktor Erzeugt eine leere Liste gesendeter Elemente. Erzeugt eine
	 * leere Liste der möglichen Elemente. Das geratene Geheimnis ist 0. Keine
	 * Liste möglicher Zahlen
	 * 
	 * @param secret
	 *            Geheime Zahl
	 */
	public SecretWordSend(BigInteger secret) {
		this.secret = secret;
		this.sendPrefix = new ArrayList<BigInteger>();
		this.possiblePrefix = new ArrayList<BigInteger>();
		this.sendedNumbers = new ArrayList<BigInteger>();
	}

	/**
	 * Das echte Geheimnis
	 * 
	 * @return
	 */
	public BigInteger getSecret() {
		return secret;
	}
	
	public BigInteger getGuessedSecret() {
		return BigInteger.ZERO;
	}

	// Gesendete Prefixes
	/**
	 * Erzeugt eine neue, leere Liste für gesendete Präfixe
	 * Kein Backup der gesendeten falschen Präfixe!
	 */
	public void resetSend() {
		sendPrefix = new ArrayList<BigInteger>();
	}

	/**
	 * Erzeugt eine neue, leere Liste für gesendete Präfixe
	 * Backup der gesendeten Präfixe
	 */
	public void resetSendAndSafe() {
		secureSend();
		resetSend();
	}
	
	public ArrayList<BigInteger> getSafedSend() {
		ArrayList<BigInteger> list = new ArrayList<BigInteger>();
		
		for (Iterator<BigInteger> it = sendedNumbers.iterator(); it.hasNext();) {
			BigInteger big = (BigInteger) it.next();
			list.add(big);
		}
		return list;
	}
	/**
	 * Füge gesendeten Prefix der Liste hinzu
	 * 
	 * @param prefix
	 */
	public void addSend(BigInteger prefix) {
		sendPrefix.add(prefix);
	}

	/**
	 * Prüft, ob Präfix gesendet worden ist
	 * 
	 * @param prefix
	 *            zu prüfender Präfix
	 * @return true wenn gesendet, false sonst
	 */
	public boolean isSend(BigInteger prefix) {
		return sendPrefix.contains(prefix);
	}

	/**
	 * Größe der Liste der gesendeten Elemente
	 * 
	 * @return Listengröße
	 */
	public int getSendSize() {
		return sendPrefix.size();
	}

	// Liste der binären Worte
	/**
	 * Erzeuge die erste binäre Zahlenliste Länge der Liste: 2^(k+1)-1
	 * 
	 * @param k
	 *            Anzahl der Bits
	 */
	public void startBinary(int k) {
		this.possiblePrefix = SecretWordSend.generateBinary(k);
	}

	/**
	 * Gibt die Anzahl der binären Worte zurück
	 * 
	 * @return Anzahl der binären Worte, die als Präfix möglich sind
	 */
	public int getBinarySize() {
		return this.possiblePrefix.size();
	}

	/**
	 * Wählt ein y aus der möglichen Liste aus y kein Präfix des Geheimnisses,
	 * noch nicht genutzt
	 * 
	 * @return y
	 */
	public BigInteger useBinary() {
		BigInteger prefix;
		boolean whileB = true;
		//System.out.println("uB: " + possiblePrefix.size());
		do {
			BigInteger size = new BigInteger("" + possiblePrefix.size());
			BigInteger r = BigIntegerUtil.randomSmallerThan(size);
			prefix = possiblePrefix.get(r.intValue());
			whileB = !isFreePrefix(prefix) || isPrefix(prefix);
		} while (whileB);

		possiblePrefix.remove(prefix);
		
		return prefix;
	}

	/**
	 * Erweitert die Elemente der binären Wortliste jeweils um 0 und 1 an den
	 * Wortenden
	 * 
	 * @param amount
	 */
	public void enhanceBinary(int amount) {
		ArrayList<BigInteger> newList = new ArrayList<BigInteger>();

		BigInteger shifted;
		for (int i = 0; i < amount; i++) {
			for (BigInteger bi : this.possiblePrefix) {
				shifted = bi.shiftLeft(1);
				newList.add(shifted);
				newList.add(shifted.flipBit(0));
			}
		}

		this.possiblePrefix = newList;
	}

	public String toString() {
		int radix = 2;
		int radixChar = 2;
		String s = "";
		
		s = "Das Geheimnis: ";
		s = s + secret.toString(radixChar);
		s = s + "\n";
		s = s + "\t Mögliche Prefix (" + possiblePrefix.size() + "): \n\t";
		for (Iterator<BigInteger> it = possiblePrefix.iterator(); it.hasNext();) {
			BigInteger t = (BigInteger) it.next();
			s = s + t.toString(radix) + "  ";
		}
		s = s + "\n\t Gesendet Prefix (" + sendPrefix.size() + "): \n\t";
		for (Iterator<BigInteger> it = sendPrefix.iterator(); it.hasNext();) {
			BigInteger t = (BigInteger) it.next();
			s = s + t.toString(radix) + "  ";
		}
		
		return s;
	}

	// Static Methods
	/**
	 * Erzeugt eine Liste mit binären Wörtern der Länge k. Zahlenwerte reichen
	 * von 0 bis 2^(k+1)-1. Anzahl der Elemente: 2^(k+1)
	 * 
	 * @param k
	 *            Anzahl der Bits
	 */
	public static ArrayList<BigInteger> generateBinary(int k) {
		// TO = 2^(k+1)
		BigInteger TO = new BigInteger("2");
		TO = TO.pow(k + 1);

		// Erzeuge Zahlen 0..2^(k+1)-1
		ArrayList<BigInteger> binWords = new ArrayList<BigInteger>();
		for (int i = 0; i < TO.intValue(); i++) {
			binWords.add(new BigInteger("" + i));
		}

		return binWords;
	}

	// Geheimnisaustausch mit Berechnungsvorteil
	/**
	 * Generiert zufälliges geheimes Wort
	 * 
	 * @param k
	 *            Startwert für k (k-1 gibt an, wie viele Bits genutzt werden)
	 * @return Gibt die Geheimnispaare zurück
	 */
	public static SecretWordSend generateSecret(int startBits) {
		BigInteger ZERO = new BigInteger("0");
		BigInteger WORD_MAX = new BigInteger("zzzzzzzzzz",36);

		BigInteger biRand = BigIntegerUtil.randomBetween(ZERO, WORD_MAX);
		SecretWordSend secret = new SecretWordSend(biRand);
		secret.startBinary(startBits);
		secret.resetSend();

		return secret;
	}

	/**
	 * Prüft, ob prefix noch nicht gesendet worden ist ("frei ist")
	 * 
	 * @param prefix
	 *            zu prüfender Präfix
	 * @return true wenn frei, false wenn bereits gesendet
	 */
	private boolean isFreePrefix(BigInteger prefix) {
		return !sendPrefix.contains(prefix);
	}

	/**
	 * Prüft, ob die gegebene binäre Zahl ein Präfix des Geheimnisses ist
	 * 
	 * @param binary
	 *            der mögliche Präfix
	 * @return true wenn Präfix, false sonst
	 */
	private boolean isPrefix(BigInteger binary) {
		boolean b = false;
	
		int size = binary.bitLength();
		int m = Math.max(binary.bitLength(),secret.bitLength());
		int shift;
		if (binary.bitLength() != 0) {
			shift = m - binary.bitLength();
		} else {
			shift = m - 1;
		}
		if (shift <= 0) {
			shift = 0;
		}
		b = binary.equals(secret.shiftRight(shift));
	
		return b;
	}

	private void secureSend() {
		if (sendPrefix.size()>0) {
			for (Iterator<BigInteger> it = sendPrefix.iterator(); it.hasNext();) {
				BigInteger element = (BigInteger) it.next();
				sendedNumbers.add(element);
			}
		}
		else {
			// nothing
		}
	}
}
