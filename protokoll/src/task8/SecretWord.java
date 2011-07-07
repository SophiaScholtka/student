package task8;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;

import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;

public class SecretWord {

	private final BigInteger TWO = new BigInteger("2");

	private BigInteger secret; // Geheimnis
	private ArrayList<BigInteger> possiblePrefix; // Mögliche Präfixverwaltung
	private ArrayList<BigInteger> sendPrefix; // Gesendete Prefixe
	private BigInteger guessedSecret; // Geratenes Geheimnis
	private boolean isGuessed;

	private ArrayList<BigInteger> allNumbers; // alle in Frage kommenden Zahlen

	/**
	 * Konstruktor Erzeugt eine leere Liste gesendeter Elemente. Erzeugt eine
	 * leere Liste der möglichen Elemente. Das geratene Geheimnis ist 0. Keine
	 * Liste möglicher Zahlen
	 * 
	 * @param secret
	 *            Geheime Zahl
	 */
	public SecretWord(BigInteger secret) {
		this.secret = secret;
		this.sendPrefix = new ArrayList<BigInteger>();
		this.possiblePrefix = new ArrayList<BigInteger>();
		this.guessedSecret = BigInteger.ZERO;
		this.isGuessed = false;

		this.allNumbers = new ArrayList<BigInteger>();
	}

	/**
	 * Konstruktor Erzeugt eine leere Liste gesendeter Elemente. Erzeugt eine
	 * leere Liste der möglichen Elemente. Das geratene Geheimnis ist 0. Erzeugt
	 * eine Liste möglicher Zahlen
	 * 
	 * @param secret
	 *            Geheime Zahl
	 */
	public SecretWord(BigInteger secret, int m) {
		this.secret = secret;
		this.sendPrefix = new ArrayList<BigInteger>();
		this.possiblePrefix = new ArrayList<BigInteger>();
		this.guessedSecret = BigInteger.ZERO;

		BigInteger maxM = TWO.pow(m + 1);
		BigInteger c = BigInteger.ZERO;
		ArrayList<BigInteger> allNumbers = new ArrayList<BigInteger>();
		while(c.compareTo(maxM) < 0) {
			allNumbers.add(c);
			c = c.add(BigInteger.ONE);
		}
		System.out.println(c);
		this.allNumbers = allNumbers;
	}

	/**
	 * Das echte Geheimnis
	 * 
	 * @return
	 */
	public BigInteger getSecret() {
		return secret;
	}

	/**
	 * Das geratene Geheimnis
	 * 
	 * @return
	 */
	public BigInteger getGuessedSecret() {
		return guessedSecret;
	}

	/**
	 * Setzt das geratene Geheimnis
	 * 
	 * @param guessedSecret
	 */
	public void setGuessedSecret(BigInteger guessedSecret) {
		this.guessedSecret = guessedSecret;
		this.isGuessed = true;
	}
	
	public boolean hasGuessed() {
		return this.isGuessed;
	}
	
	public void resetGuessed() {
		this.isGuessed = false;
	}

	// Gesendete Prefixes
	/**
	 * Erzeugt eine neue, leere Liste für gesendete Präfixe
	 */
	public void resetSend() {
		sendPrefix = new ArrayList<BigInteger>();
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
	 * Prüft, ob prefix noch nicht gesendet worden ist ("frei ist")
	 * 
	 * @param prefix
	 *            zu prüfender Präfix
	 * @return true wenn frei, false wenn bereits gesendet
	 */
	public boolean isFreePrefix(BigInteger prefix) {
		return !sendPrefix.contains(prefix);
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
		this.possiblePrefix = SecretWord.generateBinary(k);
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

	/**
	 * Gibt die Anzahl der binären Worte zurück
	 * 
	 * @return Anzahl der binären Worte, die als Präfix möglich sind
	 */
	public int getBinarySize() {
		return this.possiblePrefix.size();
	}

	/**
	 * Prüft, ob die gegebene binäre Zahl ein Präfix des Geheimnisses ist
	 * 
	 * @param binary
	 *            der mögliche Präfix
	 * @return true wenn Präfix, false sonst
	 */
	public boolean isPrefix(BigInteger binary) {
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
	
	// AllNumbers, die in Frage kommen für Secret
	/**
	 * Anzahl der möglichen Geheimnisse
	 */
	public int getSecretsCount() {
		return allNumbers.size();
	}

	/**
	 * Aktualisiert die in Frage kommenden Zahlen, indem alle Zahlen entfernt
	 * werden, die ein Präfix in den gesendeten Werten haben. Ist nur noch ein
	 * Element vorhanden, so wird guessedSecret auf diesen Wert gesetzt.
	 * 
	 * @return Anzahl der verbleibenden Elemente
	 */
	public int refreshSecrets() {
		if (!allNumbers.isEmpty()) {
			ArrayList<BigInteger> stored = new ArrayList<BigInteger>();
			for (Iterator<BigInteger> it = allNumbers.iterator(); it.hasNext();) {
				BigInteger tPoss = (BigInteger) it.next();
				boolean store = true;
				for (Iterator<BigInteger> itSend = sendPrefix.iterator(); itSend
						.hasNext();) {
					BigInteger tSend = (BigInteger) itSend.next();
					int m = Math.max(tPoss.bitLength(),tSend.bitLength());
					int shift = m - tSend.bitLength();
					if(tSend.bitLength() == 0) {
						shift = shift - 1;
					}
					if (tSend.equals(tPoss.shiftRight(shift))) {
						// allNumbers.remove(tPoss);
						store = false;
						break;
					}
				}
				if (store) {
					stored.add(tPoss);
				}
			}
			this.allNumbers = stored;
		}

		// Prüfe, ob nur noch Präfixe des größten Wertes vorhanden sind
		boolean onlyPrefixes = false;
		if(allNumbers!=null && allNumbers.size()>1) {
			onlyPrefixes = true;
			int lastIndex = allNumbers.size()-1;
			if(lastIndex < 0) {
				lastIndex = 0;
			}
			BigInteger maxValue = allNumbers.get(lastIndex);
			for (Iterator<BigInteger> it = allNumbers.iterator(); it.hasNext();) {
				BigInteger t = (BigInteger) it.next();
				if (!SecretWord.isPrefix(maxValue, t)) {
					onlyPrefixes = false;
					break;
				}
			}
		}
		
		// Organisiere guessedSecret und Rückgabe
		if (allNumbers.isEmpty()) {
			// this.guessedSecret = null;
			return 0;
		} 
		else if (allNumbers.size() == 1) {
			this.isGuessed = true;
			this.guessedSecret = allNumbers.get(0);
			return allNumbers.size();
		} 
		else if (onlyPrefixes) {
			this.isGuessed = true;
			this.guessedSecret = allNumbers.get(allNumbers.size()-1);
			return allNumbers.size();
		}
		else {
			return allNumbers.size();
		}
	}

	/**
	 * Gibt einen Array der möglichen Zahlen zurück
	 * 
	 * @return
	 */
	public BigInteger[] getSecrets() {
		int i = 0;
		BigInteger[] ret = new BigInteger[allNumbers.size()];
		for (Iterator<BigInteger> iterator = allNumbers.iterator(); iterator
				.hasNext();) {
			ret[i] = (BigInteger) iterator.next();
		}
		return ret;
	}
	
	public String toString() {
		int radix = 2;
		int radixChar = 2;
		String s = "";
		
		s = "Das Geheimnis: ";
		s = s + secret.toString(radixChar);
		s = s + " (" + guessedSecret.toString(radixChar) + ")";
		s = s + " hasGuessed=" + isGuessed + "\n";
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
		s = s + "\n\t allNumbers (" + allNumbers.size() + "): \n\t";
		for (Iterator<BigInteger> it = allNumbers.iterator(); it.hasNext();) {
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
	public static SecretWord generateSecret(int k) {
		BigInteger ZERO = new BigInteger("0");
		BigInteger WORD_MAX = new BigInteger("zzzzzzzzzz",36);

		BigInteger biRand = BigIntegerUtil.randomBetween(ZERO, WORD_MAX);
		SecretWord secret = new SecretWord(biRand);
		secret.startBinary(k);
		secret.resetSend();

		return secret;
	}

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
