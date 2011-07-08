package task8;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;

public class SecretWordGuess extends SecretWord {

	private final BigInteger TWO = new BigInteger("2");

	private ArrayList<BigInteger> receivedPrefix; // Gesendete Prefixe
	private BigInteger secret; // Geheimnis
	private BigInteger guessedSecret; // Geratenes Geheimnis
	private boolean isGuessed;
	
	private BigIntegerList[] received;
	
	private BigInteger maxSecret;

	private ArrayList<BigInteger> allNumbers; // alle in Frage kommenden Zahlen


	/**
	 * Konstruktor Erzeugt eine leere Liste gesendeter Elemente. Erzeugt eine
	 * leere Liste der möglichen Elemente. Das geratene Geheimnis ist 0. Erzeugt
	 * eine Liste möglicher Zahlen
	 * 
	 * @param secret
	 *            Geheime Zahl
	 * @param m 
	 *            Anzahl der maximalen Bits
	 */
	public SecretWordGuess(BigInteger secret, int m) {
		this.secret = secret;
		this.receivedPrefix = new ArrayList<BigInteger>();
		this.guessedSecret = BigInteger.ZERO;
		
		received = new BigIntegerList[m];
		for (int i = 0; i < m; i++) {
			received[i] = new BigIntegerList();
		}

		BigInteger maxSecret = TWO.pow(m).subtract(BigInteger.ONE);
		this.maxSecret = maxSecret;
		
		this.allNumbers = new ArrayList<BigInteger>();
	}

	/**
	 * Das echte Geheimnis
	 * Dient nur zur Deko :>
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
	 * Setzt das geratene Geheimnis als echtes Geheimnis
	 * 
	 * @param guessedSecret
	 */
	public void setGuessedSecret(BigInteger guessedSecret) {
		this.guessedSecret = guessedSecret;
		this.secret = guessedSecret;
		this.isGuessed = false;
	}
	
	public boolean hasGuessed() {
		return this.isGuessed;
	}
	

	// Empfangene Prefixes
	/**
	 * Erzeugt eine neue, leere Liste für gesendete Präfixe
	 */
	public void resetReceived() {
		receivedPrefix = new ArrayList<BigInteger>();
	}
	

	/**
	 * Erzeugt eine neue, leere Liste für gesendete Präfixe.
	 * Speichert die alte ab
	 */
	public void resetAndSafeReceived() {
		secureSend();
		resetReceived();
	}
	
	/**
	 * Füge gesendeten Prefix der Liste hinzu
	 * 
	 * @param prefix
	 */
	public void addReceived(BigInteger prefix) {
		receivedPrefix.add(prefix);
	}

	/**
	 * Größe der Liste der gesendeten Elemente
	 * 
	 * @return Listengröße
	 */
	public int getReceivedSize() {
		return receivedPrefix.size();
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

	
	public int refreshSecrets() {
		// Aktualisie die empfangenen falschen Präfixe
		secureSend();
		
		// Organisiere falsche Präfixe als Liste
		ArrayList<BigInteger> falsePrefixes = new ArrayList<BigInteger>();
		for (int i = 0 ; i < received.length ; i++) {
			ArrayList<BigInteger> list = received[i].getList();
			for (Iterator<BigInteger> it = list.iterator(); it.hasNext();) {
				BigInteger bigInteger = (BigInteger) it.next();
				falsePrefixes.add(bigInteger);
			}
		}
		
		// Prüfe die in Frage kommenden Zahlen
		if (allNumbers == null) {
		}
		else {
			
		}
		this.allNumbers = new ArrayList<BigInteger>();
		BigInteger i = BigInteger.ZERO;
		BigInteger counter = BigInteger.ZERO;
		boolean checkWhile1 = true;
		while (checkWhile1 && i.compareTo(maxSecret) < 0) {
			boolean isPrefix = false;
			for (Iterator<BigInteger> it = falsePrefixes.iterator(); it.hasNext();) {
				BigInteger big = (BigInteger) it.next();
				if (SecretWord.isPrefix(i, big)) {
					isPrefix = true;
					break;
				}
			}
			if(isPrefix == false) {
				allNumbers.add(i);
			}
			
			i = i.add(BigInteger.ONE); // Next Value
			counter = counter.add(BigInteger.ONE);
			checkWhile1 = (counter.compareTo(new BigInteger("10000")) < 0);
			if(checkWhile1) {
//				System.err.println("Berechnung wird wegen zu vieler Zahlen abgebrochen.");
			}
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
	 * Aktualisiert die in Frage kommenden Zahlen, indem alle Zahlen entfernt
	 * werden, die ein Präfix in den gesendeten Werten haben. Ist nur noch ein
	 * Element vorhanden, so wird guessedSecret auf diesen Wert gesetzt.
	 * 
	 * @return Anzahl der verbleibenden Elemente
	 * @deprecated ersetzt durch refreshSecrets()
	 */
	public int refreshSecretsOld() {
		if (!allNumbers.isEmpty()) {
			ArrayList<BigInteger> stored = new ArrayList<BigInteger>();
			for (Iterator<BigInteger> it = allNumbers.iterator(); it.hasNext();) {
				BigInteger tPoss = (BigInteger) it.next();
				boolean store = true;
				for (Iterator<BigInteger> itSend = receivedPrefix.iterator(); itSend
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
		if(allNumbers!=null && allNumbers.size()>0) {
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
		s = s + " hasGuessed=" + isGuessed + "";
		s = s + "\n\t Empfangene Präfix (" + receivedPrefix.size() + "): \n\t";
		for (Iterator<BigInteger> it = receivedPrefix.iterator(); it.hasNext();) {
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

	private void secureSend() {
		if (receivedPrefix.size()>0) {
			for (Iterator<BigInteger> it = receivedPrefix.iterator(); it.hasNext();) {
				BigInteger element = (BigInteger) it.next();
				int index = element.bitLength()-1;
				if (index < 0) {
					index = 0;
				}
				received[index].addElementOnce(element);
			}
		}
		else {
			received = null;
		}
	}
}
