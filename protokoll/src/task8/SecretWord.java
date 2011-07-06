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
	
	private ArrayList<BigInteger> allNumbers; // alle in Frage kommenden Zahlen
	/**
	 * Konstruktor
	 * Erzeugt eine leere Liste gesendeter Elemente. 
	 * Erzeugt eine leere Liste der möglichen Elemente. 
	 * Das geratene Geheimnis ist 0.
	 * Keine Liste möglicher Zahlen
	 * @param secret Geheime Zahl
	 */
	public SecretWord(BigInteger secret) {
		this.secret = secret;
		this.sendPrefix = new ArrayList<BigInteger>();
		this.possiblePrefix = new ArrayList<BigInteger>();
		this.guessedSecret = BigInteger.ZERO;
		
		this.allNumbers = new ArrayList<BigInteger>();
	}
	/**
	 * Konstruktor
	 * Erzeugt eine leere Liste gesendeter Elemente. 
	 * Erzeugt eine leere Liste der möglichen Elemente. 
	 * Das geratene Geheimnis ist 0.
	 * Erzeugt eine Liste möglicher Zahlen
	 * @param secret Geheime Zahl
	 */
	public SecretWord(BigInteger secret,int k) {
		this.secret = secret;
		this.sendPrefix = new ArrayList<BigInteger>();
		this.possiblePrefix = new ArrayList<BigInteger>();
		this.guessedSecret = BigInteger.ZERO;
		
		BigInteger maxK = TWO.pow(k+1);
		this.allNumbers = new ArrayList<BigInteger>();
		for(int i = 0 ; i < maxK.intValue();i++) {
			allNumbers.add(new BigInteger("" + i));
		}
	}

	/**
	 * Das echte Geheimnis
	 * @return
	 */
	public BigInteger getSecret() {
		return secret;
	}

	/**
	 * Das geratene Geheimnis
	 * @return
	 */
	public BigInteger getGuessedSecret() {
		return guessedSecret;
	}
	
	/**
	 * Setzt das geratene Geheimnis
	 * @param guessedSecret
	 */
	public void setGuessedSecret(BigInteger guessedSecret) {
		this.guessedSecret = guessedSecret;
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
	 * @param prefix
	 */
	public void addSend(BigInteger prefix) {
		sendPrefix.add(prefix);
	}

	/**
	 * Prüft, ob Präfix gesendet worden ist
	 * @param prefix zu prüfender Präfix
	 * @return true wenn gesendet, false sonst
	 */
	public boolean isSend(BigInteger prefix) {
		return sendPrefix.contains(prefix);
	}

	/**
	 * Prüft, ob prefix noch nicht gesendet worden ist ("frei ist")
	 * @param prefix zu prüfender Präfix
	 * @return true wenn frei, false wenn bereits gesendet
	 */
	public boolean isFreePrefix(BigInteger prefix) {
		return !sendPrefix.contains(prefix);
	}

	/**
	 * Größe der Liste der gesendeten Elemente
	 * @return Listengröße
	 */
	public int getSendSize() {
		return sendPrefix.size();
	}

	// Liste der binären Worte
	/**
	 * Erzeuge die erste binäre Zahlenliste
	 * Länge der Liste: 2^(k+1)-1
	 * @param k Anzahl der Bits
	 */
	public void startBinary(int k) {
		this.possiblePrefix = SecretWord.generateBinary(k);
	}
	
	/**
	 * Wählt ein y aus der möglichen Liste aus
	 * y kein Präfix des Geheimnisses, noch nicht genutzt
	 * @return y
	 */
	public BigInteger useBinary() {
		BigInteger prefix;
		do {
			BigInteger size = new BigInteger("" + possiblePrefix.size());
			BigInteger r = BigIntegerUtil.randomSmallerThan(size);
			prefix = possiblePrefix.get(r.intValue());
		} while(!isFreePrefix(prefix) || !isPrefix(prefix));
		
		possiblePrefix.remove(prefix);
		return prefix;
	}

	/**
	 * Erweitert die Elemente der binären Wortliste jeweils 
	 * um 0 und 1 an den Wortenden
	 * @param amount
	 */
	public void enhanceBinary(int amount) {
		ArrayList<BigInteger> newList = new ArrayList<BigInteger>();

		BigInteger shifted;
		for(int i = 0 ; i < amount ; i++) {
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
	 * @return Anzahl der binären Worte, die als Präfix möglich sind
	 */
	public int getBinarySize() {
		return this.possiblePrefix.size();
	}
	
	/**
	 * Prüft, ob die gegebene binäre Zahl ein Präfix des Geheimnisses ist
	 * @param binary der mögliche Präfix
	 * @return true wenn Präfix, false sonst
	 */
	public boolean isPrefix(BigInteger binary) {
		boolean b = false;
		
		int size = binary.bitLength();
		b = binary.equals(secret.shiftRight(52-size));
		
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
	 * werden, die ein Präfix in den gesendeten Werten haben.
	 * Ist nur noch ein Element vorhanden, so wird guessedSecret auf diesen Wert gesetzt.
	 * @return Anzahl der verbleibenden Elemente
	 */
	public int refreshSecrets() {
		for (Iterator<BigInteger> it = allNumbers.iterator(); it.hasNext();) {
			BigInteger tPoss = (BigInteger) it.next();
			for (Iterator<BigInteger> itSend = sendPrefix.iterator(); itSend.hasNext();) {
				BigInteger tSend = (BigInteger) itSend.next();
				int shift = 52 - tSend.bitLength();
				if(tSend.equals(tPoss.shiftRight(shift))) {
					allNumbers.remove(tPoss);
					break;
				}
			}
		}
		
		if(allNumbers.isEmpty()) {
			//this.guessedSecret = null;
			return 0;
		} else if(allNumbers.size() == 1) {
			this.guessedSecret = allNumbers.get(0);
			return allNumbers.size();
		} else {
			return allNumbers.size();
		}
	}
	
	/**
	 * Gibt einen Array der möglichen Zahlen zurück
	 * @return
	 */
	public BigInteger[] getSecrets() {
		int i = 0;
		BigInteger[] ret = new BigInteger[allNumbers.size()];
		for (Iterator<BigInteger> iterator = allNumbers.iterator(); iterator.hasNext();) {
			ret[i] = (BigInteger) iterator.next();
		}
		return ret;
	}
	
	
	// Static Methods
	/**
	 * Erzeugt eine Liste mit binären Wörtern der Länge k. 
	 * Zahlenwerte reichen von 0 bis 2^(k+1)-1.
	 * Anzahl der Elemente: 2^(k+1)
	 * @param k Anzahl der Bits
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
}
