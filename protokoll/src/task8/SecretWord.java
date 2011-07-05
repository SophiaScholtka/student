package task8;

import java.math.BigInteger;
import java.util.ArrayList;

public class SecretWord {
	

	private BigInteger secret;
	private ArrayList<BigInteger> possiblePrefix;
	private ArrayList<BigInteger> sendPrefix;
	private BigInteger guessedSecret;
	
	
	public SecretWord(BigInteger secret) {
		this.secret = secret;
		this.sendPrefix = new ArrayList<BigInteger>();
		this.possiblePrefix = new ArrayList<BigInteger>();
		this.guessedSecret = BigInteger.ZERO;
	}
	
	public SecretWord(BigInteger secret, int k) {
		this.secret = secret;
		this.sendPrefix = new ArrayList<BigInteger>();
		this.possiblePrefix = SecretWord.generateBinary(k);
		this.guessedSecret = BigInteger.ZERO;
		
	}
	
	public BigInteger getSecret() {
		return secret;
	}
	
	public BigInteger getGuessedSecret() {
		return guessedSecret;
	}
	
//	public void refreshGuessedSecret() {
//	}

//	public void setGuessedSecret(BigInteger secret) {
//		this.guessedSecret = secret;
//	}
	
	// Gesendete Prefixes
	public void resetPrefixes() {
		sendPrefix = new ArrayList<BigInteger>();
	}
	
	public void addPrefix(BigInteger prefix) {
		sendPrefix.add(prefix);
	}
	
	public boolean isSendPrefix(BigInteger prefix) {
		return sendPrefix.contains(prefix);
	}
	
	public boolean isFreePrefix(BigInteger prefix) {
		return !sendPrefix.contains(prefix);
	}
	
	public int getSendSize() {
		return sendPrefix.size();
	}
	
	
	// Generierte Prefixe
//	public void resetWords() {
//		this.possiblePrefix = new ArrayList<BigInteger>();
//	}
	
	public void startBinary(int k) {
		this.possiblePrefix = SecretWord.generateBinary(k);
	}
	
	public void removeBinary(BigInteger binaryWord) {
		this.possiblePrefix.remove(binaryWord);
	}
	
	public void enhanceBinary(int amount) {
		ArrayList<BigInteger> newList = new ArrayList<BigInteger>();
		
		BigInteger shifted;
		for (BigInteger bi : possiblePrefix) {
			shifted = bi.shiftLeft(1);
			newList.add(shifted);
			newList.add(shifted.flipBit(0));
		}
		
		possiblePrefix = newList;
	}
	
	public int getBinarySize() {
		return possiblePrefix.size();
	}
	
	// Static Methods
	public static ArrayList<BigInteger> generateBinary(int k) {
		// TO = 2^(k+1)
		BigInteger TO = new BigInteger("2");
		TO = TO.pow(k+1); 
		
		// Erzeuge Zahlen 0..2^(k+1)-1
		ArrayList<BigInteger> binWords = new ArrayList<BigInteger>();
		for (int i = 0 ; i < TO.intValue() ; i++) {
			binWords.add(new BigInteger("" + i));
		}
		
		return binWords;
	}
}
