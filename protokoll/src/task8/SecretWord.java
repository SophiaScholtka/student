package task8;

import java.math.BigInteger;
import java.util.ArrayList;

public class SecretWord {

	private BigInteger secret;
	private ArrayList<BigInteger> sendPrefix;
	private BigInteger guessedSecret;
	
	
	public SecretWord(BigInteger secret) {
		this.secret = secret;
		this.sendPrefix = new ArrayList<BigInteger>();
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
	
	public int getCount() {
		return sendPrefix.size();
	}
}
