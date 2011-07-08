package test;

import java.math.BigInteger;

import task8.SecretWord;
import task8.SecretWordGuess;
import task8.SecretWordSend;

public class TestSecretWord {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
//		testSend();
		
		testGuess();
	}
	
	private static void testGuess() {
		System.err.println("===> SecretWordGuess <===");
		System.err.println("==> sw1");
		SecretWordGuess sw1 = new SecretWordGuess(new BigInteger("11",2), 3);
		System.out.println("resetRec:\n" + sw1);
		sw1.addReceived(new BigInteger("0",2));
		sw1.addReceived(new BigInteger("101",2));
		sw1.addReceived(new BigInteger("111",2));
		sw1.addReceived(new BigInteger("10",2));
		sw1.addReceived(new BigInteger("110",2));
		System.out.println("addRec 2x:\n" + sw1);
		sw1.refreshSecrets();
		System.out.println("refreshSecrets:\n" + sw1);
	}
	
	private static void testSend() {
		System.err.println("===> SecretWordSend <===");
		
		System.err.println("==> sw1");
		SecretWordSend sw1 = new SecretWordSend(new BigInteger("2"));
		System.out.println("Standard:\n" + sw1);
		sw1.startBinary(2);
		System.out.println("startBinary:\n" + sw1);
		sw1.resetSend();
		System.out.println("resetSend:\n" + sw1);
		sw1.addSend(sw1.useBinary());
		sw1.addSend(sw1.useBinary());
		sw1.addSend(sw1.useBinary());
		sw1.addSend(sw1.useBinary());
		System.out.println("usebinary+addSend 4x:\n" + sw1);
		sw1.resetSend();
		System.out.println("resetSend:\n" + sw1);
		sw1.enhanceBinary(1);
		System.out.println("enhanceBinary:\n" + sw1);
		
	}
}
