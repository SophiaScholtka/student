package test;

import java.math.BigInteger;

import task8.SecretWord;

public class TestSecretWord {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		BigInteger K = new BigInteger("2");
		
		BigInteger sec1 = new BigInteger("2", 36);
		BigInteger sec2 = new BigInteger("1", 36);
		SecretWord sw1 = new SecretWord(sec1);
		SecretWord sw2 = new SecretWord(sec2, K.intValue());
		SecretWord[] secs = {sw1,sw2};

		System.err.println("======>Zeige Startwerte:");
		System.out.println("sec1 = " +sec1.toString(2));
		System.out.println("sec2 = " +sec2.toString(2));
		System.out.println(sw1);
		System.out.println(sw2);
		System.out.println();
		System.out.println();
		System.err.println("======>Zeige sw1");
		sw1.startBinary(K.intValue());
//		sw1.resetSend();
		System.out.println("startbinary:\n" + sw1);
		sw1.addSend(new BigInteger("3"));
		System.out.println("addSend:\n" + sw1);
		sw1.resetSend();
		System.out.println("ResetSend:\n" + sw1);

		for(int i = 0; i < 4; i++) {
			BigInteger use = sw1.useBinary();
			sw1.addSend(use);
			System.out.println("used " + i + ": " + use.toString(2));
			System.out.println("useBinary:\n" + sw1);
		}
		
		sw1.enhanceBinary(1);
		System.out.println("enhanceBinary:\n" + sw1);

		// Konstruktor k
		System.out.println();
		System.out.println();
		System.err.println("======>Zeige sw2");
		System.out.println("Standard:\n" + sw2);
		
		sw2.startBinary(K.intValue());
		sw2.resetSend();
		System.out.println("startBinary and resetSend:\n" + sw2);

		sw2.addSend(new BigInteger("3"));
		System.out.println("addSend:\n" + sw2);
		
		sw2.refreshSecrets();
		System.out.println("refreshSecrets:\n" + sw2);
		

		sw2.addSend(new BigInteger("101",2));
		sw2.refreshSecrets();
		System.out.println("refreshSecrets:\n" + sw2);
		sw2.addSend(new BigInteger("100",2));
		sw2.refreshSecrets();
		System.out.println("refreshSecrets:\n" + sw2);
		sw2.addSend(new BigInteger("10",2));
		sw2.refreshSecrets();
		System.out.println("refreshSecrets:\n" + sw2);
		sw2.addSend(new BigInteger("0",2));
		sw2.refreshSecrets();
		System.out.println("refreshSecrets:\n" + sw2);
		
		System.out.println();System.out.println();
		SecretWord sw3 = new SecretWord(new BigInteger("11",2),K.intValue());
		System.err.println("======> Wort 3");
		System.out.println(sw3);
		sw3.addSend(new BigInteger("0",2));
		sw3.addSend(new BigInteger("10",2));
		sw3.addSend(new BigInteger("111",2));
		sw3.addSend(new BigInteger("110",2));
//		sw3.addSend(new BigInteger("1",2)); // FIXME 11 muss drinbleiben! 
		sw3.refreshSecrets();
		System.out.println(sw3);
	}

	private static void showSecret(String pre, SecretWord[] secrets, int rad) {
		for (int i = 0; i < secrets.length; i++) {
			System.out.print(pre);
			System.out.print(secrets[i].getSecret().toString(rad));
			System.out.print("\t");
			System.out.print("(" + secrets[i].getGuessedSecret().toString(rad) + ")");
			System.out.println();
		}
	}
}
