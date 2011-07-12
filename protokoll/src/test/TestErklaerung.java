package test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;

import task9.Erklaerung;
import chiffre.Grundlagen;

public class TestErklaerung {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		System.err.println("Test für die Zerlegung von BigInteger zu Byte");
		BigInteger[] bigs = new BigInteger[1];
		bigs[0] = new BigInteger("0110000010",2);
		System.out.println("bigs to byte");
		System.out.println(bigs[0].toString(2));
		byte[] bytes = Erklaerung.changeToBytes(bigs);
		System.out.println(Arrays.toString(bytes));
		
		for (int i = 0; i < bytes.length; i++) {
			System.out.println((new BigInteger("" + bytes[i]).toString(2)));
		}
		
		
		// TEST: Erklärung+Vertrag=Gesamt
		System.out.println();System.out.println();
		System.err.println("Test Erkärung+Vertrag");
		// Parametervariablen
		int amount = 1;
		int n = 4;
		String path = "../protokoll/vertrag.txt";
		
		// Lese Erklärung
		String statementS;
		BigInteger[] statementBigs;
		ArrayList<BigInteger> statementList;
		statementS = Erklaerung.generateStatement("A", "Bob", n);
		statementBigs = Erklaerung.changeToBigs(statementS, amount);
		statementList = Erklaerung.changeToList(statementBigs);
		String testS = Erklaerung.changeToString(statementBigs);
		
		// Lese Vertrag
		String vertragS;
		BigInteger[] vertragBigs;
		ArrayList<BigInteger> vertragList;
		vertragBigs = Grundlagen.readFile(path, amount);
		vertragList = Erklaerung.changeToList(vertragBigs);
		vertragS = Erklaerung.changeToString(vertragBigs);
		
		// Kombiniere
		String combinedS;
		BigInteger[] combinedBigs;
		ArrayList<BigInteger> combinedList;
		combinedBigs = Erklaerung.createStateContract(statementBigs, vertragBigs);
		combinedList = Erklaerung.changeToList(combinedBigs);
		combinedS = Erklaerung.changeToString(combinedBigs);

		// Ausgaben
		System.out.println(">>> Stringausgaben");
		System.out.println("Erkärung (Text):");
		System.out.println(statementS);
		System.out.println("Vertrag (Text):");
		System.out.println(vertragS);
		System.out.println("Gesamt (Text):");
		System.out.println(combinedS);
		
		System.out.println();
		System.out.println(">>> Längenüberprüfung:");
		System.out.println("Vertragslänge:  " + vertragBigs.length);
		System.out.println("Agreementlänge: " + statementBigs.length);
		
		System.out.println("Gesamtlänge:    " + combinedBigs.length);
		System.out.println("Vertrag+Agreement = kombiniert ist " + (vertragBigs.length + statementBigs.length == combinedBigs.length));
		
		System.out.println();
		System.out.println(">>> Inhalte der BigInteger");
		System.out.println("Erklärung: " + statementList.size());
		System.out.println(statementList);
		System.out.println("Vertrag: " + vertragList.size());
		System.out.println(vertragList);
		System.out.println("Gesamten Erklärung: " + combinedList.size());
		System.out.println(combinedList);
	}

}
