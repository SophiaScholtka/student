package test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;

import task9.Erklaerung;
import chiffre.Grundlagen;

public class TestErklaerung {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		BigInteger[] bigs = new BigInteger[1];
		bigs[0] = new BigInteger("0110000010",2);
		System.out.println("bigs to byte");
		System.out.println(bigs[0].toString(2));
		byte[] bytes = Erklaerung.changeBigsToByte(bigs);
		System.out.println(Arrays.toString(bytes));
		
		for (int i = 0; i < bytes.length; i++) {
			System.out.println((new BigInteger("" + bytes[i]).toString(2)));
		}
		
		
		System.out.println();System.out.println();
		int amount = 1;
		int n = 4;
		String path = "../protokoll/vertrag.txt";
		
		BigInteger[] v = Grundlagen.readFile(path, amount);
		String agreement = Erklaerung.generateStatement("A", "Bob", n);
		System.out.println(agreement);
		System.out.println();
		
		ArrayList<BigInteger> list = Erklaerung.changeStringToList(agreement, amount);
		System.out.println("Vertragslänge:  " + v.length);
		System.out.println("Agreementlänge: " + list.size());
		
		BigInteger[] contract = Erklaerung.createStateContract("A", "Bob", v,n,amount);
		System.out.println("Gesamtlänge: " + contract.length);
		System.out.println("Vertrag+Agreement = gesamt ist " + (v.length + list.size() == contract.length));
		
		System.out.println();
		ArrayList<BigInteger> contractList = new ArrayList<BigInteger>();
		for (int i = 0; i < contract.length; i++) {
			contractList.add(contract[i]);
		}
		System.out.println("größe der Liste: " + contractList.size());
		System.out.println("contractList:");
		System.out.println(contractList);
		
		System.out.println();
		BigInteger[] contract2 = Grundlagen.readFile(path, amount);
		ArrayList<BigInteger> contractList2 = new ArrayList<BigInteger>();
		for (int i = 0; i < contract2.length; i++) {
			contractList2.add(contract2[i]);
		}
		System.out.println("größe der Liste2: " + contractList2.size());
		System.out.println("contractList2:");
		System.out.println(contractList2);
	}

}
