package task8;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;

public class BigIntegerList {
	ArrayList<BigInteger> list;
	
	/**
	 * Constructor
	 * legt Liste an
	 */
	public BigIntegerList() {
		list = new ArrayList<BigInteger>();
	}
	
	/**
	 * Gibt eine Kopie der Liste heraus
	 * @return Kopie der BigInteger Liste
	 */
	public ArrayList<BigInteger> getList() {
		ArrayList<BigInteger> clone = new ArrayList<BigInteger>();
		for (Iterator<BigInteger> it = list.iterator(); it.hasNext();) {
			BigInteger bigInteger = (BigInteger) it.next();
			clone.add(bigInteger);
		}
		return clone;
	}
	
	public int getSize() {
		return list.size();
	}
	
	/**
	 * Fügt ein Element in die Liste ein, das noch nicht enthalten ist
	 * @param big hinzuzufügendes Element
	 */
	public void addElementOnce(BigInteger big) {
		if (list.contains(big) == false) {
			list.add(big);
		}
	}
}
