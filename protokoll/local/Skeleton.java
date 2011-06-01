/*
 * @(#)Skeleton.java
 */

import de.tubs.cs.iti.krypto.protokoll.*;

/**
 *
 */

public final class Skeleton implements Protocol
{
  /**
   *
   */

	static private int MinPlayer        = 2; // Minimal number of players
	static private int MaxPlayer        = 2; // Maximal number of players
	static private String NameOfTheGame = "Don't forget the name of the game";
    private Communicator Com;
	
	public void setCommunicator(Communicator com)
	{
	  Com = com;
	}	
	
	public void sendFirst ()
  /**
   * Aktionen der beginnenden Partei. Bei den 2-Parteien-Protokollen
   * seien dies die Aktionen von Alice.
   */
	{
	}
	
	public void receiveFirst ()
  /**
   * Aktionen der uebrigen Parteien. Bei den 2-Parteien-Protokollen
   * seien dies die Aktionen von Bob.
   */
	{
	}
	
	public String nameOfTheGame ()
	{
		return NameOfTheGame;
	}
	
	public int minPlayer ()
	{
		return MinPlayer;
	}
	
	public int maxPlayer ()
	{
		return MaxPlayer;
	}
}
