/*
 * @(#)example.java	1.00 17-Oct-1998
 */

import de.tubs.cs.iti.krypto.protokoll.*;

public final class example implements Protocol
{
	static private int MinPlayer        = 2;
	static private int MaxPlayer        = 41; // 40 + Auktionator
	static private String NameOfTheGame = "Boring Game";

    private Communicator Com;
	
	public void setCommunicator(Communicator com)
	{
	  Com = com;
	}
	
	
	public void sendFirst ()
	{
		System.out.println ( "Ich beginne!" );
	  int b = (int) '\n';
		while (b == (int) '\n')
		{
			System.out.println ( "Meine Nummer: " + Com.myNumber () );
			System.out.print ( "Die Nummern meiner Mitspieler: " );
			for ( int i = Com.playerNumber () - 1; i >= 0; i-- )
			{
		  	if ( i != Com.myNumber () )
				{
			  	Com.sendTo ( i, String.valueOf (Com.myNumber ()) );
					System.out.print ( Com.receive () + " - " );
				}
			}
			System.out.println ( "\nWeiter mit RETURN" ); 
			try
			{ b = System.in.read(); }catch(java.io.IOException e){	}
		}
	}
	
	public void receiveFirst ()
	{
		System.out.println ( "Ich auch!" );
	  int b = (int) '\n';
		while (b == (int) '\n')
		{
			System.out.println ( "Meine Nummer: " + Com.myNumber () );
			System.out.print ( "Die Nummern meiner Mitspieler: " );
			for ( int i = Com.playerNumber () - 1; i >= 0; i-- )
			{
		  	if ( i != Com.myNumber () )
				{
			  	Com.sendTo ( i, String.valueOf (Com.myNumber ()) );
					System.out.print ( Com.receive () + " - " );
				}
			}
			System.out.println ( "\nWeiter mit RETURN" ); 
			try
			{ b = System.in.read(); }catch(java.io.IOException e){	}
		}
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
