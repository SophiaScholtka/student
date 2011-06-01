/*
 * Created on 05.05.2003
 *
 * This Code was initially written by Lars Girndt
 */
package de.tubs.cs.iti.krypto.protokoll;

/**
 * @author <a href="l.girndt@tu-bs.de">Lars Girndt</a>
 *
 */
public interface IClient {
	public void end( String message );
	public void playerNumberChanged( int newPlayerNumber );
}
