/*
 * @(#)Certificate.java		1.00, 13-Feb-2004
 */

package de.tubs.cs.iti.krypto.protokoll;

import java.math.BigInteger;

/**
 * This is a data class modelling a certificate to be issued by the
 * <cite>TrustedAuthority</cite>-class.
 *<br>
 * Its methods allow access to ID, data and signature of a certificate. 
 *
 * @author   <a href="mailto:milius@iti.cs.tu-bs.de">Stefan Milius</a>
 * @version  1.00, 13-Feb-2004
 * @see de.tubs.cs.iti.krypto.protokoll.TrustedAuthority
 */
public class Certificate {

    // private data fields of the certificate
    private String ID;
    private byte[] data;
    private BigInteger signature;

    /**
     * Instantiates a new Certificate object with the given parameters. 
     * This constructor is called by <cite>TrustedAuthority</cite> to generate certificates.
     *
     * @param    ID        the ID-String of the certificate
     * @param    data      the data contained in the certificate (e.g. a key of a public key kryptosystem)
     * @param    signature the signature on ID and data that is computed by the trusted authority
     */
    public Certificate(String ID, byte[] data, BigInteger signature) {
	this.ID = ID;
	this.data = data;
	this.signature = signature;
    }

    /**
     * Access method for the ID-String of the certificate.
     *
     * @returns  the ID-String.
     */
    public String getID() {
	return ID;
    }

    /**
     * Access method for the data of the certificate.
     *
     * @returns  the data as a byte array.
     */
    public byte[] getData() {
	return data;
    }

    /**
     * Access method for the signature of the certificate.
     *
     * @returns  the signature as one BigInteger. 
     */
    public BigInteger getSignature() {
	return signature;
    }
}
