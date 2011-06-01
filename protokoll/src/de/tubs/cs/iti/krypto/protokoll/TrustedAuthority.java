/*
 * @(#)TrustedAuthority.java		1.00, 13-Feb-2004
 */

package de.tubs.cs.iti.krypto.protokoll;

import java.io.*;
import java.math.*;
import java.security.*;
import java.util.*;
import de.tubs.cs.iti.jcrypt.chiffre.*;
// import de.tubs.cs.iti.krypto.chiffre.*;


/**
 * This class provides a trusted authority for key exchange protocols. 
 * 
 * Its methods allow the user to obtain a new certificate based on his system login information.
 * The issued certificates are objects of the <cite>Certificate</cite>-class. 
 * <br>
 * There are also methods to access the public part of the trusted authority's
 * RSA key.
 * 
 *
 * @author   <a href="mailto:milius@iti.cs.tu-bs.de">Stefan Milius</a>
 * @version  1.00, 13-Feb-2004
 * @see de.tubs.cs.iti.krypto.protokoll.Certificate
 */
public class TrustedAuthority {
    private static final BigInteger n = new BigInteger("79789947245034048876449632331010537488007838227754096616496400243172779697173491917503541030774060122406734057542931654034376201867932349157694914353473530057321261403684234412726751583511641702515524622585646506469184584287454398409323036519654853301047393604564215922344133987055405809886008559516734814117");;
    private static final BigInteger e = new BigInteger("66521496587850474376357140529596842365087891876187610406483868799857889961951283650375568500827986423778207176156549938475445916970489584298302007149743446467536742271946525093161141046905545133033264363457199206522460043917508490763145351897758009383884628600108233917921659020706650578693206398690137965077");
    private static final BigInteger d = new BigInteger("43641238253617447523006112542934041719316513886681942242954994833699811849570014439194772218645541473783772125276580840882569698244217070408872324742608883226214359106648923455604737058937579909737435205242834293482093569557247655140298037889838267973874317636971423951666441257452283786276496196640865373565");

    /**
     * Issues a new certificate to the caller containing the given data. 
     * The issued certificate contains the username under which the program calling this method
     * is running. If no such username can be obtained a random String of length 50 is used as ID.   
     * The signature of the certificate is obtained by applying first the SHA hash function to 
     * the ID-String followed by data, see the <cite>MessageDigest</cite>-class. That is, 
     * if <code>md</code> is the SHA <cite>MessageDigest</cite>-object and <code>ID</code> is the ID-String, 
     * then <code>newCertificate</code> will call <br> <br>
     * <code>md.update(ID.getBytes());</code><br>
     * <code>md.update(data);</code><br>	
     * <code>digest = md.digest();</code><br><br>
     * After that the resulting message digest <code>digest</code> of 128 bits is converted to a <cite>BigInteger</cite>-object
     * by using the appropriate constructor and signed with the secret RSA key of the trusted authority. 
     * <strong>Important:</strong> When checking a certificate notice that because of the usage of RSA the two values 
     * to be compared are only equal modulo the trusted authorities modulus <cite>getModulus</cite>. 
     *
     * @param       data      contains the data to be included in the certificate (e.g. a public RSA key).
     * @returns     a <cite>Certificate</cite>-object containing the issued certificate.
     * @see java.security.MessageDigest
     * @see java.math.BigInteger
     */
    public static Certificate newCertificate(byte[] data) {
	BigInteger signature, M;
	String ID;	
	MessageDigest sha = null;
	byte[] digest;

	// Get user's id as ID-String
	ID = System.getProperty("user.name");
	if (ID == null) {                   // if no user id take Random-String of length 50
	    Random ran = new Random();
	    byte[] rbytes = new byte[50];
	    ran.nextBytes(rbytes);
	    ID = new String(rbytes);
	}

	// Compute signature on ID and data
	
	// make SHA Hashfunction
	try {
	    sha = MessageDigest.getInstance("SHA");
	} catch (Exception e) {
	    System.out.println("Could not create message digest! Exception " + e.toString());
	}
	
	// Hashwert bestimmen
	sha.update(ID.getBytes());
	sha.update(data);
	digest = sha.digest();
	 
	// RSA signature
	M = new BigInteger(digest);
	signature = M.modPow(d, n);

	return new Certificate(ID, data, signature);
    }

    /**
     * Access method for the modulus of the RSA key of the trusted authority.
     *
     * @return   the modulus n of the public key as BigInteger.
     */
    public static BigInteger getModulus() {
	return n;
    }
    
    /**
     * Access method for the exponent part of the public RSA key of the trusted authority.
     *
     * @return  the exponent e of the public key as BigInteger. 
     */
    public static BigInteger getPublicExponent() {
	return e;
    }
}
