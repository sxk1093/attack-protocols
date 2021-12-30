import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;




public class Protocol2Attack {
	static String ipAddy = "127.0.0.1";
	static int portNo = 11338;
	static BigInteger g = new BigInteger("129115595377796797872260754286990587373919932143310995152019820961988539107450691898237693336192317366206087177510922095217647062219921553183876476232430921888985287191036474977937325461650715797148343570627272553218190796724095304058885497484176448065844273193302032730583977829212948191249234100369155852168");
	static BigInteger p = new BigInteger("165599299559711461271372014575825561168377583182463070194199862059444967049140626852928438236366187571526887969259319366449971919367665844413099962594758448603310339244779450534926105586093307455534702963575018551055314397497631095446414992955062052587163874172731570053362641344616087601787442281135614434639");
	static boolean debug = true;
	static Cipher decAESsessionCipher1;
	static Cipher encAESsessionCipher1;
	static Cipher decAESsessionCipher2;
	static Cipher encAESsessionCipher2;

	public static void main(String args[]) throws Exception {
		Socket s1 = new Socket(ipAddy, portNo);
		Socket s2 = new Socket(ipAddy, portNo);

		DataOutputStream out1 = new DataOutputStream(s1.getOutputStream());
		DataInputStream in1 = new DataInputStream(s1.getInputStream());
		DataOutputStream out2 = new DataOutputStream(s2.getOutputStream());
		DataInputStream in2 = new DataInputStream(s2.getInputStream());

		DHParameterSpec dhSpec = new DHParameterSpec(p,g);
		KeyPairGenerator diffieHellmanGen = KeyPairGenerator.getInstance("DiffieHellman");
		diffieHellmanGen.initialize(dhSpec);
		KeyPair serverPair = diffieHellmanGen.generateKeyPair();
		PrivateKey x = serverPair.getPrivate();
		PublicKey gToTheX = serverPair.getPublic();


		// Protocol 1 (s1)
		out1.writeInt(gToTheX.getEncoded().length);
		out1.write(gToTheX.getEncoded());
		if (debug) System.out.println("g^x len: " + gToTheX.getEncoded().length);
		if (debug) System.out.println("g^x cert: " + byteArrayToHexString(gToTheX.getEncoded()));

		// Protocol 2 (s1)
		int publicKeyLen = in1.readInt();
		byte[] msggToTheY = new byte[publicKeyLen];
		in1.read(msggToTheY);
		KeyFactory keyfactoryDH = KeyFactory.getInstance("DH");
		X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(msggToTheY);
		PublicKey gToTheY = keyfactoryDH.generatePublic(x509Spec);
		calculateSessionKey1(x, gToTheY);

		//Protocol 3 (s1)
		SecureRandom gen = new SecureRandom();
		int serverNonce = gen.nextInt();
		byte[] serverNonceBytes = BigInteger.valueOf(serverNonce).toByteArray();
		out1.write(encAESsessionCipher1.doFinal(serverNonceBytes));

		//Protocol 4 (s1)
		byte[] message4ct = new byte[32];
		in1.read(message4ct);
		byte[] nonceReplyBytes = decAESsessionCipher1.doFinal(message4ct);
		byte[] Ns = new byte[4];
		System.arraycopy(nonceReplyBytes,16,Ns,0,4);

		//Protocol 1 (s2)
		out2.writeInt(gToTheX.getEncoded().length);
		out2.write(gToTheX.getEncoded());

		//Protocol 2 (s2)
		int publicKeyLen2 = in2.readInt();
		byte[] msggToTheY2 = new byte[publicKeyLen2];
		in2.read(msggToTheY2);
		keyfactoryDH = KeyFactory.getInstance("DH");
		x509Spec = new X509EncodedKeySpec(msggToTheY2);
		PublicKey gToTheY2 = keyfactoryDH.generatePublic(x509Spec);
		calculateSessionKey2(x, gToTheY2);

		//Protocol 3 (s2)
		out2.write(encAESsessionCipher2.doFinal(Ns));

		//Protocol 4 (s2)
		byte[] message4ct2 = new byte[32];
		in2.read(message4ct2);
		byte[] nonceReplyBytes2 = decAESsessionCipher2.doFinal(message4ct2);
		byte[] Nsincr = new byte[16];
		System.arraycopy(nonceReplyBytes2,0,Nsincr,0,16);

		//Protocol 5 (s1)
		out1.write(encAESsessionCipher1.doFinal(Nsincr));

		//Protocol 6 (s1)
		while (in1.available() == 0);
		byte[] secret = new byte[in1.available()];
		in1.read(secret);
		byte[] secretkey = decAESsessionCipher1.doFinal(secret);
		System.out.println(new String(secretkey, "UTF-8"));





	}

	private static void calculateSessionKey1(PrivateKey y, PublicKey gToTheX)  {
	    try {
		// Find g^xy
		KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DiffieHellman");
		serverKeyAgree.init(y);
		serverKeyAgree.doPhase(gToTheX, true);
		byte[] secretDH = serverKeyAgree.generateSecret();
		if (debug) System.out.println("g^xy: "+byteArrayToHexString(secretDH));
		//Use first 16 bytes of g^xy to make an AES key
		byte[] aesSecret = new byte[16];
		System.arraycopy(secretDH,0,aesSecret,0,16);
		Key aesSessionKey = new SecretKeySpec(aesSecret, "AES");
		if (debug) System.out.println("Session key: "+byteArrayToHexString(aesSessionKey.getEncoded()));
		// Set up Cipher Objects
		decAESsessionCipher1 = Cipher.getInstance("AES");
		decAESsessionCipher1.init(Cipher.DECRYPT_MODE, aesSessionKey);
		encAESsessionCipher1 = Cipher.getInstance("AES");
		encAESsessionCipher1.init(Cipher.ENCRYPT_MODE, aesSessionKey);
	    } catch (NoSuchAlgorithmException e ) {
		System.out.println(e);
	    } catch (InvalidKeyException e) {
		System.out.println(e);
	    } catch (NoSuchPaddingException e) {
		e.printStackTrace();
	    }
	}

	// This method sets decAESsessioncipher2 & encAESsessioncipher2
	private static void calculateSessionKey2(PrivateKey y, PublicKey gToTheX)  {
	    try {
		// Find g^xy
		KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DiffieHellman");
		serverKeyAgree.init(y);
		serverKeyAgree.doPhase(gToTheX, true);
		byte[] secretDH = serverKeyAgree.generateSecret();
		if (debug) System.out.println("g^xy: "+byteArrayToHexString(secretDH));
		//Use first 16 bytes of g^xy to make an AES key
		byte[] aesSecret = new byte[16];
		System.arraycopy(secretDH,0,aesSecret,0,16);
		Key aesSessionKey = new SecretKeySpec(aesSecret, "AES");
		if (debug) System.out.println("Session key: "+byteArrayToHexString(aesSessionKey.getEncoded()));
		// Set up Cipher Objects
		decAESsessionCipher2 = Cipher.getInstance("AES");
		decAESsessionCipher2.init(Cipher.DECRYPT_MODE, aesSessionKey);
		encAESsessionCipher2 = Cipher.getInstance("AES");
		encAESsessionCipher2.init(Cipher.ENCRYPT_MODE, aesSessionKey);
	    } catch (NoSuchAlgorithmException e ) {
		System.out.println(e);
	    } catch (InvalidKeyException e) {
		System.out.println(e);
	    } catch (NoSuchPaddingException e) {
		e.printStackTrace();
	    }
	}

	private static String byteArrayToHexString(byte[] data) { 
	    StringBuffer buf = new StringBuffer();
	    for (int i = 0; i < data.length; i++) { 
		int halfbyte = (data[i] >>> 4) & 0x0F;
		int two_halfs = 0;
		do { 
		    if ((0 <= halfbyte) && (halfbyte <= 9)) 
			buf.append((char) ('0' + halfbyte));
		    else 
			buf.append((char) ('a' + (halfbyte - 10)));
		    halfbyte = data[i] & 0x0F;
		} while(two_halfs++ < 1);
	    } 
	    return buf.toString();
	} 
	
	private static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
		data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
				      + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}

	
}