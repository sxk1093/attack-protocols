import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;


public class Protocol1Client {
    static int portNo = 11337;
    static String ipAddy = "127.0.0.1";
    static String hexKey = "00000000000000000000000000000000";
    static Cipher decAEScipher;
	static Cipher encAEScipher;

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

    

    public static void main (String[] args) throws IOException {

        Key aesKey = new SecretKeySpec(hexStringToByteArray(hexKey), "AES");
	    try {
		decAEScipher = Cipher.getInstance("AES");
		decAEScipher.init(Cipher.DECRYPT_MODE, aesKey);
		encAEScipher = Cipher.getInstance("AES");
		encAEScipher.init(Cipher.ENCRYPT_MODE, aesKey);
	    } catch (Exception e) {
		System.out.println("Doh "+e);
	    }
        	

        try {
            Socket socket = new Socket(ipAddy, portNo);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            // Protocol 1
            byte[] message1 = new byte[18];
            message1 = hexStringToByteArray("Connect Protocol 1");
            out.write(message1);

            // Protocol 2
            byte[] cipherTextM2 = new byte[32];
            in.read(cipherTextM2);

            // Protocol 3
            out.write(cipherTextM2);

            // Protocol 4
            byte[] cipherTextM4 = new byte [48];
            in.read(cipherTextM4);

            // Protocol 5
            out.write(cipherTextM4);

            // Protocol 6
            byte[] cipherTextM6 = new byte[208];  
            in.read(cipherTextM6);
            System.out.println(byteArrayToHexString(cipherTextM6));
            byte[] plainTextM6 = decAEScipher.doFinal(cipherTextM6);
            System.out.println(new String(plainTextM6));
            socket.close();
        } catch (Exception e) {
            System.out.println("Doh "+e);
        } 
    }
}
