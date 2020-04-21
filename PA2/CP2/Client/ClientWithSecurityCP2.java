import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class ClientWithSecurityCP2{

	static PublicKey pubkey = null;
	public static void handshake(DataOutputStream toServer,DataInputStream fromServer, X509Certificate CAcert) throws Exception{
		
		String msg_verify = null;
		String msg_verified = null;
		String msg_init = null;
		byte [] msg_verify_bytes =null;
		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;
		int numBytes = 0;

		// initialising the handshake	

		//Generating NONCE	
		String dateTimeString = Long.toString(new Date().getTime());
        byte[] nonceByte = dateTimeString.getBytes();
		String nonce =  new String(nonceByte);
		toServer.writeInt(2);
		toServer.writeInt(nonce.getBytes().length);
		toServer.write(nonce.getBytes());
		
	
		// waiting for SecStore response
		while(msg_verify == null){
			int packetType = fromServer.readInt();
			if (packetType == 2){
				System.out.println("receiving msg_verify...");
				numBytes = fromServer.readInt();
				msg_verify_bytes = new byte[numBytes];
				fromServer.readFully(msg_verify_bytes, 0, numBytes);
				msg_verify = new String(msg_verify_bytes);
				System.out.println("Received Encrypted block from Server");
			}
		}
		
		// ask for CA cert to get server's public key
		msg_init = "Give me your certificate signed by CA";
		System.out.println("Sending msg_init :" + msg_init);
		toServer.writeInt(2);
		toServer.writeInt(msg_init.getBytes().length);
		toServer.write(msg_init.getBytes());

		// wait for SecStore to provide CA
		boolean condition = true;
		while(condition){
			int packetType = fromServer.readInt();
			if(packetType==0){
				numBytes = fromServer.readInt();
				byte [] filename = new byte[numBytes];
				fromServer.readFully(filename, 0, numBytes);
				fileOutputStream = new FileOutputStream("recv_"+new String(filename, 0, numBytes));
				bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

			}else if (packetType == 1) {
				numBytes = fromServer.readInt();
				byte [] block = new byte[numBytes];
				fromServer.readFully(block, 0, numBytes);
					if (numBytes > 0){
						bufferedFileOutputStream.write(block, 0, numBytes);
					}
					if (numBytes < 117) {

						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();
						condition = false;
					}

			}
		}

		// get public key from certificate
		//does the name need to be dynamic?
		InputStream fileInputStream = new FileInputStream("recv_example-bd710400-8079-11ea-ae9d-89114163ae84.crt");
		CertificateFactory certf = CertificateFactory.getInstance("X.509");
		X509Certificate serverCert =(X509Certificate)(certf.generateCertificate(fileInputStream));

		//verify that this serverCert is indeed from SecServer
		serverCert.verify(CAcert.getPublicKey());

		//extract SecServer's public key
		pubkey = serverCert.getPublicKey();
		
		Cipher rsaCipher = Cipher.getInstance("RSA"); 
		rsaCipher.init(Cipher.DECRYPT_MODE, pubkey);
		byte[] decryptedBlock = rsaCipher.doFinal(msg_verify_bytes);
		msg_verified = new String(decryptedBlock);
		System.out.println("This is decrypted message: " + msg_verified);
		toServer.flush();
		if(nonce.compareTo(msg_verified) == 0){
			System.out.println("decrypted message is the exact same as the nonce. Check succeeded.");
		}else{System.out.println("decrypted message is not the same as the nonce. Check failed.");}

	}
	public static void main(String[] args) {
		int counter = args.length;
		String serverAddress = "localhost";
		String filename = null;
    	int port = 4321;
		int numBytes = 0;
		Socket clientSocket = null;
        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

		long timeStarted = System.nanoTime();

		try {

			System.out.println("Establishing connection to server...");
			
			//Create X509Certificate object
			InputStream fis = new FileInputStream("cacse.crt");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);

			// //Extract public key from X509Certificate object
			// PublicKey key = CAcert.getPublicKey();

			//Verify signed certificate
			//CAcert.verify(key);
			
			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());
			
			//Handshake Protocol
			handshake(toServer, fromServer, CAcert);

			// LOOKHERE: Generate symmetric key
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			SecretKey AESkey = keyGen.generateKey();
			//Encrypt encodedKey
			Cipher rsaCipher = Cipher.getInstance("RSA");
			rsaCipher.init(Cipher.ENCRYPT_MODE, pubkey);
			//LOOKHERE : Send symmetric key to server (encrypted with server’s public key):
			byte[] encryptedBlock = rsaCipher.doFinal(AESkey.getEncoded());
			//Sending AES key
			System.out.println("Sending AES key...");
			toServer.writeInt(3);
			toServer.writeInt(encryptedBlock.length);
			toServer.write(encryptedBlock);
			System.out.println("Sent AES key");
			System.out.println("this is AESkey: " + new String(AESkey.getEncoded()));
			// Connect to server

			// send number of files
			toServer.writeInt(1234);
			toServer.writeInt(counter);

			// Encrypt file with symmetric key
			Cipher AESCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			
			System.out.println("sending files...");
			AESCipher.init(Cipher.ENCRYPT_MODE, AESkey);
			for (int i = 0; i < counter; i++) {
				filename = args[i];
				encryptedBlock = AESCipher.doFinal(filename.getBytes());
				//send encryptedBlock to SecServer
				toServer.writeInt(0);
				toServer.writeInt(encryptedBlock.length);
				toServer.write(encryptedBlock);
				//toServer.flush();
				// Open the file
				fileInputStream = new FileInputStream(filename);
				bufferedFileInputStream = new BufferedInputStream(fileInputStream);

				byte [] fromFileBuffer = new byte[128];
				// Send the file
				
				for (boolean fileEnded = false; !fileEnded;) {
					//encrypt the file in blocks of 128 bytes
					numBytes = bufferedFileInputStream.read(fromFileBuffer);
					// LOOKHERE: Encrypt file chunk with symmetric key
					encryptedBlock = AESCipher.doFinal(fromFileBuffer);
					fileEnded = numBytes < 128;
					toServer.writeInt(1);
					toServer.writeInt(numBytes);
					toServer.write(encryptedBlock);
					//toServer.flush();
		
				}
				bufferedFileInputStream.close();
				fileInputStream.close();
	
			}
			
			System.out.println("Done transferring all files");
			

			try{
				while (true){
					int packetType = fromServer.readInt();
					if (packetType == 4){
						System.out.println("Closing connection...");
						//clientSocket.close();
						break;
					}
				}
			}catch(EOFException e){
				System.out.println("Closing connection...");
			}
		
			long timeTaken = System.nanoTime() - timeStarted;
			System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	
		} catch (Exception e) {e.printStackTrace();}

	}
}
