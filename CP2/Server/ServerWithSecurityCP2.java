import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class ServerWithSecurityCP2 {

	public static PrivateKey getPrivKey(String filename) throws Exception { 
	  byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
	  PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
	  KeyFactory kf = KeyFactory.getInstance("RSA");
	  return kf.generatePrivate(spec);
	}

	public static PublicKey getPubKey(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
  	}



	public static void main(String[] args) throws Exception {
		Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); 
		byte[] decryptedBlock = null;
		int count = 0;
		int done = 0;
    	int port = 4321;
    	if (args.length > 0) port = Integer.parseInt(args[0]);

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		SecretKey AESKey= null;

		try {
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());

			while (!connectionSocket.isClosed()) {


				int packetType = fromClient.readInt();
				PrivateKey privKey = getPrivKey("private_key.der");

				// If the packet is for transferring the filename
				if (packetType == 0) {


					int numBytes = fromClient.readInt();
					byte [] filename = new byte[numBytes];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(filename, 0, numBytes);
					aesCipher.init(Cipher.DECRYPT_MODE,AESKey);
					decryptedBlock = aesCipher.doFinal(filename);
					
					System.out.println("Receiving " + new String(decryptedBlock, 0, decryptedBlock.length));

					fileOutputStream = new FileOutputStream("recv_"+new String(decryptedBlock, 0, decryptedBlock.length));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {

					int numBytes = fromClient.readInt();
					byte [] block = new byte[144];
					fromClient.readFully(block, 0, 144);

					if (numBytes > 0)
						//LOOKHERE: Decrypt file chunks with symmetric key
						decryptedBlock = aesCipher.doFinal(block);
						bufferedFileOutputStream.write(decryptedBlock, 0, numBytes);

					if (numBytes< 128 && done < count){
						done++;
						System.out.println("file is fully received.");
						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();
					}
					if (numBytes < 128 && count == done) {
						System.out.println("Closing connection...");
						toClient.writeInt(4);
						fromClient.close();
						toClient.close();
						connectionSocket.close();
					}
					
				}else if (packetType ==2){
					int numBytes = fromClient.readInt();
					byte[] block = new byte[numBytes];
					fromClient.readFully(block, 0, numBytes);
					System.out.println("Client says: " + new String(block));
					
					
					Cipher rsaCipher = Cipher.getInstance("RSA"); 
					rsaCipher.init(Cipher.ENCRYPT_MODE, privKey);
					byte[] encryptedBlock = rsaCipher.doFinal(block);
					System.out.println("Sending to Client the encrypted nonce. ");

					toClient.writeInt(2);
					toClient.writeInt(encryptedBlock.length);
					toClient.write(encryptedBlock);

					String msg = null;
					while(msg == null){
						packetType = fromClient.readInt();
						if (packetType == 2){
							numBytes = fromClient.readInt();
							block = new byte[numBytes];
							fromClient.readFully(block, 0, numBytes);
							System.out.println("Client says: " + new String(block));
							// Send the filename
							String filename = "example-bd710400-8079-11ea-ae9d-89114163ae84.crt";
							toClient.writeInt(0);
							toClient.writeInt(filename.getBytes().length);
							toClient.write(filename.getBytes());
				

							// Open the file
							FileInputStream fileInputStream = new FileInputStream(filename);
							BufferedInputStream bufferedFileInputStream = new BufferedInputStream(fileInputStream);

							byte [] fromFileBuffer = new byte[117];
									
							// Send the file
							for (boolean fileEnded = false; !fileEnded;) {
								numBytes = bufferedFileInputStream.read(fromFileBuffer);
								fileEnded = numBytes < 117;
								toClient.writeInt(1);
								toClient.writeInt(numBytes);
								toClient.write(fromFileBuffer);
								toClient.flush();
							}

							bufferedFileInputStream.close();
							fileInputStream.close();
							System.out.println("Sent the CA-verified certificate");
							
							msg = "Sent cert";
							toClient.writeInt(2);
							toClient.writeInt(msg.getBytes().length);
							toClient.write(msg.getBytes());

							break;
						}
					}
					
				}else if (packetType ==3){
					System.out.println("Receiving AES Key");
					int numBytes = fromClient.readInt();
					byte[] block = new byte[numBytes];
					fromClient.readFully(block, 0, numBytes);
					//LOOKHERE: Decrypt symmetric key with private key
					Cipher rsaCipher = Cipher.getInstance("RSA"); 
					rsaCipher.init(Cipher.DECRYPT_MODE, privKey);
					byte[] decodedBlock = rsaCipher.doFinal(block);
					// decode the base64 encoded string
					AESKey = new SecretKeySpec(decodedBlock,0,decodedBlock.length, "AES");					
					// rebuild key using SecretKeySpec
				}
				else if(packetType == 1234){
					count = fromClient.readInt();
					System.out.println("There are " + count + " number of files to receive.");
				}

			}
		} catch (Exception e) {e.printStackTrace();}

	}

}


 


