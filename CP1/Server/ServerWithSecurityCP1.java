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
import javax.crypto.Cipher;


public class ServerWithSecurityCP1 {

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
		int counter = 0;

		PrivateKey privKey = getPrivKey("private_key.der");
		PublicKey pubKey = getPubKey("public_key.der");

    	int port = 4321;
    	if (args.length > 0) port = Integer.parseInt(args[0]);

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		try {
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());

			while (!connectionSocket.isClosed()) {

				int packetType = fromClient.readInt();

				// If the packet is for transferring the filename
				if (packetType == 0) {

					System.out.println("Receiving file...");

					int numBytes = fromClient.readInt();
					byte [] filename = new byte[128];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(filename, 0, 128);
					Cipher rsaCipher = Cipher.getInstance("RSA"); 
					rsaCipher.init(Cipher.DECRYPT_MODE,privKey);
					byte[] decryptedBlock = rsaCipher.doFinal(filename);

					fileOutputStream = new FileOutputStream("recv_"+new String(decryptedBlock, 0, decryptedBlock.length));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {

					int numBytes = fromClient.readInt();
					byte [] block = new byte[128];
					fromClient.readFully(block, 0, 128);
					
					Cipher rsaCipher = Cipher.getInstance("RSA"); 
					rsaCipher.init(Cipher.DECRYPT_MODE,privKey);
					byte[] decryptedBlock = null;

					if(numBytes>0){
						decryptedBlock = rsaCipher.doFinal(block);
						bufferedFileOutputStream.write(decryptedBlock, 0, numBytes);
					}
					if (numBytes<117) {
						System.out.println("Closing connection...");
						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();
						fromClient.close();
						toClient.close();
						connectionSocket.close();
					}



				// if the package is for establishing connection
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
				}

			}
		} catch (Exception e) {e.printStackTrace();}

	}

}


 


