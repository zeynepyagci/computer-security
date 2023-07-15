import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.zip.GZIPInputStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Server {
    static Cipher encryptcipher, decryptcipher;
    private static DataOutputStream dataOutputStream = null;
    private static DataInputStream dataInputStream = null;

    public static void main(String[] args) {
        try(ServerSocket serverSocket = new ServerSocket(12347)){
            
            System.out.println("listening to port:12347");
            
            Socket clientSocket = serverSocket.accept();
            
            System.out.println(clientSocket+" connected.");
            
            dataInputStream = new DataInputStream(clientSocket.getInputStream());
            
            dataOutputStream = new DataOutputStream(clientSocket.getOutputStream());

            receiveFile();

            dataInputStream.close();
            dataOutputStream.close();
            clientSocket.close();
        } catch (Exception e){
            e.printStackTrace();
        }
    }
    private static void PGP(String data, String hash, String key) throws Exception
    {
        String[] message={data,hash,key};
        
        byte[] bytes = Files.readAllBytes(Paths.get("public.pub"));
        
        X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(ks);

        byte[] bytes2 = Files.readAllBytes(Paths.get("private.key"));
        
        PKCS8EncodedKeySpec ks2 = new PKCS8EncodedKeySpec(bytes2);
        
        KeyFactory kf2 = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf2.generatePrivate(ks2);

        byte[] encrypted=Base64.getDecoder().decode(key);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        
		byte[] utf8 = cipher.doFinal(encrypted);
        String eRecevierSecretKey=new String(utf8,"UTF8");
        
        byte[] dReceiverSecretKey = Base64.getDecoder().decode(eRecevierSecretKey);
        SecretKey originalKey = new SecretKeySpec(dReceiverSecretKey, 0, dReceiverSecretKey.length, "DES");
		String receiverdEcryptedMessage[] = new String[message.length-1];
        
		decryptcipher = Cipher.getInstance("DES");
		
		decryptcipher.init(Cipher.DECRYPT_MODE, originalKey);
		
        for(int i=0;i<message.length-1;i++)
        {
            byte[] dec=Base64.getDecoder().decode(message[i]);
            byte[] utf8_ = decryptcipher.doFinal(dec);  
            message[i]= new String(utf8_,"UTF8");
        }
        String unzippedString[]=new String[receiverdEcryptedMessage.length];

        File fout = new File("copy.txt");
        FileOutputStream fos = new FileOutputStream(fout);

        for(int i=0;i<unzippedString.length;i++)
        {
            byte[] compressed=Base64.getDecoder().decode(message[i]);
        	ByteArrayInputStream bais = new ByteArrayInputStream(compressed);
            GZIPInputStream gis = new GZIPInputStream(bais);
            BufferedReader br = new BufferedReader(new InputStreamReader(gis, "UTF-8"));
            StringBuilder sb = new StringBuilder();
            String line;
            
            while((line = br.readLine()) != null) {
                if(i==0)
                {
                    fos.write(line.getBytes("utf8"));
                    fos.write(10);
                    
                }
                sb.append(line);
            }
            fos.close();
            br.close();
            gis.close();
            bais.close();
            unzippedString[i]=sb.toString();
         }
         byte[] encrypted2=Base64.getDecoder().decode(unzippedString[1]);
         cipher.init(Cipher.DECRYPT_MODE,publicKey);
         byte[] utf8_2 = cipher.doFinal(encrypted2);
         String receivedHash=new String(utf8_2,"UTF8");

         MessageDigest digest = MessageDigest.getInstance("SHA-512");
		digest.reset();
		digest.update(unzippedString[0].getBytes("utf8"));
		String calculatedHash = String.format("%040x", new BigInteger(1, digest.digest()));

        if(receivedHash.equalsIgnoreCase(calculatedHash))
        {
            System.out.println("No Error!");
        }
    }

    private static void receiveFile() throws Exception{
        
        
        
        int length=dataInputStream.readInt();
        byte[] data_=new byte[length];
        dataInputStream.readFully(data_);
        String data =new String(data_,"UTF-8");

        System.out.println(data+"\n\n");
        
        int length2=dataInputStream.readInt();
        byte[] hash_=new byte[length2];
        dataInputStream.readFully(hash_);
        String hash=new String(hash_,"UTF-8");

        System.out.println(hash+"\n\n");
        
        int length3=dataInputStream.readInt();
        byte[] key_=new byte[length3];
        dataInputStream.readFully(key_);
        String key=new String(key_,"UTF-8");
        
        PGP(data,hash,key);
        
       
    }
}