import java.awt.event.*;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import javax.swing.*;
import java.util.*;
import java.math.*;
import javax.crypto.Cipher;
import java.security.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.util.zip.GZIPOutputStream;

public class Client {
    static Cipher encryptcipher, decryptcipher;
    final int keySize = 2048;
    static JFrame frame;
    static JLabel label;
    static JButton button;
    static JTextField text;
    static JPanel panel;
    private static DataOutputStream dataOutputStream = null;
    private static DataInputStream dataInputStream = null;
   
    public static void main(String[] args) {

    	frame = new JFrame("File Transfer");
    	label = new JLabel("Enter the file name");
    	button = new JButton("Submit");
    	button.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e) {
               
                String s = text.getText();
                chooseFile(s);
            }

        });
    	text = new JTextField(15);
        panel = new JPanel();
        panel.setBounds(0, 75, 300, 250);
        panel.add(text);
        panel.add(button);
        panel.add(label);
        frame.add(panel);
        frame.setSize(350, 300);
        frame.setLayout(null);
        frame.setVisible(true);


    }
   
    public static void PGP(String path) throws Exception{

        String input = new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        
        KeyPairGenerator keyPairGenerator2 = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator2.initialize(2048);
        
        KeyPair keyPair1=keyPairGenerator.genKeyPair();
        KeyPair keyPair2=keyPairGenerator.genKeyPair();
        
        PrivateKey senderPrivateKey =  keyPair1.getPrivate();
        
        PublicKey receiverPubKey =  keyPair2.getPublic();
    
    
        try (FileOutputStream fos = new FileOutputStream("private.key")) {
        	fos.write(keyPair2.getPrivate().getEncoded());
        }
     
        try (FileOutputStream fos = new FileOutputStream("public.pub")) {
        	fos.write(keyPair1.getPublic().getEncoded() );
        }
    
    
        String hash ="";
        MessageDigest digest=MessageDigest.getInstance("SHA-512");
        digest.reset();
        digest.update(input.getBytes("utf8"));
        hash = String.format("%040x", new BigInteger(1, digest.digest()));
        Cipher cipher = Cipher.getInstance("RSA");
        
        cipher.init(Cipher.ENCRYPT_MODE,senderPrivateKey);  //auth
        
        byte[] utf8 =cipher.doFinal(hash.getBytes("UTF-8"));
        String encryptedPrivateHash= Base64.getEncoder().encodeToString(utf8);
        String beforeZip[]={input,encryptedPrivateHash};
        String afterZip[]=new String[beforeZip.length];
    
    
        for(int i=0;i<beforeZip.length;i++)
        {
        	ByteArrayOutputStream byteArrayOutputStream=new ByteArrayOutputStream(beforeZip[i].length());
        	GZIPOutputStream gZip=new GZIPOutputStream(byteArrayOutputStream);
        	gZip.write(beforeZip[i].getBytes());
        	gZip.close();
        	
        	byte[] compressed=byteArrayOutputStream.toByteArray();
        	
        	byteArrayOutputStream.close();
        	afterZip[i]=Base64.getEncoder().encodeToString(compressed);
        }
    
        SecretKey key=KeyGenerator.getInstance("DES").generateKey();
        
        String afterZipDES[]=new String[afterZip.length+1];
        for(int i=0;i<afterZip.length;i++)
        {
        	encryptcipher = Cipher.getInstance("DES");
        	
        	encryptcipher.init(Cipher.ENCRYPT_MODE, key);  //ziplenmis dosyayý DES key ile encrypt
        	
        	byte[] utf8str =afterZip[i].getBytes("UTF8");
        	byte[] encrypted = encryptcipher.doFinal(utf8str);
        	afterZipDES[i]=Base64.getEncoder().encodeToString(encrypted);
        }
    
        String encodedKey=Base64.getEncoder().encodeToString(key.getEncoded());
        Cipher cipher2 = Cipher.getInstance("RSA");
        
        cipher2.init(Cipher.ENCRYPT_MODE, receiverPubKey);  
        
        byte[] utf8new2 = cipher2.doFinal(encodedKey.getBytes("UTF-8"));
        String encryptedKey=Base64.getEncoder().encodeToString(utf8new2);

        afterZipDES[2]=encryptedKey;
    
        String messageToServer[]=afterZipDES;

        sendFile(messageToServer);

    }

        
    public static void chooseFile(String path) {
    	
    	try(Socket socket = new Socket("localhost",12347)) {
        	
    		dataInputStream = new DataInputStream(socket.getInputStream());
    		dataOutputStream = new DataOutputStream(socket.getOutputStream());
    		PGP(path);
    		dataInputStream.close();
            
    	}catch (Exception e){
    		e.printStackTrace();
    	}
    
    }

    private static void sendFile(String array[]) throws Exception{
    
        System.out.println(array[0]);
        System.out.println(array[1]);
        System.out.println(array[2]);
        byte[] data=array[0].getBytes("UTF-8");
        dataOutputStream.writeInt(data.length);
        dataOutputStream.write(data);

        byte[] hash=array[1].getBytes("UTF-8"); 
        dataOutputStream.writeInt(hash.length);
        dataOutputStream.write(hash);

        byte[] key=array[2].getBytes("UTF-8"); 
        dataOutputStream.writeInt(key.length);
        dataOutputStream.write(key);
        
    }

   

    
}