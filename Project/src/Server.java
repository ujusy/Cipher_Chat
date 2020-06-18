import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.util.Date;
import java.util.Scanner;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Formatter;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;


public class Server {
    private ServerSocket serverSocket;
    private Socket clientSocket;


    //서버 소켓(서비스를 제공하기 위한 용도) 생성
    //들어오는 정보가 저장되는, 클라이언트와 통신을 위한 소켓

    private DataInputStream dataInputStream;
    private DataOutputStream dataOutputStream;

    ObjectOutputStream sender = null;
    ObjectInputStream receiver = null;

    public void serverSetting() {
        try {

            serverSocket = new ServerSocket(10004);
            clientSocket = serverSocket.accept();
            System.out.println("클라이언트 소켓 연결");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void closeAll() {
        try {
            sender.close();
            receiver.close();
            clientSocket.close();
            dataInputStream.close();
            dataOutputStream.close();
            serverSocket.close();
        }catch(Exception e) {
            e.printStackTrace();
        }
    }
    public void  keySetting() {
        try {
            sender = new ObjectOutputStream(clientSocket.getOutputStream());
            receiver = new ObjectInputStream(clientSocket.getInputStream());

            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            Charset charset = Charset.forName("UTF-8");
            KeyPair pair = generator.generateKeyPair();
            PublicKey publicKey = pair.getPublic();
            PrivateKey privateKey = pair.getPrivate();
            System.out.println("공개키 포맷 : " + publicKey.getFormat());
            System.out.println("개인키 포맷 : " + privateKey.getFormat());
            System.out.println("> Creating RSA key Pair ...");
            System.out.println("Private Key: "+bytesToHex(privateKey.getEncoded()));
            System.out.println("Public Key: "+bytesToHex(publicKey.getEncoded()));

            byte[] publicKeyBytes = publicKey.getEncoded();
            byte[] privateKeyBytes = privateKey.getEncoded();

            sender.writeObject(publicKey);
            System.out.println(" 데이터를 전송했습니다.");
//            SecretKey secretKey = (SecretKey)receiver.readObject();
            byte[] encryptKey1 = (byte[])receiver.readObject();
//            IvParameterSpec ivParameterSpec =(IvParameterSpec)receiver.readObject();
            byte[] encryptKey2 = (byte[])receiver.readObject();
            System.out.println("> Received AES Key : "+bytesToHex(encryptKey1));
            System.out.println("> Received IV : "+bytesToHex(encryptKey2));
            byte[] decryptKey1 = decrypt(privateKey, encryptKey1);
            System.out.println("Decrypted AES Key : "+bytesToHex(decryptKey1));
            byte[] decryptKey2 = decrypt(privateKey, encryptKey2);
            System.out.println("Decrypted IV : "+bytesToHex(decryptKey2));

            dataSend(decryptKey1,decryptKey2,charset);
            dataRecv(decryptKey1,decryptKey2,charset);
        }catch(Exception e) {
            e.printStackTrace();
        }
    }
    public void StreamSetting() {
        try {
            dataInputStream = new DataInputStream(clientSocket.getInputStream());
            dataOutputStream = new DataOutputStream(clientSocket.getOutputStream());


        }catch(Exception e) {
            e.printStackTrace();
        }
    }

    public void dataRecv(byte[] secretKey,byte[] ivParameterSpec,Charset charset) {
        new Thread(new Runnable() {
            boolean isThread = true;
            @Override
            public void run() {
                while(isThread) {
                    try {
                        byte[] recvData = (byte[])receiver.readObject();

                        SecretKeySpec skeySpec = new SecretKeySpec(secretKey,0,secretKey.length ,"AES");
                        IvParameterSpec ivParameterSpec1 = new IvParameterSpec(ivParameterSpec);

                        byte[] decryptData = decrypt(skeySpec, ivParameterSpec1, recvData);
                        String str = new String(decryptData,"UTF-8");
                        String result = str.substring(1,5);
                        if(result.equals("exit"))
                        {
                            SimpleDateFormat formatter = new SimpleDateFormat ("yyyy-MM-dd hh:mm:ss");
                            Date date= new Date();
                            String today = formatter.format(date);
                            String sendData1 ="\""+result + "\"" + " [" + today + "]";
                            byte[] encryptData = encrypt(skeySpec, ivParameterSpec1, sendData1.getBytes(charset));
                            System.out.println("Received : "+str);
                            System.out.println("Encrypted Message :"+ "\""+bytesToHex(decryptData)+"\"");
                            sender.writeObject(encryptData);
                            isThread = false;
                        }
                        else{
                            System.out.println("Received : "+str);
                            System.out.println("Encrypted Message :"+ "\""+bytesToHex(decryptData)+"\"");
                            System.out.print(">");
                        }


                    } catch (Exception e) {
                    }
                }
                closeAll();
                System.out.println("Connection closed.");
            }

        }).start();
    }

    public void dataSend(byte[] secretKey,byte[] ivParameterSpec,Charset charset) {
        new Thread(new Runnable() {
            Scanner in = new Scanner(System.in);
            boolean isThread = true;
            @Override
            public void run() {
                while(isThread){
                    try {
                        System.out.print(">");
                        String sendData = in.nextLine();
                        SimpleDateFormat formatter = new SimpleDateFormat ("yyyy-MM-dd hh:mm:ss");
                        Date date= new Date();
                        String today = formatter.format(date);
                        String sendData1 ="\""+sendData + "\"" + " [" + today + "]";
                        SecretKeySpec skeySpec = new SecretKeySpec(secretKey,0,secretKey.length ,"AES");
                        IvParameterSpec ivParameterSpec1 = new IvParameterSpec(ivParameterSpec);
                        byte[] encryptData = encrypt(skeySpec, ivParameterSpec1, sendData1.getBytes(charset));
                        sender.writeObject(encryptData);
                    } catch (Exception e) {
                    }
                }
            }
        }).start();
    }

    public Server() {
        serverSetting();
        keySetting();
        StreamSetting();
    }
    public static void main(String[] args) {
        new Server();
    }
    public static byte[] encrypt(SecretKey secretKey, IvParameterSpec
            ivParameterSpec, byte[] plainData) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptData = cipher.doFinal(plainData);
        return encryptData;
    }

    public static byte[] decrypt(SecretKey secretKey, IvParameterSpec
            ivParameterSpec, byte[] encryptData) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] plainData = cipher.doFinal(encryptData);
        return plainData;
    }

    public static byte[] encrypt(PublicKey publicKey, byte[] plainData)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptData = cipher.doFinal(plainData);
        return encryptData;
    }

    public static byte[] decrypt(PrivateKey privateKey, byte[] encryptData)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plainData = cipher.doFinal(encryptData);
        return plainData;
    }


    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);

        Formatter formatter = new Formatter(sb);
        for (byte b : bytes) {
            formatter.format("%02x", b);
        }

        return sb.toString();
    }
}