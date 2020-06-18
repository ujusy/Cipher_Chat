import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.charset.Charset;
import java.util.Date;
import java.util.Scanner;
import java.nio.*;
import java.security.*;
import java.security.KeyFactory;
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


public class Client {
    private Socket clientSocket;
    private DataInputStream dataInputStream;
    private DataOutputStream dataOutputStream;
    private PublicKey publicKey = null;

    ObjectOutputStream sender = null;
    ObjectInputStream receiver = null;

    public void connect() {
        try {
            clientSocket = new Socket("127.0.0.1",10004);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public  void keySetting() {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            sender = new ObjectOutputStream(clientSocket.getOutputStream());
            receiver = new ObjectInputStream(clientSocket.getInputStream());
            publicKey = (PublicKey)receiver.readObject();

            System.out.println("> Received Public Key  : " + bytesToHex(publicKey.getEncoded()));


            SecureRandom random = new SecureRandom();
            byte[] ivData = new byte[16];
            random.nextBytes(ivData);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivData);
            Charset charset = Charset.forName("UTF-8");



            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] printKey = secretKey.getEncoded();
            System.out.println();
            System.out.println("> Creating AES 256b key ...");
            System.out.println("IV: "+bytesToHex(ivParameterSpec.getIV()));
            System.out.println();
            System.out.println("AES 256 Key : "+bytesToHex(printKey));
            byte[] encryptKey1 = encrypt(publicKey, printKey);
            byte[] encryptKey2 = encrypt(publicKey, ivParameterSpec.getIV());
            sender.writeObject(encryptKey1);
            sender.writeObject(encryptKey2);
            System.out.println();
            System.out.println("Encrypted AES Key : "+bytesToHex(encryptKey1));
            System.out.println("Encrypted IV : "+bytesToHex(encryptKey2));

            dataSend(secretKey,ivParameterSpec,charset);
            dataRecv(secretKey,ivParameterSpec,charset);


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

    public void dataSend(SecretKey secretKey,IvParameterSpec
            ivParameterSpec,Charset charset) {
        new Thread(new Runnable() {
            Scanner in = new Scanner(System.in);
            boolean isThread = true;
            @Override
            public void run() {
                while(isThread){
                    try {
                        System.out.println();
                        System.out.println();
                        System.out.print(">");
                        String sendData = in.nextLine();
                        SimpleDateFormat formatter = new SimpleDateFormat ("yyyy-MM-dd hh:mm:ss");
                        Date date= new Date();
                        String today = formatter.format(date);
                        String sendData1 ="\""+sendData + "\"" + " [" + today + "]";
                        byte[] encryptData = encrypt(secretKey, ivParameterSpec, sendData1.getBytes(charset));
                        sender.writeObject(encryptData);
                    } catch (Exception e) {
                    }
                }
            }
        }).start();
    }

    public void dataRecv(SecretKey secretKey,IvParameterSpec
            ivParameterSpec,Charset charset) {
        new Thread(new Runnable() {
            boolean isThread = true;
            @Override
            public void run() {
                while(isThread) {
                    try {
                        byte[] recvData = (byte[])receiver.readObject();
                        byte[] decryptData = decrypt(secretKey, ivParameterSpec, recvData);
                        String str = new String(decryptData,"UTF-8");
                        String result = str.substring(1,5);
                        if(result.equals("exit"))
                        {
                            SimpleDateFormat formatter = new SimpleDateFormat ("yyyy-MM-dd hh:mm:ss");
                            Date date= new Date();
                            String today = formatter.format(date);
                            String sendData1 ="\""+result + "\"" + " [" + today + "]";
                            byte[] encryptData = encrypt(secretKey, ivParameterSpec, sendData1.getBytes(charset));
                            System.out.println("Received : "+str);
                            System.out.println("Encrypted Message :"+ "\""+bytesToHex(decryptData)+"\"");
                            sender.writeObject(encryptData);
                            isThread = false;
                        }
                        else{
                            System.out.println("Received : "+str);
                            System.out.println("Encrypted Message :"+ "\""+bytesToHex(decryptData)+"\"");
                            System.out.println();
                            System.out.println();
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


    public void closeAll() {
        try {
            //소켓 사용 후 반납
            sender.close();
            receiver.close();
            clientSocket.close();
            dataInputStream.close();
            dataOutputStream.close();
        }catch(Exception e) {
            e.printStackTrace();
        }
    }

    public Client() {
        connect();
        keySetting();
        StreamSetting();

    }


    public static void main(String[] args) {
        new Client();
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