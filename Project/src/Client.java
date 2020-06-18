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
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Formatter;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Calendar;

public class Client {
    private Socket clientSocket;
    private DataInputStream dataInputStream;
    private DataOutputStream dataOutputStream;
    private PublicKey publicKey = null;

    ObjectOutputStream sender = null;
    ObjectInputStream receiver = null;
    //1. 데이터를 지속적으로 송신해줄 스레드
    //2. 데이터를 지속적으로 수신해줄 스레드
    //이 두가지 작업을 지속적으로 해줄 스레드가 필요함 -> 두 개의 메소드에 스레드 생성
    public void connect() {
        try {
            System.out.println("접속 시도");
            clientSocket = new Socket("127.0.0.1",10004);
            System.out.println("접속 완료");

        } catch (Exception e) {
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
                        System.out.print(">");
                        String sendData = in.nextLine();
                        SimpleDateFormat formatter = new SimpleDateFormat ("yyyy-MM-dd hh:mm:ss");
                        Date date= new Date();
                        String today = formatter.format(date);
                        String sendData1 =sendData + " [" + today + "]";
                        byte[] encryptData = encrypt(secretKey, ivParameterSpec, sendData1.getBytes(charset));
                        dataOutputStream.writeUTF(encryptData.toString());
//                        if(sendData.equals("exit"))
//                            isThread = false;
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
                        String recvData = dataInputStream.readUTF();//연결된 InputSteram 객체의 readUTF 메소드를 호출하여 데이터 읽어들임
//                        SimpleDateFormat formatter = new SimpleDateFormat ("yyyy-MM-dd hh:mm:ss");
//                        Date date= new Date();
//                        String today = formatter.format(date);
//                        String recvData1 =recvData + " [" + today + "]";
//                        System.out.println("Received : "+recvData1);
//                        SecretKeySpec skeySpec = new SecretKeySpec(secretKey,0,secretKey.length ,"AES");
//                        IvParameterSpec ivParameterSpec1 = new IvParameterSpec(ivParameterSpec);
                        byte[] encryptData = decrypt(secretKey, ivParameterSpec, recvData.getBytes(charset));
                        System.out.println("Received : "+recvData);
                        System.out.println("Encrypted Message :"+bytesToHex(encryptData));
                        if(recvData.equals("exit"))
                        {
                            dataOutputStream.writeUTF("exit");
                            isThread = false;
                        }
                        else
                            System.out.print(">");

                    } catch (Exception e) {

                    }
                }
                closeAll();
                System.out.println("Connection closed.");
            }
        }).start();
    }
    public  void keySetting() {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            sender = new ObjectOutputStream(clientSocket.getOutputStream());
            receiver = new ObjectInputStream(clientSocket.getInputStream());
            publicKey = (PublicKey)receiver.readObject();
            System.out.println("서버로부터 받은 메세지 : " + publicKey);
            System.out.println("> Received Public Key  : " + bytesToHex(publicKey.getEncoded()));


            SecureRandom random = new SecureRandom();
            byte[] ivData = new byte[16]; // 128 bit
            random.nextBytes(ivData);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivData);
            Charset charset = Charset.forName("UTF-8");

            System.out.println("IV는: "+bytesToHex(ivParameterSpec.getIV()));

            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] printKey = secretKey.getEncoded();

            System.out.println("> Creating AES 256b key ...");
            System.out.println("AES 256 Key : "+bytesToHex(printKey));
            byte[] encryptKey1 = encrypt(publicKey, printKey);
            byte[] encryptKey2 = encrypt(publicKey, ivParameterSpec.getIV());
            System.out.println("Encrypted AES Key : "+bytesToHex(encryptKey1));
            System.out.println("Encrypted IV : "+bytesToHex(encryptKey2));
            sender.writeObject(encryptKey1);
            sender.writeObject(encryptKey2);
            dataRecv(secretKey,ivParameterSpec,charset);
            dataSend(secretKey,ivParameterSpec,charset);
            System.out.println();

        }catch(Exception e) {
            e.printStackTrace();
        }

    }
    public void StreamSetting() {
        try {
            dataInputStream = new DataInputStream(clientSocket.getInputStream()); // clientSocket에 InputStream 객체를 연결
            dataOutputStream = new DataOutputStream(clientSocket.getOutputStream()); //clientSocket에 OutputStream 객체를 연결

            System.out.println();
        }catch(Exception e) {
            e.printStackTrace();
        }
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
//        dataSend();
//        dataRecv();
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

    // RSA 암호화 함수
    public static byte[] encrypt(PublicKey publicKey, byte[] plainData)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptData = cipher.doFinal(plainData);
        return encryptData;
    }

    // RSA 복호화 함수
    public static byte[] decrypt(PrivateKey privateKey, byte[] encryptData)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plainData = cipher.doFinal(encryptData);
        return plainData;
    }
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);

        @SuppressWarnings("resource")
        Formatter formatter = new Formatter(sb);
        for (byte b : bytes) {
            formatter.format("%02x", b);
        }

        return sb.toString();
    }
}