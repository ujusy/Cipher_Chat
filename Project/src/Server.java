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

public class Server {
    private ServerSocket serverSocket; //서버 소켓(서비스를 제공하기 위한 용도) 생성
    private Socket clientSocket;//들어오는 정보가 저장되는, 클라이언트와 통신을 위한 소켓

    private DataInputStream dataInputStream;//서버가 받은 데이터
    private DataOutputStream dataOutputStream;

    ObjectOutputStream sender = null;
    ObjectInputStream receiver = null;
    //1. 데이터를 지속적으로 송신해줄 스레드
    //2. 데이터를 지속적으로 수신해줄 스레드
    //이 두가지 작업을 지속적으로 해줄 스레드가 필요함

    public void serverSetting() {
        try {
            serverSocket = new ServerSocket(10004);//생성과 바인드. IP주소를 안주면 localhost가 default 값.
            clientSocket = serverSocket.accept(); // 어셉트의 결과로 클라이언트가 접속하면 해당 클라이언트를 관리할 소켓을 생성하여 리턴. 이걸  clientSocket에 받음.
            //실질적으로 소켓에 접속 완료된 시점

            System.out.println("클라이언트 소켓 연결");

        } catch (Exception e) {
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


            dataRecv(decryptKey1,decryptKey2,charset);
        }catch(Exception e) {
            e.printStackTrace();
        }
    }
    public void StreamSetting() {
        try {
            dataInputStream = new DataInputStream(clientSocket.getInputStream()); // clientSocket에 InputStream 객체를 연결
            dataOutputStream = new DataOutputStream(clientSocket.getOutputStream()); //clientSocket에 OutputStream 객체를 연결


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
                        String recvData = dataInputStream.readUTF();//연결된 InputSteram 객체의 readUTF 메소드를 호출하여 데이터 읽어들임
                        SimpleDateFormat formatter = new SimpleDateFormat ("yyyy-MM-dd hh:mm:ss");
                        Date date= new Date();
                        String today = formatter.format(date);
                        String recvData1 =recvData + " [" + today + "]";
                        System.out.println("Received : "+recvData1);
                        SecretKeySpec skeySpec = new SecretKeySpec(secretKey,0,secretKey.length ,"AES");
                        IvParameterSpec ivParameterSpec1 = new IvParameterSpec(ivParameterSpec);
                        byte[] encryptData = encrypt(skeySpec, ivParameterSpec1, recvData1.getBytes(charset));
                        System.out.println("Encrypted Message :"+bytesToHex(encryptData));
                        if(recvData.equals("exit"))
                            isThread = false;
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

    public void dataSend() {
        new Thread(new Runnable() {
            Scanner in = new Scanner(System.in);
            boolean isThread = true;
            @Override
            public void run() {
                while(isThread){
                    try {
                        System.out.print(">");
                        String sendData = in.nextLine();
                        dataOutputStream.writeUTF(sendData);//연결된 출력스트림에 메세지 실어보냄
                        if(sendData.equals("exit"))
                            isThread = false;
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
        //dataRecv();
        dataSend();
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
//    public static byte[] encrypt(byte[] secretKey,byte[] ivParameterSpec, byte[] encryptData) throws GeneralSecurityException {
//        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//        SecretKeySpec skeySpec = new SecretKeySpec(secretKey,0,secretKey.length, "AES");
//        IvParameterSpec ivParameterSpec1 = new IvParameterSpec(ivParameterSpec);
//        cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivParameterSpec1);
//        byte[] plainData = cipher.doFinal(encryptData);
//        return plainData;
//    }
    public static byte[] decrypt(SecretKey secretKey, IvParameterSpec
            ivParameterSpec, byte[] encryptData) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] plainData = cipher.doFinal(encryptData);
        return plainData;
    }
//    public static byte[] decrypt(byte[] secretKey,byte[] ivParameterSpec, byte[] encryptData) throws GeneralSecurityException {
//        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//        SecretKeySpec skeySpec = new SecretKeySpec(secretKey, "AES");
//        IvParameterSpec ivParameterSpec1 = new IvParameterSpec(ivParameterSpec);
//        cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivParameterSpec1);
//        byte[] plainData = cipher.doFinal(encryptData);
//        return plainData;
//    }
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