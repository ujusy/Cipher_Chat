# Cipher_Chat

---------

본 프로젝트는 암호화 채팅 프로젝트를 구현한 프로젝트이다.

### GOAL

>1. 소켓 프로그래밍을 위한 통신 프로그램 구현
>2. 대칭키 분배를 위한 RSA 사용
>3. 분배한 키를 기준으로 AES-256 암호화를 수행하여 안전한 통신 구현

### Structure

<img width="518" alt="image-20200708211852231" src="https://user-images.githubusercontent.com/49120090/86920383-b07b9180-c164-11ea-96a6-f15030c23381.png">

### Detail Implementation

>1. 소켓 프로그래밍을 이용해 Server와 Client 양방향 통신이 가능.
>2. Server가 RSA 공개키/ 개인키 쌍(2048bit)을 생성하여 Client에게 공개키를 전송한다. 
>3. Client는 AES 비밀키(256bit)를 생성하고 이를 받은 RSA 공개키로 암호화 하여 Server에게 전송한다.
>4. Server는 암호화된 AES 비밀키를 개인키로 복호화 한다.
>5. AES를 통한 암호화 통신을 하는데 RSA를 이용해 공유된 AES 비밀키를 이용해 통신한다. 
>6. AES256 을 사용하여 CBC Mode를 사용하며 블록 크기를 맞추기 위해 PKCS7 패딩을 사용한다. 
>7. 암호화 통신은 평문과 암호문 타임 스탬프를 함께 출력한다. 

### Developement ISSUE

>##### 1. Key 교환을 위한 Stream -> DataInputStream vs ObjectStream
>
>처음에는 소켓 프로그래밍을 이용해 채팅 프로그램을 작성 하여 DataInputStream을 사용하였다. 그러나 DataInputStream을 통해서는 바이트나 객체를 주고 받기 힘들었다. 그리하여 객체 혹은 바이트를 주고 받을 수 있는 ObjectStream사용해주어 키 교환을 진행하였다.
>
>##### 2. timeStamp 얻기
>
>Date 객체를 사용하였다.
>
>```java
>SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
>Date date = new Date();
>String today = formatter.format(date);
>```
>
>##### 3. Ping Pong 처럼 왔다 갔다하는 채팅 구조가 아님 자유롭게 데이터 송수신 가능하도록.
>
>java thread를 이용하여 구현해 주었다. 

#### Result

1. Server.java

   >- RSA Key pair 출력(Client 접속 후)
   >
   >  <img width="1624" alt="image-20200708214423559" src="https://user-images.githubusercontent.com/49120090/86920420-bcffea00-c164-11ea-8ce0-189d7e559861.png">

2. Client.java

   >+ Client 접속 후
   >
   >  <img width="785" alt="image-20200708214536418" src="https://user-images.githubusercontent.com/49120090/86920442-c5f0bb80-c164-11ea-8fa1-41a390d61aec.png">

   3. 통신

     ><img width="788" alt="image-20200708214615531" src="https://user-images.githubusercontent.com/49120090/86920461-ce48f680-c164-11ea-9ada-7da2060fbe4c.png">

   

