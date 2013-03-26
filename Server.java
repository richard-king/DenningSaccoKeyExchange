import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/*
 * DS Key for A = { (byte) 0xff, (byte) 0x81, (byte) 0xcd, (byte) 0x46, (byte) 0xa9, (byte) 0xa9, (byte) 0x7b, (byte) 0xb6, (byte) 0x38, (byte) 0x9c, (byte) 0x7a, (byte) 0xce, (byte) 0x7c, (byte) 0x6b, (byte) 0xcf, (byte) 0x75 };
 * DS  IV for A = { (byte) 0x41, (byte) 0x78, (byte) 0xb6, (byte) 0x45, (byte) 0x9e, (byte) 0xff, (byte) 0xc1, (byte) 0xf4, (byte) 0x37, (byte) 0x37, (byte) 0x67, (byte) 0x77, (byte) 0x2d, (byte) 0x7d, (byte) 0x33, (byte) 0xf6 };
 * DS Key for B = { (byte) 0x45, (byte) 0x6b, (byte) 0x1d, (byte) 0x8e, (byte) 0x81, (byte) 0x2a, (byte) 0xf3, (byte) 0x3c, (byte) 0x60, (byte) 0xf1, (byte) 0x4b, (byte) 0x31, (byte) 0x45, (byte) 0x21, (byte) 0xfc, (byte) 0xdb };
 * DS  IV for B = { (byte) 0x41, (byte) 0x23, (byte) 0xb6, (byte) 0x00, (byte) 0x9e, (byte) 0xff, (byte) 0xc1, (byte) 0xf4, (byte) 0x67, (byte) 0x34, (byte) 0x67, (byte) 0x23, (byte) 0x2d, (byte) 0xdd, (byte) 0x11, (byte) 0xf6 };
 * DS  IV for Session = { (byte) 0x41, (byte) 0x78, (byte) 0xb6, (byte) 0x00, (byte) 0x9e, (byte) 0xff, (byte) 0xc1, (byte) 0xf4, (byte) 0x37, (byte) 0x34, (byte) 0x67, (byte) 0x23, (byte) 0x2d, (byte) 0xdd, (byte) 0x33, (byte) 0xf6 };
 */

public class Server
{

    public static byte[] A(byte[] a, int mode) throws Exception
    {
        System.out.println("Processing AES for ClientA.\nInitialising cipher...");
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] keybytes = { (byte) 0xff, (byte) 0x81, (byte) 0xcd, (byte) 0x46, (byte) 0xa9, (byte) 0xa9, (byte) 0x7b, (byte) 0xb6, (byte) 0x38, (byte) 0x9c, (byte) 0x7a, (byte) 0xce, (byte) 0x7c, (byte) 0x6b, (byte) 0xcf, (byte) 0x75 };
        SecretKeySpec key = new SecretKeySpec(keybytes, "AES");
        byte[] ivbytes = { (byte) 0x41, (byte) 0x78, (byte) 0xb6, (byte) 0x45, (byte) 0x9e, (byte) 0xff, (byte) 0xc1, (byte) 0xf4, (byte) 0x37, (byte) 0x37, (byte) 0x67, (byte) 0x77, (byte) 0x2d, (byte) 0x7d, (byte) 0x33, (byte) 0xf6 };
        IvParameterSpec iv = new IvParameterSpec(ivbytes);
        aes.init(mode, key, iv);
        System.out.println("Initialised.\nApplying AES...");

        return aes.doFinal(a);
    }

    public static byte[] B(byte[] b, int mode) throws Exception
    {
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] keybytes = { (byte) 0x45, (byte) 0x6b, (byte) 0x1d, (byte) 0x8e, (byte) 0x81, (byte) 0x2a, (byte) 0xf3, (byte) 0x3c, (byte) 0x60, (byte) 0xf1, (byte) 0x4b, (byte) 0x31, (byte) 0x45, (byte) 0x21, (byte) 0xfc, (byte) 0xdb };
        SecretKeySpec key = new SecretKeySpec(keybytes, "AES");
        byte[] ivbytes = { (byte) 0x41, (byte) 0x23, (byte) 0xb6, (byte) 0x00, (byte) 0x9e, (byte) 0xff, (byte) 0xc1, (byte) 0xf4, (byte) 0x67, (byte) 0x34, (byte) 0x67, (byte) 0x23, (byte) 0x2d, (byte) 0xdd, (byte) 0x11, (byte) 0xf6 };
        IvParameterSpec iv = new IvParameterSpec(ivbytes);
        aes.init(mode, key, iv);
        System.out.println("Initialised.\nApplying AES...");

        return aes.doFinal(b);
    }

    public static void main(String[] args)
    {

        if(args.length != 1)
        {
            System.err.println("Invalid arguments.\nUsage: java Server <port S>");
            System.exit(0);
        }

        System.out.println("Beginning Denning-Sacco server...\nCtrl-C to quit.");

        try
        {
            ServerSocket s = new ServerSocket(Integer.parseInt(args[0]));

            while(true)
            {
                System.out.println("Listening...");
                Socket socket = s.accept();
                System.out.println("Connection accepted!");
                new ServerThread(socket).start();
            }
        }
        catch (Exception e)
        {
            System.err.println("An exception occurred.");
            e.printStackTrace();
            System.exit(0);
        }
    }
}

class ServerThread extends Thread
{
    private DataInputStream _in;
    private DataOutputStream _out;
    private Socket _incoming;

    public ServerThread(Socket i) throws Exception
    {
        System.out.println("Creating new thread...");
        this._incoming = i;
        this._in = new DataInputStream(i.getInputStream());
        this._out = new DataOutputStream(i.getOutputStream());
        System.out.println("Created.\nBeginning communication...");
    }

    public void run()
    {
        try
        {
            System.out.println("Receiving message...");
            byte[] message = new byte[65536];
            int cut = this._in.read(message, 0, 65535);
            System.out.println("Received.");
            message = Arrays.copyOfRange(message, 0, cut);
            message = Server.A(message, Cipher.DECRYPT_MODE);
            System.out.print("Decrypted.\n");
            Object[] o = TLV.decode(message);
            String a = (String) o[0];
            String b = (String) o[1];
            System.out.println("A: " + a + "; B: " + b);
            int timestamp = (int) (System.currentTimeMillis() / 1000L);
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(128);
            SecretKey key = keygen.generateKey();
            byte[] payload = Server.A(
                                TLV.merge(
                                    new TLV(timestamp).getBytes(),
                                    TLV.merge(
                                        new TLV(b).getBytes(),
                                        TLV.merge(
                                            new TLV(key.getEncoded(), false).getBytes(),
                                            new TLV(
                                                Server.B(
                                                    TLV.merge(
                                                        new TLV(timestamp).getBytes(),
                                                        TLV.merge(
                                                            new TLV(a).getBytes(),
                                                            new TLV(key.getEncoded(), false).getBytes()
                                                        )
                                                    ),
                                                    Cipher.ENCRYPT_MODE),
                                                false).getBytes()
                                        )
                                    )
                                ),
                                Cipher.ENCRYPT_MODE
                            );
            this._out.write(payload, 0, payload.length);
            this._incoming.close();
            System.out.println("Communication complete.\nConnection closed.");
        }
        catch (Exception e)
        {
            System.err.println("An exception occurred.");
            e.printStackTrace();
            System.exit(0);
        }
    }


}

