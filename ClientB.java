import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ClientB
{

    public static byte[] A(byte[] a, byte[] keybytes, int mode) throws Exception
    {
        System.out.println("Processing AES for ClientA.\nInitialising cipher...");
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(keybytes, "AES");
        byte[] ivbytes = { (byte) 0x41, (byte) 0x78, (byte) 0xb6, (byte) 0x45, (byte) 0x9e, (byte) 0xff, (byte) 0xc1, (byte) 0xf4, (byte) 0x37, (byte) 0x37, (byte) 0x67, (byte) 0x77, (byte) 0x2d, (byte) 0x7d, (byte) 0x33, (byte) 0xf6 };
        IvParameterSpec iv = new IvParameterSpec(ivbytes);
        aes.init(mode, key, iv);
        System.out.println("Initialised.\nApplying AES...");

        return aes.doFinal(a);
    }

    public static byte[] S(byte[] b, int mode) throws Exception
    {
        System.out.println("Processing AES for Server.\nInitialising cipher...");
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

        if(args.length != 1 && args.length != 2)
        {
            System.err.println("Invalid arguments.\nUsage: java ClientB <port S> [delta]");
            System.exit(0);
        }

        int d = (args.length == 2) ? Integer.parseInt(args[1]) : 60;
        System.out.println("Beginning Denning-Sacco ClientB...\n\t[Delta: " + d + "]\nCtrl-C to quit.");

        try
        {
            ServerSocket s = new ServerSocket(Integer.parseInt(args[0]));

            while(true)
            {
                System.out.println("Listening...");
                Socket socket = s.accept();
                System.out.println("Connection accepted!");
                new ClientThread(socket, d).start();
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

class ClientThread extends Thread
{
    private DataInputStream _in;
    private DataOutputStream _out;
    private Socket _incoming;
    private int _delta;

    public ClientThread(Socket i, int d) throws Exception
    {
        System.out.println("Creating new thread...");
        this._incoming = i;
        this._in = new DataInputStream(i.getInputStream());
        this._out = new DataOutputStream(i.getOutputStream());
        this._delta = d;
        System.out.println("Created.\nBeginning communication...");
    }

    public void run()
    {
        try
        {
            System.out.println("Receiving session key...");
            byte[] message = new byte[65536];
            int timestamp = (int) (System.currentTimeMillis() / 1000L);
            int cut = this._in.read(message, 0, 65535);
            System.out.println("Received.");
            message = Arrays.copyOfRange(message, 0, cut);

            Object[] o = TLV.decode(ClientB.S(message, Cipher.DECRYPT_MODE));

            if(((Integer) o[0]) < (timestamp - this._delta) || ((Integer) o[0]) > (timestamp + this._delta))
            {
                System.err.println("Invalid timestamp.\n\tCurrent: " + timestamp + "\n\tReceived: " + ((Integer) o[0]) + "\n\tDelta: " + this._delta);
                System.exit(0);
            }

            if(!"Student".equals((String) o[1]))
            {
                System.err.println("Invalid B.\n\tExpected: Student\n\tReceived: " + ((String) o[1]));
                System.exit(0);
            }

            byte[] akey = (byte[]) o[2];

            System.out.println("Receiving message...");
            message = new byte[65536];
            cut = this._in.read(message, 0, 65535);
            System.out.println("Received.");
            message = Arrays.copyOfRange(message, 0, cut);

            Object[] tmp_m_1 = TLV.decode(ClientB.A(message, akey, Cipher.DECRYPT_MODE));
            System.out.println("Decrypted.");

            String m1 = (String) tmp_m_1[0];

            System.out.println("Inverting message...");
            byte[] response = ClientB.A(new TLV(new StringBuffer(m1).reverse().toString()).getBytes(), akey, Cipher.ENCRYPT_MODE);
            System.out.println("Encrypted.\nInverted.");

            System.out.println("Writing response...");
            this._out.write(response, 0, response.length);
            System.out.println("Done.");

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

