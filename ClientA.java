import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;

public class ClientA
{
    public static byte[] S(byte[] s, int mode) throws Exception
    {
        System.out.println("Processing AES for Server.\nInitialising cipher...");
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] keybytes = { (byte) 0xff, (byte) 0x81, (byte) 0xcd, (byte) 0x46, (byte) 0xa9, (byte) 0xa9, (byte) 0x7b, (byte) 0xb6, (byte) 0x38, (byte) 0x9c, (byte) 0x7a, (byte) 0xce, (byte) 0x7c, (byte) 0x6b, (byte) 0xcf, (byte) 0x75 };
        SecretKeySpec key = new SecretKeySpec(keybytes, "AES");
        byte[] ivbytes = { (byte) 0x41, (byte) 0x78, (byte) 0xb6, (byte) 0x45, (byte) 0x9e, (byte) 0xff, (byte) 0xc1, (byte) 0xf4, (byte) 0x37, (byte) 0x37, (byte) 0x67, (byte) 0x77, (byte) 0x2d, (byte) 0x7d, (byte) 0x33, (byte) 0xf6 };
        IvParameterSpec iv = new IvParameterSpec(ivbytes);
        aes.init(mode, key, iv);
        System.out.println("Initialised.\nApplying AES...");

        return aes.doFinal(s);
    }

    public static byte[] B(byte[] s, byte[] keybytes, int mode) throws Exception
    {
        System.out.println("Processing AES for B.\nInitialising cipher...");
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(keybytes, "AES");
        byte[] ivbytes = { (byte) 0x41, (byte) 0x78, (byte) 0xb6, (byte) 0x45, (byte) 0x9e, (byte) 0xff, (byte) 0xc1, (byte) 0xf4, (byte) 0x37, (byte) 0x37, (byte) 0x67, (byte) 0x77, (byte) 0x2d, (byte) 0x7d, (byte) 0x33, (byte) 0xf6 };
        IvParameterSpec iv = new IvParameterSpec(ivbytes);
        aes.init(mode, key, iv);
        System.out.println("Initialised.\nApplying AES...");

        return aes.doFinal(s);
    }

    public static void main(String[] args) throws Exception
    {
        if(args.length != 4 && args.length != 5)
        {
            System.err.println("Invalid arguments.\nUsage: java ClientA <IP B> <port B> <IP S> <port S> [delta]");
            System.exit(0);
        }

        try
        {
            System.out.println("Initialising Denning-Sacco Protocol transaction...");
            int delta = (args.length == 5) ? Integer.parseInt(args[4]) : 60;
            System.out.println("\t[Delta = " + delta + "]\n\t[Server At: " + args[2] + ":" + args[3] + "]\n\t[Target At: " + args[0] + ":" + args[1] + "]\nInitialising connections...");
            Socket clientb = new Socket(args[0], Integer.parseInt(args[1]));
            System.out.println("Connected to Target!");
            Socket server = new Socket(args[2], Integer.parseInt(args[3]));
            System.out.println("Connected to Server!");

            DataInputStream clientb_reader = new DataInputStream(clientb.getInputStream());
            DataInputStream server_reader = new DataInputStream(server.getInputStream());

            DataOutputStream clientb_writer = new DataOutputStream(clientb.getOutputStream());
            DataOutputStream server_writer = new DataOutputStream(server.getOutputStream());

            byte[] message = S(TLV.merge(new TLV("Student").getBytes(), new TLV("Lecturer").getBytes()), Cipher.ENCRYPT_MODE);
            System.out.println("Encrypted.\nSending message...");
            server_writer.write(message, 0, message.length);
            System.out.println("Message sent.");

            System.out.println("Receiving message...");
            message = new byte[65536];
            int timestamp = (int) (System.currentTimeMillis() / 1000L);
            int cut = server_reader.read(message, 0, message.length);
            server.close();
            message = Arrays.copyOfRange(message, 0, cut);
            message = S(message, Cipher.DECRYPT_MODE);
            System.out.println("Received.");

            Object[] o = TLV.decode(message);

            if(((Integer) o[0]) < (timestamp - delta) || ((Integer) o[0]) > (timestamp + delta))
            {
                System.err.println("Invalid timestamp.\n\tCurrent: " + timestamp + "\n\tReceived: " + ((Integer) o[0]) + "\n\tDelta: " + delta);
                System.exit(0);
            }

            if(!"Lecturer".equals((String) o[1]))
            {
                System.err.println("Invalid B.\n\tExpected: Lecturer\n\tReceived: " + ((String) o[1]));
                System.exit(0);
            }

            byte[] bkey = (byte[]) o[2];
            byte[] bdata = (byte[]) o[3];

            System.out.println("Sending {T, A, k<A,B>} to B...");
            clientb_writer.write(bdata, 0, bdata.length);
            System.out.println("Sent.");

            System.out.print("Enter your message: ");
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            String m = br.readLine();

            byte[] tosend = B(new TLV(m).getBytes(), bkey, Cipher.ENCRYPT_MODE);

            System.out.println("Sending M1 to B...");
            clientb_writer.write(tosend, 0, tosend.length);
            System.out.println("Sent.");

            System.out.println("Receiving response...");
            message = new byte[65536];
            cut = clientb_reader.read(message, 0, message.length);
            System.out.println("Done.");

            message = Arrays.copyOfRange(message, 0, cut);
            message = B(message, bkey, Cipher.DECRYPT_MODE);

            o = TLV.decode(message);

            System.out.println("------------------------\n" + ((String) o[0]));

            clientb.close();

        }
        catch (Exception e)
        {
            System.err.println("An exception occurred.");
            e.printStackTrace();
            System.exit(0);
        }
    }
}


