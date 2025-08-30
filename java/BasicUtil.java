package com.example.kutil6_yas;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.zip.CRC32;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// basic functions
public class BasicUtil {
    private ServerSocket svrSocket;
    private Socket cliSocket;
    public InputStream sin;
    public OutputStream sout;

    // little endian encode
    public byte[] Encode(long num) {
        byte[] res = new byte[8];
        for (int i = 0; i < 8; i++) {
            res[i] = (byte) (num % 256);
            num /= 256;
        }
        return res;
    }

    // little endian decode
    public long Decode(byte[] data) {
        long res = 0;
        for (int i = 7; i >= 0; i--) {
            res = res * 256 + (data[i] & 0xFF);
        }
        return res;
    }

    // Base64 encode
    public String B64en(byte[] data) {
        if (data == null) { return ""; }
        else { return Base64.getEncoder().encodeToString(data); }
    }

    // Base64 decode
    public byte[] B64de(String data) {
        try {
            return Base64.getDecoder().decode(data);
        } catch (Exception e) {
            return null;
        }
    }

    // generate random data
    public byte[] Genrand(int n) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[n];
        random.nextBytes(bytes);
        return bytes;
    }

    // CRC32 hash
    public long Crc32(byte[] data) {
        CRC32 crc32 = new CRC32();
        crc32.update(data);
        return crc32.getValue();
    }

    // SHA3-256 hash (requires bouncycastle)
    public byte[] Sha3256(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        return digest.digest(data);
    }

    // AES128 enc & dec, no padding
    byte[] Aes128(byte[] key, byte[] iv, byte[] data, boolean ispad, boolean isenc) throws Exception {
        Cipher cipher = null;
        if (ispad) { cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); }
        else { cipher = Cipher.getInstance("AES/CBC/NoPadding"); }
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        if (isenc) { cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec); }
        else { cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec); }
        return cipher.doFinal(data);
    }

    // get IP of device
    public String[] GetIP(int port) throws Exception {
        List<String> out = new ArrayList<>();
        List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
        for (NetworkInterface networkInterface : interfaces) {
            List<InetAddress> addresses = Collections.list(networkInterface.getInetAddresses());
            for (InetAddress address : addresses) {
                if (!address.isLoopbackAddress() && address.getHostAddress().contains(".")) {
                    out.add( String.format("%s:%d", address.getHostAddress(), port) );
                }
            }
        }
        return out.toArray(new String[0]);
    }

    // open socket
    public void OpenSocket(boolean isServer, String ip, int port) throws Exception {
        if (isServer) {
            this.svrSocket = new ServerSocket(port);
            this.cliSocket = this.svrSocket.accept();
        } else {
            this.cliSocket = new Socket(ip, port);
        }
        this.sin = new BufferedInputStream( this.cliSocket.getInputStream() );
        this.sout = new BufferedOutputStream( this.cliSocket.getOutputStream() );
    }

    // close socket
    public void CloseSocket() throws Exception {
        if (this.sin != null) {
            this.sin.close();
            this.sin = null;
        }
        if (this.sout != null) {
            this.sout.close();
            this.sout = null;
        }
        if (this.cliSocket != null) {
            this.cliSocket.close();
            this.cliSocket = null;
        }
        if (this.svrSocket != null) {
            this.svrSocket.close();
            this.svrSocket = null;
        }
    }
}