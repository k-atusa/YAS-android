package com.example.kutil6_yas;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

// abstract file encrypt & decrypt
public class EncryptUtil {
    private int count;
    private BasicUtil bu;
    private FileUtil io;
    public EncryptUtil(BasicUtil b, FileUtil f) {
        this.bu = b;
        this.io = f;
    }

    // android dependent reader
    public InputStream DependentReader(String name, boolean isLocal) throws Exception  {
        if (isLocal) { return new FileInputStream(this.io.GetLocalFile(name)); }
        else { return this.io.context.getContentResolver().openInputStream(this.io.GetDownloadsFile(name)); }
    }

    // android dependent writer
    public OutputStream DependentWriter(String name, boolean isLocal) throws Exception {
        if (isLocal) { return new FileOutputStream(this.io.GetLocalFile(name)); }
        else { return this.io.context.getContentResolver().openOutputStream(this.io.GetDownloadsFile(name)); }
    }

    // android dependent filesize of local
    public long DependentFilesize(String name) {
        return this.io.GetFileSize(this.io.GetLocalFile(name));
    }

    // join bytes
    private byte[] append(byte[] a, byte[] b) {
        byte[] res = new byte[a.length + b.length];
        System.arraycopy(a, 0, res, 0, a.length);
        System.arraycopy(b, 0, res, a.length, b.length);
        return res;
    }

    // padding & unpadding
    private byte[] pad(byte[] data, boolean ispad) {
        if (ispad) {
            int padlen = 16 - data.length % 16;
            byte[] res = new byte[data.length + padlen];
            System.arraycopy(data, 0, res, 0, data.length);
            for (int i = data.length; i < res.length; i++) { res[i] = (byte) padlen; }
            return res;
        } else {
            int padlen = data[data.length - 1] & 0xFF;
            return Arrays.copyOfRange(data, 0, data.length - padlen);
        }
    }

    // key expand inline
    private byte[] expkey(byte[] pre, byte[] sub) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        byte[] res = sub;
        for (int i = 0; i < 10000; i++) { res = digest.digest(append(pre, res)); }
        return res;
    }

    // key expand (get key/iv)
    private byte[][] getkey(byte[] ckey) throws Exception {
        byte[][] order = new byte[16][];
        byte[][] res = new byte[32][];
        ExecutorService ex = Executors.newFixedThreadPool(16);

        for (int i = 0; i < 16; i++) {
            int temp = (7 * i) % 16; // round st point
            byte[] pre;
            byte[] sub;
            if (temp > 8) {
                pre = Arrays.copyOfRange(ckey, 8 * temp - 64, 8 * temp);
                sub = append(Arrays.copyOfRange(ckey, 8 * temp, ckey.length), Arrays.copyOfRange(ckey, 0, 8 * temp - 64));
            } else {
                pre = append(Arrays.copyOfRange(ckey, 8 * temp + 64, ckey.length), Arrays.copyOfRange(ckey, 0, 8 * temp));
                sub = Arrays.copyOfRange(ckey, 8 * temp, 8 * temp + 64);
            }
            order[i] = ex.submit(() -> expkey(pre, sub)).get();
        }
        ex.shutdown();

        for (int i = 0; i < 16; i++) {
            res[i] = Arrays.copyOfRange(order[i], 0, 16);
            res[i + 16] = Arrays.copyOfRange(order[i], 16, 32);
        }
        return res;
    }

    // zip files -> ./yas_temp
    public void Dozip(InputStream[] files, String[] names, long[] sizes) throws Exception {
        OutputStream f = this.DependentWriter("yas_temp", true);
        f.write(new byte[] { (byte) (files.length % 256), (byte) (files.length / 256) });
        byte[] buffer;

        for (int i = 0; i < files.length; i++) {
            buffer = names[i].getBytes(StandardCharsets.UTF_8); // file name
            f.write(new byte[] { (byte) (buffer.length % 256), (byte) (buffer.length / 256) });
            f.write(buffer);

            long fsize = sizes[i]; // file size
            buffer = new byte[8];
            for (int j = 0; j < 8; j++) {
                buffer[j] = (byte) (fsize % 256);
                fsize /= 256;
            }
            f.write(buffer);

            fsize = sizes[i]; // buffered file copy
            long num0 = fsize / 1048576;
            long num1 = fsize % 1048576;
            InputStream t = files[i];
            buffer = new byte[1048576];
            for (long j = 0; j < num0; j++) {
                t.read(buffer);
                f.write(buffer);
            }
            buffer = new byte[(int) num1];
            t.read(buffer);
            f.write(buffer);
            t.close();
        }
        f.close();
    }

    // unzip files : ./yas_temp -> path + files
    public void Unzip(boolean unpackLocal) throws Exception {
        InputStream f = this.DependentReader("yas_temp", true);
        byte[] buffer = new byte[2];
        f.read(buffer);
        int num = (buffer[0] & 0xFF) + (buffer[1] & 0xFF) * 256; // number of files

        for (int i = 0; i < num; i++) {
            buffer = new byte[2];
            f.read(buffer);
            buffer = new byte[(buffer[0] & 0xFF) + (buffer[1] & 0xFF) * 256];
            f.read(buffer);
            String name = new String(buffer, StandardCharsets.UTF_8); // file name

            long fsize = 0; // file size
            buffer = new byte[8];
            f.read(buffer);
            for (int j = 7; j >= 0; j--) { fsize = fsize * 256 + (buffer[j] & 0xFF); }

            long num0 = fsize / 1048576; // buffered file copy
            long num1 = fsize % 1048576;
            OutputStream t = this.DependentWriter(name, unpackLocal);
            buffer = new byte[1048576];
            for (long j = 0; j < num0; j++) {
                f.read(buffer);
                t.write(buffer);
            }
            buffer = new byte[(int) num1];
            f.read(buffer);
            t.write(buffer);
            t.close();
        }
        f.close();
    }

    // encrypt ./yas_temp -> path, 8 threads
    public void Encrypt(String msg, String pw, OutputStream f) throws Exception {
        byte[] salt = this.bu.Genrand(32); // generate random key
        byte[] ckey = this.bu.Genrand(128);
        byte[] iv = this.bu.Genrand(16);

        MessageDigest digest = MessageDigest.getInstance("SHA3-256"); // get pwhash & master key
        byte[] pwhash = pw.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < 100000; i++) { pwhash = digest.digest(append(salt, pwhash)); }
        byte[] mkey = pw.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < 10000; i++) { mkey = digest.digest(append(mkey, salt)); }

        byte[] msgdata = msg.getBytes(StandardCharsets.UTF_8); // make header
        byte[] ckeydata = this.bu.Aes128(Arrays.copyOfRange(mkey, 16, 32), Arrays.copyOfRange(mkey, 0, 16), ckey, false, true);
        byte[] header = "OTE1".getBytes(StandardCharsets.UTF_8);
        header = append(append(header, new byte[] { (byte) (msgdata.length % 256), (byte) (msgdata.length / 256) }), msgdata);
        header = append(append(append(append(header, salt), pwhash), ckeydata), iv);

        byte[][] keys = getkey(ckey); // get threads key
        byte[][] ivs = new byte[32][];
        Arrays.fill(ivs, iv);
        long fsize = this.DependentFilesize("yas_temp"); // get file size
        long num0 = fsize / 131072; // chunk num
        long num1 = fsize % 131072; // left size

        byte[][] order = new byte[8][];
        byte[][] write = new byte[32][];
        Arrays.fill(order, null);
        Arrays.fill(write, null);
        ExecutorService ex = Executors.newFixedThreadPool(8);
        count = 0;
        InputStream t = this.DependentReader("yas_temp", true);
        f.write(header);

        for (long i = 0; i < num0; i++) {
            byte[] buffer = new byte[131072]; // read & compute
            t.read(buffer);
            count = (int) (i % 32); // keyiv position
            order[(int) (i % 8)] = ex.submit(() -> this.bu.Aes128(keys[count], ivs[count], buffer, false, true)).get();

            if (i % 8 == 7) { // move data from order to write
                ex.shutdown();
                ex = Executors.newFixedThreadPool(8);
                for (int j = 0; j < 8; j++) { write[count - 7 + j] = order[j]; }
            }

            if (i % 32 == 31) { // write data
                for (int j = 0; j < 32; j++) {
                    ivs[j] = Arrays.copyOfRange(write[j], 131056, 131072);
                    f.write(write[j]);
                }
                Arrays.fill(order, null);
                Arrays.fill(write, null);
            }
        }

        if (num0 % 8 != 0) {
            ex.shutdown();
            for (int i = 0; i < num0 % 8; i++) { write[count - (int) (num0 % 8) + i + 1] = order[i]; }
        }
        if (num0 % 32 != 0) {
            for (int i = 0; i < num0 % 32; i++) { f.write(write[i]); }
        }
        byte[] buffer = new byte[(int) num1];
        t.read(buffer);
        buffer = this.bu.Aes128(keys[(int) (num0 % 32)], ivs[(int) (num0 % 32)], pad(buffer, true), false, true);
        f.write(buffer);
        t.close();
        f.close();
    }

    // decrypt path -> ./yas_temp, 8 threads
    public void Decrypt(String pw, InputStream f, long fsize) throws Exception {
        byte[] buf = new byte[6];
        f.read(buf);
        int msglen = (buf[4] & 0xFF) + (buf[5] & 0xFF) * 256;
        buf = new byte[msglen];
        f.read(buf);
        byte[] salt = new byte[32];
        f.read(salt);
        byte[] pwhash = new byte[32];
        f.read(pwhash);
        byte[] ckeydata = new byte[128];
        f.read(ckeydata);
        byte[] iv = new byte[16];
        f.read(iv);

        MessageDigest digest = MessageDigest.getInstance("SHA3-256"); // get nph & master key
        byte[] nph = pw.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < 100000; i++) { nph = digest.digest(append(salt, nph)); }
        byte[] mkey = pw.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < 10000; i++) { mkey = digest.digest(append(mkey, salt)); }
        if (!Arrays.equals(pwhash, nph)) { // check password
            f.close();
            throw new Exception("InvalidPassword");
        }

        byte[] ckey = this.bu.Aes128(Arrays.copyOfRange(mkey, 16, 32), Arrays.copyOfRange(mkey, 0, 16), ckeydata, false, false);
        byte[][] keys = getkey(ckey); // get threads key
        byte[][] ivs = new byte[32][];
        Arrays.fill(ivs, iv);
        fsize = fsize - 214 - msglen; // get actual file size
        long num0 = fsize / 131072; // chunk num
        long num1 = fsize % 131072; // left size
        if (num1 == 0) {
            num0--;
            num1 = 131072;
        }
        
        OutputStream t = this.DependentWriter("yas_temp", true);
        byte[][] order = new byte[8][];
        byte[][] write = new byte[32][];
        ExecutorService ex = Executors.newFixedThreadPool(8);
        Arrays.fill(order, null);
        Arrays.fill(write, null);

        for (long i = 0; i < num0; i++) {
            byte[] buffer = new byte[131072]; // read & compute
            f.read(buffer);
            count = (int) (i % 32); // keyiv position
            order[(int) (i % 8)] = ex.submit(() -> this.bu.Aes128(keys[count], ivs[count], buffer, false, false)).get();
            ivs[count] = Arrays.copyOfRange(buffer, 131056, 131072);

            if (i % 8 == 7) { // move data from order to write
                ex.shutdown();
                ex = Executors.newFixedThreadPool(8);
                for (int j = 0; j < 8; j++) { write[count - 7 + j] = order[j]; }
            }

            if (i % 32 == 31) { // write data
                for (int j = 0; j < 32; j++) { t.write(write[j]); }
                Arrays.fill(order, null);
                Arrays.fill(write, null);
            }
        }

        if (num0 % 8 != 0) {
            ex.shutdown();
            for (int i = 0; i < num0 % 8; i++) { write[count - (int) (num0 % 8) + i + 1] = order[i]; }
        }
        if (num0 % 32 != 0) {
            for (int i = 0; i < num0 % 32; i++) { t.write(write[i]); }
        }
        byte[] buffer = new byte[(int) num1];
        f.read(buffer);
        buffer = pad(this.bu.Aes128(keys[(int) (num0 % 32)], ivs[(int) (num0 % 32)], buffer, false, false), false);
        t.write(buffer);
        t.close();
        f.close();
    }

    // check file validity, read msg
    public String View(InputStream f) throws Exception {
        byte[] buffer = new byte[4];
        f.read(buffer);
        if (!Arrays.equals(buffer, "OTE1".getBytes(StandardCharsets.UTF_8))) {
            f.close();
            throw new Exception("InvalidFile");
        }

        buffer = new byte[2];
        f.read(buffer);
        int msglen = (buffer[0] & 0xFF) + (buffer[1] & 0xFF) * 256;
        buffer = new byte[msglen];
        f.read(buffer);
        f.close();
        return new String(buffer, StandardCharsets.UTF_8);
    }
}