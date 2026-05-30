package com.example.k7yas.engine;
// test794d : USAG-Lib opsec
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.zip.CRC32;

// Opsec header handler
public class Opsec {
    private static volatile Object DUMMY;

    private static void sclear(byte[] data) {
        java.util.Arrays.fill(data, (byte) 0);
        DUMMY = data;
    }

    public static void ClearDummy() {
        DUMMY = null;
    }

    // Outer Layer
    public String Msg; // non-secured message
    public byte[] MsgInfo; // additional info (for RSA-mode)

    private String headAlgo; // header algorithm
    private byte[] salt; // salt
    private byte[] pwHash; // pw hash
    private byte[] encHeadData; // encrypted header data

    // Inner Layer
    public String Smsg; // secured message
    public byte[] SmsgInfo; // private additional info (timestamp, ID, etc.)
    private byte[] sign; // signature

    public String BodyAlgo; // body algorithm
    public byte[] BodyKey; // body key
    public long BodySize; // full body size, flag for bodyKey generation (-1 if not used)
    public byte[] BodyInfo; // additional info for body (packing info, etc.)

    public int SaltLen = 32;

    public Opsec() {
        Reset();
    }

    // reset after reading BodyKey
    public void Reset() {
        Msg = "";
        MsgInfo = new byte[0];
        headAlgo = "";
        salt = new byte[0];
        pwHash = new byte[0];
        encHeadData = new byte[0];

        Smsg = "";
        SmsgInfo = new byte[0];
        sign = new byte[0];

        BodyAlgo = "";
        BodyKey = new byte[0];
        BodySize = -1;
        BodyInfo = new byte[0];
    }

    // ========== Helper Functions ==========
    public static String Crc32(byte[] data) {
        CRC32 crc = new CRC32();
        crc.update(data);
        long value = crc.getValue();
        return String.format("%02x%02x%02x%02x", (value & 0xFF), (value >> 8) & 0xFF, (value >> 16) & 0xFF,
                (value >> 24) & 0xFF); // 8 chars hex string
    }

    public static long PadLen(long size) {
        if (size <= 0) {
            return 0;
        }

        // 1. 0-16k: 4k*N
        if (size <= 16384) {
            long remainder = size % 4096;
            if (remainder == 0) {
                return 0;
            }
            return 4096 - remainder;
        }

        // get sup bit position
        int bitLen = 64 - Long.numberOfLeadingZeros(size);
        int k;
        if (bitLen <= 24) { // 16k-16m: K=2
            k = 2;
        } else if (bitLen <= 29) { // 16m-512m: K=3
            k = 3;
        } else if (bitLen <= 33) { // 512m-8g: K=4
            k = 4;
        } else { // 8g+: K=5
            k = 5;
        }

        // mask and ceiling
        int shift = bitLen - k;
        long mask = (1L << shift) - 1L;
        if ((size & mask) == 0) { // on border size is not padded
            return 0;
        }

        // return actual padding length
        long aftersize = ((size >> shift) + 1L) << shift;
        return aftersize - size;
    }

    public static void PadFile(OutputStream f, long size) throws Exception {
        if (size <= 0)
            return;
        int chunkSize = 1048576; // 1MB
        BlockingQueue<byte[]> queue = new ArrayBlockingQueue<>(4);
        final Thread mainThread = Thread.currentThread();

        // Random Number Generator
        Thread generatorThread = new Thread(() -> {
            Bencrypt rg = new Bencrypt();
            long remaining = size;
            try {
                while (remaining > 0) {
                    int currentSize = (int) Math.min(chunkSize, remaining);
                    queue.put(rg.Random(currentSize));
                    remaining -= currentSize;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt(); // quit when interrupted
            } catch (Throwable t) {
                mainThread.interrupt();
            }
        });
        generatorThread.start();

        // writer
        long remaining = size;
        try {
            while (remaining > 0) {
                int currentSize = (int) Math.min(chunkSize, remaining);
                byte[] data = queue.take();
                f.write(data);
                remaining -= currentSize;
            }
        } catch (Exception e) {
            generatorThread.interrupt(); // stop generator thread
            throw e;
        }
    }

    public byte[] EncodeInt(long data, int size) {
        ByteBuffer buf = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
        if (size == 1)
            buf.put((byte) data);
        else if (size == 2)
            buf.putShort((short) data);
        else if (size == 4)
            buf.putInt((int) data);
        else if (size == 8)
            buf.putLong(data);
        return buf.array();
    }

    public long DecodeInt(byte[] data) {
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        if (data.length == 1)
            return Byte.toUnsignedInt(buf.get());
        if (data.length == 2)
            return Short.toUnsignedInt(buf.getShort());
        if (data.length == 4)
            return Integer.toUnsignedLong(buf.getInt());
        if (data.length == 8)
            return buf.getLong(); // Java long is signed, but bits are same
        return 0;
    }

    private byte[] concat(byte[]... arrays) {
        int len = 0;
        for (byte[] a : arrays)
            len += a.length;
        byte[] res = new byte[len];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, res, pos, a.length);
            pos += a.length;
        }
        return res;
    }

    private byte[] strToBytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private String bytesToStr(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }

    // Config Encoding
    public byte[] EncodeCfg(Map<String, byte[]> data) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Map.Entry<String, byte[]> entry : data.entrySet()) {
            byte[] keyBytes = strToBytes(entry.getKey());
            byte[] valBytes = entry.getValue();
            int keyLen = keyBytes.length;
            int dataLen = valBytes.length;
            if (keyLen > 127)
                throw new IllegalArgumentException("Key length too long: " + keyLen);
            if (dataLen > 65535)
                throw new IllegalArgumentException("Data size too big: " + dataLen);

            if (dataLen > 255) {
                out.write(keyLen + 128);
                out.write(keyBytes);
                out.write(EncodeInt(dataLen, 2));
            } else {
                out.write(keyLen);
                out.write(keyBytes);
                out.write(dataLen);
            }
            out.write(valBytes);
        }
        return out.toByteArray();
    }

    // Config Decoding
    public Map<String, byte[]> DecodeCfg(byte[] data) {
        Map<String, byte[]> result = new HashMap<>();
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        while (buf.hasRemaining()) {
            int keyLen = Byte.toUnsignedInt(buf.get());
            boolean isLongData = false;
            if (keyLen > 127) {
                keyLen -= 128;
                isLongData = true;
            }
            byte[] keyBytes = new byte[keyLen];
            buf.get(keyBytes);
            String key = bytesToStr(keyBytes);

            int dataLen;
            if (isLongData) {
                dataLen = Short.toUnsignedInt(buf.getShort());
            } else {
                dataLen = Byte.toUnsignedInt(buf.get());
            }
            byte[] valBytes = new byte[dataLen];
            buf.get(valBytes);
            result.put(key, valBytes);
        }
        return result;
    }

    // read stream, return opsec header
    public byte[] Read(InputStream ins, int cut) throws IOException {
        int c = 0;
        while (true) {
            byte[] buf4 = ins.readNBytes(4);
            if (buf4.length == 0)
                return new byte[0];
            c += 4;

            if (Arrays.equals(buf4, strToBytes("YAS2"))) {
                byte[] buf2 = ins.readNBytes(2);
                long size = DecodeInt(buf2);
                if (size == 65535) {
                    buf2 = ins.readNBytes(2);
                    size += DecodeInt(buf2);
                }
                byte[] packet = new byte[(int) size];
                int totalRead = 0;
                while (totalRead < size) {
                    int r = ins.readNBytes(packet, totalRead, (int) size - totalRead);
                    if (r == -1 || (r == 0 && totalRead < size))
                        throw new java.io.EOFException("Unexpected EOF while reading opsec header");
                    totalRead += r;
                }
                return packet;

            } else {
                ins.readNBytes(124);
                c += 124;
            }
            if (cut > 0 && c > cut)
                return new byte[0];
        }
    }

    // write opsec header to stream
    public void Write(OutputStream outs, byte[] head) throws IOException {
        outs.write(strToBytes("YAS2"));
        int size = head.length;
        if (size < 65535) {
            outs.write(EncodeInt(size, 2));
        } else if (size <= 65535 * 2) {
            outs.write(EncodeInt(65535, 2));
            outs.write(EncodeInt(size - 65535, 2));
        } else {
            throw new IOException("Data size too big: " + size);
        }
        outs.write(head);
    }

    private byte[] wrapEncHead() throws IOException {
        Map<String, byte[]> cfg = new HashMap<>();
        if (!Smsg.isEmpty())
            cfg.put("smsg", strToBytes(Smsg));
        if (SmsgInfo.length > 0)
            cfg.put("sinf", SmsgInfo);
        if (sign.length > 0)
            cfg.put("sgn", sign);
        if (!BodyAlgo.isEmpty())
            cfg.put("bal", strToBytes(BodyAlgo));
        if (BodyKey.length > 0)
            cfg.put("bkey", BodyKey);

        if (BodySize >= 0) {
            if (BodySize < 65536)
                cfg.put("bsz", EncodeInt(BodySize, 2));
            else if (BodySize < 4294967296L)
                cfg.put("bsz", EncodeInt(BodySize, 4));
            else
                cfg.put("bsz", EncodeInt(BodySize, 8));
        }
        if (BodyInfo.length > 0)
            cfg.put("binf", BodyInfo);

        return EncodeCfg(cfg);
    }

    private void unwrapEncHead(byte[] data) {
        Map<String, byte[]> cfg = DecodeCfg(data);
        if (cfg.containsKey("smsg"))
            Smsg = bytesToStr(cfg.get("smsg"));
        if (cfg.containsKey("sinf"))
            SmsgInfo = cfg.get("sinf");
        if (cfg.containsKey("sgn"))
            sign = cfg.get("sgn");
        if (cfg.containsKey("bal"))
            BodyAlgo = bytesToStr(cfg.get("bal"));
        if (cfg.containsKey("bkey"))
            BodyKey = cfg.get("bkey");
        if (cfg.containsKey("bsz"))
            BodySize = DecodeInt(cfg.get("bsz"));
        if (cfg.containsKey("binf"))
            BodyInfo = cfg.get("binf");
    }

    // encrypt with password
    public byte[] Encpw(String method, byte[] pw, byte[] kf) throws Exception {
        // generate random parameters
        Bencrypt worker = new Bencrypt();
        headAlgo = method;
        salt = worker.Random(SaltLen);
        if (BodySize >= 0) {
            BodyKey = worker.Random(44);
        }

        // get pwhash & header key, encrypt header
        byte[] combinedPw = (kf == null || kf.length == 0) ? pw.clone() : concat(pw, kf);
        Bencrypt.HashMaster hm = new Bencrypt.HashMaster(method);
        byte[][] keys = hm.KDF(combinedPw, salt);
        sclear(combinedPw);
        pwHash = keys[0];
        byte[] hkey = keys[1];

        // Encrypt Header using SymMaster
        byte[] headData = wrapEncHead();
        Bencrypt.SymMaster sm = new Bencrypt.SymMaster("gcm1", hkey);
        encHeadData = sm.EnBin(headData);
        sclear(hkey);
        sclear(headData);

        // wrap header
        Map<String, byte[]> cfg = new HashMap<>();
        if (!Msg.isEmpty())
            cfg.put("msg", strToBytes(Msg));
        if (MsgInfo.length > 0)
            cfg.put("minf", MsgInfo);
        cfg.put("hal", strToBytes(headAlgo));
        cfg.put("salt", salt);
        cfg.put("pwh", pwHash);
        cfg.put("ehd", encHeadData);

        return EncodeCfg(cfg);
    }

    // encrypt with public key, sign if private key is not null
    public byte[] Encpub(String method, byte[] peerPub, byte[] myPri) throws Exception {
        Bencrypt worker = new Bencrypt();
        headAlgo = method;
        if (BodySize >= 0) {
            BodyKey = worker.Random(44);
        }

        // sign with private key if provided
        if (myPri != null) {
            Bencrypt.AsymMaster am = new Bencrypt.AsymMaster(method);
            am.Loadkey(null, myPri);
            // sign to [hal][peerPub][smsg][sinf]
            byte[] signTgt = concat(strToBytes(method), peerPub, strToBytes(Smsg), SmsgInfo);
            sign = am.Sign(signTgt);
            sclear(signTgt);
        }

        // encrypt header
        Bencrypt.AsymMaster am = new Bencrypt.AsymMaster(method);
        am.Loadkey(peerPub, null);
        byte[] headData = wrapEncHead();

        if (method.equals("rsa1") || method.equals("rsa2")) {
            // RSA Hybrid: Encrypt Key with RSA, Data with AES
            byte[] hkey = worker.Random(44);
            MsgInfo = am.Encrypt(hkey); // store encHeadKey to MsgInfo

            Bencrypt.SymMaster sm = new Bencrypt.SymMaster("gcm1", hkey);
            encHeadData = sm.EnBin(headData);
            sclear(hkey);
        } else {
            // ECC/PQC Hybrid: Handled internally
            encHeadData = am.Encrypt(headData);
        }
        sclear(headData);

        // wrap header
        Map<String, byte[]> cfg = new HashMap<>();
        if (!Msg.isEmpty())
            cfg.put("msg", strToBytes(Msg));
        if (MsgInfo.length > 0)
            cfg.put("minf", MsgInfo);
        cfg.put("hal", strToBytes(headAlgo));
        cfg.put("ehd", encHeadData);

        return EncodeCfg(cfg);
    }

    // load outer layer of header
    public void View(byte[] data) {
        Reset();
        Map<String, byte[]> cfg = DecodeCfg(data);
        if (cfg.containsKey("msg"))
            Msg = bytesToStr(cfg.get("msg"));
        if (cfg.containsKey("minf"))
            MsgInfo = cfg.get("minf");
        if (cfg.containsKey("hal"))
            headAlgo = bytesToStr(cfg.get("hal"));
        if (cfg.containsKey("salt"))
            salt = cfg.get("salt");
        if (cfg.containsKey("pwh"))
            pwHash = cfg.get("pwh");
        if (cfg.containsKey("ehd"))
            encHeadData = cfg.get("ehd");
    }

    // decrypt with password
    public void Decpw(byte[] pw, byte[] kf) throws Exception {
        if (headAlgo.isEmpty())
            throw new IllegalStateException("Call view() first");
        byte[] combinedPw = (kf == null || kf.length == 0) ? pw.clone() : concat(pw, kf);

        // check parameters, get header key
        Bencrypt.HashMaster hm = new Bencrypt.HashMaster(headAlgo);
        byte[][] keys = hm.KDF(combinedPw, salt);
        sclear(combinedPw);
        byte[] calcHash = keys[0];
        byte[] hkey = keys[1];

        // check password (Constant time comparison)
        if (calcHash.length != pwHash.length)
            throw new SecurityException("Incorrect password");
        int diff = 0;
        for (int i = 0; i < calcHash.length; i++) {
            diff |= calcHash[i] ^ pwHash[i];
        }
        if (diff != 0)
            throw new SecurityException("Incorrect password");

        // decrypt header
        Bencrypt.SymMaster sm = new Bencrypt.SymMaster("gcm1", hkey);
        byte[] decryptedHead = sm.DeBin(encHeadData);
        sclear(hkey);
        if (decryptedHead == null)
            throw new SecurityException("AES decryption failed");
        unwrapEncHead(decryptedHead);
        sclear(decryptedHead);
    }

    // decrypt with private key, verify if public key is not null
    public void Decpub(byte[] myPri, byte[] myPub, byte[] peerPub) throws Exception {
        if (headAlgo.isEmpty())
            throw new IllegalStateException("Call view() first");

        // check parameters, decrypt header
        Bencrypt.AsymMaster am = new Bencrypt.AsymMaster(headAlgo);
        am.Loadkey(null, myPri);

        byte[] decryptedHead;
        if (headAlgo.equals("rsa1") || headAlgo.equals("rsa2")) {
            // RSA Hybrid
            byte[] hkey = am.Decrypt(MsgInfo);
            Bencrypt.SymMaster sm = new Bencrypt.SymMaster("gcm1", hkey);
            decryptedHead = sm.DeBin(encHeadData);
            sclear(hkey);
        } else {
            decryptedHead = am.Decrypt(encHeadData);
        }

        if (decryptedHead == null)
            throw new SecurityException("Decryption failed");
        unwrapEncHead(decryptedHead);
        sclear(decryptedHead);

        // verify sign
        if (myPub == null && peerPub == null)
            return;
        if (myPub == null || peerPub == null) {
            if (sign.length > 0)
                throw new IllegalArgumentException("Both myPub and peerPub should be provided to verify sign");
            return;
        }

        Bencrypt.AsymMaster amVerify = new Bencrypt.AsymMaster(headAlgo);
        amVerify.Loadkey(peerPub, null);
        byte[] signTgt = concat(strToBytes(headAlgo), myPub, strToBytes(Smsg), SmsgInfo);

        if (!amVerify.Verify(signTgt, sign)) {
            throw new SecurityException("Signature verification failed");
        }
    }
}
