// test799b : USAG-KOX TP1
package com.example.k7yas.engine;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

public class TP1 {
    private static volatile Object DUMMY;

    private static void sclear(byte[] data) {
        java.util.Arrays.fill(data, (byte) 0);
        DUMMY = data;
    }

    public static void ClearDummy() {
        DUMMY = null;
    }

    // Operation Mode
    public static final int MODE_MSGONLY = 0x1;

    // Hash Function Mode
    public static final int HASH_SHA3 = 0x10;
    public static final int HASH_PBK2 = 0x20;
    public static final int HASH_ARG2 = 0x30;

    // Symmetric Encryption Mode
    public static final int SYM_GCM1 = 0x100;
    public static final int SYM_GCMX1 = 0x200;

    // Asymmetric Encryption Mode
    public static final int ASYM_RSA1 = 0x1000;
    public static final int ASYM_RSA2 = 0x2000;
    public static final int ASYM_ECC1 = 0x3000;
    public static final int ASYM_PQC1 = 0x4000;

    // Status
    public static final int STAGE_IDLE = 0;
    public static final int STAGE_HANDSHAKE = 1;
    public static final int STAGE_ENCRYPTING = 2;
    public static final int STAGE_TRANSFERRING = 3;
    public static final int STAGE_COMPLETE = 4;
    public static final int STAGE_ERROR = -1;

    // ========== Helper Functions ==========
    public static List<String> GetIPs(boolean v4only) throws Exception {
        List<String> res = new ArrayList<>();
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
        while (interfaces.hasMoreElements()) {
            NetworkInterface iface = interfaces.nextElement();
            if (iface.isLoopback() || !iface.isUp())
                continue;
            Enumeration<InetAddress> addresses = iface.getInetAddresses();
            while (addresses.hasMoreElements()) {
                InetAddress addr = addresses.nextElement();
                if (v4only && !(addr instanceof Inet4Address))
                    continue;
                res.add(addr.getHostAddress());
            }
        }
        return res;
    }

    public static String CleanPath(String path) {
        String[] replaceChars = { "\\", "/", ":", "*", "?", "\"", "<", ">", "|" };
        for (String c : replaceChars) {
            path = path.replace(c, "_");
        }
        return path;
    }

    private static void readFull(InputStream in, byte[] buf) throws IOException {
        int total = 0;
        while (total < buf.length) {
            int r = in.read(buf, total, buf.length - total);
            if (r == -1)
                throw new EOFException("Unexpected EOF");
            total += r;
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] res = new byte[a.length + b.length];
        System.arraycopy(a, 0, res, 0, a.length);
        System.arraycopy(b, 0, res, a.length, b.length);
        return res;
    }

    // ========== TP1 Class ==========
    public int Mode;
    public boolean InMem;
    public boolean DoPad;
    public byte[] SharedS; // masked

    private Bencrypt.Masker mask;
    private int stage;
    private long sent;
    private long total;
    private final ReentrantLock lock = new ReentrantLock();

    private Socket conn;
    private InputStream in;
    private OutputStream out;
    private final Object outLock = new Object();

    private final byte[] magic = { 'U', 'T', 'P', '1' };
    private final byte[] zero8 = { 0, 0, 0, 0, 0, 0, 0, 0 };
    private final byte[] max8 = { (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
            (byte) 255 };

    public TP1(int mode, boolean inMem, boolean doPad, byte[] secret, Socket conn) throws IOException {
        this.Mode = mode;
        this.InMem = inMem;
        this.DoPad = doPad;
        this.mask = Bencrypt.Masker.GetMasker();
        this.SharedS = this.mask.XOR(secret); // secret input as plain

        this.stage = 0;
        this.sent = 0;
        this.total = 0;
        this.conn = conn;
        this.in = conn.getInputStream();
        this.out = conn.getOutputStream();
    }

    public long[] GetStatus() {
        this.lock.lock();
        try {
            return new long[] { this.stage, this.sent, this.total };
        } finally {
            this.lock.unlock();
        }
    }

    private void setStage(int stage) {
        this.lock.lock();
        try {
            this.stage = stage;
        } finally {
            this.lock.unlock();
        }
    }

    private void setSent(long sent) {
        this.lock.lock();
        try {
            this.sent = sent;
        } finally {
            this.lock.unlock();
        }
    }

    private void setTotal(long total) {
        this.lock.lock();
        try {
            this.total = total;
        } finally {
            this.lock.unlock();
        }
    }

    private Thread startSyncStatus(AtomicBoolean stopFlag, AtomicBoolean errorFlag) {
        Thread t = new Thread(() -> {
            try {
                while (!stopFlag.get()) {
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        break;
                    } // sleep 1s, break loop if interrupted
                    synchronized (outLock) {
                        out.write(zero8);
                        out.flush();
                    } // write working signal
                }
                if (errorFlag.get()) {
                    synchronized (outLock) {
                        out.write(max8);
                        out.flush();
                    } // write error signal
                }
            } catch (Exception e) {
                setStage(STAGE_ERROR);
            }
        });
        t.start();
        return t;
    }

    // ========== Handshake Methods ==========
    private static class HandshakeResult {
        byte[] peerPub;
        byte[] myPub;
        byte[] myPriv;

        public HandshakeResult(byte[] peerPub, byte[] myPub, byte[] myPriv) {
            this.peerPub = peerPub;
            this.myPub = myPub;
            this.myPriv = myPriv;
        }
    }

    private HandshakeResult handshakeSend() throws Exception {
        // 1. Generate key pair
        String algo = "";
        int asymMode = this.Mode & 0xF000;
        if (asymMode == ASYM_RSA1)
            algo = "rsa1";
        else if (asymMode == ASYM_RSA2)
            algo = "rsa2";
        else if (asymMode == ASYM_ECC1)
            algo = "ecc1";
        else if (asymMode == ASYM_PQC1)
            algo = "pqc1";
        else
            throw new Exception("invalid mode: no valid algorithm flag set");
        Bencrypt.AsymMaster am = new Bencrypt.AsymMaster(algo);
        byte[][] keyPair = am.Genkey();
        byte[] myPub = keyPair[0];
        byte[] myPriv = keyPair[1];

        // 2. Send init packet
        Opsec util = new Opsec();
        byte[] initPkt = new byte[6];
        System.arraycopy(magic, 0, initPkt, 0, 4);
        System.arraycopy(util.EncodeInt(this.Mode, 2), 0, initPkt, 4, 2);
        synchronized (outLock) {
            out.write(initPkt);
            out.flush();
        }

        // 3. Send sender auth: Nonce 8B + Hash 32B
        Bencrypt worker = new Bencrypt();
        byte[] nonce = worker.Random(8);
        String hashAlgo = "";
        int hashMode = this.Mode & 0xF0;
        if (hashMode == HASH_SHA3)
            hashAlgo = "sha3";
        else if (hashMode == HASH_PBK2)
            hashAlgo = "pbk2";
        else if (hashMode == HASH_ARG2)
            hashAlgo = "arg2";
        else
            throw new Exception("invalid mode: no valid algorithm flag set");
        Bencrypt.HashMaster hm = new Bencrypt.HashMaster(hashAlgo, 32, 44);
        byte[] shs = this.mask.XOR(this.SharedS);
        byte[] hashSrc = concat(myPub, shs);
        byte[] hash = hm.KDF(hashSrc, nonce)[0];
        byte[] authPkt = concat(nonce, hash);
        sclear(shs);
        sclear(hashSrc);
        synchronized (outLock) {
            out.write(authPkt);
            out.flush();
        }

        // 4. Receive receiver auth: Nonce 8B + Hash 32B
        byte[] peerAuth = new byte[40];
        readFull(in, peerAuth);
        byte[] peerNonce = Arrays.copyOfRange(peerAuth, 0, 8);
        byte[] peerHash = Arrays.copyOfRange(peerAuth, 8, 40);

        // 5. Send sender public key
        if (myPub.length > 65535)
            throw new Exception("public key is too long");
        byte[] pubPkt = concat(util.EncodeInt(myPub.length, 2), myPub);
        synchronized (outLock) {
            out.write(pubPkt);
            out.flush();
        }

        // 6. Receive receiver public key
        byte[] head = new byte[2];
        readFull(in, head);
        int peerPubLen = (int) util.DecodeInt(head);
        byte[] peerPub = new byte[peerPubLen];
        readFull(in, peerPub);

        // 7. Verify receiver auth
        shs = this.mask.XOR(this.SharedS);
        byte[] verifySrc = concat(peerPub, shs);
        byte[] verifyHash = hm.KDF(verifySrc, peerNonce)[0];
        sclear(shs);
        sclear(verifySrc);
        if (!Arrays.equals(peerHash, verifyHash)) {
            throw new Exception("receiver authentication failed");
        }
        return new HandshakeResult(peerPub, myPub, myPriv);
    }

    private HandshakeResult handshakeReceive() throws Exception {
        // 1. Receive init packet
        Opsec util = new Opsec();
        byte[] header = new byte[6];
        readFull(in, header);
        if (!Arrays.equals(Arrays.copyOfRange(header, 0, 4), magic)) {
            throw new Exception("invalid magic number");
        }
        this.Mode = (int) util.DecodeInt(Arrays.copyOfRange(header, 4, 6));

        // 2. Generate key pair
        String algo = "";
        int asymMode = this.Mode & 0xF000;
        if (asymMode == ASYM_RSA1)
            algo = "rsa1";
        else if (asymMode == ASYM_RSA2)
            algo = "rsa2";
        else if (asymMode == ASYM_ECC1)
            algo = "ecc1";
        else if (asymMode == ASYM_PQC1)
            algo = "pqc1";
        else
            throw new Exception("invalid mode: no valid algorithm flag set");
        Bencrypt.AsymMaster am = new Bencrypt.AsymMaster(algo);
        byte[][] keyPair = am.Genkey();
        byte[] myPub = keyPair[0];
        byte[] myPriv = keyPair[1];

        // 3. Receive sender auth: Nonce 8B + Hash 32B
        byte[] peerAuth = new byte[40];
        readFull(in, peerAuth);
        byte[] peerNonce = Arrays.copyOfRange(peerAuth, 0, 8);
        byte[] peerHash = Arrays.copyOfRange(peerAuth, 8, 40);

        // 4. Initialize HashMaster based on received Mode
        String hashAlgo = "";
        int hashMode = this.Mode & 0xF0;
        if (hashMode == HASH_SHA3)
            hashAlgo = "sha3";
        else if (hashMode == HASH_PBK2)
            hashAlgo = "pbk2";
        else if (hashMode == HASH_ARG2)
            hashAlgo = "arg2";
        else
            throw new Exception("invalid mode: no valid hash algorithm flag set");
        Bencrypt.HashMaster hm = new Bencrypt.HashMaster(hashAlgo, 32, 44);

        // 5. Send receiver auth: Nonce 8B + Hash 32B
        Bencrypt worker = new Bencrypt();
        byte[] shs = this.mask.XOR(this.SharedS);
        byte[] myNonce = worker.Random(8);
        byte[] hashSrc = concat(myPub, shs);
        byte[] myHash = hm.KDF(hashSrc, myNonce)[0];
        byte[] authPkt = concat(myNonce, myHash);
        sclear(shs);
        sclear(hashSrc);
        synchronized (outLock) {
            out.write(authPkt);
            out.flush();
        }

        // 6. Receive sender public key
        byte[] head = new byte[2];
        readFull(in, head);
        int peerPubLen = (int) util.DecodeInt(head);
        byte[] peerPub = new byte[peerPubLen];
        readFull(in, peerPub);

        // 7. Send receiver public key
        if (myPub.length > 65535)
            throw new Exception("generated public key is too long");
        byte[] resp = concat(util.EncodeInt(myPub.length, 2), myPub);
        synchronized (outLock) {
            out.write(resp);
            out.flush();
        }

        // 8. Verify sender auth
        shs = this.mask.XOR(this.SharedS);
        byte[] verifySrc = concat(peerPub, shs);
        byte[] verifyHash = hm.KDF(verifySrc, peerNonce)[0];
        sclear(shs);
        sclear(verifySrc);
        if (!Arrays.equals(peerHash, verifyHash)) {
            throw new Exception("sender authentication failed");
        }
        return new HandshakeResult(peerPub, myPub, myPriv);
    }

    // ========== Send & Receive Results ==========
    public static class TP1Result {
        public byte[] FromPub;
        public byte[] ToPub;
        public String Smsg;
        public Exception Err;

        public TP1Result(byte[] fromPub, byte[] toPub, String smsg, Exception err) {
            this.FromPub = fromPub;
            this.ToPub = toPub;
            this.Smsg = smsg;
            this.Err = err;
        }
    }

    /**
     * Send encrypted data stream
     * 
     * @param tempFile Pass writable temporary file handle if InMem is false.
     */
    public TP1Result Send(InputStream src, long size, String smsg, File tempFile) {
        HandshakeResult hs = null;
        try {
            // 1. Handshake
            setStage(STAGE_HANDSHAKE);
            conn.setSoTimeout(30000);
            hs = handshakeSend();
            conn.setSoTimeout(0);

            AtomicBoolean stopFlag = new AtomicBoolean(false);
            AtomicBoolean errorFlag = new AtomicBoolean(false);
            Thread syncThread = startSyncStatus(stopFlag, errorFlag);
            setStage(STAGE_ENCRYPTING);

            try {
                // 2. Prepare encryption worker
                String symAlgo = "";
                int symMode = this.Mode & 0xF00;
                if (symMode == SYM_GCM1)
                    symAlgo = "gcm1";
                else if (symMode == SYM_GCMX1)
                    symAlgo = "gcmx1";
                else
                    throw new Exception("invalid mode: no valid algorithm flag set");
                Bencrypt.SymMaster sm = new Bencrypt.SymMaster(symAlgo, new byte[44]);

                // 3. Prepare Opsec Header
                Opsec ops = new Opsec();
                ops.Smsg = smsg;
                ops.SmsgInfo = ops.EncodeInt(System.currentTimeMillis() / 1000L, 8);
                ops.BodyAlgo = symAlgo;
                ops.BodySize = sm.AfterSize(size);

                String asymAlgo = "";
                int asymMode = this.Mode & 0xF000;
                if (asymMode == ASYM_RSA1)
                    asymAlgo = "rsa1";
                else if (asymMode == ASYM_RSA2)
                    asymAlgo = "rsa2";
                else if (asymMode == ASYM_ECC1)
                    asymAlgo = "ecc1";
                else if (asymMode == ASYM_PQC1)
                    asymAlgo = "pqc1";

                byte[] opsHead = ops.Encpub(asymAlgo, hs.peerPub, hs.myPriv);
                sm = new Bencrypt.SymMaster(ops.BodyAlgo, ops.BodyKey);
                sclear(hs.myPriv);
                sclear(ops.BodyKey);

                // 4. Prepare Temp Storage based on InMem
                OutputStream tempWriter;
                ByteArrayOutputStream memBuf = null;
                if (this.InMem) {
                    memBuf = new ByteArrayOutputStream();
                    tempWriter = memBuf;
                } else {
                    if (tempFile == null) {
                        throw new IllegalArgumentException("tempFile cannot be null when InMem is false");
                    }
                    tempWriter = new FileOutputStream(tempFile);
                }

                // 5. Write Opsec Header, Body, Padding
                try {
                    long writed = 0;
                    writed += opsHead.length + 6;
                    if (opsHead.length >= 65535)
                        writed += 2;

                    ops.Write(tempWriter, opsHead);
                    writed += ops.BodySize;
                    sm.EnFile(src, size, tempWriter);

                    if (this.DoPad) {
                        long padLen = Opsec.PadLen(writed);
                        Opsec.PadFile(tempWriter, padLen);
                        writed += padLen;
                    }
                } finally {
                    tempWriter.close(); // Flush and close
                }

                // 6. Transfer the Entire Temp Data
                setStage(STAGE_TRANSFERRING);
                stopFlag.set(true);
                syncThread.interrupt();

                InputStream tempReader;
                long totalSize;
                if (this.InMem) {
                    byte[] memData = memBuf.toByteArray();
                    totalSize = memData.length;
                    tempReader = new ByteArrayInputStream(memData);
                } else {
                    totalSize = tempFile.length();
                    tempReader = new FileInputStream(tempFile);
                }

                // 6-2. Send Total Size Packet
                setSent(0);
                setTotal(totalSize);
                synchronized (outLock) {
                    out.write(ops.EncodeInt(totalSize, 8));
                    out.flush();
                }

                // 6-4. Stream Send
                try {
                    byte[] buf = new byte[32768];
                    long currentSent = 0;
                    while (true) {
                        int nr = tempReader.read(buf);
                        if (nr == -1)
                            break;
                        if (nr > 0) {
                            synchronized (outLock) {
                                out.write(buf, 0, nr);
                                out.flush();
                            }
                            currentSent += nr;
                            setSent(currentSent);
                        }
                    }
                } finally {
                    tempReader.close();
                }

                // 7. Receive Termination
                byte[] term = new byte[8];
                readFull(in, term);
                if (!Arrays.equals(term, zero8)) {
                    throw new Exception("abnormal termination signal");
                }
                setStage(STAGE_COMPLETE);
                return new TP1Result(hs.myPub, hs.peerPub, smsg, null);

            } catch (Exception e) {
                stopFlag.set(true);
                errorFlag.set(true);
                syncThread.interrupt();
                throw e;
            }

        } catch (Exception e) {
            setStage(STAGE_ERROR);
            byte[] peer = hs != null ? hs.peerPub : null;
            byte[] my = hs != null ? hs.myPub : null;
            return new TP1Result(my, peer, "", e);
        }
    }

    /**
     * Receive encrypted data stream
     * 
     * @param tempFile Pass writable temporary file handle if InMem is false.
     */
    public TP1Result Receive(OutputStream dst, File tempFile) {
        HandshakeResult hs = null;
        try {
            // 1. Handshake
            setStage(STAGE_HANDSHAKE);
            conn.setSoTimeout(30000);
            hs = handshakeReceive();
            conn.setSoTimeout(0);

            // 2. Wait for Status (Start Signal)
            setStage(STAGE_TRANSFERRING);
            Opsec util = new Opsec();
            byte[] buf8 = new byte[8];
            long totalSize;
            while (true) {
                readFull(in, buf8);
                if (Arrays.equals(buf8, zero8))
                    continue;
                else if (Arrays.equals(buf8, max8))
                    throw new Exception("remote error reported");
                else {
                    totalSize = util.DecodeInt(buf8);
                    setTotal(totalSize);
                    break;
                }
            }

            // 3. Download Stream to Temp Storage
            OutputStream tempWriter;
            ByteArrayOutputStream memBuf = null;
            if (this.InMem) {
                memBuf = new ByteArrayOutputStream();
                tempWriter = memBuf;
            } else {
                if (tempFile == null) {
                    throw new IllegalArgumentException("tempFile cannot be null when InMem is false");
                }
                tempWriter = new FileOutputStream(tempFile);
            }

            // 3-1. Stream Receive
            try {
                setSent(0);
                byte[] buf = new byte[32768];
                long currentReceived = 0;
                while (currentReceived < totalSize) {
                    long remaining = totalSize - currentReceived;
                    int toRead = (int) Math.min(remaining, buf.length);
                    int n = in.read(buf, 0, toRead);
                    if (n == -1) {
                        if (currentReceived == totalSize)
                            break;
                        throw new EOFException("Connection closed early");
                    }
                    if (n > 0) {
                        tempWriter.write(buf, 0, n);
                        currentReceived += n;
                        setSent(currentReceived);
                    }
                }
            } finally {
                tempWriter.close();
            }

            // 4. Send Termination
            synchronized (outLock) {
                out.write(zero8);
                out.flush();
            }

            // 5. Decrypt Header
            InputStream tempReader;
            if (this.InMem) {
                tempReader = new ByteArrayInputStream(memBuf.toByteArray());
            } else {
                tempReader = new FileInputStream(tempFile);
            }

            try {
                Opsec ops = new Opsec();
                byte[] headBytes = ops.Read(tempReader, 0);
                ops.View(headBytes);
                ops.Decpub(hs.myPriv, hs.myPub, hs.peerPub);
                sclear(hs.myPriv);

                long currentTime = System.currentTimeMillis() / 1000L;
                if (currentTime > ops.DecodeInt(ops.SmsgInfo) + 7200) {
                    sclear(ops.BodyKey);
                    throw new Exception("Connection timed out (session expired)");
                }

                // 6. Prepare decryption worker
                setStage(STAGE_ENCRYPTING);
                Bencrypt.SymMaster sm = new Bencrypt.SymMaster(ops.BodyAlgo, ops.BodyKey);
                sclear(ops.BodyKey);

                // 7. Decrypt Body to Stream
                sm.DeFile(tempReader, ops.BodySize, dst);
                setStage(STAGE_COMPLETE);
                return new TP1Result(hs.peerPub, hs.myPub, ops.Smsg, null);
            } finally {
                tempReader.close();
            }

        } catch (Exception e) {
            setStage(STAGE_ERROR);
            byte[] peer = hs != null ? hs.peerPub : null;
            byte[] my = hs != null ? hs.myPub : null;
            return new TP1Result(peer, my, "", e);
        }
    }

    // ========== Make TCP Socket ==========
    public static class TCPsocket {
        public ServerSocket Listener;
        public Socket Conn;

        public void MakeListener(int port) throws IOException {
            Listener = new ServerSocket(port);
            Listener.setSoTimeout(90000);
            Conn = Listener.accept();
        }

        public void MakeConnection(String addr, int port) throws Exception {
            Exception lastErr = null;
            for (int i = 0; i < 5; i++) {
                try {
                    Conn = new Socket();
                    Conn.connect(new java.net.InetSocketAddress(addr, port), 10000);
                    lastErr = null;
                    break;
                } catch (Exception e) {
                    lastErr = e;
                    try {
                        Thread.sleep(3000);
                    } catch (InterruptedException ignored) {
                    }
                }
            }
            if (lastErr != null)
                throw lastErr;
        }

        public void Close() {
            try {
                if (Conn != null)
                    Conn.close();
            } catch (IOException ignored) {
            }
            try {
                if (Listener != null)
                    Listener.close();
            } catch (IOException ignored) {
            }
        }
    }
}
