package com.example.k7yas.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.Bundle;
import android.os.IBinder;
import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;
import androidx.lifecycle.Observer;

import com.example.k7yas.R;
import com.example.k7yas.engine.Bencode;
import com.example.k7yas.engine.Bencrypt;
import com.example.k7yas.engine.Icons;
import com.example.k7yas.engine.Opsec;
import com.example.k7yas.engine.Star;
import com.example.k7yas.engine.Szip;
import com.example.k7yas.engine.TP1;

import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SvcYas extends Service {
    // methods
    public static final String METHOD_HASH = "arg2";
    public static final String METHOD_ASYM = "pqc1";
    public static final String METHOD_SYM = "gcmx1";
    public static final String METHOD_SYM_I = "gcm1";

    // worker datas
    private static final String CHANNEL_ID = "YasForegroundServiceChannel";
    private ExecutorService executor;
    private final SVCC1 chan = SVCC1.getChan();
    private Observer<SVCC1.VEvent> cmdObserver;

    @Override
    public void onCreate() {
        super.onCreate();
        executor = Executors.newSingleThreadExecutor();
        cmdObserver = vEvent -> {
            if (vEvent != null && vEvent.action != null) {
                Bundle args = (Bundle) vEvent.data;
                executor.execute(() -> handleTask(vEvent.action, args)); // work on new thread
            }
        };
        chan.ToSvcBus.observeForever(cmdObserver);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        createNotificationChannel();
        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("YAS Service")
                .setContentText("YAS is running in the foreground")
                .setSmallIcon(R.drawable.icon_service)
                .build();
        startForeground(1, notification);
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        if (chan != null && cmdObserver != null) {
            chan.ToSvcBus.removeObserver(cmdObserver);
        }
        if (executor != null) {
            executor.shutdown();
        }
        super.onDestroy();
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onTaskRemoved(Intent rootIntent) {
        super.onTaskRemoved(rootIntent);
        stopSelf();
    }

    private void createNotificationChannel() {
        NotificationChannel serviceChannel = new NotificationChannel(
                CHANNEL_ID,
                "YAS Foreground Service Channel",
                NotificationManager.IMPORTANCE_DEFAULT
        );
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(serviceChannel);
    }

    // Command Task Handler
    private void handleTask(String action, Bundle args) {
        // reset slots
        for (int i = 0; i < 4; i++) {
            chan.SetInt(i, 0);
            chan.SetLong(i, 0);
            chan.SetDouble(i, 0);
            chan.SetString(i, "");
        }
        chan.SetInt(0, 1); // set flag as working
        chan.SetString(0, "Initializing Engine");

        // match handles
        try {
            switch (action) {
                case "TASK_PACK":
                    handlePack(args);
                    break;
                case "TASK_UNPACK":
                    handleUnpack(args);
                    break;
                case "TASK_SEND":
                    handleSend(args);
                    break;
                case "TASK_RECEIVE":
                    handleReceive(args);
                    break;
                case "TASK_ENC_PW":
                    handleEncPw(args);
                    break;
                case "TASK_DEC_PW":
                    handleDecPw(args);
                    break;
                case "TASK_ENC_PUB":
                    handleEncPub(args);
                    break;
                case "TASK_DEC_PUB":
                    handleDecPub(args);
                    break;
                default:
                    throw new IllegalArgumentException("Unknown action: " + action);
            }
            chan.SetString(0, "Task Complete");

        } catch (Exception e) {
            chan.SetInt(1, 1); // set flag as error
            chan.SetString(1, e.toString());
        } finally {
            chan.SetInt(0, 0); // set flag as completed
            chan.SetDouble(0, 1.0);
            cleanTemp();
        }

        // clear dummies
        Account.ClearDummy();
        Bencrypt.ClearDummy();
        Opsec.ClearDummy();
        TP1.ClearDummy();
    }

    // Pack files
    private void handlePack(Bundle b) throws Exception {
        // Get target files
        ArrayList<IO1.VFile> srcs = b.getParcelableArrayList("srcs", IO1.VFile.class);
        if (srcs == null || srcs.isEmpty()) throw new IllegalArgumentException("Target resources null");

        // Get output file
        Account account = Account.GetAccount(this);
        String outName = account.PackType.equals("zip1") ? "archive.zip" : "archive.tar" ;
        IO1.VFile dst = IO1.CreateDownloadsFile(this, outName);
        if (dst == null) throw new java.io.IOException("Failed to create file in Downloads");

        // pack and copy
        chan.SetString(0, "Packing targets...");
        packFiles(srcs, account.PackType);
        chan.SetString(0, "Copying file...");
        File temp = new File(getFilesDir(), "archive.temp");
        try (InputStream in = new java.io.FileInputStream(temp); OutputStream out = dst.OpenWriter(this, false)) {
            in.transferTo(out);
        }
    }

    // Unpack file
    private void handleUnpack(Bundle b) throws Exception {
        // Get target files
        IO1.VFile src = b.getParcelable("src", IO1.VFile.class);
        if (src == null) throw new IllegalArgumentException("Source archive null");
        Account account = Account.GetAccount(this);

        // copy and unpack
        chan.SetString(0, "Copying file...");
        File temp = new File(getFilesDir(), "archive.temp");
        try (InputStream in = src.OpenReader(this); OutputStream out = new java.io.FileOutputStream(temp)) {
            in.transferTo(out);
        }
        chan.SetString(0, "Unpacking archive...");
        unpackFiles(account.PackType);
    }

    // Send files and message
    private void handleSend(Bundle b) throws Exception {
        // get targets and parameters
        ArrayList<IO1.VFile> srcs = b.getParcelableArrayList("srcs", IO1.VFile.class);
        String addr = b.getString("addr", "127.0.0.1:8002");
        String secret = b.getString("context", "");
        String smsg = b.getString("smsg", "");

        String ip = addr;
        int port = 8002;
        if (addr.contains(":")) {
            String[] parts = addr.split(":");
            ip = parts[0];
            port = Integer.parseInt(parts[1]);
        }

        // start connection
        chan.SetString(0, "Connecting to Peer...");
        TP1.TCPsocket socket = new TP1.TCPsocket();
        try {
            // make connection, prepare temp files
            socket.MakeConnection(ip, port);
            int mode = TP1.SYM_GCMX1 | TP1.HASH_ARG2 | TP1.ASYM_PQC1; // arg2, pqc1, gcmx1
            if (srcs == null || srcs.isEmpty()) {
                mode |= TP1.MODE_MSGONLY;
            }
            chan.SetDouble(0, 0.1); // connection is 10%
            File tempPack = new File(getFilesDir(), "archive.temp");
            File tempCrypto = new File(getFilesDir(), "crypto.temp");

            // pack with zip1
            long size = 0;
            if (srcs != null && !srcs.isEmpty()) {
                chan.SetString(0, "Packing targets to ZIP...");
                size = packFiles(srcs, "zip1");
            }
            chan.SetDouble(0, 0.2); // packing is 20%

            // load secret, TP1 protocol
            byte[] secretBytes = Bencode.NormPW(secret);
            TP1 tp1 = new TP1(mode, false, true, secretBytes, socket.Conn);
            if (secretBytes != null) {
                Account.sclear(secretBytes);
            }

            // status checker thread
            java.util.concurrent.atomic.AtomicBoolean stopMonitor = new java.util.concurrent.atomic.AtomicBoolean(false);
            Thread monitorThread = new Thread(() -> {
                while (!stopMonitor.get()) {
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        break;
                    }
                    long[] status = tp1.GetStatus();
                    long stage = status[0];
                    long sentBytes = status[1];
                    long totalBytes = status[2];

                    if (stage == TP1.STAGE_HANDSHAKE) {
                        chan.SetString(0, "Handshaking with peer...");
                    } else if (stage == TP1.STAGE_ENCRYPTING) {
                        chan.SetString(0, "Encrypting payloads...");
                    } else if (stage == TP1.STAGE_TRANSFERRING) {
                        chan.SetString(0, "Transferring encrypted stream...");
                        if (totalBytes > 0) {
                            chan.SetDouble(0, 0.2 + 0.8 * ((double) sentBytes / totalBytes));
                        }
                    }
                }
            });
            monitorThread.start();

            // TP1 send
            TP1.TP1Result result = null;
            if (srcs == null || srcs.isEmpty()) {
                try (InputStream emptySrc = new java.io.ByteArrayInputStream(new byte[0])) {
                    result = tp1.Send(emptySrc, 0, smsg, tempCrypto);
                }
            } else {
                try (InputStream fis = new java.io.FileInputStream(tempPack)) {
                    result = tp1.Send(fis, size, smsg, tempCrypto);
                }
            }
            stopMonitor.set(true); // stop monitor thread
            monitorThread.interrupt();

            // delete temp files, get results
            if (tempPack.exists()) tempPack.delete();
            if (tempCrypto.exists()) tempCrypto.delete();
            if (result != null) {
                chan.SetString(2, "From " + Opsec.Crc32(result.FromPub) + " To " + Opsec.Crc32(result.ToPub)); // chan 2 to show transfer info
                if (result.Err != null) { throw result.Err; }
            }

        } finally {
            socket.Close();
        }
    }

    // Receive files and message
    private void handleReceive(Bundle b) throws Exception {
        // get parameters
        String portStr = b.getString("port", "8002");
        int port = 8002;
        try {
            port = Integer.parseInt(portStr);
        } catch (NumberFormatException e) {
            port = b.getInt("port", 8002);
        }
        String secret = b.getString("context", "");

        // prepare temp files
        chan.SetString(0, "Waiting for Peer Connection...");
        TP1.TCPsocket socket = new TP1.TCPsocket();
        File tempCrypto = new File(getFilesDir(), "crypto.temp");
        File tempPack = new File(getFilesDir(), "archive.temp");
        TP1.TP1Result result = null;

        try {
            // make connection
            socket.MakeListener(port);
            byte[] secretBytes = Bencode.NormPW(secret);
            TP1 tp1 = new TP1(0, false, true, secretBytes, socket.Conn);
            if (secretBytes != null) {
                Account.sclear(secretBytes);
            }
            chan.SetDouble(0, 0.1); // connection is 10%

            // status monitor thread
            java.util.concurrent.atomic.AtomicBoolean stopMonitor = new java.util.concurrent.atomic.AtomicBoolean(false);
            Thread monitorThread = new Thread(() -> {
                while (!stopMonitor.get()) {
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        break;
                    }
                    long[] status = tp1.GetStatus();
                    long stage = status[0];
                    long receivedBytes = status[1];
                    long totalBytes = status[2];

                    if (stage == TP1.STAGE_HANDSHAKE) {
                        chan.SetString(0, "Handshaking with peer...");
                    } else if (stage == TP1.STAGE_TRANSFERRING) {
                        chan.SetString(0, "Receiving encrypted stream...");
                        if (totalBytes > 0) {
                            chan.SetDouble(0, 0.1 + 0.8 * ((double) receivedBytes / totalBytes));
                        }
                    } else if (stage == TP1.STAGE_ENCRYPTING) {
                        chan.SetString(0, "Decrypting payloads...");
                        chan.SetDouble(0, 0.8);
                    }
                }
            });
            monitorThread.start();

            // TP1 receive
            try (OutputStream fos = new java.io.FileOutputStream(tempPack)) {
                result = tp1.Receive(fos, tempCrypto);
            } finally {
                stopMonitor.set(true);
                monitorThread.interrupt();
            }

            // get results, set smsg
            if (result == null) {
                throw new Exception("TP1 result is null");
            } else {
                chan.SetString(2, "From " + Opsec.Crc32(result.FromPub) + " To " + Opsec.Crc32(result.ToPub)); // chan 2 to show transfer info
                if (result.Err != null) { throw result.Err; }
                if (result.Smsg != null && !result.Smsg.isEmpty()) { chan.SetString(3, result.Smsg); } // chan 3 to show smsg
            }

            // unpack zip if file mode
            if ((tp1.Mode & TP1.MODE_MSGONLY) == 0) {
                chan.SetString(0, "Unpacking received files...");
                unpackFiles("zip1");
            }
            chan.SetDouble(0, 1.0);

        } finally {
            if (tempCrypto.exists()) tempCrypto.delete();
            if (tempPack.exists()) tempPack.delete();
            socket.Close();
        }
    }

    // Encrypt with password
    private void handleEncPw(Bundle b) throws Exception {
        // get parameters
        ArrayList<IO1.VFile> srcs = b.getParcelableArrayList("srcs", IO1.VFile.class);
        byte[] maskedPw = b.getByteArray("password");
        String kfName = b.getString("keyfile", "");
        String smsg = b.getString("smsg", "");
        String msg = b.getString("msg", "");

        Account account = Account.GetAccount(this);
        Bencrypt.Masker masker = Bencrypt.Masker.GetMasker();
        byte[] unmaskedPw = null;
        byte[] unmaskedKf = null;

        try {
            // unmask pw kf
            unmaskedPw = masker.XOR(maskedPw);
            if (!kfName.isEmpty()) unmaskedKf = masker.XOR(account.KeyFiles.get(kfName));

            if (srcs == null || srcs.isEmpty()) { // msg-only mode
                chan.SetString(0, "Encrypting secure message...");
                Opsec ops = new Opsec();
                ops.Reset();
                ops.Msg = msg;
                ops.Smsg = smsg;

                byte[] header = ops.Encpw(METHOD_HASH, unmaskedPw, unmaskedKf); // always use arg2
                java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                ops.Write(baos, header);
                String txtRes = Bencode.Encode64(baos.toByteArray(), "#", 80, 10);
                chan.SetString(3, txtRes); // chan 3 to return cipher-msg

            } else { // file mode
                chan.SetString(0, "Packing files to archive...");
                long zsize = packFiles(srcs, account.PackType);
                chan.SetDouble(0, 0.25); // packing is 25%

                // make header
                chan.SetString(0, "Creating encryption header...");
                IO1.VFile dst = IO1.CreateDownloadsFile(this, "encrypted." + account.ImgType);
                if (dst == null) throw new java.io.IOException("Failed to create download file");
                Bencrypt.SymMaster dummySm = new Bencrypt.SymMaster(METHOD_SYM, new byte[44]);

                Opsec ops = new Opsec();
                ops.Reset();
                ops.Msg = msg;
                ops.Smsg = smsg;
                ops.BodySize = dummySm.AfterSize(zsize);
                ops.BodyAlgo = METHOD_SYM;
                ops.BodyInfo = account.PackType.getBytes(java.nio.charset.StandardCharsets.UTF_8);

                byte[] header = ops.Encpw(METHOD_HASH, unmaskedPw, unmaskedKf);
                Bencrypt.SymMaster sm = new Bencrypt.SymMaster(ops.BodyAlgo, ops.BodyKey);
                Account.sclear(ops.BodyKey);

                long totalWritten = 0;
                try (OutputStream out = dst.OpenWriter(this, false)) {
                    // write prehead
                    byte[] prehead = null;
                    if (account.ImgType.equals("webp")) {
                        prehead = Icons.AesWebp.clone();
                    } else if (account.ImgType.equals("png")) {
                        prehead = Icons.AesPng.clone();
                    }
                    if (prehead != null) {
                        int alignmentPadding = (128 - (prehead.length % 128)) % 128;
                        if (alignmentPadding > 0) {
                            byte[] balancedPrehead = new byte[prehead.length + alignmentPadding];
                            System.arraycopy(prehead, 0, balancedPrehead, 0, prehead.length);
                            prehead = balancedPrehead;
                        }
                        out.write(prehead);
                        totalWritten += prehead.length;
                    }

                    // write opsec header
                    ops.Write(out, header);
                    long headerLenBytes = 4 + 2 + header.length;
                    if (header.length >= 65535) {
                        headerLenBytes += 2;
                    }
                    totalWritten += headerLenBytes;
                    chan.SetDouble(0, 0.50); // header is 25%

                    chan.SetString(0, "Encrypting archive payload...");
                    long cryptoBodySize = encFile(sm, out);
                    totalWritten += cryptoBodySize;
                    chan.SetDouble(0, 0.75); // body encryption is 25%

                    chan.SetString(0, "Applying padding...");
                    long padLen = Opsec.PadLen(totalWritten);
                    if (padLen > 0) {
                        Opsec.PadFile(out, padLen);
                    }
                }
            }
        } finally {
            if (unmaskedPw != null) Account.sclear(unmaskedPw);
            if (unmaskedKf != null) Account.sclear(unmaskedKf);
        }
    }

    // Decrypt with password
    private void handleDecPw(Bundle b) throws Exception {
        // get parameters
        IO1.VFile srcFile = b.getParcelable("src", IO1.VFile.class);
        byte[] maskedPw = b.getByteArray("password");
        String kfName = b.getString("keyfile", "");
        String text = b.getString("text", "");

        Account account = Account.GetAccount(this);
        Bencrypt.Masker masker = Bencrypt.Masker.GetMasker();
        byte[] unmaskedPw = null;
        byte[] unmaskedKf = null;

        try {
            // unmask pw kf
            unmaskedPw = masker.XOR(maskedPw);
            if (!kfName.isEmpty()) unmaskedKf = masker.XOR(account.KeyFiles.get(kfName));

            if (srcFile == null) { // msg-only mode
                chan.SetString(0, "Decoding secure message...");
                byte[] data;
                if (text.contains("#")) {
                    data = Bencode.Decode64(text, "#");
                } else {
                    data = Bencode.Decode64(text, "");
                }

                Opsec ops = new Opsec();
                ops.Reset();
                try (java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(data)) {
                    byte[] header = ops.Read(bais, 0);
                    ops.View(header);
                    ops.Decpw(unmaskedPw, unmaskedKf);
                }
                if (ops.Msg != null) chan.SetString(2, ops.Msg); // chan 2 for msg
                if (ops.Smsg != null) chan.SetString(3, ops.Smsg); // chan 3 for smsg

            } else { // file mode
                chan.SetString(0, "Reading encrypted file header...");
                Opsec ops = new Opsec();
                ops.Reset();

                try (InputStream is = srcFile.OpenReader(this)) {
                    byte[] header = ops.Read(is, 0);
                    ops.View(header);
                    ops.Decpw(unmaskedPw, unmaskedKf);
                    if (ops.Msg != null) chan.SetString(2, ops.Msg); // chan 2 for msg
                    if (ops.Smsg != null) chan.SetString(3, ops.Smsg); // chan 3 for smsg

                    chan.SetString(0, "Decrypting archive payload...");
                    Bencrypt.SymMaster sm = new Bencrypt.SymMaster(ops.BodyAlgo, ops.BodyKey);
                    Account.sclear(ops.BodyKey);
                    decFile(sm, is, ops.BodySize);
                    chan.SetDouble(0, 0.5);
                }

                // unpack if required
                if (ops.BodyInfo != null && ops.BodyInfo.length > 0) {
                    chan.SetString(0, "Unpacking decrypted files...");
                    String packType = new String(ops.BodyInfo, java.nio.charset.StandardCharsets.UTF_8);
                    unpackFiles(packType);
                }
            }
        } finally {
            if (unmaskedPw != null) Account.sclear(unmaskedPw);
            if (unmaskedKf != null) Account.sclear(unmaskedKf);
        }
    }

    // Encrypt with public key
    private void handleEncPub(Bundle b) throws Exception {
        // get parameters
        ArrayList<IO1.VFile> srcs = b.getParcelableArrayList("srcs", IO1.VFile.class);
        String pubName = b.getString("pubName", "");
        boolean doSign = b.getBoolean("doSign", false);
        String smsg = b.getString("smsg", "");
        String msg = b.getString("msg", "");

        Account account = Account.GetAccount(this);
        Bencrypt.Masker masker = Bencrypt.Masker.GetMasker();
        byte[] unmaskedPri = null;

        try {
            // get peer public and my private
            byte[] peerPub = account.PubKeys.get(pubName);
            if (doSign) unmaskedPri = masker.XOR(account.PriKey);

            if (srcs == null || srcs.isEmpty()) { // msg-only mode
                chan.SetString(0, "Encrypting secure message...");
                Opsec ops = new Opsec();
                ops.Reset();
                ops.Msg = msg;
                ops.Smsg = smsg;

                byte[] header = ops.Encpub(account.KeyType, peerPub, unmaskedPri);
                java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                ops.Write(baos, header);
                String txtRes = Bencode.Encode64(baos.toByteArray(), "#", 80, 10);
                chan.SetString(3, txtRes); // chan 3 to return cipher-msg

            } else { // file mode
                chan.SetString(0, "Packing files to archive...");
                long zsize = packFiles(srcs, account.PackType);
                chan.SetDouble(0, 0.25); // packing is 25%

                // make header
                chan.SetString(0, "Creating encryption header...");
                IO1.VFile dst = IO1.CreateDownloadsFile(this, "encrypted." + account.ImgType);
                if (dst == null) throw new java.io.IOException("Failed to create download file");
                Bencrypt.SymMaster dummySm = new Bencrypt.SymMaster(METHOD_SYM, new byte[44]);

                Opsec ops = new Opsec();
                ops.Reset();
                ops.Msg = msg;
                ops.Smsg = smsg;
                ops.BodySize = dummySm.AfterSize(zsize);
                ops.BodyAlgo = METHOD_SYM;
                ops.BodyInfo = account.PackType.getBytes(java.nio.charset.StandardCharsets.UTF_8);

                byte[] header = ops.Encpub(account.KeyType, peerPub, unmaskedPri);
                Bencrypt.SymMaster sm = new Bencrypt.SymMaster(ops.BodyAlgo, ops.BodyKey);
                Account.sclear(ops.BodyKey);

                long totalWritten = 0;
                try (OutputStream out = dst.OpenWriter(this, false)) {
                    // get prehead
                    byte[] prehead = null;
                    if (account.ImgType.equals("webp")) {
                        prehead = Icons.CloudWebp.clone();
                    } else if (account.ImgType.equals("png")) {
                        prehead = Icons.CloudPng.clone();
                    }
                    if (prehead != null) {
                        int alignmentPadding = (128 - (prehead.length % 128)) % 128;
                        if (alignmentPadding > 0) {
                            byte[] balancedPrehead = new byte[prehead.length + alignmentPadding];
                            System.arraycopy(prehead, 0, balancedPrehead, 0, prehead.length);
                            prehead = balancedPrehead;
                        }
                        out.write(prehead);
                        totalWritten += prehead.length;
                    }

                    // write opsec header
                    ops.Write(out, header);
                    long headerLenBytes = 4 + 2 + header.length;
                    if (header.length >= 65535) {
                        headerLenBytes += 2;
                    }
                    totalWritten += headerLenBytes;
                    chan.SetDouble(0, 0.50); // header is 25%

                    chan.SetString(0, "Encrypting archive payload...");
                    long cryptoBodySize = encFile(sm, out);
                    totalWritten += cryptoBodySize;
                    chan.SetDouble(0, 0.75); // body encryption is 25%

                    chan.SetString(0, "Applying padding...");
                    long padLen = Opsec.PadLen(totalWritten);
                    if (padLen > 0) {
                        Opsec.PadFile(out, padLen);
                    }
                }
            }
        } finally {
            if (unmaskedPri != null) Account.sclear(unmaskedPri);
        }
    }

    // Decrypt with private key
    private void handleDecPub(Bundle b) throws Exception {
        // get parameters
        IO1.VFile srcFile = b.getParcelable("src", IO1.VFile.class);
        String pubName = b.getString("pubName", "");
        String text = b.getString("text", "");
        Account account = Account.GetAccount(this);
        Bencrypt.Masker masker = Bencrypt.Masker.GetMasker();
        byte[] unmaskedPri = null;

        try {
            // get myPriv, myPub, peerPub
            unmaskedPri = masker.XOR(account.PriKey);
            byte[] peerPub = !pubName.isEmpty() ? account.PubKeys.get(pubName) : null;
            byte[] myPub = (peerPub != null) ? account.PubKey : null;

            if (srcFile == null) { // msg-only mode
                chan.SetString(0, "Decoding secure message...");
                byte[] data;
                if (text.contains("#")) {
                    data = Bencode.Decode64(text, "#");
                } else {
                    data = Bencode.Decode64(text, "");
                }

                Opsec ops = new Opsec();
                ops.Reset();
                try (java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(data)) {
                    byte[] header = ops.Read(bais, 0);
                    ops.View(header);
                    ops.Decpub(unmaskedPri, myPub, peerPub);
                }
                if (ops.Msg != null) chan.SetString(2, ops.Msg); // chan 2 for msg
                if (ops.Smsg != null) chan.SetString(3, ops.Smsg); // chan 3 for smsg

            } else { // file mode
                chan.SetString(0, "Reading encrypted file header...");
                Opsec ops = new Opsec();
                ops.Reset();

                try (InputStream is = srcFile.OpenReader(this)) {
                    byte[] header = ops.Read(is, 0);
                    ops.View(header);
                    ops.Decpub(unmaskedPri, myPub, peerPub);
                    if (ops.Msg != null) chan.SetString(2, ops.Msg); // chan 2 for msg
                    if (ops.Smsg != null) chan.SetString(3, ops.Smsg); // chan 3 for smsg

                    chan.SetString(0, "Decrypting archive payload...");
                    Bencrypt.SymMaster sm = new Bencrypt.SymMaster(ops.BodyAlgo, ops.BodyKey);
                    Account.sclear(ops.BodyKey);
                    decFile(sm, is, ops.BodySize);
                    chan.SetDouble(0, 0.5);
                }

                // unpack if required
                if (ops.BodyInfo != null && ops.BodyInfo.length > 0) {
                    chan.SetString(0, "Unpacking decrypted files...");
                    String packType = new String(ops.BodyInfo, java.nio.charset.StandardCharsets.UTF_8);
                    unpackFiles(packType);
                }
            }
        } finally {
            if (unmaskedPri != null) Account.sclear(unmaskedPri);
        }
    }

    // helpers
    private long packFiles(ArrayList<IO1.VFile> srcs, String packType) throws Exception {
        File temp = new File(getFilesDir(), "archive.temp");

        if (packType.equals("zip1")) { // zip1
            try (Szip.ZipWriter zw = new Szip.ZipWriter()) {
                zw.Open(temp, true);
                for (IO1.VFile f : srcs) {
                    try (InputStream is = f.OpenReader(this)) {
                        zw.Write(f.GetName(this), is);
                    }
                }
            }

        } else { // tar1
            try (OutputStream out = new java.io.FileOutputStream(temp); Star.TarWriter tw = new Star.TarWriter()) {
                tw.Open(out);
                for (IO1.VFile f : srcs) {
                    try (InputStream is = f.OpenReader(this)) {
                        tw.Write(f.GetName(this), is, f.GetSize(this), 0644, f.IsDir(this));
                    }
                }
            }
        }
        return temp.length(); // return packed file size
    }

    private void unpackFiles(String packType) throws Exception {
        File temp = new File(getFilesDir(), "archive.temp");

        if (packType.equals("zip1")) { // zip1
            try (Szip.ZipReader zr = new Szip.ZipReader()) {
                zr.Open(temp);
                for (int i = 0; i < zr.Names.size(); i++) {
                    String name = zr.Names.get(i);
                    if (name.endsWith("/") || name.endsWith("\\")) {
                        continue; // skip directories
                    }
                    String safeName = name.replace("/", ".").replace("\\", "."); // replace separators
                    IO1.VFile target = IO1.CreateDownloadsFile(this, safeName);
                    if (target != null) {
                        try (OutputStream os = target.OpenWriter(this, false); InputStream is = zr.Open(i)) {
                            is.transferTo(os);
                        }
                    }
                }
            }

        } else { // tar1
            try (InputStream is = new java.io.FileInputStream(temp); Star.TarReader tr = new Star.TarReader()) {
                tr.Open(is);
                while (tr.Next()) {
                    if (tr.IsDir) {
                        continue; // skip directories
                    }
                    String safeName = tr.Name.replace("/", ".").replace("\\", "."); // replace separators
                    IO1.VFile target = IO1.CreateDownloadsFile(this, safeName);
                    if (target != null) {
                        try (OutputStream os = target.OpenWriter(this, false)) {
                            tr.Mkfile(os);
                        }
                    }
                }
            }
        }
    }

    private long encFile(Bencrypt.SymMaster sm, OutputStream dst) throws Exception {
        File temp = new File(getFilesDir(), "archive.temp");
        long fsize = temp.length();
        try (InputStream fis = new java.io.FileInputStream(temp)) {
            sm.EnFile(fis, fsize, dst);
        }
        return sm.AfterSize(fsize); // return crypto size
    }

    private void decFile(Bencrypt.SymMaster sm, InputStream src, long size) throws Exception {
        File temp = new File(getFilesDir(), "archive.temp");
        try (OutputStream fos = new java.io.FileOutputStream(temp)) {
            sm.DeFile(src, size, fos);
        }
    }

    private void cleanTemp() {
        String[] temps = {"archive.temp", "crypto.temp"};
        for (String name : temps) {
            File f = new File(getFilesDir(), name);
            if (f.exists()) f.delete();
        }
    }
}
