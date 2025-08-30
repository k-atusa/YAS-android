package com.example.kutil6_yas;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

import org.bouncycastle.util.encoders.Hex;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

public class ServiceActivity extends Service {
    // inline worker
    private Thread svcThread = null;
    private boolean svcFlag = false;
    private int svcMode = 0; // 1-8

    // data buffers
    private String[] sBuffer;
    private int sBufPos;
    private Uri[] uBuffer;
    private int uBufPos;
    private String[] oBuffer;
    private int oBufPos;
    private int[] iBuffer;
    private int iBufPos;

    // sub modules
    private BasicUtil bu;
    private ZipUtil zu;
    private FileUtil io;
    private YASaes yaes;
    private YASrsa yrsa;

    // service communication
    private Messenger svc2main = null;
    private Messenger main2svc = new Messenger(new IncomingHandler());
    private class IncomingHandler extends Handler {
        @Override
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case 1: // register messenger
                    svc2main = msg.replyTo;
                    break;
                case 2: // unregister messenger
                    svc2main = null;
                    break;
                case 3: // make string space
                    sBuffer = new String[msg.getData().getInt("int")];
                    sBufPos = 0;
                    break;
                case 4: // push string
                    sBuffer[sBufPos++] = msg.getData().getString("string");
                    break;
                case 5: // make uri space
                    uBuffer = new Uri[msg.getData().getInt("int")];
                    uBufPos = 0;
                    break;
                case 6: // push uri
                    uBuffer[uBufPos++] = msg.getData().getParcelable("uri", Uri.class);
                    break;
                case 7: // make order space
                    oBuffer = new String[msg.getData().getInt("int")];
                    oBufPos = 0;
                    break;
                case 8: // push order
                    oBuffer[oBufPos++] = msg.getData().getString("string");
                    break;
                case 9: // make int space
                    iBuffer = new int[msg.getData().getInt("int")];
                    iBufPos = 0;
                    break;
                case 10: // push int
                    iBuffer[iBufPos++] = msg.getData().getInt("int");
                    break;
                case 11: // enc
                    svcMode = 1;
                    svcThread = new Thread(ServiceActivity.this::order11);
                    svcThread.start();
                    break;
                case 12: // dec
                    svcMode = 2;
                    svcThread = new Thread(ServiceActivity.this::order12);
                    svcThread.start();
                    break;
                case 13: // send
                    svcMode = 3;
                    svcThread = new Thread(ServiceActivity.this::order13);
                    svcThread.start();
                    break;
                case 14: // receive
                    svcMode = 4;
                    svcThread = new Thread(ServiceActivity.this::order14);
                    svcThread.start();
                    break;
                case 15: // pgp txt enc
                    svcMode = 5;
                    svcThread = new Thread(ServiceActivity.this::order15);
                    svcThread.start();
                    break;
                case 16: // pgp txt dec
                    svcMode = 6;
                    svcThread = new Thread(ServiceActivity.this::order16);
                    svcThread.start();
                    break;
                case 17: // pgp file enc
                    svcMode = 7;
                    svcThread = new Thread(ServiceActivity.this::order17);
                    svcThread.start();
                    break;
                case 18: // pgp file dec
                    svcMode = 8;
                    svcThread = new Thread(ServiceActivity.this::order18);
                    svcThread.start();
                    break;
                default:
                    Toast.makeText(getApplicationContext(), "ERROR : unexpected message type " + msg.what, Toast.LENGTH_SHORT).show();
            }
        }
    }
    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return main2svc.getBinder();
    }
    @Override
    public boolean onUnbind(Intent intent) {
        svc2main = null;
        return super.onUnbind(intent);
    }

    // start service
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Notification notification = new NotificationCompat.Builder(this, "Kutil6YASServiceChannel")
                .setContentTitle("YAS-android")
                .setContentText("YAS-android Backend TaskManager Working")
                .setSmallIcon(R.drawable.icon_key) // mini icon
                .build();
        startForeground(1, notification);
        return START_STICKY;
    }
    @Override
    public void onCreate() {
        super.onCreate();
        int importance = NotificationManager.IMPORTANCE_DEFAULT;
        NotificationChannel channel = new NotificationChannel("Kutil6YASServiceChannel", "service channel", importance);
        channel.setDescription("kutil6_yas service channel");
        NotificationManager notificationManager = getSystemService(NotificationManager.class);
        if (notificationManager != null) {
            notificationManager.createNotificationChannel(channel);
        }
        this.bu = new BasicUtil();
        this.io = new FileUtil(this);
        this.zu = new ZipUtil(this.io, this);
        this.yaes = new YASaes(this);
        this.yrsa = new YASrsa();
    }
    @Override
    public void onDestroy() {
        if (svcThread != null) {
            svcThread.interrupt();
        } // stop the work
        super.onDestroy();
    }

    // common functions
    public void addLog(String msg) {
        try {
            Message doneMsg = Message.obtain(null, this.svcMode + 10);
            Bundle data = new Bundle();
            data.putString("string", msg);
            doneMsg.setData(data);
            svc2main.send(doneMsg);
        } catch (Exception e) {
            Toast.makeText(getApplicationContext(), e.toString(), Toast.LENGTH_SHORT).show();
        }
    }
    public void addLog(int code) {
        try {
            svc2main.send(Message.obtain(null, code));
        } catch (Exception e) {
            Toast.makeText(getApplicationContext(), e.toString(), Toast.LENGTH_SHORT).show();
        }
    }

    // working code
    private void clear() {
        this.sBuffer = null;
        this.sBufPos = 0;
        this.uBuffer = null;
        this.uBufPos = 0;
        this.oBuffer = null;
        this.oBufPos = 0;
        this.iBuffer = null;
        this.iBufPos = 0;
        this.svcMode = 0;
    }
    private void order11() {
        this.yaes.msg = this.oBuffer[0];
        this.yaes.Encrypt(this.uBuffer, this.sBuffer, this.oBuffer[1], "encrypted.bin.txt", false);
        addLog("encrypt output: Download/encrypted.bin.txt");
        if (this.yaes.err.isEmpty()) {
            addLog("Done!");
        } else {
            addLog("ERROR: "+this.yaes.err);
        }
        clear();
        addLog(10);
    }
    private void order12() {
        if (this.uBuffer.length == 0) { addLog("ERROR: no input file"); return; }
        this.yaes.View(this.uBuffer[0]);
        if (!this.yaes.err.isEmpty()) { addLog("ERROR: "+this.yaes.err); return; }
        this.yaes.Decrypt(this.oBuffer[0], this.uBuffer[0], false);
        addLog("decrypt output: Download/*");
        if (this.yaes.err.isEmpty()) {
            addLog("Done!");
        } else {
            addLog("ERROR: "+this.yaes.err);
        }
        clear();
        addLog(10);
    }
    private void order13() {
        // make key and open port
        addLog("generating RSA key...");
        byte[][] keypair = this.yrsa.Genkey(false);
        if (!this.yrsa.err.isEmpty()) { addLog("ERROR: " + this.yrsa.err); return; }
        SecureRandom s = new SecureRandom();
        int port = 5000 + s.nextInt(60000);
        addLog("opening port " + port + "...");
        try {
            for (String temp: this.bu.GetIP(port)) { addLog("IP: " + temp); }
            this.bu.OpenSocket(true, "", port);
        } catch (Exception e) {
            addLog("ERROR: " + e.toString());
            return;
        }

        // step 1 : send public key & receive pw
        addLog("exchanging secret key...");
        String pw;
        try {
            this.bu.sout.write(this.bu.Encode(keypair[0].length));
            this.bu.sout.write(keypair[0]);
            this.bu.sout.flush();
            byte[] buf = new byte[8];
            this.bu.sin.read(buf);
            buf = new byte[ (int) this.bu.Decode(buf) ];
            this.bu.sin.read(buf);
            pw = Hex.toHexString(this.yrsa.Decrypt(buf)).toLowerCase();
            if (!this.yrsa.err.isEmpty()) { addLog("ERROR: " + this.yrsa.err); return; }
        } catch (Exception e) {
            addLog("ERROR: " + e.toString());
            return;
        }

        // step 2 : wait zip & encryption
        svcFlag = true;
        new Thread( ()->{ order13_sub(pw); } ).start();
        try {
            while (svcFlag) {
                this.bu.sout.write(new byte[]{0, 0, 0, 0, 0, 0, 0, 0});
                this.bu.sout.flush();
                Thread.sleep(1000);
            }
        } catch (Exception e) {
            addLog("ERROR: " + e.toString());
            return;
        }

        // step 3 : send buffer file
        addLog("start transmitting...");
        int tempNum = 0;
        long readSize = 0;
        long fileSize = this.io.GetFileSize( this.io.GetLocalFile("yas_buffer") );
        int splitSize = 13107200;
        if (fileSize < 1310720) { splitSize = 65536; } else if (fileSize < 26214400) { splitSize = 655360; }
        try {
            this.bu.sout.write( this.bu.Encode(fileSize) );
            this.bu.sout.flush();
            InputStream f = new FileInputStream(this.io.GetLocalFile("yas_buffer"));
            byte[] buf = new byte[4096];
            while (true) {
                tempNum = f.read(buf);
                if (tempNum == -1) { break; }
                readSize += tempNum;
                if (readSize/splitSize != (readSize - tempNum)/splitSize) {
                    addLog( String.format("sending %d%% (%dk/%dk)", readSize*100/fileSize, readSize/1024, fileSize/1024) );
                }
                this.bu.sout.write(buf, 0, tempNum);
            }
            this.bu.sout.flush();
            f.close();
            buf = new byte[8];
            this.bu.sin.read(buf);
            if (this.bu.Decode(buf) != 0) {
                addLog("Warning: invalid socket exit sign");
            }
            this.bu.CloseSocket();
        } catch (Exception e) {
            addLog("ERROR: " + e.toString());
            return;
        }

        addLog("Done!");
        this.io.GetLocalFile("yas_buffer").delete();
        clear();
        addLog(10);
    }
    private void order13_sub(String pw) {
        addLog("making zip file...");
        try {
            this.zu.OpenZip("yas_chunk.zip", true, false);
            for (Uri u : uBuffer) { this.zu.AddZip(u); }
            this.zu.CloseZip();
        } catch (Exception e) {
            addLog("ERROR: " + e.toString());
            svcFlag = false;
            return;
        }
        addLog("encrypting...");
        this.yaes.msg = "autosend";
        this.yaes.Encrypt(new File[] { this.io.GetLocalFile("yas_chunk.zip") }, new String[] {"yas_chunk.zip"}, pw, "yas_buffer", true);
        this.io.GetLocalFile("yas_chunk.zip").delete();
        if ( !this.yaes.err.isEmpty() ) { addLog("ERROR: " + this.yaes.err); }
        svcFlag = false;
    }
    private void order14() {
        try {
            this.bu.OpenSocket(false, oBuffer[0], Integer.parseInt(oBuffer[1]));
        } catch (Exception e) {
            addLog("ERROR: " + e.toString());
            return;
        }

        // step 1 : get public key & send pw
        addLog("exchanging secret key...");
        byte[] buf = new byte[8];
        String pw;
        try {
            this.bu.sin.read(buf);
            buf = new byte[ (int) this.bu.Decode(buf) ];
            this.bu.sin.read(buf);
            this.yrsa.LoadKey(buf, null);
            if (!this.yrsa.err.isEmpty()) { addLog("ERROR: " + this.yrsa.err); return; }

            SecureRandom s = new SecureRandom();
            byte[] pwh = new byte[32];
            s.nextBytes(pwh);
            pw = Hex.toHexString(pwh).toLowerCase();
            buf = this.yrsa.Encrypt(pwh);
            if (!this.yrsa.err.isEmpty()) { addLog("ERROR: " + this.yrsa.err); return; }
            this.bu.sout.write(this.bu.Encode(buf.length));
            this.bu.sout.write(buf);
            this.bu.sout.flush();
        } catch (Exception e) {
            addLog("ERROR: " + e.toString());
            return;
        }

        // step 2 : wait & receive file
        addLog("waiting for sender...");
        long fileSize = 0;
        buf = new byte[8];
        try {
            while (true) {
                this.bu.sin.read(buf);
                boolean flag = true;
                for (byte b : buf) { if (b != (byte) 255) { flag = false; } }
                if (flag) { throw new Exception("sender quit transmittion"); }
                fileSize = this.bu.Decode(buf);
                if (fileSize != 0) { break; }
                Thread.sleep(500);
            }
        } catch (Exception e) {
            addLog("ERROR: " + e.toString());
            return;
        }

        addLog("start receiving...");
        int tempNum = 0;
        long readSize = 0;
        int splitSize = 13107200;
        if (fileSize < 1310720) { splitSize = 65536; } else if (fileSize < 26214400) { splitSize = 655360; }
        buf = new byte[4096];
        try {
            OutputStream f = new FileOutputStream(this.io.GetLocalFile("yas_buffer"));
            while (readSize < fileSize) {
                tempNum = this.bu.sin.read(buf);
                if (tempNum == -1) { break; }
                f.write(buf, 0, tempNum);
                readSize += tempNum;
                if (readSize/splitSize != (readSize - tempNum)/splitSize) {
                    addLog( String.format("receiving %d%% (%dk/%dk)", readSize*100/fileSize, readSize/1024, fileSize/1024) );
                }
            }
            f.close();
            this.bu.sout.write(new byte[] {0, 0, 0, 0, 0, 0, 0, 0});
            this.bu.sout.flush();
            this.bu.CloseSocket();
        } catch (Exception e) {
            addLog("ERROR : " + e.toString());
            return;
        }

        // step 3 : decryption & unzip
        addLog("decrypting...");
        this.yaes.Decrypt(pw, this.io.GetLocalFile("yas_buffer"), true);
        if (!this.yaes.err.isEmpty()) {
            addLog("ERROR : " + this.yaes.err);
            return;
        }
        this.io.GetLocalFile("yas_buffer").delete();
        addLog("unzipping file...");
        try {
            this.zu.OpenZip("yas_chunk.zip", true, true);
            boolean flag = this.zu.UnZip();
            this.zu.CloseZip();
            if (flag) { this.zu.CopyZip("yas_chunk.zip", "yas_downloaded.zip"); }
            addLog("output: Download/*");
        } catch (Exception e) {
            addLog("ERROR: " + e.toString());
            return;
        }

        addLog("Done!");
        this.io.GetLocalFile("yas_chunk.zip").delete();
        clear();
        addLog(10);
    }
    private void order15() {
        // step 1 : load keys
        addLog("loading key...");
        if (this.iBuffer[0] == 1) {
            this.yrsa.LoadKey( null, this.bu.B64de(this.oBuffer[2]) );
            if (!this.yrsa.err.isEmpty()) { addLog("ERROR: " + this.yrsa.err); return; }
        }
        YASrsa you = new YASrsa();
        you.LoadKey(this.bu.B64de(this.oBuffer[1]), null);
        if (!you.err.isEmpty()) { addLog("ERROR: " + you.err); return; }

        // step 2 : encrypt key
        addLog("encrypting key...");
        byte[] pw = this.bu.Genrand(32);
        byte[] pw_enc = you.Encrypt(pw);
        if (!you.err.isEmpty()) { addLog("ERROR: " + you.err); return; }

        // step 3 : sign message
        byte[] pw_sign = null;
        if (this.iBuffer[0] == 1) {
            addLog("signing key...");
            try {
                pw_sign = this.yrsa.Sign(pw);
                if (!this.yrsa.err.isEmpty()) { addLog("ERROR: " + this.yrsa.err); return; }
            } catch (Exception e) {
                addLog("ERROR: " + e.toString());
                return;
            }
        }

        // step 4 : encrypt message
        addLog("encrypting message...");
        byte[] msg_enc = null;
        try {
            msg_enc = this.bu.Aes128(Arrays.copyOfRange(pw, 16, 32), Arrays.copyOfRange(pw, 0, 16), this.oBuffer[0].getBytes(StandardCharsets.UTF_8), true, true);
        } catch (Exception e) {
            addLog("ERROR: " + e.toString());
            return;
        }
        try {
            Message doneMsg = Message.obtain(null, 19);
            Bundle data = new Bundle();
            data.putString( "string", this.bu.B64en(pw_enc) + "," + this.bu.B64en(pw_sign) + "," + this.bu.B64en(msg_enc) );
            doneMsg.setData(data);
            svc2main.send(doneMsg);
        } catch (Exception e) {
            addLog("ERROR: " + e.toString());
            return;
        }
        addLog("Done!");
        clear();
        addLog(10);
    }
    private void order16() {
        // step 1 : load keys
        addLog("loading key...");
        this.yrsa.LoadKey( null, this.bu.B64de(this.oBuffer[2]) );
        if (!this.yrsa.err.isEmpty()) { addLog("ERROR: " + this.yrsa.err); return; }
        YASrsa you = new YASrsa();
        if (this.iBuffer[1] != -1) {
            you.LoadKey(this.bu.B64de(this.oBuffer[1]), null);
            if (!you.err.isEmpty()) { addLog("ERROR: " + you.err); return; }
        }

        // step 2 : decrypt key
        addLog("decrypting key...");
        this.oBuffer[0] = this.oBuffer[0].replace(" ", "").replace("\n", "");
        this.sBuffer = this.oBuffer[0].split(",", -1);
        if (this.sBuffer.length != 3) { addLog("ERROR: invalid key format"); return; }
        byte[] pw = this.yrsa.Decrypt( this.bu.B64de( this.sBuffer[0] ) );
        if (!this.yrsa.err.isEmpty()) { addLog("ERROR: " + this.yrsa.err); return; }

        // step 3 : verify signature
        if (this.iBuffer[0] == 1) {
            addLog("verifying signature...");
            if (this.sBuffer[1].isEmpty()) {
                addLog("WARN: no signature data");
            } else if (this.iBuffer[1] == -1) {
                addLog("WARN: receiver not selected");
            } else {
                try {
                    if ( you.Verify( pw, this.bu.B64de(this.sBuffer[1]) ) ) {
                        addLog("signature verified");
                    } else {
                        addLog("WARN: signature verification failed");
                    }
                    if (!you.err.isEmpty()) { addLog("ERROR: " + you.err); return; }
                } catch (Exception e) {
                    addLog("ERROR: " + e.toString());
                    return;
                }
            }
        }

        // step 4 : decrypt message
        addLog("decrypting message...");
        String msg;
        try {
            msg = new String(this.bu.Aes128(Arrays.copyOfRange(pw, 16, 32), Arrays.copyOfRange(pw, 0, 16), this.bu.B64de(this.sBuffer[2]), true, false), StandardCharsets.UTF_8);
        } catch (Exception e) {
            addLog("ERROR: " + e.toString());
            return;
        }
        try {
            Message doneMsg = Message.obtain(null, 20);
            Bundle data = new Bundle();
            data.putString("string", msg);
            doneMsg.setData(data);
            svc2main.send(doneMsg);
        } catch (Exception e) {
            addLog("ERROR: " + e.toString());
            return;
        }
        addLog("Done!");
        clear();
        addLog(10);
    }
    private void order17() {
// step 1 : load keys
        addLog("loading key...");
        if (this.iBuffer[0] == 1) {
            this.yrsa.LoadKey( null, this.bu.B64de(this.oBuffer[1]) );
            if (!this.yrsa.err.isEmpty()) { addLog("ERROR: " + this.yrsa.err); return; }
        }
        YASrsa you = new YASrsa();
        you.LoadKey(this.bu.B64de(this.oBuffer[0]), null);
        if (!you.err.isEmpty()) { addLog("ERROR: " + you.err); return; }

        // step 2 : encrypt key
        addLog("encrypting key...");
        byte[] pw = this.bu.Genrand(32);
        byte[] pw_enc = you.Encrypt(pw);
        if (!you.err.isEmpty()) { addLog("ERROR: " + you.err); return; }

        // step 3 : sign message
        byte[] pw_sign = null;
        if (this.iBuffer[0] == 1) {
            addLog("signing key...");
            try {
                pw_sign = this.yrsa.Sign(pw);
                if (!this.yrsa.err.isEmpty()) { addLog("ERROR: " + this.yrsa.err); return; }
            } catch (Exception e) {
                addLog("ERROR: " + e.toString());
                return;
            }
        }

        // step 4 : zip data
        addLog("making zip file...");
        try {
            this.zu.OpenZip("yas_chunk.zip", true, false);
            for (Uri u : uBuffer) { this.zu.AddZip(u); }
            this.zu.CloseZip();
        } catch (Exception e) {
            addLog("ERROR: " + e.toString());
            svcFlag = false;
            return;
        }

        // step 5 : encrypt data
        addLog("encrypting...");
        this.yaes.msg = this.bu.B64en(pw_enc) + "," + this.bu.B64en(pw_sign);
        this.yaes.Encrypt(new File[] { this.io.GetLocalFile("yas_chunk.zip") }, new String[] {"yas_chunk.zip"}, Hex.toHexString(pw).toLowerCase(), "encrypted.bin.txt", false);
        addLog("encrypt output: Download/encrypted.bin.txt");
        this.io.GetLocalFile("yas_chunk.zip").delete();
        if (this.yaes.err.isEmpty()) {
            addLog("Done!");
        } else {
            addLog("ERROR: "+this.yaes.err);
        }
        clear();
        addLog(10);
    }
    private void order18() {
        // step 1 : load keys
        addLog("loading key...");
        this.yrsa.LoadKey( null, this.bu.B64de(this.oBuffer[1]) );
        if (!this.yrsa.err.isEmpty()) { addLog("ERROR: " + this.yrsa.err); return; }
        YASrsa you = new YASrsa();
        if (this.iBuffer[1] != -1) {
            you.LoadKey(this.bu.B64de(this.oBuffer[0]), null);
            if (!you.err.isEmpty()) { addLog("ERROR: " + you.err); return; }
        }

        // step 2 : decrypt key
        addLog("decrypting key...");
        this.yaes.View(uBuffer[0]);
        if (!this.yaes.err.isEmpty()) { addLog("ERROR: " + this.yaes.err); return; }
        this.sBuffer = this.yaes.msg.split(",", -1);
        if (this.sBuffer.length != 2) { addLog("ERROR: invalid message format"); return; }
        byte[] pw = this.yrsa.Decrypt( this.bu.B64de( this.sBuffer[0] ) );
        if (!this.yrsa.err.isEmpty()) { addLog("ERROR: " + this.yrsa.err); return; }

        // step 3 : verify signature
        if (this.iBuffer[0] == 1) {
            addLog("verifying signature...");
            if (this.sBuffer[0].isEmpty()) {
                addLog("WARN: no signature data");
            } else if (this.iBuffer[1] == -1) {
                addLog("WARN: receiver not selected");
            } else {
                try {
                    if ( you.Verify( pw, this.bu.B64de(this.sBuffer[1]) ) ) {
                        addLog("signature verified");
                    } else {
                        addLog("WARN: signature verification failed");
                    }
                    if (!you.err.isEmpty()) { addLog("ERROR: " + you.err); return; }
                } catch (Exception e) {
                    addLog("ERROR: " + e.toString());
                    return;
                }
            }
        }

        // step 4 : decrypt data
        addLog("decrypting data...");
        this.yaes.Decrypt(Hex.toHexString(pw).toLowerCase(), uBuffer[0], true);
        if (!this.yaes.err.isEmpty()) { addLog("ERROR : " + this.yaes.err); return; }
        addLog("decrypt output: Download/*");

        // step 5 : unzip data
        addLog("unzipping file...");
        try {
            this.zu.OpenZip("yas_chunk.zip", true, true);
            boolean flag = this.zu.UnZip();
            this.zu.CloseZip();
            if (flag) { this.zu.CopyZip("yas_chunk.zip", "yas_downloaded.zip"); }
        } catch (Exception e) {
            addLog("ERROR: " + e.toString());
            return;
        }

        addLog("Done!");
        this.io.GetLocalFile("yas_chunk.zip").delete();
        clear();
        addLog(10);
    }
}

