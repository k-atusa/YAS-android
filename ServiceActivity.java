package com.example.kutil6_yas;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.content.Intent;
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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

public class ServiceActivity extends Service {
    private String CHANNEL_ID = "Kutil6YASServiceChannel";
    private Thread svcThread = null;
    private boolean workFlag = false;
    private IOmanager ioManager = ioManager = new IOmanager(this);
    private Messenger recvMessenger = null;
    private Messenger svcMessenger = new Messenger(new IncomingHandler());

    private String[] sBuffer;
    private int sBufPos;
    private Uri[] uBuffer;
    private int uBufPos;
    private String[] oBuffer;
    private int oBufPos;

    private class IncomingHandler extends Handler {
        @Override
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case 1: // register messenger
                    recvMessenger = msg.replyTo;
                    break;
                case 2: // unregister messenger
                    recvMessenger = null;
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
                    uBuffer[uBufPos++] = msg.getData().getParcelable("uri");
                    break;
                case 7: // make order space
                    oBuffer = new String[msg.getData().getInt("int")];
                    oBufPos = 0;
                    break;
                case 8: // push order
                    oBuffer[oBufPos++] = msg.getData().getString("string");
                    break;
                case 11: // send data
                    svcThread = new Thread(ServiceActivity.this::order11);
                    svcThread.start();
                    break;
                case 12: // recv data
                    svcThread = new Thread(ServiceActivity.this::order12);
                    svcThread.start();
                    break;
                case 13: // do encryption
                    svcThread = new Thread(ServiceActivity.this::order13);
                    svcThread.start();
                    break;
                case 14: // do decryption
                    svcThread = new Thread(ServiceActivity.this::order14);
                    svcThread.start();
                    break;
                default:
                    addLog("ERROR : unexpected message type "+msg.what);
            }
        }
    }
    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return svcMessenger.getBinder();
    }
    @Override
    public boolean onUnbind(Intent intent) {
        recvMessenger = null;
        return super.onUnbind(intent);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("YAS-android")
                .setContentText("YAS-android Backend TaskManager Working")
                .setSmallIcon(R.drawable.alerticon) // mini icon
                .build();
        startForeground(1, notification);
        return START_STICKY;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        int importance = NotificationManager.IMPORTANCE_DEFAULT;
        NotificationChannel channel = new NotificationChannel(CHANNEL_ID, "service channel", importance);
        channel.setDescription("kutil6_yas service channel");
        NotificationManager notificationManager = getSystemService(NotificationManager.class);
        if (notificationManager != null) { notificationManager.createNotificationChannel(channel); }
    }

    @Override
    public void onDestroy() {
        if (svcThread != null) {
            svcThread.interrupt();
        } // stop the work
        super.onDestroy();
    }

    public void addLog(String msg) {
        try {
            Message doneMsg = Message.obtain(null, 21);
            Bundle data = new Bundle();
            data.putString("string", msg);
            doneMsg.setData(data);
            recvMessenger.send(doneMsg);
        } catch (Exception e) {
            Toast.makeText(getApplicationContext(), e.toString(), Toast.LENGTH_SHORT).show();
        }
    }

    public void addLog(int code) {
        try {
            recvMessenger.send(Message.obtain(null, code));
        } catch (Exception e) {
            Toast.makeText(getApplicationContext(), e.toString(), Toast.LENGTH_SHORT).show();
        }
    }

    // send data
    private void order11() {
        addLog("generating RSA key..."); // make key and open port
        yas_java k0 = new yas_java(this, ioManager);
        byte[] public_key = k0.GenKey(uBuffer.length > 1);
        SecureRandom s = new SecureRandom();
        int port = 5000 + s.nextInt(60000);
        addLog("opening port " + port + "...");
        SubActivity k1 = new SubActivity(ioManager, this, recvMessenger);
        try {
            k1.PrintIP(port); // get local ip
            k1.OpenSocket(true, "", port);
        }
        catch (Exception e) {
            addLog("ERROR : " + e.toString());
            return;
        }

        // step 1 : send public key & receive pw
        addLog("exchanging secret key...");
        String pw;
        try {
            k1.sout.write(k1.Encode(public_key.length));
            k1.sout.write(public_key);
            k1.sout.flush();
            byte[] buf = new byte[8];
            k1.sin.read(buf);
            buf = new byte[ (int) k1.Decode(buf) ];
            k1.sin.read(buf);
            pw = Hex.toHexString( k0.RSAcrypt(buf, false) ).toLowerCase();
        } catch (Exception e) {
            addLog("ERROR : " + e.toString());
            return;
        }

        // step 2 : wait zip & encryption
        workFlag = true;
        new Thread( ()->{ order11_sub(pw, k0, k1); } ).start();
        try {
            while (workFlag) {
                k1.sout.write(new byte[]{0, 0, 0, 0, 0, 0, 0, 0});
                k1.sout.flush();
                Thread.sleep(1000);
            }
        } catch (Exception e) {
            addLog("ERROR : " + e.toString());
            return;
        }

        // step 3 : send buffer file
        addLog("start transmitting...");
        int tempNum = 0;
        long readSize = 0;
        long fileSize = ioManager.GetFileSize( ioManager.GetLocalFile("yas_buffer") );
        int splitSize = 13107200;
        if (fileSize < 1310720) { splitSize = 65536; } else if (fileSize < 26214400) { splitSize = 655360; }
        try {
            k1.sout.write( k1.Encode(fileSize) );
            k1.sout.flush();
            InputStream f = new FileInputStream(ioManager.GetLocalFile("yas_buffer"));
            byte[] buf = new byte[4096];
            while (true) {
                tempNum = f.read(buf);
                if (tempNum == -1) { break; }
                readSize += tempNum;
                if (readSize/splitSize != (readSize - tempNum)/splitSize) {
                    addLog( String.format("sending %d%% (%dk/%dk)", readSize*100/fileSize, readSize/1024, fileSize/1024) );
                }
                k1.sout.write(buf, 0, tempNum);
            }
            k1.sout.flush();
            f.close();
            buf = new byte[8];
            k1.sin.read(buf);
            if (k1.Decode(buf) != 0) {
                addLog("Warning : invalid socket exit sign");
            }
            k1.CloseSocket();
        } catch (Exception e) {
            addLog("ERROR : " + e.toString());
            return;
        }

        addLog("sending finished");
        ioManager.GetLocalFile("yas_buffer").delete();
        addLog(22);
        sBuffer = null;
        uBuffer = null;
        oBuffer = null;
    }
    private void order11_sub(String pw, yas_java k0, SubActivity k1) {
        addLog("making zip file...");
        try {
            k1.OpenZip("yas_chunk.zip", true, false);
            for (Uri u : uBuffer) { k1.AddZip(u); }
            k1.CloseZip();
        } catch (Exception e) {
            addLog("ERROR : " + e.toString());
            workFlag = false;
            return;
        }
        addLog("encrypting...");
        k0.Encrypt(new File[] { ioManager.GetLocalFile("yas_chunk.zip") }, new String[] {"yas_chunk.zip"}, pw, "yas_buffer", true);
        ioManager.GetLocalFile("yas_chunk.zip").delete();
        if ( !k0.err.isEmpty() ) { addLog("ERROR : " + k0.err); }
        workFlag = false;
    }

    // recv data
    private void order12() {
        yas_java k0 = new yas_java(this, ioManager);
        SubActivity k1 = new SubActivity(ioManager, this, recvMessenger);
        try {
            k1.OpenSocket(false, oBuffer[0], Integer.parseInt(oBuffer[1]));
        } catch (Exception e) {
            addLog("ERROR : " + e.toString());
            return;
        }

        // step 1 : get public key & send pw
        addLog("exchanging secret key...");
        byte[] buf = new byte[8];
        String pw;
        try {
            k1.sin.read(buf);
            buf = new byte[ (int) k1.Decode(buf) ];
            k1.sin.read(buf);
            k0.LoadKey(buf);

            SecureRandom s = new SecureRandom();
            byte[] pwh = new byte[32];
            s.nextBytes(pwh);
            pw = Hex.toHexString(pwh).toLowerCase();
            buf = k0.RSAcrypt(pwh, true);
            k1.sout.write(k1.Encode(buf.length));
            k1.sout.write(buf);
            k1.sout.flush();
        } catch (Exception e) {
            addLog("ERROR : " + e.toString());
            return;
        }

        // step 2 : wait & receive file
        addLog("waiting for sender...");
        long fileSize = 0;
        buf = new byte[8];
        try {
            while (true) {
                k1.sin.read(buf);
                boolean flag = true;
                for (byte b : buf) { if (b != (byte) 255) { flag = false; } }
                if (flag) { throw new Exception("sender quit transmittion"); }
                fileSize = k1.Decode(buf);
                if (fileSize != 0) { break; }
                Thread.sleep(500);
            }
        } catch (Exception e) {
            addLog("ERROR : " + e.toString());
            return;
        }

        addLog("start receiving...");
        int tempNum = 0;
        long readSize = 0;
        int splitSize = 13107200;
        if (fileSize < 1310720) { splitSize = 65536; } else if (fileSize < 26214400) { splitSize = 655360; }
        buf = new byte[4096];
        try {
            OutputStream f = new FileOutputStream(ioManager.GetLocalFile("yas_buffer"));
            while (readSize < fileSize) {
                tempNum = k1.sin.read(buf);
                if (tempNum == -1) { break; }
                f.write(buf, 0, tempNum);
                readSize += tempNum;
                if (readSize/splitSize != (readSize - tempNum)/splitSize) {
                    addLog( String.format("receiving %d%% (%dk/%dk)", readSize*100/fileSize, readSize/1024, fileSize/1024) );
                }
            }
            f.close();
            k1.sout.write(new byte[] {0, 0, 0, 0, 0, 0, 0, 0});
            k1.sout.flush();
            k1.CloseSocket();
        } catch (Exception e) {
            addLog("ERROR : " + e.toString());
            return;
        }

        // step 3 : decryption & unzip
        addLog("decrypting...");
        k0.Decrypt(pw, ioManager.GetLocalFile("yas_buffer"), true);
        if (!k0.err.isEmpty()) {
            addLog("ERROR : " + k0.err);
            return;
        }
        ioManager.GetLocalFile("yas_buffer").delete();
        addLog("unzipping file...");
        try {
            k1.OpenZip("yas_chunk.zip", true, true);
            boolean flag = k1.UnZip();
            k1.CloseZip();
            if (flag) { k1.CopyZip("yas_chunk.zip", "yas_downloaded.zip"); }
        } catch (Exception e) {
            addLog("ERROR : " + e.toString());
            return;
        }

        addLog("receiving finished");
        ioManager.GetLocalFile("yas_chunk.zip").delete();
        addLog(22);
        sBuffer = null;
        uBuffer = null;
        oBuffer = null;
    }

    // do encryption
    private void order13() {
        yas_java k = new yas_java(this, ioManager);
        k.msg = oBuffer[1];
        k.Encrypt(uBuffer, sBuffer, oBuffer[0], oBuffer[2], false);
        addLog("encryption finished");
        if (!k.err.isEmpty()) { addLog("ERROR : " + k.err); }
        addLog(22);
        sBuffer = null;
        uBuffer = null;
        oBuffer = null;
    }

    // do decryption
    private void order14() {
        yas_java k = new yas_java(this, ioManager);
        k.Decrypt(oBuffer[0], uBuffer[0], false);
        addLog("decryption finished");
        if (!k.err.isEmpty()) { addLog("ERROR : " + k.err); }
        addLog(22);
        sBuffer = null;
        uBuffer = null;
        oBuffer = null;
    }
}
