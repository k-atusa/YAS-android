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
import com.example.k7yas.engine.Star;
import com.example.k7yas.engine.Szip;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SvcYas extends Service {
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
        }
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

        double count = 0;
        if (account.PackType.equals("zip1")) { // zip1
            File temp = new File(getFilesDir(), "archive.temp");
            try (Szip.ZipWriter zw = new Szip.ZipWriter()) {
                zw.Open(temp, true);
                for (IO1.VFile f : srcs) {
                    try (InputStream is = f.OpenReader(this)) {
                        zw.Write(f.GetName(this), is);
                    }
                    count++;
                    chan.SetDouble(0, count / srcs.size());
                }
            }
            try (InputStream in = new java.io.FileInputStream(temp); OutputStream out = dst.OpenWriter(this, false)) {
                in.transferTo(out);
            }
            temp.delete();

        } else { // tar1
            try (OutputStream out = dst.OpenWriter(this, false); Star.TarWriter tw = new Star.TarWriter()) {
                tw.Open(out);
                for (IO1.VFile f : srcs) {
                    try (InputStream is = f.OpenReader(this)) {
                        tw.Write(f.GetName(this), is, f.GetSize(this), 0644, f.IsDir(this));
                    }
                    count++;
                    chan.SetDouble(0, count / srcs.size());
                }
            }
        }
    }

    // Unpack file
    private void handleUnpack(Bundle b) throws Exception {
        IO1.VFile src = b.getParcelable("src", IO1.VFile.class);
        if (src == null) throw new IllegalArgumentException("Source archive null");
        Account account = Account.GetAccount(this);

        double count = 0;
        if (account.PackType.equals("zip1")) { // zip1
            File temp = new File(getFilesDir(), "archive.temp");
            try (InputStream in = src.OpenReader(this); OutputStream out = new java.io.FileOutputStream(temp)) {
                in.transferTo(out);
            }
            try (Szip.ZipReader zr = new Szip.ZipReader()) {
                zr.Open(temp);
                for (int i = 0; i < zr.Names.size(); i++) {
                    IO1.VFile target = IO1.CreateDownloadsFile(this, zr.Names.get(i));
                    if (target != null) {
                        try (OutputStream os = target.OpenWriter(this, false); InputStream is = zr.Open(i)) {
                            is.transferTo(os);
                        }
                    }
                    count++;
                    chan.SetDouble(0, count / zr.Names.size());
                }
                chan.SetDouble(0, 1.0);
            }
            temp.delete();

        } else { // tar1
            try (InputStream is = src.OpenReader(this); Star.TarReader tr = new Star.TarReader()) {
                tr.Open(is);
                while (tr.Next()) {
                    IO1.VFile target = IO1.CreateDownloadsFile(this, tr.Name);
                    if (target != null) {
                        try (OutputStream os = target.OpenWriter(this, false)) {
                            tr.Mkfile(os);
                        }
                    }
                    count++;
                    chan.SetDouble(0, 1 - 1 / count);
                }
            }
        }
    }
}
