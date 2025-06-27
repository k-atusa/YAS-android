package com.example.kutil6_yas;

import android.Manifest;
import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class MainActivity extends AppCompatActivity {
    // layout components
    private LinearLayout viewSend, viewRecv, viewEnc, viewDec;
    private Button sendFiles, sendFolder, sendSend, recvRecv, encFiles, encEnc, decFile, decDec, modeSend, modeRecv, modeEnc, modeDec;
    private EditText recvIp, encMsg, encPw, decPw;
    private TextView sendText0, sendText1, recvText0, encText0, decMsg, decText0;
    private ScrollView sendScroll0, sendScroll1, recvScroll0, encScroll0, decScroll0;
    private int selectedMode = 0; // 0: send, 1: recv, 2: enc, 3: dec

    // file picker
    private IOmanager ioManager;
    private ActivityResultLauncher<Intent> filePickerLauncher;
    private ActivityResultLauncher<Intent> folderPickerLauncher;

    // selected files
    private Uri[] sendUris;
    private String[] sendNames;
    private Uri[] encUris;
    private String[] encNames;
    private Uri[] decUris;
    private String[] decNames;

    // service communication
    private boolean isWorking = false;
    private boolean svcBound = false;
    private Messenger svcMessenger;
    private Messenger recvMessenger = new Messenger(new Handler(Looper.getMainLooper()) {
        @Override
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case 21: // add log
                    String logMsg = msg.getData().getString("string");
                    addLog(logMsg);
                    break;
                case 22: // set isWorking false
                    isWorking = false;
                    break;
                default:
                    addLog("ERROR : unexpected message type "+msg.what);
            }
        }
    });
    private ServiceConnection conn = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder binder) {
            svcMessenger = new Messenger(binder);
            svcBound = true;
            Message registerMsg = Message.obtain(null, 1);
            registerMsg.replyTo = recvMessenger;
            try {
                svcMessenger.send(registerMsg);
            } catch (Exception e) {
                addLog(e.toString());
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            svcBound = false;
            svcMessenger = null;
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        if (Security.getProvider("BC") != null) { Security.removeProvider("BC"); }
        Security.insertProviderAt(new BouncyCastleProvider(), 1); // Bouncy Castle for sha3-512

        ioManager = new IOmanager(this);
        ioManager.GetLocalFile("yas_temp").delete();
        ioManager.GetLocalFile("yas_chunk.zip").delete();
        ioManager.GetLocalFile("yas_buffer").delete();

        // setup components
        viewSend = findViewById(R.id.view_send);
        viewRecv = findViewById(R.id.view_recv);
        viewEnc = findViewById(R.id.view_enc);
        viewDec = findViewById(R.id.view_dec);
        modeSend = findViewById(R.id.mode_send);
        modeRecv = findViewById(R.id.mode_recv);
        modeEnc = findViewById(R.id.mode_enc);
        modeDec = findViewById(R.id.mode_dec);

        sendFiles = findViewById(R.id.send_files);
        sendFolder = findViewById(R.id.send_folder);
        sendSend = findViewById(R.id.send_send);
        sendScroll0 = findViewById(R.id.send_scroll0);
        sendText0 = findViewById(R.id.send_text0);
        sendScroll1 = findViewById(R.id.send_scroll1);
        sendText1 = findViewById(R.id.send_text1);

        recvRecv = findViewById(R.id.recv_recv);
        recvIp = findViewById(R.id.recv_ip);
        recvScroll0 = findViewById(R.id.recv_scroll0);
        recvText0 = findViewById(R.id.recv_text0);

        encFiles = findViewById(R.id.enc_files);
        encEnc = findViewById(R.id.enc_enc);
        encMsg = findViewById(R.id.enc_msg);
        encPw = findViewById(R.id.enc_pw);
        encScroll0 = findViewById(R.id.enc_scroll0);
        encText0 = findViewById(R.id.enc_text0);

        decFile = findViewById(R.id.dec_file);
        decDec = findViewById(R.id.dec_dec);
        decMsg = findViewById(R.id.dec_msg);
        decPw = findViewById(R.id.dec_pw);
        decScroll0 = findViewById(R.id.dec_scroll0);
        decText0 = findViewById(R.id.dec_text0);

        // listeners of mode buttons
        modeSend.setOnClickListener(v -> {
            if (!isWorking) {
                selectedMode = 0;
                viewSend.setVisibility(View.VISIBLE);
                viewRecv.setVisibility(View.GONE);
                viewEnc.setVisibility(View.GONE);
                viewDec.setVisibility(View.GONE);
            }
        });
        modeRecv.setOnClickListener(v -> {
            if (!isWorking) {
                selectedMode = 1;
                viewSend.setVisibility(View.GONE);
                viewRecv.setVisibility(View.VISIBLE);
                viewEnc.setVisibility(View.GONE);
                viewDec.setVisibility(View.GONE);
            }
        });
        modeEnc.setOnClickListener(v -> {
            if (!isWorking) {
                selectedMode = 2;
                viewSend.setVisibility(View.GONE);
                viewRecv.setVisibility(View.GONE);
                viewEnc.setVisibility(View.VISIBLE);
                viewDec.setVisibility(View.GONE);
            }
        });
        modeDec.setOnClickListener(v -> {
            if (!isWorking) {
                selectedMode = 3;
                viewSend.setVisibility(View.GONE);
                viewRecv.setVisibility(View.GONE);
                viewEnc.setVisibility(View.GONE);
                viewDec.setVisibility(View.VISIBLE);
            }
        });

        // listeners of selector buttons
        filePickerLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        ioManager.HandleSelectionFile(result.getData());
                        handleSelection();
                    }
                });
        folderPickerLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        ioManager.HandleSelectionFolder(result.getData());
                        handleSelection();
                    }
                });

        sendFiles.setOnClickListener(v -> {
            if (!isWorking) { ioManager.SelectFile(filePickerLauncher, true); }
        });
        sendFolder.setOnClickListener(v -> {
            if (!isWorking) { ioManager.SelectFolder(folderPickerLauncher); }
        });
        encFiles.setOnClickListener(v -> {
            if (!isWorking) { ioManager.SelectFile(filePickerLauncher, true); }
        });
        decFile.setOnClickListener(v -> {
            if (!isWorking) { ioManager.SelectFile(filePickerLauncher, false); }
        });

        // link buttons and methods
        sendSend.setOnClickListener(v -> { sendText1.setText(""); sendWork(); });
        recvRecv.setOnClickListener(v -> { recvText0.setText(""); recvWork(); });
        encEnc.setOnClickListener(v -> { encWork(); });
        decDec.setOnClickListener(v -> { decWork(); });

        // init service modules
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 100);
            }
        }
        Intent intent = new Intent(this, ServiceActivity.class).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        startForegroundService(intent);
        bindService(intent, conn, Context.BIND_AUTO_CREATE);
        svcBound = true;
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (svcBound) {
            try {
                svcMessenger.send(Message.obtain(null, 2));
            } catch (Exception e) {
                addLog(e.toString());
            }
            unbindService(conn);
            svcBound = false;

        }
        stopService(new Intent(this, ServiceActivity.class));
    }

    private void handleSelection() {
        switch (selectedMode) {
            case 0:
                sendUris = ioManager.selUris;
                sendNames = ioManager.selNames;
                sendText0.setText(ioManager.PrintSelection());
                sendScroll0.fullScroll(View.FOCUS_DOWN);
                break;
            case 2:
                encUris = ioManager.selUris;
                encNames = ioManager.selNames;
                encText0.setText(ioManager.PrintSelection());
                break;
            case 3:
                decUris = ioManager.selUris;
                decNames = ioManager.selNames;
                decText0.setText(ioManager.PrintSelection());
                decView();
                break;
        }
    }

    private void addLog(String text) {
        switch (selectedMode) {
            case 0:
                sendText1.append(text + "\n");
                sendScroll1.fullScroll(View.FOCUS_DOWN);
                break;
            case 1:
                recvText0.append(text + "\n");
                recvScroll0.fullScroll(View.FOCUS_DOWN);
                break;
            case 2:
                encText0.append(text + "\n");
                encScroll0.fullScroll(View.FOCUS_DOWN);
                break;
            case 3:
                decText0.append(text + "\n");
                decScroll0.fullScroll(View.FOCUS_DOWN);
                break;
        }
    }

    private void sendData(String[] data) {
        Message msg;
        Bundle bdl;
        msg = Message.obtain(null, 3);
        bdl = new Bundle();
        bdl.putInt("int", data.length);
        msg.setData(bdl);
        try {
            svcMessenger.send(msg);
        } catch (Exception e) {
            addLog(e.toString());
        }

        for (String s : data) {
            msg = Message.obtain(null, 4);
            bdl = new Bundle();
            bdl.putString("string", s);
            msg.setData(bdl);
            try {
                svcMessenger.send(msg);
            } catch (Exception e) {
                addLog(e.toString());
            }
        }
    }

    private void sendData(Uri[] data) {
        Message msg;
        Bundle bdl;
        msg = Message.obtain(null, 5);
        bdl = new Bundle();
        bdl.putInt("int", data.length);
        msg.setData(bdl);
        try {
            svcMessenger.send(msg);
        } catch (Exception e) {
            addLog(e.toString());
        }

        for (Uri u : data) {
            msg = Message.obtain(null, 6);
            bdl = new Bundle();
            bdl.putParcelable("uri", u);
            msg.setData(bdl);
            try {
                svcMessenger.send(msg);
            } catch (Exception e) {
                addLog(e.toString());
            }
        }
    }

    private void sendOrder(String[] data) {
        Message msg;
        Bundle bdl;
        msg = Message.obtain(null, 7);
        bdl = new Bundle();
        bdl.putInt("int", data.length);
        msg.setData(bdl);
        try {
            svcMessenger.send(msg);
        } catch (Exception e) {
            addLog(e.toString());
        }

        for (String s : data) {
            msg = Message.obtain(null, 8);
            bdl = new Bundle();
            bdl.putString("string", s);
            msg.setData(bdl);
            try {
                svcMessenger.send(msg);
            } catch (Exception e) {
                addLog(e.toString());
            }
        }
    }

    private void sendOrder(int code) {
        try {
            svcMessenger.send( Message.obtain(null, code) );
        } catch (Exception e) {
            addLog(e.toString());
        }
    }

    private void sendWork() {
        isWorking = true;
        sendData(sendUris);
        sendData(sendNames);
        addLog("flushed : data buffer");
        sendOrder(11); // send data
        addLog("flushed : sending order");
    }

    private void recvWork() {
        isWorking = true;
        String[] ips = recvIp.getText().toString().split(":");
        if (ips.length != 2) { addLog("ERROR : invalid ip address"); return; }
        sendOrder(ips); // [ip, port]
        addLog("flushed : data buffer");
        sendOrder(12); // recv data
        addLog("flushed : receiving order");
        addLog("Result : Downloads/*");
    }

    private void encWork() {
        isWorking = true;
        String name = String.format("encrypt_%d.bin", System.currentTimeMillis() % 2000);
        sendOrder( new String[] {encPw.getText().toString(), encMsg.getText().toString(), name} ); // [pw, msg, name]
        sendData(encUris);
        sendData(encNames);
        addLog("flushed : data buffer");
        sendOrder(13); // do encryption
        addLog("flushed : encryption order");
        addLog("Result : Downloads/" + name);
    }

    private void decWork() {
        isWorking = true;
        sendOrder( new String[] { decPw.getText().toString() } ); // [pw]
        sendData(decUris);
        addLog("flushed : data buffer");
        sendOrder(14); // do decryption
        addLog("flushed : decryption order");
        addLog("Result : Downloads/*");
    }

    private void decView() {
        if (decUris.length == 0) { addLog("ERROR : no file selected"); return; }
        yas_java k = new yas_java(this, ioManager);
        k.View(decUris[0]);
        addLog("view finished");
        decMsg.setText(k.msg);
        if (!k.err.isEmpty()) { addLog("ERROR : " + k.err); }
    }
}