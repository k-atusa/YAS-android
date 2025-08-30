package com.example.kutil6_yas;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.widget.ArrayAdapter;
import android.widget.AutoCompleteTextView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.materialswitch.MaterialSwitch;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;

public class MainActivity extends AppCompatActivity {
    // ui components
    ImageButton toolbar_menu;
    TextView toolbar_title;
    Button toolbar_run;
    private void toolbar_setup() {
        toolbar_menu = findViewById(R.id.toolbar_menu);
        toolbar_title = findViewById(R.id.toolbar_title);
        toolbar_run = findViewById(R.id.toolbar_run);
        toolbar_menu.setOnClickListener(v -> { menu_click(0); });
        toolbar_run.setOnClickListener(v -> { toolbar_run(); });
    }
    private void toolbar_run() {
        if (this.isWorking) {
            msgToast("Already Working");
            return;
        }
        this.isWorking = true;
        switch (this.mode) {
            case 1:
                enc_run();
                break;
            case 2:
                dec_run();
                break;
            case 3:
                send_run();
                break;
            case 4:
                receive_run();
                break;
            case 5:
                penc_run();
                break;
            case 6:
                pdec_run();
                break;
            case 7:
                psend_run();
                break;
            case 8:
                preceive_run();
                break;
        }
    }

    Button menu_enc;
    Button menu_dec;
    Button menu_send;
    Button menu_receive;
    Button menu_penc;
    Button menu_pdec;
    Button menu_psend;
    Button menu_preceive;
    Button menu_key;
    private void menu_setup() {
        setContentView(R.layout.menu);
        toolbar_setup();
        toolbar_title.setText("Menu");
        this.mode = 0;

        menu_enc = findViewById(R.id.menu_enc);
        menu_dec = findViewById(R.id.menu_dec);
        menu_send = findViewById(R.id.menu_send);
        menu_receive = findViewById(R.id.menu_receive);
        menu_penc = findViewById(R.id.menu_penc);
        menu_pdec = findViewById(R.id.menu_pdec);
        menu_psend = findViewById(R.id.menu_psend);
        menu_preceive = findViewById(R.id.menu_preceive);
        menu_key = findViewById(R.id.menu_key);
        menu_enc.setOnClickListener(v -> { menu_click(1); });
        menu_dec.setOnClickListener(v -> { menu_click(2); });
        menu_send.setOnClickListener(v -> { menu_click(3); });
        menu_receive.setOnClickListener(v -> { menu_click(4); });
        menu_penc.setOnClickListener(v -> { menu_click(5); });
        menu_pdec.setOnClickListener(v -> { menu_click(6); });
        menu_psend.setOnClickListener(v -> { menu_click(7); });
        menu_preceive.setOnClickListener(v -> { menu_click(8); });
        menu_key.setOnClickListener(v -> { menu_click(9); });
    }
    public void menu_click(int i) {
        switch (i) {
            case 0:
                menu_setup();
                break;
            case 1:
                enc_setup();
                break;
            case 2:
                dec_setup();
                break;
            case 3:
                send_setup();
                break;
            case 4:
                receive_setup();
                break;
            case 5:
                penc_setup();
                break;
            case 6:
                pdec_setup();
                break;
            case 7:
                psend_setup();
                break;
            case 8:
                preceive_setup();
                break;
            case 9:
                address_setup();
                break;
        }
    }

    Button enc_addfile;
    Button enc_delete;
    TextView enc_files;
    EditText enc_message;
    EditText enc_password;
    TextView enc_log;
    Uri[] enc_uris = new Uri[0];
    String[] enc_names = new String[0];
    private void enc_setup() {
        setContentView(R.layout.enc);
        toolbar_setup();
        toolbar_title.setText("Encrypt");
        this.mode = 1;

        enc_addfile = findViewById(R.id.enc_addfile);
        enc_delete = findViewById(R.id.enc_delete);
        enc_files = findViewById(R.id.enc_files);
        enc_message = findViewById(R.id.enc_message);
        enc_password = findViewById(R.id.enc_password);
        enc_log = findViewById(R.id.enc_log);

        enc_uris = new Uri[0];
        enc_names = new String[0];
        enc_addfile.setOnClickListener(v -> { if (!isWorking) { io.SelectFile(filePickerLauncher, true); } });
        enc_delete.setOnClickListener(v -> { if (!isWorking) { handleDelete(1); } });
    }
    public void enc_run() {
        enc_log.setText("");
        sendOrder(new String[] {enc_message.getText().toString(), enc_password.getText().toString()}, 1);
        sendData(enc_names, 1);
        sendData(enc_uris, 1);
        sendOrder(11, 1);
        msgLog("flushed: sending order", 1);
    }

    Button dec_addfile;
    TextView dec_file;
    TextView dec_message;
    EditText dec_password;
    TextView dec_log;
    Uri dec_uri = null;
    String dec_name = null;
    private void dec_setup() {
        setContentView(R.layout.dec);
        toolbar_setup();
        toolbar_title.setText("Decrypt");
        this.mode = 2;

        dec_addfile = findViewById(R.id.dec_addfile);
        dec_file = findViewById(R.id.dec_file);
        dec_message = findViewById(R.id.dec_message);
        dec_password = findViewById(R.id.dec_password);
        dec_log = findViewById(R.id.dec_log);

        dec_uri = null;
        dec_name = null;
        dec_addfile.setOnClickListener(v -> { if (!isWorking) { io.SelectFile(filePickerLauncher, false); } });
    }
    public void dec_run() {
        dec_log.setText("");
        sendOrder(new String[] {dec_password.getText().toString()}, 2);
        sendData(new String[] {dec_name}, 2);
        sendData(new Uri[] {dec_uri}, 2);
        sendOrder(12, 2);
        msgLog("flushed: sending order", 2);
    }

    Button send_addfile;
    Button send_addfolder;
    Button send_delete;
    TextView send_files;
    TextView send_log;
    Uri[] send_uris = new Uri[0];
    String[] send_names = new String[0];
    private void send_setup() {
        setContentView(R.layout.send);
        toolbar_setup();
        toolbar_title.setText("Send");
        this.mode = 3;

        send_addfile = findViewById(R.id.send_addfile);
        send_addfolder = findViewById(R.id.send_addfolder);
        send_delete = findViewById(R.id.send_delete);
        send_files = findViewById(R.id.send_files);
        send_log = findViewById(R.id.send_log);

        send_uris = new Uri[0];
        send_names = new String[0];
        send_addfile.setOnClickListener(v -> { if (!isWorking) { io.SelectFile(filePickerLauncher, true); } });
        send_addfolder.setOnClickListener(v -> { if (!isWorking) { io.SelectFolder(folderPickerLauncher); } });
        send_delete.setOnClickListener(v -> { if (!isWorking) { handleDelete(3); } });
    }
    public void send_run() {
        send_log.setText("");
        sendData(send_names, 3);
        sendData(send_uris, 3);
        sendOrder(13, 3);
        msgLog("flushed: sending order", 3);
    }

    EditText receive_ip;
    TextView receive_log;
    private void receive_setup() {
        setContentView(R.layout.receive);
        toolbar_setup();
        toolbar_title.setText("Receive");
        this.mode = 4;

        receive_ip = findViewById(R.id.receive_ip);
        receive_log = findViewById(R.id.receive_log);
    }
    public void receive_run() {
        receive_log.setText("");
        String[] ip = receive_ip.getText().toString().split(":");
        if (ip.length == 2) {
            sendOrder(ip, 4);
            sendOrder(14, 4);
            msgLog("flushed: sending order", 4);
        } else {
            msgLog("ERROR: invalid ip format", 4);
            this.isWorking = false;
        }
    }

    Button penc_copy0;
    Button penc_copy1;
    EditText penc_plain;
    TextView penc_cipher;
    AutoCompleteTextView penc_receiver;
    MaterialSwitch penc_sign;
    TextView penc_log;
    boolean penc_signflag;
    private void penc_setup() {
        setContentView(R.layout.penc);
        toolbar_setup();
        toolbar_title.setText("Ext-TEn");
        this.mode = 5;

        penc_copy0 = findViewById(R.id.penc_copy0);
        penc_copy1 = findViewById(R.id.penc_copy1);
        penc_plain = findViewById(R.id.penc_plain);
        penc_cipher = findViewById(R.id.penc_cipher);
        penc_receiver = findViewById(R.id.penc_receiver);
        penc_sign = findViewById(R.id.penc_sign);
        penc_log = findViewById(R.id.penc_log);

        penc_copy0.setOnClickListener(v -> { copyClipboard(penc_plain.getText().toString()); });
        penc_copy1.setOnClickListener(v -> { copyClipboard(penc_cipher.getText().toString()); });
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_dropdown_item_1line, this.keyNames);
        penc_receiver.setAdapter(adapter);
        penc_receiver.setOnClickListener(v -> { penc_receiver.showDropDown(); });
        penc_signflag = true;
        penc_sign.setOnCheckedChangeListener((buttonView, isChecked) -> { penc_signflag = isChecked; });
    }
    public void penc_run() {
        penc_log.setText("");
        int index = findKey(penc_receiver.getText().toString());
        if (index == -1) {
            msgLog("ERROR: receiver not selected", 5);
            this.isWorking = false;
            return;
        }
        sendOrder(new String[] {penc_plain.getText().toString(), this.keyData[index], this.myPrivate}, 5);
        sendFlag(new int[] {penc_signflag ? 1 : 0}, 5);
        sendOrder(15, 5);
        msgLog("flushed: sending order", 5);
    }

    Button pdec_copy0;
    Button pdec_copy1;
    TextView pdec_plain;
    EditText pdec_cipher;
    AutoCompleteTextView pdec_sender;
    MaterialSwitch pdec_sign;
    TextView pdec_log;
    boolean pdec_signflag;
    private void pdec_setup() {
        setContentView(R.layout.pdec);
        toolbar_setup();
        toolbar_title.setText("Ext-TDe");
        this.mode = 6;

        pdec_copy0 = findViewById(R.id.pdec_copy0);
        pdec_copy1 = findViewById(R.id.pdec_copy1);
        pdec_plain = findViewById(R.id.pdec_plain);
        pdec_cipher = findViewById(R.id.pdec_cipher);
        pdec_sender = findViewById(R.id.pdec_sender);
        pdec_sign = findViewById(R.id.pdec_sign);
        pdec_log = findViewById(R.id.pdec_log);

        pdec_copy0.setOnClickListener(v -> { copyClipboard(pdec_plain.getText().toString()); });
        pdec_copy1.setOnClickListener(v -> { copyClipboard(pdec_cipher.getText().toString()); });
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_dropdown_item_1line, this.keyNames);
        pdec_sender.setAdapter(adapter);
        pdec_sender.setOnClickListener(v -> { pdec_sender.showDropDown(); });
        pdec_signflag = true;
        pdec_sign.setOnCheckedChangeListener((buttonView, isChecked) -> { pdec_signflag = isChecked; });
    }
    public void pdec_run() {
        pdec_log.setText("");
        int index = -1;
        if (pdec_signflag) { index = findKey(pdec_sender.getText().toString()); }
        if (index == -1) {
            sendOrder(new String[] {pdec_cipher.getText().toString(), "", this.myPrivate}, 6);
        } else {
            sendOrder(new String[] {pdec_cipher.getText().toString(), this.keyData[index], this.myPrivate}, 6);
        }
        sendFlag(new int[] {pdec_signflag ? 1 : 0, index}, 6);
        sendOrder(16, 6);
        msgLog("flushed: sending order", 6);
    }

    Button psend_addfile;
    Button psend_addfolder;
    Button psend_delete;
    TextView psend_files;
    AutoCompleteTextView psend_receiver;
    MaterialSwitch psend_sign;
    TextView psend_log;
    Uri[] psend_uris = new Uri[0];
    String[] psend_names = new String[0];
    boolean psend_signflag;
    private void psend_setup() {
        setContentView(R.layout.psend);
        toolbar_setup();
        toolbar_title.setText("Ext-FEn");
        this.mode = 7;

        psend_addfile = findViewById(R.id.psend_addfile);
        psend_addfolder = findViewById(R.id.psend_addfolder);
        psend_delete = findViewById(R.id.psend_delete);
        psend_files = findViewById(R.id.psend_files);
        psend_receiver = findViewById(R.id.psend_receiver);
        psend_sign = findViewById(R.id.psend_sign);
        psend_log = findViewById(R.id.psend_log);

        psend_uris = new Uri[0];
        psend_names = new String[0];
        psend_addfile.setOnClickListener(v -> { if (!isWorking) { io.SelectFile(filePickerLauncher, true); } });
        psend_addfolder.setOnClickListener(v -> { if (!isWorking) { io.SelectFolder(folderPickerLauncher); } });
        psend_delete.setOnClickListener(v -> { if (!isWorking) { handleDelete(7); } });
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_dropdown_item_1line, this.keyNames);
        psend_receiver.setAdapter(adapter);
        psend_receiver.setOnClickListener(v -> { psend_receiver.showDropDown(); });
        psend_signflag = true;
        psend_sign.setOnCheckedChangeListener((buttonView, isChecked) -> { psend_signflag = isChecked; });
    }
    public void psend_run() {
        psend_log.setText("");
        int index = findKey(psend_receiver.getText().toString());
        if (index == -1) {
            msgLog("ERROR: receiver not selected", 7);
            this.isWorking = false;
            return;
        }
        sendData(psend_names, 7);
        sendData(psend_uris, 7);
        sendOrder(new String[] {this.keyData[index], this.myPrivate}, 7);
        sendFlag(new int[] {psend_signflag ? 1 : 0}, 7);
        sendOrder(17, 7);
        msgLog("flushed: sending order", 7);
    }

    Button preceive_addfile;
    TextView preceive_file;
    AutoCompleteTextView preceive_sender;
    MaterialSwitch preceive_sign;
    TextView preceive_log;
    Uri preceive_uri = null;
    String preceive_name = null;
    boolean preceive_signflag;
    private void preceive_setup() {
        setContentView(R.layout.preceive);
        toolbar_setup();
        toolbar_title.setText("Ext-FDe");
        this.mode = 8;

        preceive_addfile = findViewById(R.id.preceive_addfile);
        preceive_file = findViewById(R.id.preceive_file);
        preceive_sender = findViewById(R.id.preceive_sender);
        preceive_sign = findViewById(R.id.preceive_sign);
        preceive_log = findViewById(R.id.preceive_log);

        preceive_uri = null;
        preceive_name = null;
        preceive_addfile.setOnClickListener(v -> { if (!isWorking) { io.SelectFile(filePickerLauncher, false); } });
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_dropdown_item_1line, this.keyNames);
        preceive_sender.setAdapter(adapter);
        preceive_sender.setOnClickListener(v -> { preceive_sender.showDropDown(); });
        preceive_signflag = true;
        preceive_sign.setOnCheckedChangeListener((buttonView, isChecked) -> { preceive_signflag = isChecked; });
    }
    public void preceive_run() {
        preceive_log.setText("");
        int index = -1;
        if (preceive_signflag) { index = findKey(preceive_sender.getText().toString()); }
        if (index == -1) {
            sendOrder(new String[] {"", this.myPrivate}, 8);
        } else {
            sendOrder(new String[] {this.keyData[index], this.myPrivate}, 8);
        }
        sendData(new String[] {preceive_name}, 8);
        sendData(new Uri[] {preceive_uri}, 8);
        sendFlag(new int[] {preceive_signflag ? 1 : 0, index}, 8);
        sendOrder(18, 8);
        msgLog("flushed: sending order", 8);
    }

    Button address_regen0;
    Button address_regen1;
    TextView address_text0;
    ImageButton address_edit0;
    ImageButton address_copy0;
    TextView address_text1;
    ImageButton address_edit1;
    ImageButton address_copy1;
    Button address_addkey;
    Button address_delete;
    AutoCompleteTextView address_key;
    EditText address_keyname;
    EditText address_keydata;
    private void address_setup() {
        setContentView(R.layout.address);
        toolbar_setup();
        toolbar_title.setText("Address");
        this.mode = 9;

        address_regen0 = findViewById(R.id.address_regen0);
        address_regen1 = findViewById(R.id.address_regen1);
        address_text0 = findViewById(R.id.address_text0);
        address_edit0 = findViewById(R.id.address_edit0);
        address_copy0 = findViewById(R.id.address_copy0);
        address_text1 = findViewById(R.id.address_text1);
        address_edit1 = findViewById(R.id.address_edit1);
        address_copy1 = findViewById(R.id.address_copy1);
        address_addkey = findViewById(R.id.address_addkey);
        address_delete = findViewById(R.id.address_delete);
        address_key = findViewById(R.id.address_key);
        address_keyname = findViewById(R.id.address_keyname);
        address_keydata = findViewById(R.id.address_keydata);

        address_regen0.setOnClickListener(v -> { if (!isWorking) { address_regen(false); } });
        address_regen1.setOnClickListener(v -> { if (!isWorking) { address_regen(true); } });
        address_edit0.setOnClickListener(v -> { if (!isWorking) { address_update(true); } });
        address_copy0.setOnClickListener(v -> { copyClipboard(myPublic); });
        address_text0.setText(this.myPublic);
        address_edit1.setOnClickListener(v -> { if (!isWorking) { address_update(false); } });
        address_copy1.setOnClickListener(v -> { copyClipboard(myPrivate); });
        address_text1.setText(this.myPrivate);
        address_addkey.setOnClickListener(v -> { if (!isWorking) { address_run(true); } });
        address_delete.setOnClickListener(v -> { if (!isWorking) { address_run(false); } });
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_dropdown_item_1line, this.keyNames);
        address_key.setAdapter(adapter);
        address_key.setOnClickListener(v -> { address_key.showDropDown(); });
    }
    private void address_regen(boolean is4k) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("Regenerate Key");
        if (is4k) { builder.setMessage("Delete current key and make new RSA-4096 key?"); } else { builder.setMessage("Delete current key and make new RSA-2048 key?"); }
        builder.setPositiveButton("Ok", (dialog, which) -> {
            byte[][] keys;
            if (is4k) { keys = this.yrsa.Genkey(true); } else { keys = this.yrsa.Genkey(false); }
            if ( !this.yrsa.err.isEmpty() ) {
                address_keydata.setText(this.yrsa.err);
                msgToast("Key Generation Failed");
            } else {
                this.myPublic = this.bu.B64en(keys[0]);
                this.myPrivate = this.bu.B64en(keys[1]);
                address_text0.setText(this.myPublic);
                address_text1.setText(this.myPrivate);
                writeText("mykey.txt", this.myPublic + "\n" + this.myPrivate);
                msgToast("Key Generated");
            }
        });
        builder.setNegativeButton("Cancel", (dialog, which) -> dialog.cancel());
        builder.show();
    }
    private void address_update(boolean isPublic) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("Update Key");
        if (isPublic) { builder.setMessage("Update current public key?"); } else { builder.setMessage("Update current private key?"); }
        builder.setPositiveButton("Ok", (dialog, which) -> {
            if (isPublic) { this.myPublic = address_text0.getText().toString().replace("\n", "").replace(" ", ""); }
            else { this.myPrivate = address_text1.getText().toString().replace("\n", "").replace(" ", ""); }
            writeText("mykey.txt", this.myPublic + "\n" + this.myPrivate);
            msgToast("Key Updated");
        });
        builder.setNegativeButton("Cancel", (dialog, which) -> dialog.cancel());
        builder.show();
    }
    private void address_run(boolean isAdd) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        if (isAdd) { builder.setTitle("Add Key"); } else { builder.setTitle("Delete Key"); }
        if (isAdd) { builder.setMessage("Add key to address list?"); } else { builder.setMessage("Delete key from address list?"); }
        builder.setPositiveButton("Ok", (dialog, which) -> {
            if (isAdd) {
                String name = address_keyname.getText().toString().replace("\n", "");
                String data = address_keydata.getText().toString().replace("\n", "").replace(" ", "");
                if (this.bu.B64de(data) == null) {
                    msgToast("Invalid Key Data");
                    return;
                }
                name = name + String.format(" (%08x)", this.bu.Crc32(this.bu.B64de(data)));
                for (String keyName : this.keyNames) {
                    if (keyName.equals(name)) {
                        msgToast("Key Name Already Exists");
                        return;
                    }
                }
                String[] tempname = new String[this.keyNames.length + 1];
                String[] tempdata = new String[this.keyData.length + 1];
                System.arraycopy(this.keyNames, 0, tempname, 0, this.keyNames.length);
                System.arraycopy(this.keyData, 0, tempdata, 0, this.keyData.length);
                tempname[tempname.length - 1] = name;
                tempdata[tempdata.length - 1] = data;
                this.keyNames = tempname;
                this.keyData = tempdata;
            } else {
                int index = findKey( address_key.getText().toString() );
                if (index == -1) {
                    msgToast("Key Not Found");
                    return;
                }
                String[] tempname = new String[this.keyNames.length - 1];
                String[] tempdata = new String[this.keyData.length - 1];
                System.arraycopy(this.keyNames, 0, tempname, 0, index);
                System.arraycopy(this.keyData, 0, tempdata, 0, index);
                System.arraycopy(this.keyNames, index + 1, tempname, index, this.keyNames.length - index - 1);
                System.arraycopy(this.keyData, index + 1, tempdata, index, this.keyData.length - index - 1);
                this.keyNames = tempname;
                this.keyData = tempdata;
            }
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < this.keyNames.length; i++) {
                sb.append(this.keyNames[i]).append("\n");
                sb.append(this.keyData[i]).append("\n");
            }
            writeText("yourkey.txt", sb.toString());
            msgToast("Key Updated");
            address_setup();
        });
        builder.setNegativeButton("Cancel", (dialog, which) -> dialog.cancel());
        builder.show();
    }

    // status data
    public int mode = 0;
    public boolean isWorking = false;
    public String[] keyNames = new String[0];
    public String[] keyData = new String[0];
    public String myPublic = "";
    public String myPrivate = "";

    // sub modules
    private BasicUtil bu;
    private FileUtil io;
    private YASaes yaes;
    private YASrsa yrsa;
    private ActivityResultLauncher<Intent> filePickerLauncher;
    private ActivityResultLauncher<Intent> folderPickerLauncher;

    // service communication
    private boolean svcBound = false;
    private Messenger main2svc;
    private Messenger svc2main = new Messenger(new Handler(Looper.getMainLooper()) {
        @Override
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case 10: // set isWorking false
                    isWorking = false;
                    break;
                case 11: // log to enc
                    msgLog(msg.getData().getString("string"), 1);
                    break;
                case 12: // log to dec
                    msgLog(msg.getData().getString("string"), 2);
                    break;
                case 13: // log to send
                    msgLog(msg.getData().getString("string"), 3);
                    break;
                case 14: // log to receive
                    msgLog(msg.getData().getString("string"), 4);
                    break;
                case 15: // log to penc
                    msgLog(msg.getData().getString("string"), 5);
                    break;
                case 16: // log to pdec
                    msgLog(msg.getData().getString("string"), 6);
                    break;
                case 17: // log to psend
                    msgLog(msg.getData().getString("string"), 7);
                    break;
                case 18: // log to preceive
                    msgLog(msg.getData().getString("string"), 8);
                    break;
                case 19: // set penc.cipher
                    if (mode == 5) { penc_cipher.setText(msg.getData().getString("string")); }
                    break;
                case 20: // set pdec.plain
                    if (mode == 6) { pdec_plain.setText(msg.getData().getString("string")); }
                    break;
                default:
                    msgToast("ERROR : unexpected message type "+msg.what);
            }
        }
    });
    private ServiceConnection conn = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder binder) {
            main2svc = new Messenger(binder);
            svcBound = true;
            Message registerMsg = Message.obtain(null, 1);
            registerMsg.replyTo = svc2main;
            try {
                main2svc.send(registerMsg);
            } catch (Exception e) {
                msgToast(e.toString());
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            svcBound = false;
            main2svc = null;
        }
    };

    // start program
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        // init program
        if (Security.getProvider("BC") != null) { Security.removeProvider("BC"); }
        Security.insertProviderAt(new BouncyCastleProvider(), 1); // Bouncy Castle for sha3-512
        this.bu = new BasicUtil();
        this.io = new FileUtil(this);
        this.yaes = new YASaes(this);

        // init view
        super.onCreate(savedInstanceState);
        setContentView(R.layout.menu);

        // init sub modules
        this.filePickerLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        io.HandleSelectionFile(result.getData());
                        handleSelect(this.mode);
                    }
                });
        this.folderPickerLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        io.HandleSelectionFolder(result.getData());
                        handleSelect(this.mode);
                    }
                });

        // get key data
        this.yaes = new YASaes(this);
        this.yrsa = new YASrsa();
        if ( !this.io.GetLocalFile("mykey.txt").exists() ) { writeText("mykey.txt", ""); }
        if ( !this.io.GetLocalFile("yourkey.txt").exists() ) { writeText("yourkey.txt", ""); }
        String[] temp = readText("mykey.txt").split("\n");
        if (temp.length == 2) {
            this.myPublic = temp[0];
            this.myPrivate = temp[1];
        }
        temp = readText("yourkey.txt").split("\n");
        keyNames = new String[temp.length / 2];
        keyData = new String[temp.length / 2];
        for (int i = 0; i < temp.length / 2; i++) {
            keyNames[i] = temp[2 * i];
            keyData[i] = temp[2 * i + 1];
        }

        // init service & main
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 100);
        }
        Intent intent = new Intent(this, ServiceActivity.class).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        startForegroundService(intent);
        bindService(intent, conn, Context.BIND_AUTO_CREATE);
        svcBound = true;
        menu_setup();
    }
    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (svcBound) {
            try {
                main2svc.send(Message.obtain(null, 2));
            } catch (Exception e) {
                msgToast(e.toString());
            }
            unbindService(conn);
            svcBound = false;
        }
        stopService(new Intent(this, ServiceActivity.class));
    }

    // common functions
    public void msgToast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
    }
    public void msgLog(String msg, int domain) {
        switch (domain) {
            case 1:
                enc_log.append(msg+"\n");
                break;
            case 2:
                dec_log.append(msg+"\n");
                break;
            case 3:
                send_log.append(msg+"\n");
                break;
            case 4:
                receive_log.append(msg+"\n");
                break;
            case 5:
                penc_log.append(msg+"\n");
                break;
            case 6:
                pdec_log.append(msg+"\n");
                break;
            case 7:
                psend_log.append(msg+"\n");
                break;
            case 8:
                preceive_log.append(msg+"\n");
                break;
        }
    }
    public void copyClipboard(String msg) {
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText("Copied Text", msg);
        if (clipboard != null) {
            clipboard.setPrimaryClip(clip);
            msgToast("Copied to clipboard");
        }
    }
    private void handleSelect(int domain) {
        Uri[] a;
        String[] b;
        switch (domain) {
            case 1:
                a = new Uri[enc_uris.length + this.io.selUris.length];
                b = new String[enc_names.length + this.io.selNames.length];
                System.arraycopy(enc_uris, 0, a, 0, enc_uris.length);
                System.arraycopy(this.io.selUris, 0, a, enc_uris.length, this.io.selUris.length);
                System.arraycopy(enc_names, 0, b, 0, enc_names.length);
                System.arraycopy(this.io.selNames, 0, b, enc_names.length, this.io.selNames.length);
                enc_uris = a;
                enc_names = b;
                for (int i = 0; i < this.io.selNames.length; i++) { enc_files.append(this.io.selNames[i]+"\n"); }
                msgLog("Uris Selected", 1);
                break;
            case 2:
                dec_uri = this.io.selUris[0];
                dec_name = this.io.selNames[0];
                dec_file.setText(dec_name);
                msgLog("Uri Selected", 2);
                this.yaes.View(dec_uri);
                if (this.yaes.err.isEmpty()) {
                    dec_message.setText(this.yaes.msg);
                } else {
                    dec_message.setText("ERR:"+this.yaes.err);
                }
                msgLog("LockFile View Done!", 2);
                break;
            case 3:
                a = new Uri[send_uris.length + this.io.selUris.length];
                b = new String[send_names.length + this.io.selNames.length];
                System.arraycopy(send_uris, 0, a, 0, send_uris.length);
                System.arraycopy(this.io.selUris, 0, a, send_uris.length, this.io.selUris.length);
                System.arraycopy(send_names, 0, b, 0, send_names.length);
                System.arraycopy(this.io.selNames, 0, b, send_names.length, this.io.selNames.length);
                send_uris = a;
                send_names = b;
                for (int i = 0; i < this.io.selNames.length; i++) { send_files.append(this.io.selNames[i]+"\n"); }
                msgLog("Uris Selected", 3);
                break;
            case 7:
                a = new Uri[psend_uris.length + this.io.selUris.length];
                b = new String[psend_names.length + this.io.selNames.length];
                System.arraycopy(psend_uris, 0, a, 0, psend_uris.length);
                System.arraycopy(this.io.selUris, 0, a, psend_uris.length, this.io.selUris.length);
                System.arraycopy(psend_names, 0, b, 0, psend_names.length);
                System.arraycopy(this.io.selNames, 0, b, psend_names.length, this.io.selNames.length);
                psend_uris = a;
                psend_names = b;
                for (int i = 0; i < this.io.selNames.length; i++) { psend_files.append(this.io.selNames[i]+"\n"); }
                msgLog("Uris Selected", 7);
                break;
            case 8:
                preceive_uri = this.io.selUris[0];
                preceive_name = this.io.selNames[0];
                preceive_file.setText(preceive_name);
                msgLog("Uri Selected", 8);
                break;
        }
        this.io.selUris = new Uri[0];
        this.io.selNames = new String[0];
    }
    public void handleDelete(int domain) {
        switch (domain) {
            case 1:
                enc_uris = new Uri[0];
                enc_names = new String[0];
                enc_files.setText("");
                msgLog("Selection Deleted", 1);
                break;
            case 3:
                send_uris = new Uri[0];
                send_names = new String[0];
                send_files.setText("");
                msgLog("Selection Deleted", 3);
                break;
            case 7:
                psend_uris = new Uri[0];
                psend_names = new String[0];
                psend_files.setText("");
                msgLog("Selection Deleted", 7);
                break;
        }
    }
    public String readText(String name) {
        try {
            File f = this.io.GetLocalFile(name);
            byte[] buffer = new byte[(int) f.length()];
            FileInputStream fis = new FileInputStream(f);
            fis.read(buffer);
            fis.close();
            return new String(buffer, StandardCharsets.UTF_8);
        } catch (Exception e) {
            msgToast(e.toString());
            return "";
        }
    }
    public void writeText(String name, String msg) {
        try {
            File f = this.io.GetLocalFile(name);
            FileOutputStream fos = new FileOutputStream(f);
            fos.write(msg.getBytes(StandardCharsets.UTF_8));
            fos.close();
        } catch (Exception e) {
            msgToast(e.toString());
        }
    }
    public int findKey(String name) {
        for (int i = 0; i < this.keyNames.length; i++) {
            if (this.keyNames[i].equals(name)) {
                return i;
            }
        }
        return -1;
    }
    private void sendData(String[] data, int runMode) {
        Message msg;
        Bundle bdl;
        msg = Message.obtain(null, 3);
        bdl = new Bundle();
        bdl.putInt("int", data.length);
        msg.setData(bdl);
        try {
            main2svc.send(msg);
        } catch (Exception e) {
            msgLog(e.toString(), runMode);
        }

        for (String s : data) {
            msg = Message.obtain(null, 4);
            bdl = new Bundle();
            bdl.putString("string", s);
            msg.setData(bdl);
            try {
                main2svc.send(msg);
            } catch (Exception e) {
                msgLog(e.toString(), runMode);
            }
        }
    }
    private void sendData(Uri[] data, int runMode) {
        Message msg;
        Bundle bdl;
        msg = Message.obtain(null, 5);
        bdl = new Bundle();
        bdl.putInt("int", data.length);
        msg.setData(bdl);
        try {
            main2svc.send(msg);
        } catch (Exception e) {
            msgLog(e.toString(), runMode);
        }

        for (Uri u : data) {
            msg = Message.obtain(null, 6);
            bdl = new Bundle();
            bdl.putParcelable("uri", u);
            msg.setData(bdl);
            try {
                main2svc.send(msg);
            } catch (Exception e) {
                msgLog(e.toString(), runMode);
            }
        }
    }
    private void sendOrder(String[] data, int runMode) {
        Message msg;
        Bundle bdl;
        msg = Message.obtain(null, 7);
        bdl = new Bundle();
        bdl.putInt("int", data.length);
        msg.setData(bdl);
        try {
            main2svc.send(msg);
        } catch (Exception e) {
            msgLog(e.toString(), runMode);
        }

        for (String s : data) {
            msg = Message.obtain(null, 8);
            bdl = new Bundle();
            bdl.putString("string", s);
            msg.setData(bdl);
            try {
                main2svc.send(msg);
            } catch (Exception e) {
                msgLog(e.toString(), runMode);
            }
        }
    }
    private void sendOrder(int code, int runMode) {
        try {
            main2svc.send( Message.obtain(null, code) );
        } catch (Exception e) {
            msgLog(e.toString(), runMode);
        }
    }
    private void sendFlag(int[] data, int runMode) {
        Message msg;
        Bundle bdl;
        msg = Message.obtain(null, 9);
        bdl = new Bundle();
        bdl.putInt("int", data.length);
        msg.setData(bdl);
        try {
            main2svc.send(msg);
        } catch (Exception e) {
            msgLog(e.toString(), runMode);
        }

        for (int i : data) {
            msg = Message.obtain(null, 10);
            bdl = new Bundle();
            bdl.putInt("int", i);
            msg.setData(bdl);
            try {
                main2svc.send(msg);
            } catch (Exception e) {
                msgLog(e.toString(), runMode);
            }
        }
    }
}