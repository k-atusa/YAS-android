package com.example.k7yas.view;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.PopupMenu;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import com.example.k7yas.R;
import com.example.k7yas.app.Account;
import com.example.k7yas.app.IO1;
import com.example.k7yas.app.SVCC1;
import com.example.k7yas.engine.Bencode;
import com.example.k7yas.engine.Bencrypt;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class EncryptView extends AppCompatActivity {
    // UI Components
    private ImageButton buttonMenu, buttonCopy, buttonDownload;
    private Button buttonAddFiles, buttonAddDir, buttonClear, buttonEncrypt;
    private TextView textFilelist, textResult, textStatus;
    private EditText inputMsg, editSmsg, inputPw;
    private CheckBox checkPubkey, checkSign;
    private Spinner selectKf, selectPubkey;

    // Data
    private final List<IO1.VFile> fileList = new ArrayList<>();
    private ActivityResultLauncher<Intent> fileLauncher;
    private ActivityResultLauncher<Intent> folderLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.view_encrypt);

        // connect components
        buttonMenu = findViewById(R.id.button_menu);
        buttonCopy = findViewById(R.id.button_copy);
        buttonDownload = findViewById(R.id.button_download);
        buttonAddFiles = findViewById(R.id.button_add_files);
        buttonAddDir = findViewById(R.id.button_add_dir);
        buttonClear = findViewById(R.id.button_clear);
        buttonEncrypt = findViewById(R.id.button_encrypt);
        textFilelist = findViewById(R.id.text_filelist);
        textResult = findViewById(R.id.text_result);
        textStatus = findViewById(R.id.text_status);
        inputMsg = findViewById(R.id.input_msg);
        editSmsg = findViewById(R.id.edit_smsg);
        inputPw = findViewById(R.id.input_pw);
        checkPubkey = findViewById(R.id.check_pubkey);
        checkSign = findViewById(R.id.check_sign);
        selectKf = findViewById(R.id.select_kf);
        selectPubkey = findViewById(R.id.select_pubkey);

        // bind file selection
        initLaunchers();
        buttonAddFiles.setOnClickListener(v -> IO1.SelectFile(fileLauncher, true));
        buttonAddDir.setOnClickListener(v -> IO1.SelectFolder(folderLauncher));
        buttonClear.setOnClickListener(v -> {
            fileList.clear();
            textFilelist.setText("No Files Selected...");
        });

        // bind mode toggle
        checkPubkey.setOnCheckedChangeListener((buttonView, isChecked) -> {
            selectKf.setEnabled(!isChecked);
            inputPw.setEnabled(!isChecked);
            selectPubkey.setEnabled(isChecked);
            checkSign.setEnabled(isChecked);
        });

        // initial state
        checkPubkey.setChecked(false);
        selectPubkey.setEnabled(false);
        checkSign.setEnabled(false);

        // populate spinners
        refreshSpinners();

        // bind actions
        buttonMenu.setOnClickListener(v -> {
            if (isEngineWorking()) {
                Toast.makeText(this, "Engine Working", Toast.LENGTH_SHORT).show();
                return;
            }
            showMenu();
        });
        buttonEncrypt.setOnClickListener(v -> doEncrypt());
        buttonCopy.setOnClickListener(v -> doCopy());
        buttonDownload.setOnClickListener(v -> doDownload());
    }

    private void initLaunchers() {
        fileLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == RESULT_OK && result.getData() != null) {
                        List<IO1.VFile> files = IO1.HandleSelectedFile(result.getData());
                        if (files != null && !files.isEmpty()) {
                            fileList.addAll(files);
                            refreshFileview();
                        }
                    }
                }
        );
        folderLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == RESULT_OK && result.getData() != null) {
                        IO1.VFile folder = IO1.HandleSelectedFolder(result.getData());
                        if (folder != null) {
                            fileList.add(folder);
                            refreshFileview();
                        }
                    }
                }
        );
    }

    private void refreshFileview() {
        if (fileList.isEmpty()) {
            textFilelist.setText("No Files Selected...");
            return;
        }
        StringBuilder sb = new StringBuilder();
        for (IO1.VFile f : fileList) {
            sb.append(f.GetName(this)).append("\n");
        }
        textFilelist.setText(sb.toString().trim());
    }

    private void refreshSpinners() {
        Account account = Account.GetAccount(this);
        
        String[] kfs = account.GetList(true);
        ArrayAdapter<String> kfAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, kfs);
        kfAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        selectKf.setAdapter(kfAdapter);

        String[] pubs = account.GetList(false);
        ArrayAdapter<String> pubAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, pubs);
        pubAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        selectPubkey.setAdapter(pubAdapter);
    }

    private boolean isEngineWorking() {
        Integer status = SVCC1.getChan().IntSlots[0].getValue();
        return status != null && status == 1;
    }

    private void showMenu() {
        PopupMenu popup = new PopupMenu(this, buttonMenu);
        popup.getMenu().add(0, 1, 0, "Pack");
        popup.getMenu().add(0, 2, 0, "Sign");
        popup.getMenu().add(0, 3, 0, "Send");
        popup.getMenu().add(0, 4, 0, "Encrypt");
        popup.getMenu().add(0, 5, 0, "Decrypt");
        popup.getMenu().add(0, 6, 0, "Config");

        popup.setOnMenuItemClickListener(item -> {
            Intent intent = null;
            switch (item.getItemId()) {
                case 1: intent = new Intent(this, PackView.class); break;
                case 2: intent = new Intent(this, SignView.class); break;
                case 3: intent = new Intent(this, SendView.class); break;
                case 4: intent = new Intent(this, EncryptView.class); break;
                case 5: intent = new Intent(this, DecryptView.class); break;
                case 6: intent = new Intent(this, ConfigView.class); break;
            }
            if (intent != null) {
                startActivity(intent);
                finish();
            }
            return true;
        });
        popup.show();
    }

    private void doEncrypt() {
        // check status, pack parameters
        if (isEngineWorking()) return;
        Bundle b = new Bundle();
        b.putParcelableArrayList("srcs", new ArrayList<>(fileList));
        b.putString("msg", inputMsg.getText().toString());
        b.putString("smsg", editSmsg.getText().toString());

        if (checkPubkey.isChecked()) { // public key encryption
            String pubName = (String) selectPubkey.getSelectedItem();
            if (pubName == null) {
                Toast.makeText(this, "Select Public Key", Toast.LENGTH_SHORT).show();
                return;
            }

            b.putString("pubName", pubName);
            b.putBoolean("doSign", checkSign.isChecked());
            SVCC1.getChan().SendToSvc("TASK_ENC_PUB", b);

        } else { // password encryption
            byte[] pw = Bencode.NormPW(inputPw.getText().toString());
            inputPw.setText("");
            String kfName = (String) selectKf.getSelectedItem();
            Bencrypt.Masker masker = Bencrypt.Masker.GetMasker();
            byte[] maskedPw = masker.XOR(pw);
            Account.sclear(pw);

            b.putByteArray("password", maskedPw);
            b.putString("keyfile", kfName != null ? kfName : "");
            SVCC1.getChan().SendToSvc("TASK_ENC_PW", b);
        }
        monitorEngine();
    }

    private void monitorEngine() {
        new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    break;
                }

                Integer working = SVCC1.getChan().IntSlots[0].getValue();
                Integer error = SVCC1.getChan().IntSlots[1].getValue();
                Double progress = SVCC1.getChan().DoubleSlots[0].getValue();
                String statusMsg = SVCC1.getChan().StringSlots[0].getValue();
                String errorMsg = SVCC1.getChan().StringSlots[1].getValue();
                String resultTxt = SVCC1.getChan().StringSlots[3].getValue(); // Result for text mode

                final int isWorking = (working != null) ? working : 0;
                final int isError = (error != null) ? error : 0;
                final double progVal = (progress != null) ? progress : 0.0;

                runOnUiThread(() -> {
                    // line 1: process, error
                    String line1 = String.format(Locale.US, "%.1f%%", progVal * 100);
                    if (isError == 1) {
                        line1 += " / Error: " + (errorMsg != null ? errorMsg : "Unknown");
                    }

                    // line 2: status
                    String line2 = (statusMsg != null ? statusMsg : "");
                    if (isWorking == 0 && isError == 0) {
                        line2 = "Completed";
                        if (resultTxt != null && !resultTxt.isEmpty()) {
                            textResult.setText(resultTxt); // update cipher text
                        }
                    }

                    textStatus.setText(line1 + "\n" + line2 + "\n");
                });
                if (isWorking == 0) break;
            }
        }).start();
    }

    private void doCopy() {
        String content = textResult.getText().toString();
        if (content.isEmpty()) return;
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText("Encrypted Message", content);
        clipboard.setPrimaryClip(clip);
        Toast.makeText(this, "Copied to clipboard", Toast.LENGTH_SHORT).show();
    }

    private void doDownload() {
        String content = textResult.getText().toString();
        if (content.isEmpty()) return;
        try {
            IO1.VFile file = IO1.CreateDownloadsFile(this, "cipher.txt");
            if (file != null) {
                try (OutputStream os = file.OpenWriter(this, false)) {
                    os.write(content.getBytes(StandardCharsets.UTF_8));
                    Toast.makeText(this, "Saved to Downloads", Toast.LENGTH_SHORT).show();
                }
            }
        } catch (Exception e) {
            Toast.makeText(this, "Save Failed: " + e.toString(), Toast.LENGTH_LONG).show();
        }
    }
}
