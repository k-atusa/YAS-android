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
import com.example.k7yas.engine.Opsec;

import java.io.InputStream;
import java.util.List;
import java.util.Locale;

public class DecryptView extends AppCompatActivity {
    // UI Components
    private ImageButton buttonMenu;
    private Button buttonGetText, buttonGetFile, buttonDecrypt;
    private TextView textFileStatus, textStatus, textMessage, textSmsg;
    private EditText editCipher, inputPw;
    private CheckBox checkPubmode;
    private Spinner selectKf, selectPubkey;

    // Data
    private IO1.VFile targetFile;
    private ActivityResultLauncher<Intent> fileLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.view_decrypt);

        // connect components
        buttonMenu = findViewById(R.id.button_menu);
        buttonGetText = findViewById(R.id.button_get_text);
        buttonGetFile = findViewById(R.id.button_get_file);
        buttonDecrypt = findViewById(R.id.button_decrypt);
        textFileStatus = findViewById(R.id.text_file_status);
        textStatus = findViewById(R.id.text_status);
        textMessage = findViewById(R.id.text_message);
        textSmsg = findViewById(R.id.text_smsg);
        editCipher = findViewById(R.id.edit_cipher);
        inputPw = findViewById(R.id.input_pw);
        checkPubmode = findViewById(R.id.check_pubmode);
        selectKf = findViewById(R.id.select_kf);
        selectPubkey = findViewById(R.id.select_pubkey);

        // bind file selection
        fileLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == RESULT_OK && result.getData() != null) {
                        List<IO1.VFile> files = IO1.HandleSelectedFile(result.getData());
                        if (files != null && !files.isEmpty()) {
                            targetFile = files.get(0);
                            textFileStatus.setText(targetFile.GetName(this));
                            editCipher.setText(""); // clear text mode if file selected

                            // peek opsec header
                            try (InputStream is = targetFile.OpenReader(this)) {
                                Opsec ops = new Opsec();
                                ops.Reset();
                                byte[] header = ops.Read(is, 0);
                                if (header != null && header.length > 0) {
                                    ops.View(header);
                                    if (ops.Msg != null) textMessage.setText(ops.Msg);
                                }
                            } catch (Exception e) {
                                textStatus.setText("Error: " + e.toString());
                            }
                        }
                    }
                }
        );
        buttonGetFile.setOnClickListener(v -> IO1.SelectFile(fileLauncher, false));
        buttonGetText.setOnClickListener(v -> {
            ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard.hasPrimaryClip()) {
                ClipData.Item item = clipboard.getPrimaryClip().getItemAt(0);
                editCipher.setText(item.getText());
                targetFile = null; // clear file mode if text pasted
                textFileStatus.setText("No file selected");
            }
        });

        // bind mode toggle
        checkPubmode.setOnCheckedChangeListener((buttonView, isChecked) -> {
            selectKf.setEnabled(!isChecked);
            inputPw.setEnabled(!isChecked);
            selectPubkey.setEnabled(isChecked);
        });

        // initial state
        checkPubmode.setChecked(false);
        selectPubkey.setEnabled(false);

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
        buttonDecrypt.setOnClickListener(v -> doDecrypt());
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

    private void doDecrypt() {
        // check status, pack parameters
        if (isEngineWorking()) return;
        Bundle b = new Bundle();
        b.putParcelable("src", targetFile);
        b.putString("text", editCipher.getText().toString());

        if (checkPubmode.isChecked()) { // public key mode
            String pubName = (String) selectPubkey.getSelectedItem();
            b.putString("pubName", pubName != null ? pubName : "");
            SVCC1.getChan().SendToSvc("TASK_DEC_PUB", b);

        } else { // password mode
            byte[] pw = Bencode.NormPW(inputPw.getText().toString());
            inputPw.setText("");
            String kfName = (String) selectKf.getSelectedItem();
            
            // mask password
            Bencrypt.Masker masker = Bencrypt.Masker.GetMasker();
            byte[] maskedPw = masker.XOR(pw);
            Account.sclear(pw);
            b.putByteArray("password", maskedPw);
            b.putString("keyfile", kfName != null ? kfName : "");
            SVCC1.getChan().SendToSvc("TASK_DEC_PW", b);
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
                String msgRes = SVCC1.getChan().StringSlots[2].getValue(); 
                String smsgRes = SVCC1.getChan().StringSlots[3].getValue(); 

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
                        if (msgRes != null) textMessage.setText(msgRes); // update msg, smsg
                        if (smsgRes != null) textSmsg.setText(smsgRes);
                    }
                    textStatus.setText(line1 + "\n" + line2 + "\n");
                });
                if (isWorking == 0) break;
            }
        }).start();
    }
}
