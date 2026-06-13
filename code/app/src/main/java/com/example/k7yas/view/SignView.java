package com.example.k7yas.view;

import android.content.Intent;
import android.os.Bundle;
import android.widget.ArrayAdapter;
import android.widget.Button;
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

import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

public class SignView extends AppCompatActivity {
    // UI Components
    private ImageButton buttonMenu, buttonFetch, buttonSave;
    private EditText editSign;
    private Spinner selectPubkey;
    private Button buttonFile, buttonSign, buttonVerify;
    private TextView textFile, textStatus;

    // Data
    private IO1.VFile targetFile;
    private ActivityResultLauncher<Intent> fileLauncher;
    private ActivityResultLauncher<Intent> signFetchLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.view_sign);

        // connect components
        buttonMenu = findViewById(R.id.button_menu);
        editSign = findViewById(R.id.edit_sign);
        buttonFetch = findViewById(R.id.button_fetch);
        buttonSave = findViewById(R.id.button_save);
        selectPubkey = findViewById(R.id.select_pubkey);
        buttonFile = findViewById(R.id.button_file);
        buttonSign = findViewById(R.id.button_sign);
        buttonVerify = findViewById(R.id.button_verify);
        textFile = findViewById(R.id.text_file);
        textStatus = findViewById(R.id.text_status);

        // bind launchers
        initLaunchers();

        // bind menu
        buttonMenu.setOnClickListener(v -> {
            Integer status = SVCC1.getChan().IntSlots[0].getValue();
            if (status != null && status == 1) {
                Toast.makeText(this, "Engine Working", Toast.LENGTH_SHORT).show();
                return;
            }
            showMenu();
        });

        // bind file selection
        buttonFile.setOnClickListener(v -> IO1.SelectFile(fileLauncher, false));
        buttonFetch.setOnClickListener(v -> IO1.SelectFile(signFetchLauncher, false));
        buttonSave.setOnClickListener(v -> {
            String content = editSign.getText().toString();
            if (content.isEmpty()) return;
            try {
                IO1.VFile file = IO1.CreateDownloadsFile(this, "sign.txt");
                if (file != null) {
                    try (OutputStream os = file.OpenWriter(this, false)) {
                        os.write(content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                        Toast.makeText(this, "Saved to Downloads", Toast.LENGTH_SHORT).show();
                    }
                }
            } catch (Exception e) {
                Toast.makeText(this, "Save Failed: " + e.toString(), Toast.LENGTH_LONG).show();
            }
        });

        // populate spinner
        refreshSpinner();

        // bind actions
        buttonSign.setOnClickListener(v -> doSign());
        buttonVerify.setOnClickListener(v -> doVerify());
    }

    private void initLaunchers() {
        fileLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == RESULT_OK && result.getData() != null) {
                        List<IO1.VFile> files = IO1.HandleSelectedFile(result.getData());
                        if (files != null && !files.isEmpty()) {
                            targetFile = files.get(0);
                            textFile.setText(targetFile.GetName(this));
                        }
                    }
                }
        );

        signFetchLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == RESULT_OK && result.getData() != null) {
                        List<IO1.VFile> files = IO1.HandleSelectedFile(result.getData());
                        if (files != null && !files.isEmpty()) {
                            try (InputStream is = files.get(0).OpenReader(this)) {
                                byte[] data = is.readAllBytes();
                                editSign.setText(new String(data, java.nio.charset.StandardCharsets.UTF_8));
                            } catch (Exception e) {
                                Toast.makeText(this, "Fetch Failed: " + e.toString(), Toast.LENGTH_LONG).show();
                            }
                        }
                    }
                }
        );
    }

    private void refreshSpinner() {
        String[] keys = Account.GetAccount(this).GetList(false);
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, keys);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        selectPubkey.setAdapter(adapter);
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

    private void doSign() {
        if (targetFile == null) {
            Toast.makeText(this, "Select a file first", Toast.LENGTH_SHORT).show();
            return;
        }
        Integer status = SVCC1.getChan().IntSlots[0].getValue();
        if (status != null && status == 1) return; // check if engine is working

        new Thread(() -> {
            SVCC1.getChan().SetInt(0, 1);
            byte[] unmaskedPri = null;
            try {
                // get private key and data
                if (targetFile.GetSize(this) > 64 * 1024 * 1024) {
                    throw new Exception("File size over 64MiB limit");
                }
                Account account = Account.GetAccount(this);
                Bencrypt.Masker masker = Bencrypt.Masker.GetMasker();
                unmaskedPri = masker.XOR(account.PriKey);
                byte[] data;
                try (InputStream is = targetFile.OpenReader(this)) {
                    data = is.readAllBytes();
                }

                Bencrypt.AsymMaster am = new Bencrypt.AsymMaster(account.KeyType);
                am.Loadkey(account.PubKey, unmaskedPri);
                byte[] signature = am.Sign(data);
                String encodedSign = Bencode.Encode64(signature, "#", 80, 10);
                runOnUiThread(() -> {
                    editSign.setText(encodedSign);
                    textStatus.setText("Sign Complete\n" + targetFile.GetName(this));
                });

            } catch (Exception e) {
                runOnUiThread(() -> textStatus.setText("Error: " + e.toString()));
            } finally {
                SVCC1.getChan().SetInt(0, 0);
                if (unmaskedPri != null) Account.sclear(unmaskedPri);
            }
        }).start();
    }

    private void doVerify() {
        if (targetFile == null) {
            Toast.makeText(this, "Select a file first", Toast.LENGTH_SHORT).show();
            return;
        }
        String encodedSign = editSign.getText().toString();
        if (encodedSign.isEmpty()) {
            Toast.makeText(this, "Enter signature first", Toast.LENGTH_SHORT).show();
            return;
        }
        Integer status = SVCC1.getChan().IntSlots[0].getValue();
        if (status != null && status == 1) return; // check if engine is working

        new Thread(() -> {
            SVCC1.getChan().SetInt(0, 1);
            try {
                // get public key
                if (targetFile.GetSize(this) > 64 * 1024 * 1024) {
                    throw new Exception("File size over 64MB limit");
                }
                String selectedKeyName = (String) selectPubkey.getSelectedItem();
                if (selectedKeyName == null) throw new Exception("No public key selected");
                Account account = Account.GetAccount(this);
                byte[] peerPub = account.PubKeys.get(selectedKeyName);
                if (peerPub == null) throw new Exception("Invalid public key");

                // get sign and file data
                byte[] signature = Bencode.Decode64(encodedSign, "#");
                byte[] data;
                try (InputStream is = targetFile.OpenReader(this)) {
                    data = is.readAllBytes();
                }

                Bencrypt.AsymMaster am = new Bencrypt.AsymMaster(account.KeyType);
                am.Loadkey(peerPub, null);
                boolean valid = am.Verify(data, signature);
                runOnUiThread(() -> {
                    if (valid) {
                        textStatus.setText("VERIFIED OK\nSignature is valid");
                    } else {
                        textStatus.setText("VERIFICATION FAILED\nSignature is invalid");
                    }
                });

            } catch (Exception e) {
                runOnUiThread(() -> textStatus.setText("Error: " + e.toString()));
            } finally {
                SVCC1.getChan().SetInt(0, 0);
            }
        }).start();
    }
}
