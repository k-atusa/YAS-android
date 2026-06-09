package com.example.k7yas.view;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
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
import com.example.k7yas.engine.Bencode;
import com.example.k7yas.engine.Bencrypt;
import com.example.k7yas.engine.Opsec;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

public class ConfigView extends AppCompatActivity {
    // UI Components
    private Spinner selectPackType, selectImgType, selectPubkey, selectKf;
    private Button buttonSaveConfig, buttonAddPubkey, buttonDelPubkey, buttonSelectFile, buttonAddKf, buttonDelKf;
    private ImageButton buttonMenu, buttonView, buttonDownload, buttonEdit;
    private EditText editPubkey, inputPubkeyName, inputKfName;
    private TextView textFileStatus, editPubkeyContent, editPrivkeyContent, textStatus;

    // Data
    private IO1.VFile targetFile;
    private ActivityResultLauncher<Intent> fileLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.view_config);

        // connect components
        buttonMenu = findViewById(R.id.button_menu);
        selectPackType = findViewById(R.id.select_pack_type);
        selectImgType = findViewById(R.id.select_img_type);
        buttonSaveConfig = findViewById(R.id.button_save_config);

        editPubkey = findViewById(R.id.edit_pubkey);
        inputPubkeyName = findViewById(R.id.input_pubkey_name);
        selectPubkey = findViewById(R.id.select_pubkey);
        buttonAddPubkey = findViewById(R.id.button_add_pubkey);
        buttonDelPubkey = findViewById(R.id.button_del_pubkey);

        buttonSelectFile = findViewById(R.id.button_select_file);
        textFileStatus = findViewById(R.id.text_file_status);
        inputKfName = findViewById(R.id.input_kf_name);
        selectKf = findViewById(R.id.select_kf);
        buttonAddKf = findViewById(R.id.button_add_kf);
        buttonDelKf = findViewById(R.id.button_del_kf);

        editPubkeyContent = findViewById(R.id.edit_pubkey_content);
        editPrivkeyContent = findViewById(R.id.edit_privkey_content);
        buttonView = findViewById(R.id.button_view);
        buttonDownload = findViewById(R.id.button_download);
        buttonEdit = findViewById(R.id.button_edit);
        textStatus = findViewById(R.id.text_status);

        // hide key contents
        editPubkeyContent.setVisibility(View.GONE);
        editPrivkeyContent.setVisibility(View.GONE);
        buttonDownload.setEnabled(false);
        buttonEdit.setEnabled(false);

        // bind file selection
        fileLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == RESULT_OK && result.getData() != null) {
                        List<IO1.VFile> files = IO1.HandleSelectedFile(result.getData());
                        if (files != null && !files.isEmpty()) {
                            targetFile = files.get(0);
                            textFileStatus.setText(targetFile.GetName(this));
                        }
                    }
                }
        );
        buttonSelectFile.setOnClickListener(v -> IO1.SelectFile(fileLauncher, false));

        // init spinners and values
        initSettings();
        refreshLists();
        updateStatus();

        // bind actions
        buttonMenu.setOnClickListener(v -> showMenu());
        buttonSaveConfig.setOnClickListener(v -> doSaveSettings());
        buttonAddPubkey.setOnClickListener(v -> doAddPub());
        buttonDelPubkey.setOnClickListener(v -> doDelPub());
        buttonAddKf.setOnClickListener(v -> doAddKf());
        buttonDelKf.setOnClickListener(v -> doDelKf());
        buttonView.setOnClickListener(v -> doViewKeys());
        buttonDownload.setOnClickListener(v -> doDownloadKey());
        buttonEdit.setOnClickListener(v -> doEditKeys());
    }

    private void initSettings() {
        Account account = Account.GetAccount(this);

        String[] packs = {"zip1", "tar1"};
        selectPackType.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, packs));
        selectPackType.setSelection(Arrays.asList(packs).indexOf(account.PackType));

        String[] imgs = {"webp", "png"};
        selectImgType.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, imgs));
        selectImgType.setSelection(Arrays.asList(imgs).indexOf(account.ImgType));
    }

    private void refreshLists() {
        Account account = Account.GetAccount(this);

        String[] pubs = account.GetList(false);
        ArrayAdapter<String> pubAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, pubs);
        pubAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        selectPubkey.setAdapter(pubAdapter);

        String[] kfs = account.GetList(true);
        ArrayAdapter<String> kfAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, kfs);
        kfAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        selectKf.setAdapter(kfAdapter);
    }

    private void updateStatus() {
        Account account = Account.GetAccount(this);
        Bencrypt.Masker masker = Bencrypt.Masker.GetMasker();
        byte[] unmaskedPri = masker.XOR(account.PriKey);

        String status = String.format("Type: %s\nPub: %s\nPri: %s",
                account.KeyType,
                Opsec.Crc32(account.PubKey),
                Opsec.Crc32(unmaskedPri));
        Account.sclear(unmaskedPri);
        textStatus.setText(status);
    }

    private void doSaveSettings() {
        String pack = selectPackType.getSelectedItem().toString();
        String img = selectImgType.getSelectedItem().toString();
        Account.GetAccount(this).Store(pack, img);
        Toast.makeText(this, "Settings Saved", Toast.LENGTH_SHORT).show();
    }

    private void doAddPub() {
        String raw = editPubkey.getText().toString();
        String name = inputPubkeyName.getText().toString().trim();
        if (raw.isEmpty()) return;
        if (name.isEmpty()) name = "Imported";

        final String finalName = name;
        new Thread(() -> {
            try {
                byte[] data = Bencode.Decode64(raw, "#");
                Account.GetAccount(this).AddList(false, finalName, data);
                runOnUiThread(() -> {
                    editPubkey.setText("");
                    inputPubkeyName.setText("");
                    refreshLists();
                    Toast.makeText(this, "Public Key Added", Toast.LENGTH_SHORT).show();
                });
            } catch (Exception e) {
                runOnUiThread(() -> Toast.makeText(this, "Add Failed: " + e.toString(), Toast.LENGTH_LONG).show());
            }
        }).start();
    }

    private void doDelPub() {
        String selected = (String) selectPubkey.getSelectedItem();
        if (selected == null) return;

        new Thread(() -> {
            try {
                Account.GetAccount(this).DelList(false, selected);
                runOnUiThread(() -> {
                    refreshLists();
                    Toast.makeText(this, "Public Key Deleted", Toast.LENGTH_SHORT).show();
                });
            } catch (Exception e) {
                runOnUiThread(() -> Toast.makeText(this, "Delete Failed: " + e.toString(), Toast.LENGTH_LONG).show());
            }
        }).start();
    }

    private void doAddKf() {
        if (targetFile == null) return;
        String name = inputKfName.getText().toString().trim();
        if (name.isEmpty()) name = targetFile.GetName(this);

        final String finalName = name;
        new Thread(() -> {
            try (InputStream is = targetFile.OpenReader(this)) {
                byte[] rawData = is.readNBytes(4096); // limit to 4096 bytes
                Bencrypt.Masker masker = Bencrypt.Masker.GetMasker();
                byte[] maskedData = masker.XOR(rawData); // keyfile should be masked
                Account.sclear(rawData);
                Account.GetAccount(this).AddList(true, finalName, maskedData);
                Account.sclear(maskedData);

                runOnUiThread(() -> {
                    targetFile = null;
                    textFileStatus.setText("No file selected");
                    inputKfName.setText("");
                    refreshLists();
                    Toast.makeText(this, "KeyFile Added", Toast.LENGTH_SHORT).show();
                });
            } catch (Exception e) {
                runOnUiThread(() -> Toast.makeText(this, "Add Failed: " + e.toString(), Toast.LENGTH_LONG).show());
            }
        }).start();
    }

    private void doDelKf() {
        String selected = (String) selectKf.getSelectedItem();
        if (selected == null) return;

        new Thread(() -> {
            try {
                Account.GetAccount(this).DelList(true, selected);
                runOnUiThread(() -> {
                    refreshLists();
                    Toast.makeText(this, "KeyFile Deleted", Toast.LENGTH_SHORT).show();
                });
            } catch (Exception e) {
                runOnUiThread(() -> Toast.makeText(this, "Delete Failed: " + e.toString(), Toast.LENGTH_LONG).show());
            }
        }).start();
    }

    private void doViewKeys() {
        Account account = Account.GetAccount(this);
        Bencrypt.Masker masker = Bencrypt.Masker.GetMasker();
        byte[] unmaskedPri = masker.XOR(account.PriKey);

        editPubkeyContent.setText(Bencode.Encode64(account.PubKey, "#", 80, 10));
        editPrivkeyContent.setText(Bencode.Encode64(unmaskedPri, "#", 80, 10));
        Account.sclear(unmaskedPri);

        editPubkeyContent.setVisibility(View.VISIBLE);
        editPrivkeyContent.setVisibility(View.VISIBLE);
        buttonDownload.setEnabled(true);
        buttonEdit.setEnabled(true);
    }

    private void doDownloadKey() {
        Account account = Account.GetAccount(this);
        try {
            // Save Public Key
            IO1.VFile pubFile = IO1.CreateDownloadsFile(this, "public.txt");
            if (pubFile != null) {
                try (OutputStream os = pubFile.OpenWriter(this, false)) {
                    String encoded = Bencode.Encode64(account.PubKey, "#", 80, 10);
                    os.write(encoded.getBytes(StandardCharsets.UTF_8));
                }
            }

            // Save Private Key
            IO1.VFile priFile = IO1.CreateDownloadsFile(this, "private.txt");
            if (priFile != null) {
                Bencrypt.Masker masker = Bencrypt.Masker.GetMasker();
                byte[] unmaskedPri = masker.XOR(account.PriKey);
                try (OutputStream os = priFile.OpenWriter(this, false)) {
                    String encoded = Bencode.Encode64(unmaskedPri, "#", 80, 10);
                    os.write(encoded.getBytes(StandardCharsets.UTF_8));
                } finally {
                    Account.sclear(unmaskedPri);
                }
            }

            Toast.makeText(this, "Keys Saved to Downloads", Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Toast.makeText(this, "Save Failed: " + e.toString(), Toast.LENGTH_LONG).show();
        }
    }

    private void doEditKeys() {
        String pubStr = editPubkeyContent.getText().toString();
        String priStr = editPrivkeyContent.getText().toString();
        if (pubStr.isEmpty() || priStr.isEmpty()) return;

        new Thread(() -> {
            try {
                byte[] newPub = Bencode.Decode64(pubStr, "#");
                byte[] newPriUnmasked = Bencode.Decode64(priStr, "#");
                Account account = Account.GetAccount(this);
                Bencrypt.Masker masker = Bencrypt.Masker.GetMasker();

                // update keys
                account.PubKey = newPub;
                account.PriKey = masker.XOR(newPriUnmasked);
                Account.sclear(newPriUnmasked);
                account.Store();

                runOnUiThread(() -> {
                    updateStatus();
                    Toast.makeText(this, "Keys Updated and Saved", Toast.LENGTH_SHORT).show();
                });
            } catch (Exception e) {
                runOnUiThread(() -> Toast.makeText(this, "Edit Failed: " + e.toString(), Toast.LENGTH_LONG).show());
            }
        }).start();
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
}
