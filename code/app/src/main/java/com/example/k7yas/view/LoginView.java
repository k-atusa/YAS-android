package com.example.k7yas.view;

import android.app.AlertDialog;
import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import com.example.k7yas.R;
import com.example.k7yas.app.Account;
import com.example.k7yas.app.IO1;
import com.example.k7yas.engine.Bencode;
import com.example.k7yas.engine.Bencrypt;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

public class LoginView extends AppCompatActivity {
    // UI components
    private EditText inputMsg;
    private EditText inputPw;
    private Button buttonLogin;
    private Button buttonMknew;
    private Button buttonImport;
    private Button buttonExport;

    // worker datas
    private Account account;
    private ActivityResultLauncher<Intent> importLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        // start view, connect components
        super.onCreate(savedInstanceState);
        setContentView(R.layout.view_login);
        inputMsg = findViewById(R.id.input_msg);
        inputPw = findViewById(R.id.input_pw);
        buttonLogin = findViewById(R.id.button_login);
        buttonMknew = findViewById(R.id.button_mknew);
        buttonImport = findViewById(R.id.button_import);
        buttonExport = findViewById(R.id.button_export);

        // show account msg
        account = Account.GetAccount(this);
        if (account.Msg != null) {
            inputMsg.setText(account.Msg);
        }

        // register import function
        importLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == RESULT_OK && result.getData() != null) {
                        onFileSelected(result.getData());
                    }
                }
        );

        // Login to existing account
        buttonLogin.setOnClickListener(v -> {
            byte[] pw = Bencode.NormPW(inputPw.getText().toString());
            inputPw.setText("");
            new Thread(() -> {
                try {
                    account.Load(pw);
                    runOnUiThread(() -> {
                        Toast.makeText(this, "Login Success", Toast.LENGTH_SHORT).show();
                        startActivity(new Intent(this, PackView.class));
                        finish();
                    });
                } catch (Exception e) {
                    runOnUiThread(() -> Toast.makeText(this, "Login Failed "+e.toString(), Toast.LENGTH_LONG).show());
                } finally {
                    Account.sclear(pw);
                }
            }).start();
        });

        // Make new account
        buttonMknew.setOnClickListener(v -> {
            String msgStr = inputMsg.getText().toString();
            byte[] pw = Bencode.NormPW(inputPw.getText().toString());
            inputPw.setText("");

            new AlertDialog.Builder(this)
                    .setMessage("Make new account? (algorithm: arg2+pqc1)")
                    .setPositiveButton("Create", (d, w) -> new Thread(() -> {
                        byte[][] keys = null;
                        try {
                            // generate key pair
                            Bencrypt.AsymMaster am = new Bencrypt.AsymMaster("pqc1");
                            keys = am.Genkey(); // keys[0] = Public, keys[1] = Private
                            if (keys == null || keys.length < 2) throw new Exception("Key generation failed");
                            account.PubKey = keys[0];
                            account.PriKey = Bencrypt.Masker.GetMasker().XOR(keys[1]);

                            account.Store(msgStr, pw);
                            runOnUiThread(() -> Toast.makeText(this, "Account Created", Toast.LENGTH_SHORT).show());
                        } catch (Exception e) {
                            runOnUiThread(() -> Toast.makeText(this, "Creation Failed "+e.toString(), Toast.LENGTH_LONG).show());
                        } finally {
                            if (keys != null && keys.length > 1) Account.sclear(keys[1]);
                            Account.sclear(pw);
                        }
                    }).start())
                    .setNegativeButton("Cancel", (d, w) -> Account.sclear(pw))
                    .show();
        });

        // Import account file
        buttonImport.setOnClickListener(v -> IO1.SelectFile(importLauncher, false));

        // Export account file
        buttonExport.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setMessage("Export account file to Downloads?")
                .setPositiveButton("Export", (d, w) -> new Thread(() -> {
                    try {
                        IO1.VFile src = IO1.GetLocal(this, "account.webp");
                        IO1.VFile dst = IO1.CreateDownloadsFile(this, "account.webp");
                        if (dst == null) throw new Exception("cannot make file to Downloads");
                        copyVFile(src, dst);
                        runOnUiThread(() -> Toast.makeText(this, "Export Success", Toast.LENGTH_SHORT).show());
                    } catch (Exception e) {
                        runOnUiThread(() -> Toast.makeText(this, "Export Failed "+e.toString(), Toast.LENGTH_LONG).show());
                    }
                }).start())
                .setNegativeButton("Cancel", null)
                .show());
    }

    private void onFileSelected(Intent data) {
        List<IO1.VFile> selected = IO1.HandleSelectedFile(data);
        if (selected == null || selected.isEmpty()) return;
        IO1.VFile src = selected.get(0);
        if (src.GetSize(this) > 32L * 1024 * 1024) { // 32MB Guard
            Toast.makeText(this, "File size limit exceeded (32MiB)", Toast.LENGTH_LONG).show();
            return;
        }

        new Thread(() -> {
            try {
                IO1.VFile dst = IO1.GetLocal(this, "account.webp");
                copyVFile(src, dst);
                runOnUiThread(() -> {
                    Toast.makeText(this, "Import Success", Toast.LENGTH_SHORT).show();
                    recreate();
                });
            } catch (Exception e) {
                runOnUiThread(() -> Toast.makeText(this, "Import Failed " + e.toString(), Toast.LENGTH_LONG).show());
            }
        }).start();
    }

    private void copyVFile(IO1.VFile src, IO1.VFile dst) throws Exception {
        byte[] buf = new byte[8192];
        try (InputStream in = src.OpenReader(this); OutputStream out = dst.OpenWriter(this, false)) {
            int len;
            while ((len = in.read(buf)) != -1) {
                out.write(buf, 0, len);
            }
        }
    }
}