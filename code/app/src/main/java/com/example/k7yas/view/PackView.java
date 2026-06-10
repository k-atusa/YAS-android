package com.example.k7yas.view;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.PopupMenu;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import com.example.k7yas.R;
import com.example.k7yas.app.IO1;
import com.example.k7yas.app.SVCC1;

import java.util.ArrayList;
import java.util.List;

public class PackView extends AppCompatActivity {
    // UI Components
    private ImageButton buttonMenu;
    private Button buttonAddFiles, buttonClear, buttonPack, buttonUnpack;
    private TextView textFilelist, textStatus;

    // Filelist workers
    private final List<IO1.VFile> fileList = new ArrayList<>();
    private ActivityResultLauncher<Intent> fileLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        // start view, connect components
        super.onCreate(savedInstanceState);
        setContentView(R.layout.view_pack);
        buttonMenu = findViewById(R.id.button_menu);
        buttonAddFiles = findViewById(R.id.button_add_files);
        buttonClear = findViewById(R.id.button_clear);
        buttonPack = findViewById(R.id.button_pack);
        buttonUnpack = findViewById(R.id.button_unpack);
        textFilelist = findViewById(R.id.text_filelist);
        textStatus = findViewById(R.id.text_status);

        // bind filelist functions
        initLaunchers();
        buttonAddFiles.setOnClickListener(v -> IO1.SelectFile(fileLauncher, true));
        buttonClear.setOnClickListener(v -> {
            fileList.clear();
            textFilelist.setText("No Files Selected...");
        });

        // bind menu button
        buttonMenu.setOnClickListener(v -> {
            Integer engineStatus = SVCC1.getChan().IntSlots[0].getValue();
            if (engineStatus != null && engineStatus == 1) {
                Toast.makeText(this, "Engine Working", Toast.LENGTH_SHORT).show();
                return;
            }
            showMenu();
        });

        // bind pack unpack
        buttonPack.setOnClickListener(v -> doPack());
        buttonUnpack.setOnClickListener(v -> doUnpack());
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

    // monitor engine status
    private void monitorEngine() {
        new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(100); // 100ms
                } catch (InterruptedException e) {
                    break;
                }

                // SVCC1 polling
                Integer working = SVCC1.getChan().IntSlots[0].getValue();
                Integer error = SVCC1.getChan().IntSlots[1].getValue();
                Double progress = SVCC1.getChan().DoubleSlots[0].getValue();
                String statusMsg = SVCC1.getChan().StringSlots[0].getValue();
                String errorMsg = SVCC1.getChan().StringSlots[1].getValue();
                final int isWorking = (working != null) ? working : 0;
                final int isError = (error != null) ? error : 0;
                final double progVal = (progress != null) ? progress : 0.0;

                // update UI status
                runOnUiThread(() -> {
                    // Line 1: progress + error
                    String line1 = String.format("%.1f%%", progVal * 100);
                    if (isError == 1) {
                        line1 += " / Error: " + (errorMsg != null ? errorMsg : "Unknown");
                    }

                    // Line 2: status message, force "Completed" when engine stops without error
                    String line2 = (statusMsg != null ? statusMsg : "");
                    if (isWorking == 0 && isError == 0) {
                        line2 = "Completed";
                    }

                    textStatus.setText(line1 + "\n" + line2 + "\n"); // Line 3: unused
                });
                if (isWorking == 0) break;
            }
        }).start();
    }

    private void doPack() {
        if (fileList.isEmpty()) {
            Toast.makeText(this, "No files selected to pack", Toast.LENGTH_SHORT).show();
            return;
        }
        Integer status = SVCC1.getChan().IntSlots[0].getValue();
        if (status != null && status == 1) return; // check if engine is working

        Bundle b = new Bundle();
        b.putParcelableArrayList("srcs", new ArrayList<>(fileList));
        SVCC1.getChan().SendToSvc("TASK_PACK", b);
        monitorEngine();
    }

    private void doUnpack() {
        if (fileList.isEmpty()) {
            Toast.makeText(this, "No archive selected to unpack", Toast.LENGTH_SHORT).show();
            return;
        }
        Integer status = SVCC1.getChan().IntSlots[0].getValue();
        if (status != null && status == 1) return; // check if engine is working

        Bundle b = new Bundle();
        b.putParcelable("src", fileList.get(0));
        SVCC1.getChan().SendToSvc("TASK_UNPACK", b);
        monitorEngine();
    }
}