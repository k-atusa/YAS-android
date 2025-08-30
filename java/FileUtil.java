package com.example.kutil6_yas;

import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Environment;
import android.provider.DocumentsContract;
import android.provider.MediaStore;
import android.provider.OpenableColumns;
import android.webkit.MimeTypeMap;

import androidx.activity.result.ActivityResultLauncher;

import java.io.File;

// manage file IO of local & downloads scope
public class FileUtil {
    public Uri[] selUris;
    public String[] selNames;
    public Context context;

    public FileUtil(Context c) {
        this.selUris = new Uri[0];
        this.selNames = new String[0];
        this.context = c;
    }

    public void SelectFile(ActivityResultLauncher<Intent> launcher, boolean multi) {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        if (multi) { intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true); }
        launcher.launch(intent);
    }

    public void SelectFolder(ActivityResultLauncher<Intent> launcher) {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
        launcher.launch(intent);
    }

    public void HandleSelectionFile(Intent data) {
        if (data.getClipData() != null) {
            int length = data.getClipData().getItemCount();
            this.selUris = new Uri[length];
            this.selNames = new String[length];
            for (int i = 0; i < length; i++) {
                this.selUris[i] = data.getClipData().getItemAt(i).getUri();
                this.selNames[i] = getFileName(this.selUris[i]);
            }
        } else if (data.getData() != null) {
            this.selUris = new Uri[1];
            this.selNames = new String[1];
            this.selUris[0] = data.getData();
            this.selNames[0] = getFileName(this.selUris[0]);
        } else {
            this.selUris = new Uri[0];
            this.selNames = new String[0];
        }
    }

    public void HandleSelectionFolder(Intent data) {
        if (data.getData() != null) {
            this.selUris = new Uri[1];
            this.selNames = new String[1];
            this.selUris[0] = data.getData();
            this.selNames[0] = getFolderName(this.selUris[0]);
            if (!this.selNames[0].endsWith("/")) { this.selNames[0] += "/"; }
        } else {
            this.selUris = new Uri[0];
            this.selNames = new String[0];
        }
    }

    public String PrintSelection() {
        String ret = "";
        for (int i = 0; i < this.selUris.length; i++) {
            if (DocumentsContract.isTreeUri(this.selUris[i])) { ret += "Dir: " + this.selNames[i] + "/\n"; }
            else { ret += "File: " + this.selNames[i] + "\n"; }
        }
        return ret;
    }

    private String getFileName(Uri uri) {
        String name = null;
        try (Cursor cursor = this.context.getContentResolver().query(uri,
                new String[]{OpenableColumns.DISPLAY_NAME},
                null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                int idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (idx != -1) {
                    name = cursor.getString(idx);
                }
            }
        }
        return name;
    }

    private String getFolderName(Uri uri) {
        String docId = DocumentsContract.getTreeDocumentId(uri);
        String[] split = docId.split(":");
        if (split.length > 1) { docId = split[1]; }
        if (docId.endsWith("/")) { docId = docId.substring(0, docId.length() - 1); }
        split = docId.split("/");
        return split[split.length - 1];
    }

    public File GetLocalFile(String name) { return new File(this.context.getFilesDir(), name); }
    public Uri GetDownloadsFile(String name) {
        ContentValues values = new ContentValues();
        String mimeType = null;
        int dotpos = name.lastIndexOf('.');
        if (dotpos != -1 && dotpos != name.length() - 1) {
            mimeType = MimeTypeMap.getSingleton().getMimeTypeFromExtension(name.substring(dotpos + 1).toLowerCase());
        }
        if (mimeType == null) { mimeType = "application/octet-stream"; }
        values.put(MediaStore.Downloads.DISPLAY_NAME, name);
        values.put(MediaStore.Downloads.MIME_TYPE, mimeType);
        values.put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS);
        Uri collection = MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY);
        return this.context.getContentResolver().insert(collection, values);
    }
    public long GetFileSize(File f) { return f.length(); }
    public long GetFileSize(Uri f) {
        long fileSize = -1;
        try (Cursor cursor = this.context.getContentResolver().query(
                f, new String[]{OpenableColumns.SIZE}, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                int sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE);
                if (sizeIndex != -1) { fileSize = cursor.getLong(sizeIndex); }
            }
        }
        return fileSize;
    }
}