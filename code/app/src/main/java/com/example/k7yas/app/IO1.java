// test814a : USAG-KOX IO1
package com.example.k7yas.app;

import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Environment;
import android.os.Parcel;
import android.os.Parcelable;
import android.provider.MediaStore;
import android.webkit.MimeTypeMap;

import androidx.activity.result.ActivityResultLauncher;
import androidx.annotation.NonNull;
import androidx.documentfile.provider.DocumentFile;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

// USAG-IO1, supports Android15+ (API 35+)
public class IO1 {

    // Abstract File for processing both external and internal storage
    public static class VFile implements Parcelable {
        public static final int TYPE_FILE = 0;
        public static final int TYPE_SINGLE_URI = 1;
        public static final int TYPE_TREE_URI = 2;

        // internal helpers
        @NonNull
        private final Uri uri;
        private final int type;
        private VFile(@NonNull Uri uri, int type) {
            this.uri = Objects.requireNonNull(uri, "VFile.uri cannot be null");
            this.type = type;
        }
        private DocumentFile toDocumentFile(Context context) {
            if (this.type == TYPE_FILE) return DocumentFile.fromFile(this.toFile());
            if (this.type == TYPE_SINGLE_URI) return DocumentFile.fromSingleUri(context, this.uri);
            if (this.type == TYPE_TREE_URI) return DocumentFile.fromTreeUri(context, this.uri);
            return null;
        }
        private File toFile() {
            return new File(Objects.requireNonNull(this.uri.getPath(), "Cannot convert Uri to File"));
        }

        // Constructor
        public VFile(@NonNull File file) {
            this(Uri.fromFile(Objects.requireNonNull(file, "File cannot be null")), TYPE_FILE);
        }
        public VFile(@NonNull Uri uri, boolean isDir) {
            this(uri, isDir ? TYPE_TREE_URI : TYPE_SINGLE_URI);
        }

        // File handling
        public boolean Rename(Context context, String newName) {
            if (this.type == TYPE_FILE) {
                File current = this.toFile();
                File newFile = new File(current.getParentFile(), newName);
                return current.renameTo(newFile);
            } else {
                DocumentFile df = toDocumentFile(context);
                return df != null && df.renameTo(newName);
            }
        }
        public boolean Delete(Context context) {
            DocumentFile df = toDocumentFile(context);
            return df != null && df.delete();
        }
        public Uri GetUri() {
            return this.uri;
        }

        // Information Check
        public boolean Exists(Context context) {
            if (this.type == TYPE_FILE) return this.toFile().exists();
            DocumentFile df = toDocumentFile(context);
            return df != null && df.exists();
        }
        public boolean IsDir(Context context) {
            if (this.type == TYPE_FILE) return this.toFile().isDirectory();
            DocumentFile df = toDocumentFile(context);
            return df != null && df.isDirectory();
        }
        public String GetName(Context context) {
            if (this.type == TYPE_FILE) return this.toFile().getName();
            DocumentFile df = toDocumentFile(context);
            return (df != null && df.getName() != null) ? df.getName() : "";
        }
        public long GetSize(Context context) {
            if (this.type == TYPE_FILE) return this.toFile().length();
            DocumentFile df = toDocumentFile(context);
            return df != null ? df.length() : 0;
        }
        public List<VFile> ListDir(Context context) {
            List<VFile> result = new ArrayList<>();

            // File type
            if (this.type == TYPE_FILE) {
                File myFile = this.toFile();
                if (myFile.isDirectory()) {
                    File[] children = myFile.listFiles();
                    if (children != null) {
                        for (File child : children) {
                            result.add(new VFile(child));
                        }
                    }
                }
                return result;
            }

            // Uri type
            DocumentFile df = toDocumentFile(context);
            if (df != null && df.isDirectory()) {
                for (DocumentFile child : df.listFiles()) {
                    result.add(new VFile(child.getUri(), child.isDirectory()));
                }
            }
            return result;
        }

        // Open Stream
        public InputStream OpenReader(Context context) throws IOException {
            if (this.type == TYPE_FILE) return new FileInputStream(this.toFile());
            return context.getContentResolver().openInputStream(this.uri);
        }
        public OutputStream OpenWriter(Context context, boolean isAppend) throws IOException {
            if (this.type == TYPE_FILE) return new FileOutputStream(this.toFile(), isAppend);
            return context.getContentResolver().openOutputStream(this.uri, isAppend ? "wa" : "w");
        }

        // Create new file/folder, for directory VFile
        public VFile CreateFile(Context context, String mimeType, String displayName) throws IOException {
            // File type
            if (this.type == TYPE_FILE) {
                File parent = this.toFile();
                if (parent.isDirectory()) {
                    File newFile = new File(parent, displayName);
                    if (newFile.createNewFile()) {
                        return new VFile(newFile);
                    }
                }
                return null;
            }

            // Uri type
            if (mimeType == null || mimeType.isEmpty()) {
                mimeType = "application/octet-stream";
            }
            DocumentFile df = toDocumentFile(context);
            if (df != null && df.isDirectory()) {
                DocumentFile newFile = df.createFile(mimeType, displayName);
                if (newFile != null) {
                    return new VFile(newFile.getUri(), false);
                }
            }
            return null;
        }
        public VFile CreateDir(Context context, String displayName) {
            // File type
            if (this.type == TYPE_FILE) {
                File parent = this.toFile();
                if (parent.isDirectory()) {
                    File newDir = new File(parent, displayName);
                    if (newDir.exists() || newDir.mkdir()) {
                        return new VFile(newDir);
                    }
                }
                return null;
            }

            // Uri type
            DocumentFile df = toDocumentFile(context);
            if (df != null && df.isDirectory()) {
                DocumentFile newDir = df.createDirectory(displayName);
                if (newDir != null) {
                    return new VFile(newDir.getUri(), true);
                }
            }
            return null;
        }

        // Parcelable for Intent send
        protected VFile(Parcel in) {
            Uri parsedUri = in.readParcelable(Uri.class.getClassLoader(), Uri.class);
            this.uri = Objects.requireNonNull(parsedUri, "Parcel.Uri is null");
            this.type = in.readInt();
        }
        public static final Creator<VFile> CREATOR = new Creator<VFile>() {
            @Override
            public VFile createFromParcel(Parcel in) {
                return new VFile(in);
            }
            @Override
            public VFile[] newArray(int size) {
                return new VFile[size];
            }
        };
        @Override
        public int describeContents() {
            return 0;
        }
        @Override
        public void writeToParcel(Parcel dest, int flags) {
            dest.writeParcelable(this.uri, flags);
            dest.writeInt(this.type);
        }
    }

    // launch User File Selection
    public static void SelectFile(ActivityResultLauncher<Intent> launcher, boolean multi) {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        if (multi) intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
        launcher.launch(intent);
    }

    // launch User Folder Selection
    public static void SelectFolder(ActivityResultLauncher<Intent> launcher) {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
        launcher.launch(intent);
    }

    // Get VFile list from User File Selection
    public static List<VFile> HandleSelectedFile(Intent data) {
        List<VFile> files = new ArrayList<>();
        if (data == null) return files;

        if (data.getClipData() != null) {
            int count = data.getClipData().getItemCount();
            for (int i = 0; i < count; i++) {
                files.add(new VFile(data.getClipData().getItemAt(i).getUri(), false));
            }
        } else if (data.getData() != null) {
            files.add(new VFile(data.getData(), false));
        }
        return files;
    }

    // Get VFile from User Folder Selection
    public static VFile HandleSelectedFolder(Intent data) {
        if (data != null && data.getData() != null) {
            return new VFile(data.getData(), true);
        }
        return null;
    }

    /**
     * Access to App Internal Storage
     * @param name File/Folder name, empty or null means root dir
     */
    public static VFile GetLocal(Context context, String name) {
        File baseDir = context.getFilesDir();
        if (name == null || name.isEmpty()) {
            return new VFile(baseDir);
        } else {
            return new VFile(new File(baseDir, name));
        }
    }

    /**
     * Make new file to Public Download
     * @param name name of file to be created
     */
    public static VFile CreateDownloadsFile(Context context, String name) {
        ContentValues values = new ContentValues();

        // auto set mimeType
        String mimeType = "";
        int dotpos = name.lastIndexOf('.');
        if (dotpos != -1 && dotpos != name.length() - 1) {
            String ext = name.substring(dotpos + 1).toLowerCase();
            mimeType = MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext);
        }
        if (mimeType == null || mimeType.isEmpty()) {
            mimeType = "application/octet-stream";
        }

        // setup parameters
        values.put(MediaStore.Downloads.DISPLAY_NAME, name);
        values.put(MediaStore.Downloads.MIME_TYPE, mimeType);
        values.put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS);

        // make new file uri
        Uri collection = MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY);
        Uri newUri = context.getContentResolver().insert(collection, values);
        return newUri != null ? new VFile(newUri, false) : null;
    }
}
