package com.example.kutil6_yas;

import android.content.Context;
import android.net.Uri;

import androidx.documentfile.provider.DocumentFile;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

// zip & unzip data
public class ZipUtil {
    private InputStream fin;
    private OutputStream fout;
    private ZipInputStream zin;
    private ZipOutputStream zout;
    private FileUtil io;
    private Context context;
    public ZipUtil(FileUtil f, Context c) {
        this.io = f;
        this.context = c;
    }

    public void OpenZip(String name, boolean isLocal, boolean isRead) throws Exception {
        if (isRead) {
            if (isLocal) { this.fin = new FileInputStream( this.io.GetLocalFile(name) ); }
            else { this.fin = this.context.getContentResolver().openInputStream( this.io.GetDownloadsFile(name) ); }
            this.zin = new ZipInputStream(this.fin);
        } else {
            if (isLocal) { this.fout = new FileOutputStream( this.io.GetLocalFile(name) ); }
            else { this.fout = this.context.getContentResolver().openOutputStream( this.io.GetDownloadsFile(name) ); }
            this.zout = new ZipOutputStream(this.fout);
        }
    }

    public void CloseZip() throws Exception {
        if (this.zin != null) {
            this.zin.close();
            this.zin = null;
        }
        if (this.zout != null) {
            this.zout.close();
            this.zout = null;
        }
        if (this.fin != null) {
            this.fin.close();
            this.fin = null;
        }
        if (this.fout != null) {
            this.fout.close();
            this.fout = null;
        }
    }

    public void AddZip(Uri uri) throws Exception {
        DocumentFile doc;
        try { doc = DocumentFile.fromTreeUri(this.context, uri); }
        catch (Exception e) { doc = DocumentFile.fromSingleUri(this.context, uri); }
        this.AddZip(doc, "");
    }

    public void AddZip(DocumentFile doc, String basePath) throws Exception {
        String name = basePath.isEmpty() ? doc.getName() : basePath + "/" + doc.getName();

        if (doc.isDirectory()) {
            ZipEntry dirEntry = new ZipEntry(name + "/");
            this.zout.putNextEntry(dirEntry);
            this.zout.closeEntry();
            for (DocumentFile file : doc.listFiles()) { this.AddZip(file, name); }

        } else if (doc.isFile()) {
            InputStream f = this.context.getContentResolver().openInputStream(doc.getUri());
            ZipEntry fileEntry = new ZipEntry(name);
            this.zout.putNextEntry(fileEntry);
            byte[] buffer = new byte[4096];
            int len;
            while ((len = f.read(buffer)) != -1) {
                this.zout.write(buffer, 0, len);
            }
            this.zout.closeEntry();
            f.close();

        } else {
            throw new Exception("invalid file : " + name);
        }
    }

    public boolean UnZip() throws Exception {
        boolean dirFlag = false;
        ZipEntry entry;
        byte[] buffer = new byte[4096];
        entry = this.zin.getNextEntry();

        while (entry != null) {
            if (entry.isDirectory()) {
                dirFlag = true;
                break;
            }
            String name = entry.getName();
            OutputStream f = this.context.getContentResolver().openOutputStream( this.io.GetDownloadsFile(name) );
            int len;
            while ((len = this.zin.read(buffer)) != -1) { f.write(buffer, 0, len); }
            f.close();
            this.zin.closeEntry();
            entry = this.zin.getNextEntry();
        }
        return dirFlag;
    }

    public void CopyZip(String src, String dst) throws Exception {
        File f = this.io.GetLocalFile(src);
        Uri t = this.io.GetDownloadsFile(dst);
        InputStream fin = new FileInputStream(f);
        OutputStream fout = this.context.getContentResolver().openOutputStream(t);
        byte[] buffer = new byte[4096];
        int len;
        while ((len = fin.read(buffer)) != -1) { fout.write(buffer, 0, len); }
        fin.close();
        fout.close();
    }
}