package com.example.kutil6_yas;

import android.content.Context;
import android.net.Uri;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

// YAS-aes for android
public class YASaes {
    public String msg;
    public String err;
    private EncryptUtil eu;
    private FileUtil io;
    private Context context;
    public YASaes(Context c) {
        this.context = c;
        this.io = new FileUtil(c);
        this.eu = new EncryptUtil(new BasicUtil(), this.io);
    }

    public void Encrypt(Uri[] targets, String[] names, String pw, String path, boolean isLocal) {
        this.err = "";
        try {
            InputStream[] files = new InputStream[targets.length];
            long[] sizes = new long[targets.length];
            for (int i = 0; i < targets.length; i++) {
                files[i] = this.context.getContentResolver().openInputStream(targets[i]);
                sizes[i] = this.io.GetFileSize(targets[i]);
            }
            OutputStream fout;
            if (isLocal) { fout = new FileOutputStream(this.io.GetLocalFile(path)); }
            else { fout = this.context.getContentResolver().openOutputStream(this.io.GetDownloadsFile(path)); }

            this.eu.Dozip(files, names, sizes);
            this.eu.Encrypt(msg, pw, fout);
            this.io.GetLocalFile("yas_temp").delete();
        } catch (Exception e) {
            this.err = e.getMessage();
        }
    }

    public void Encrypt(File[] targets, String[] names, String pw, String path, boolean isLocal) {
        this.err = "";
        try {
            InputStream[] files = new InputStream[targets.length];
            long[] sizes = new long[targets.length];
            for (int i = 0; i < targets.length; i++) {
                files[i] = new FileInputStream(targets[i]);
                sizes[i] = this.io.GetFileSize(targets[i]);
            }
            OutputStream fout;
            if (isLocal) { fout = new FileOutputStream(this.io.GetLocalFile(path)); }
            else { fout = this.context.getContentResolver().openOutputStream(this.io.GetDownloadsFile(path)); }

            this.eu.Dozip(files, names, sizes);
            this.eu.Encrypt(msg, pw, fout);
            this.io.GetLocalFile("yas_temp").delete();
        } catch (Exception e) {
            this.err = e.getMessage();
        }
    }

    public void Decrypt(String pw, Uri target, boolean isLocal) {
        this.err = "";
        try {
            InputStream fin = this.context.getContentResolver().openInputStream(target);
            this.eu.Decrypt(pw, fin, this.io.GetFileSize(target));
            this.eu.Unzip(isLocal);
            this.io.GetLocalFile("yas_temp").delete();
        } catch (Exception e) {
            this.err = e.getMessage();
        }
    }

    public void Decrypt(String pw, File target, boolean isLocal) {
        this.err = "";
        try {
            InputStream fin = new FileInputStream(target);
            this.eu.Decrypt(pw, fin, this.io.GetFileSize(target));
            this.eu.Unzip(isLocal);
            this.io.GetLocalFile("yas_temp").delete();
        } catch (Exception e) {
            this.err = e.getMessage();
        }
    }

    public void View(Uri target) {
        this.err = "";
        try {
            this.msg = this.eu.View(this.context.getContentResolver().openInputStream(target));
        } catch (Exception e) {
            this.err = e.getMessage();
        }
    }
}