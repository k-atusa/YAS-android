package com.example.kutil6_yas;

import android.content.Context;
import android.net.Uri;
import android.os.Bundle;
import android.os.Message;
import android.os.Messenger;

import androidx.documentfile.provider.DocumentFile;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Collections;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class SubActivity {
    private IOmanager ioManager;
    private Context context;
    private Messenger logger;

    private InputStream fin;
    private OutputStream fout;
    private ZipInputStream zin;
    private ZipOutputStream zout;

    private ServerSocket svrSocket;
    private Socket cliSocket;
    public InputStream sin;
    public OutputStream sout;

    public SubActivity(IOmanager i, Context c, Messenger m) {
        this.ioManager = i;
        this.context = c;
        this.logger = m;
    }

    private void addLog(String msg) throws Exception {
        Message doneMsg = Message.obtain(null, 21);
        Bundle data = new Bundle();
        data.putString("string", msg);
        doneMsg.setData(data);
        this.logger.send(doneMsg);
    }

    public void OpenZip(String name, boolean isLocal, boolean isRead) throws Exception {
        if (isRead) {
            if (isLocal) { this.fin = new FileInputStream( this.ioManager.GetLocalFile(name) ); }
            else { this.fin = this.context.getContentResolver().openInputStream( this.ioManager.GetDownloadsFile(name) ); }
            this.zin = new ZipInputStream(this.fin);
        } else {
            if (isLocal) { this.fout = new FileOutputStream( this.ioManager.GetLocalFile(name) ); }
            else { this.fout = this.context.getContentResolver().openOutputStream( this.ioManager.GetDownloadsFile(name) ); }
            this.zout = new ZipOutputStream(this.fout);
        }
        this.addLog("zip file opened");
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
        this.addLog("zip file closed");
    }

    public void AddZip(Uri uri) throws Exception {
        DocumentFile doc;
        try { doc = DocumentFile.fromTreeUri(this.context, uri); }
        catch (Exception e) { doc = DocumentFile.fromSingleUri(this.context, uri); }
        this.AddZip(doc, "");
    }

    public void AddZip(DocumentFile doc, String basePath) throws Exception {
        String name = basePath.isEmpty() ? doc.getName() : basePath + "/" + doc.getName();
        this.addLog("adding to zip : " + name);

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
                addLog("extracting from zip : /");
                dirFlag = true;
                break;
            }
            String name = entry.getName();
            addLog("extracting from zip : " + name);
            OutputStream f = this.context.getContentResolver().openOutputStream( this.ioManager.GetDownloadsFile(name) );
            int len;
            while ((len = this.zin.read(buffer)) != -1) { f.write(buffer, 0, len); }
            f.close();
            this.zin.closeEntry();
            entry = this.zin.getNextEntry();
        }
        return dirFlag;
    }

    public void CopyZip(String src, String dst) throws Exception {
        addLog("copying zip : " + src + " -> " + dst);
        File f = this.ioManager.GetLocalFile(src);
        Uri t = this.ioManager.GetDownloadsFile(dst);
        InputStream fin = new FileInputStream(f);
        OutputStream fout = this.context.getContentResolver().openOutputStream(t);
        byte[] buffer = new byte[4096];
        int len;
        while ((len = fin.read(buffer)) != -1) { fout.write(buffer, 0, len); }
        fin.close();
        fout.close();
    }

    public void PrintIP(int port) throws Exception {
        List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
        for (NetworkInterface networkInterface : interfaces) {
            List<InetAddress> addresses = Collections.list(networkInterface.getInetAddresses());
            for (InetAddress address : addresses) {
                if (!address.isLoopbackAddress() && address.getHostAddress().contains(".")) {
                    addLog( String.format("IP %s:%d", address.getHostAddress(), port) );
                }
            }
        }
    }

    public void OpenSocket(boolean isServer, String ip, int port) throws Exception {
        if (isServer) {
            this.svrSocket = new ServerSocket(port);
            this.cliSocket = this.svrSocket.accept();
        } else {
            this.cliSocket = new Socket(ip, port);
        }
        this.sin = new BufferedInputStream( this.cliSocket.getInputStream() );
        this.sout = new BufferedOutputStream( this.cliSocket.getOutputStream() );
        this.addLog("socket opened");
    }

    public void CloseSocket() throws Exception {
        if (this.sin != null) {
            this.sin.close();
            this.sin = null;
        }
        if (this.sout != null) {
            this.sout.close();
            this.sout = null;
        }
        if (this.cliSocket != null) {
            this.cliSocket.close();
            this.cliSocket = null;
        }
        if (this.svrSocket != null) {
            this.svrSocket.close();
            this.svrSocket = null;
        }
        this.addLog("socket closed");
    }

    public byte[] Encode(long num) {
        byte[] res = new byte[8];
        for (int i = 0; i < 8; i++) {
            res[i] = (byte) (num % 256);
            num /= 256;
        }
        return res;
    }

    public long Decode(byte[] data) {
        long res = 0;
        for (int i = 7; i >= 0; i--) {
            res = res * 256 + (data[i] & 0xFF);
        }
        return res;
    }
}