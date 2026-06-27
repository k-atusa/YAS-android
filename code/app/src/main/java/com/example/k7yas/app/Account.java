package com.example.k7yas.app;

import android.content.Context;

import com.example.k7yas.engine.Bencrypt;
import com.example.k7yas.engine.Icons;
import com.example.k7yas.engine.Opsec;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Account implements Serializable {
    private static volatile Object DUMMY;

    public static void sclear(byte[] data) {
        java.util.Arrays.fill(data, (byte) 0);
        DUMMY = data;
    }

    public static void ClearDummy() {
        DUMMY = null;
    }

    // singleton generation
    private static volatile Account instance;
    public static Account GetAccount(Context c) {
        if (instance == null) {
            synchronized (Account.class) {
                if (instance == null) {
                    instance = new Account(c.getApplicationContext());
                }
            }
        }
        return instance;
    }

    // Settings
    public String PackType;
    public String ImgType;

    // Account Data
    public String KeyType;
    public byte[] PubKey;
    public byte[] PriKey; // masked
    public Map<String, byte[]> KeyFiles; // masked
    public Map<String, byte[]> PubKeys;

    // User Data
    public String Msg;
    private byte[] password; // masked
    private final Bencrypt.Masker mask = Bencrypt.Masker.GetMasker();
    private Context context;

    private Account(Context c) {
        this.context = c;

        // set basic values
        this.PackType = "zip1";
        this.ImgType = "webp";
        this.KeyType = SvcYas.METHOD_ASYM;
        this.PubKey = new byte[0];
        this.PriKey = new byte[0];
        this.KeyFiles = new HashMap<>();
        this.PubKeys = new HashMap<>();
        this.password = new byte[0];
        this.Msg = "No Account Registered";

        // load or make settings.txt
        IO1.VFile settingsFile = IO1.GetLocal(context, "settings.txt");
        if (settingsFile.Exists(context)) {
            try (InputStream is = settingsFile.OpenReader(context)) {
                byte[] data = is.readAllBytes();
                String content = new String(data, StandardCharsets.UTF_8);
                String[] parts = content.split("\n");
                if (parts.length >= 2) {
                    this.PackType = parts[0].trim();
                    this.ImgType = parts[1].trim();
                }
            } catch (Exception e) {
                this.Msg = "Error with settings.txt: " + e.toString();
            }
        } else {
            Store(this.PackType, this.ImgType); // make new with default values
        }

        // check if account.webp exists
        IO1.VFile accountFile = IO1.GetLocal(context, "account.webp");
        if (accountFile.Exists(context)) {
            try (InputStream ins = accountFile.OpenReader(context)) {
                Opsec ops = new Opsec();
                byte[] header = ops.Read(ins, 0);
                if (header != null && header.length > 0) {
                    ops.View(header);
                    this.Msg = ops.Msg;
                }
            } catch (Exception e) {
                this.Msg = "Error with account.webp: " + e.toString();
            }
        }
    }

    // Get sorted name list from account
    public String[] GetList(boolean isKF) {
        Map<String, byte[]> targetMap = isKF ? KeyFiles : PubKeys;
        List<String> list = new ArrayList<>(targetMap.keySet());
        Collections.sort(list);
        return list.toArray(new String[0]);
    }

    // Add data to account
    public void AddList(boolean isKF, String name, byte[] data) throws Exception {
        if (isKF) {
            byte[] unmasked = mask.XOR(data); // KF data is already masked
            String key = String.format("%s (%dB, %s)K", name, data.length, Opsec.Crc32(unmasked));
            sclear(unmasked);
            KeyFiles.put(key, data.clone());
        } else {
            String key = String.format("%s (%s, %s)P", name, this.KeyType, Opsec.Crc32(data));
            PubKeys.put(key, data.clone());
        }
        Store();
    }

    // Delete item from account
    public void DelList(boolean isKF, String name) throws Exception {
        if (isKF) {
            KeyFiles.remove(name);
        } else {
            PubKeys.remove(name);
        }
        Store();
    }

    // Load account.webp
    public void Load(byte[] password) throws Exception {
        IO1.VFile accountFile = IO1.GetLocal(context, "account.webp");
        if (!accountFile.Exists(context)) throw new Exception("account.webp not exists");

        // read opsec header
        try (InputStream ins = accountFile.OpenReader(context)) {
            Opsec ops = new Opsec();
            byte[] header = ops.Read(ins, 0);
            if (header == null || header.length == 0) throw new Exception("invalid Opsec format");
            ops.View(header);
            this.Msg = ops.Msg;

            // decrypt header, save password
            ops.Decpw(password, null);
            if (this.password != null) sclear(this.password);
            this.password = mask.XOR(password);

            // restore smsginfo map
            Map<String, byte[]> smsgInfoMap = ops.DecodeCfg(ops.SmsgInfo);
            if (smsgInfoMap.containsKey("keytype")) {
                this.KeyType = new String(smsgInfoMap.get("keytype"), StandardCharsets.UTF_8);
            }
            if (smsgInfoMap.containsKey("public")) {
                this.PubKey = smsgInfoMap.get("public").clone();
            }
            if (smsgInfoMap.containsKey("private")) {
                byte[] rawPriv = smsgInfoMap.get("private");
                if (this.PriKey != null) sclear(this.PriKey);
                this.PriKey = mask.XOR(rawPriv);
                sclear(rawPriv);
            }
            for (byte[] val : smsgInfoMap.values()) sclear(val);

            // decrypt body data
            byte[] encBody = ins.readNBytes((int) ops.BodySize);
            Bencrypt.SymMaster sm = new Bencrypt.SymMaster(ops.BodyAlgo, ops.BodyKey);
            sclear(ops.BodyKey);
            byte[] plainBody = sm.DeBin(encBody);
            this.KeyFiles = new HashMap<>();
            this.PubKeys = new HashMap<>();
            Map<String, byte[]> bodyCfg = ops.DecodeCfg(plainBody);
            sclear(plainBody);

            // load keyfiles and pubkeys
            for (Map.Entry<String, byte[]> entry : bodyCfg.entrySet()) {
                String name = entry.getKey();
                byte[] data = entry.getValue();
                if (name.endsWith("P")) {
                    this.PubKeys.put(name, data.clone()); // public key
                } else {
                    byte[] maskedKf = mask.XOR(data);
                    this.KeyFiles.put(name, maskedKf); // keyfile
                }
                sclear(data);
            }
        }
    }

    // Store account to account.webp
    public void Store() throws Exception {
        Opsec ops = new Opsec();

        // 1. make smsginfo map
        byte[] priv = mask.XOR(this.PriKey);
        Map<String, byte[]> innerCfgMap = new HashMap<>();
        innerCfgMap.put("keytype", this.KeyType.getBytes(StandardCharsets.UTF_8));
        innerCfgMap.put("public", this.PubKey.clone());
        innerCfgMap.put("private", priv);

        byte[] smsgInfoBytes = ops.EncodeCfg(innerCfgMap);
        sclear(priv);
        for (byte[] val : innerCfgMap.values()) sclear(val);

        // 2. make body data map
        Map<String, byte[]> bodyCfgMap = new HashMap<>();
        for (Map.Entry<String, byte[]> entry : this.KeyFiles.entrySet()) {
            byte[] unmaskedKf = mask.XOR(entry.getValue());
            bodyCfgMap.put(entry.getKey(), unmaskedKf);
        }
        for (Map.Entry<String, byte[]> entry : this.PubKeys.entrySet()) {
            bodyCfgMap.put(entry.getKey(), entry.getValue().clone());
        }

        byte[] plainBody = ops.EncodeCfg(bodyCfgMap);
        for (byte[] val : bodyCfgMap.values()) sclear(val);
        Bencrypt.SymMaster sm = new Bencrypt.SymMaster(SvcYas.METHOD_SYM_I, new byte[32]);
        long bodySizeAfter = sm.AfterSize(plainBody.length);

        // 3. set opsec format
        ops.Msg = this.Msg;
        ops.SmsgInfo = smsgInfoBytes;
        ops.BodySize = bodySizeAfter;
        ops.BodyAlgo = SvcYas.METHOD_SYM_I;

        byte[] unmaskedPw = mask.XOR(this.password);
        byte[] header = ops.Encpw(SvcYas.METHOD_HASH, unmaskedPw, null);
        sclear(unmaskedPw);

        sm = new Bencrypt.SymMaster(SvcYas.METHOD_SYM_I, ops.BodyKey);
        sclear(ops.BodyKey);
        IO1.VFile accountFile = IO1.GetLocal(context, "account.webp");
        long totalWrited = 0;

        try (OutputStream outs = accountFile.OpenWriter(context, false)) {
            // add webp image at front
            byte[] prehead = Icons.ZipWebp.clone();
            int alignmentPadding = (128 - (prehead.length % 128)) % 128;
            if (alignmentPadding > 0) {
                byte[] balancedPrehead = new byte[prehead.length + alignmentPadding];
                System.arraycopy(prehead, 0, balancedPrehead, 0, prehead.length);
                prehead = balancedPrehead;
            }
            outs.write(prehead);
            totalWrited += prehead.length;

            // write opsec header
            ops.Write(outs, header);
            long headerLenBytes = 4 + 2 + header.length;
            if (header.length >= 65535) {
                headerLenBytes += 2;
            }
            totalWrited += headerLenBytes;

            // write encrypted body
            byte[] encBody = sm.EnBin(plainBody);
            outs.write(encBody);
            totalWrited += encBody.length;
            sclear(plainBody);

            // add padding
            long padLen = Opsec.PadLen(totalWrited);
            if (padLen > 0) {
                Opsec.PadFile(outs, padLen);
            }
        }
    }

    // Store account.webp with updated user data
    public void Store(String msg, byte[] password) throws Exception {
        this.Msg = msg;
        if (this.password != null) sclear(this.password);
        this.password = mask.XOR(password);
        Store();
    }

    // Store settings data to settings.txt
    public void Store(String pack, String img) {
        this.PackType = pack;
        this.ImgType = img;
        IO1.VFile settingsFile = IO1.GetLocal(context, "settings.txt");
        try (OutputStream os = settingsFile.OpenWriter(context, false)) {
            String content = String.format("%s\n%s", pack, img);
            os.write(content.getBytes(StandardCharsets.UTF_8));
        } catch (Exception ignored) {}
    }
}
