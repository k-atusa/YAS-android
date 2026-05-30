// test789d : USAG-Lib bencode
package com.example.k7yas.engine;

import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Set;
import java.util.regex.Pattern;

public class Bencode {
    private static final Set<String> SPLITABLE = new HashSet<>(Arrays.asList(
            "!", "@", "#", "$", "%", "^", "&", "*", "~", "|"));

    public static String Encode64(byte[] data, String spliter, int linenum, int colnum) {
        if (linenum <= 0) {
            linenum = 40;
        }
        if (colnum <= 0) {
            colnum = 10;
        }
        String raw = "";
        if (data != null && data.length > 0) {
            raw = Base64.getEncoder().encodeToString(data);
        }

        // check spliter
        if (spliter == null || spliter.isEmpty()) {
            return raw;
        }
        if (!SPLITABLE.contains(spliter)) {
            throw new IllegalArgumentException("invalid spliter option");
        }

        // split text
        List<String> lines = new ArrayList<>();
        for (int i = 0; i < raw.length(); i += linenum) {
            lines.add(raw.substring(i, Math.min(i + linenum, raw.length())));
        }
        List<List<String>> cols = new ArrayList<>();
        for (int i = 0; i < lines.size(); i += colnum) {
            cols.add(lines.subList(i, Math.min(i + colnum, lines.size())));
        }

        // assemble text
        StringBuilder sb = new StringBuilder();
        sb.append(spliter).append("START").append(spliter).append("\n");

        int totalCols = cols.size();
        for (int i = 0; i < totalCols; i++) {
            sb.append(spliter).append(i + 1).append("/").append(totalCols).append(spliter).append("\n");
            List<String> col = cols.get(i);
            for (int j = 0; j < col.size(); j++) {
                sb.append(col.get(j));
                if (j < col.size() - 1) {
                    sb.append("\n");
                }
            }
            sb.append("\n");
        }
        sb.append(spliter).append("END").append(spliter);

        return sb.toString();
    }

    public static byte[] Decode64(String data, String spliter) {
        data = data.replace("\r", "").replace("\n", "").replace(" ", "").replace("\t", "");
        if (spliter != null && !spliter.isEmpty() && !SPLITABLE.contains(spliter)) {
            throw new IllegalArgumentException("invalid spliter option");
        }

        // remove comments
        if (spliter != null && !spliter.isEmpty()) {
            String[] parts = data.split(Pattern.quote(spliter), -1);
            StringBuilder pureData = new StringBuilder();
            for (int i = 0; i < parts.length; i += 2) {
                pureData.append(parts[i]);
            }
            data = pureData.toString();
        }

        // decode
        if (data.isEmpty()) {
            return new byte[0];
        }
        return Base64.getDecoder().decode(data);
    }

    public static byte[] NormPW(String pw) {
        if (pw == null || pw.isEmpty()) {
            return new byte[0];
        }
        return Normalizer.normalize(pw, Normalizer.Form.NFC).getBytes(StandardCharsets.UTF_8);
    }
}