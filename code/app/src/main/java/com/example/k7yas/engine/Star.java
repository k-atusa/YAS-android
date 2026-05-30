// test792d : USAG-Lib star
package com.example.k7yas.engine;

import java.io.*;
import java.nio.charset.StandardCharsets;

public class Star {
    private static byte[] tarHeader(String name, long size, int mode, char type) {
        byte[] h = new byte[512];
        if (size > 077777777777L) {
            size = 0;
        }

        // Name (0-100)
        writeStr(h, 0, name, 100);

        // Mode (100-108)
        writeOct(h, 100, mode, 8);

        // Size (124-136)
        writeOct(h, 124, size, 12);

        // MTime (136-148)
        writeOct(h, 136, System.currentTimeMillis() / 1000, 12);

        // Checksum (148-156) - Initially spaces
        for (int i = 148; i < 156; i++)
            h[i] = 32;

        // Typeflag (156)
        h[156] = (byte) type;

        // Magic (257) "ustar\0"
        writeStr(h, 257, "ustar", 6);

        // Version (263) "00"
        writeStr(h, 263, "00", 2);

        // Calculate Checksum
        long checksum = 0;
        for (byte b : h)
            checksum += (b & 0xFF); // unsigned sum
        String chkStr = String.format("%06o", checksum);
        System.arraycopy(chkStr.getBytes(StandardCharsets.UTF_8), 0, h, 148, 6);
        h[154] = 0;
        h[155] = 32;
        return h;
    }

    private static byte[] paxHeader(String name, long size) {
        String result = "";
        String[] keys = { "path", "size" };
        String[] vals = { name, String.valueOf(size) };

        for (int i = 0; i < 2; i++) {
            String key = keys[i];
            String val = vals[i];
            String lineData = " " + key + "=" + val + "\n";

            // Calculate length iteratively
            int len = lineData.getBytes(StandardCharsets.UTF_8).length + 1;
            int currentLen = len;
            while (true) {
                String fullLine = currentLen + lineData;
                int actualLen = fullLine.getBytes(StandardCharsets.UTF_8).length;
                if (actualLen == currentLen) {
                    result += fullLine;
                    break;
                }
                currentLen = actualLen;
            }
        }

        // Return Header + Data + Padding
        byte[] paxData = result.getBytes(StandardCharsets.UTF_8);
        byte[] header = tarHeader("PaxHeader/" + name, paxData.length, 0644, 'x');
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            baos.write(header);
            baos.write(paxData);
            baos.write(pad(paxData.length));
        } catch (IOException e) {
            /* impossible */ }
        return baos.toByteArray();
    }

    private static byte[] pad(long size) {
        int pad = (int) (512 - (size % 512));
        return new byte[pad % 512];
    }

    private static void writeStr(byte[] b, int off, String s, int len) {
        byte[] strBytes = s.getBytes(StandardCharsets.UTF_8);
        System.arraycopy(strBytes, 0, b, off, Math.min(strBytes.length, len));
    }

    private static void writeOct(byte[] b, int off, long v, int len) {
        String s = String.format("%0" + (len - 1) + "o", v); // octal format filled with 0s
        System.arraycopy(s.getBytes(StandardCharsets.UTF_8), 0, b, off, s.length());
    }

    private static String readStr(byte[] b, int off, int len) {
        return new String(b, off, len, StandardCharsets.UTF_8);
    }

    private static long readOct(byte[] b, int off, int len) {
        String s = new String(b, off, len, StandardCharsets.UTF_8).trim().replace("\0", "");
        return s.isEmpty() ? 0 : Long.parseLong(s, 8);
    }

    private static void copy(InputStream in, OutputStream out, long size) throws IOException {
        byte[] buf = new byte[65536];
        int len;
        long total = 0;
        while (total < size && (len = in.read(buf, 0, (int) Math.min(buf.length, size - total))) != -1) {
            out.write(buf, 0, len);
            total += len;
        }
    }

    public static class TarWriter implements Closeable {
        private OutputStream out = null;

        public void Open(OutputStream out) {
            if (out == null) { // memory stream
                this.out = new ByteArrayOutputStream();
            } else {
                this.out = out;
            }
        }

        public void Write(String name, byte[] data, int mode) throws IOException {
            Write(name, new ByteArrayInputStream(data), data.length, mode, false);
        }

        public void Write(String name, File data, int mode) throws IOException {
            try (FileInputStream fis = new FileInputStream(data)) {
                Write(name, fis, data.length(), mode, false);
            }
        }

        public void Write(String name, InputStream data, long size, int mode, boolean isDir) throws IOException {
            if (isDir) {
                name = name.replace('\\', '/');
                if (!name.endsWith("/"))
                    name += "/";
            }
            if (name.getBytes(StandardCharsets.UTF_8).length > 99 || size > 077777777777L) { // needs PAX
                byte[] pax = paxHeader(name, size);
                this.out.write(pax);
            }
            this.out.write(tarHeader(name, size, mode, isDir ? '5' : '0'));
            if (!isDir) {
                copy(data, this.out, size);
                this.out.write(pad(size));
            }
        }

        public byte[] Close() throws IOException {
            byte[] result = null;
            if (this.out != null) {
                this.out.write(new byte[1024]); // Two 512-byte blocks of zeros
                this.out.close();
                if (this.out instanceof ByteArrayOutputStream) {
                    result = ((ByteArrayOutputStream) this.out).toByteArray();
                }
                this.out = null;
            }
            return result;
        }

        @Override
        public void close() throws IOException {
            Close();
        }
    }

    public static class TarReader implements Closeable {
        private InputStream in = null;
        private boolean isEOF = false;

        public String Name = "";
        public long Size = 0;
        public int Mode = 0644;
        public boolean IsDir = false;

        public void Open(InputStream in) {
            this.in = in;
            this.isEOF = false;
            this.Name = "";
            this.Size = 0;
            this.Mode = 0644;
            this.IsDir = false;
        }

        private void parse(byte[] pax) {
            String data = new String(pax, StandardCharsets.UTF_8);
            String[] lines = data.split("\n");
            for (String line : lines) {
                int spaceIdx = line.indexOf(' ');
                if (spaceIdx == -1)
                    continue;
                int eqIdx = line.indexOf('=');
                if (eqIdx == -1)
                    continue;

                String key = line.substring(spaceIdx + 1, eqIdx);
                String value = line.substring(eqIdx + 1);
                if (key.equals("path"))
                    this.Name = value;
                else if (key.equals("size"))
                    this.Size = Long.parseLong(value);
            }
        }

        public boolean Next() throws IOException {
            if (this.isEOF)
                return false;
            byte[] header = this.in.readNBytes(512);
            if (header.length != 512) {
                this.isEOF = true;
                return false;
            }
            boolean isZero = true; // EOF check
            for (byte b : header) {
                if (b != 0) {
                    isZero = false;
                    break;
                }
            }
            if (isZero) {
                this.isEOF = true;
                return false;
            }

            // Parse Standard Header
            this.Name = readStr(header, 0, 100).replace("\0", "");
            this.Mode = (int) readOct(header, 100, 8);
            this.Size = readOct(header, 124, 12);
            char type = (char) header[156];
            this.IsDir = (type == '5');

            // Parse PAX
            if (type == 'x') {
                byte[] paxData = this.in.readNBytes((int) this.Size);
                unpad(this.Size);

                boolean hasNext = Next();
                if (hasNext) {
                    parse(paxData);
                }
                return hasNext;
            }
            return true;
        }

        public byte[] Read() throws IOException {
            if (this.Size > Integer.MAX_VALUE)
                throw new IOException("File too large for byte array");
            byte[] data = new byte[(int) this.Size];
            int total = 0;
            while (total < this.Size) {
                int r = this.in.read(data, total, (int) (this.Size - total));
                if (r == -1)
                    break;
                total += r;
            }
            unpad(this.Size);
            return data;
        }

        public void Mkfile(OutputStream dst) throws IOException {
            if (this.IsDir)
                return;
            copy(this.in, dst, this.Size);
            unpad(this.Size);
        }

        public void Skip() throws IOException {
            byte[] buffer = new byte[65536];
            long total = 0;
            while (total < this.Size) {
                int toRead = (int) Math.min(buffer.length, this.Size - total);
                int r = this.in.read(buffer, 0, toRead);
                if (r == -1)
                    break;
                total += r;
            }
            unpad(this.Size);
        }

        private void unpad(long size) throws IOException {
            long pad = ((512 - (size % 512)) % 512);
            if (pad > 0) {
                this.in.readNBytes((int) pad);
            }
        }

        @Override
        public void close() throws IOException {
            if (this.in != null) {
                this.in.close();
                this.in = null;
            }
        }
    }
}