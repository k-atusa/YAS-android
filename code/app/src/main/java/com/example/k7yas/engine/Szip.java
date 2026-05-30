// test790d : USAG-Lib szip
package com.example.k7yas.engine;

import java.io.*;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.*;

public class Szip {
    private static void copyStream(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[65536];
        int len;
        while ((len = in.read(buffer)) != -1) {
            out.write(buffer, 0, len);
        }
    }

    public static class ZipWriter implements Closeable {
        public File tempDir = null;

        private OutputStream writer = null; // Raw stream to write header
        private boolean isMem = false; // Whether writer is memory-based
        private ZipOutputStream zout = null;
        private boolean compress = false;

        public void Open(File file, boolean compress) throws IOException {
            if (file == null) {
                this.writer = new ByteArrayOutputStream();
                this.isMem = true;
            } else {
                this.writer = new FileOutputStream(file);
                this.isMem = false;
            }

            // Initialize ZipOutputStream
            this.zout = new ZipOutputStream(this.writer);
            this.compress = compress;
            if (compress) {
                this.zout.setMethod(ZipOutputStream.DEFLATED);
                this.zout.setLevel(Deflater.BEST_COMPRESSION);
            } else {
                this.zout.setMethod(ZipOutputStream.STORED);
            }
        }

        public void Write(String name, byte[] data) throws IOException {
            ZipEntry entry = new ZipEntry(name);
            if (!this.compress) {
                entry.setSize(data.length);
                entry.setCompressedSize(data.length);
                CRC32 crc = new CRC32();
                crc.update(data);
                entry.setCrc(crc.getValue());
            }
            this.zout.putNextEntry(entry);
            this.zout.write(data);
            this.zout.closeEntry();
        }

        public void Write(String name, File file) throws IOException {
            try (FileInputStream fis = new FileInputStream(file)) {
                Write(name, fis);
            }
        }

        public void Write(String name, InputStream inputStream) throws IOException {
            ZipEntry entry = new ZipEntry(name);

            if (!this.compress) { // STORED mode requires pre-calculated CRC and Size
                File temp = File.createTempFile("szip_write", ".tmp", this.tempDir);
                try {
                    CRC32 crc = new CRC32();
                    long size = 0;
                    try (FileOutputStream fos = new FileOutputStream(temp)) {
                        byte[] buffer = new byte[65536];
                        int len;
                        while ((len = inputStream.read(buffer)) != -1) {
                            fos.write(buffer, 0, len);
                            crc.update(buffer, 0, len);
                            size += len;
                        }
                    }

                    entry.setSize(size);
                    entry.setCompressedSize(size);
                    entry.setCrc(crc.getValue());
                    this.zout.putNextEntry(entry);
                    try (FileInputStream fis = new FileInputStream(temp)) {
                        copyStream(fis, this.zout);
                    }
                } finally {
                    temp.delete();
                }

            } else { // DEFLATED mode handles size/crc automatically
                this.zout.putNextEntry(entry);
                copyStream(inputStream, this.zout);
            }
            this.zout.closeEntry();
        }

        public byte[] Close() throws IOException {
            byte[] result = null;
            if (this.zout != null) {
                this.zout.close();
                this.zout = null;
            }
            if (this.writer != null) {
                if (this.isMem) {
                    result = ((ByteArrayOutputStream) this.writer).toByteArray();
                }
                this.writer.close();
                this.writer = null;
            }
            return result;
        }

        @Override
        public void close() throws IOException {
            Close();
        }
    }

    public static class ZipReader implements Closeable {
        private File reader = null;
        private ZipFile zin = null;
        private List<ZipEntry> entries = new ArrayList<>();
        public List<String> Names = new ArrayList<>();
        public List<Long> Sizes = new ArrayList<>();

        public File tempDir = null;

        public void Open(File file) throws IOException {
            loadZip(file);
        }

        public void Open(byte[] data) throws IOException {
            this.reader = File.createTempFile("szip_read", ".tmp", this.tempDir);
            this.reader.deleteOnExit();
            try (FileOutputStream fos = new FileOutputStream(this.reader)) {
                fos.write(data);
            }
            loadZip(this.reader);
        }

        private void loadZip(File file) throws IOException {
            this.zin = new ZipFile(file, ZipFile.OPEN_READ);
            this.entries.clear();
            this.Names.clear();
            this.Sizes.clear();

            Enumeration<? extends ZipEntry> entries = this.zin.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                this.entries.add(entry);
                this.Names.add(entry.getName());
                this.Sizes.add(entry.getSize());
            }
        }

        public InputStream Open(int idx) throws IOException {
            return this.zin.getInputStream(this.entries.get(idx));
        }

        public byte[] Read(int idx) throws IOException {
            ZipEntry entry = this.entries.get(idx);
            long size = entry.getSize();
            if (size > Integer.MAX_VALUE) {
                throw new IOException("File too large to read into memory array");
            }
            try (InputStream is = this.zin.getInputStream(entry);
                    ByteArrayOutputStream bos = new ByteArrayOutputStream((int) size)) {
                copyStream(is, bos);
                return bos.toByteArray();
            }
        }

        @Override
        public void close() throws IOException {
            if (this.zin != null) {
                this.zin.close();
                this.zin = null;
            }
            if (this.reader != null && this.reader.exists()) {
                this.reader.delete();
                this.reader = null;
            }
            this.Names.clear();
            this.Sizes.clear();
            this.entries.clear();
        }
    }
}