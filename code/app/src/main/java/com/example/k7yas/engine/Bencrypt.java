// test793d : USAG-Lib bencrypt
package com.example.k7yas.engine;

import com.lambdapioneer.argon2kt.Argon2Kt;
import com.lambdapioneer.argon2kt.Argon2KtResult;
import com.lambdapioneer.argon2kt.Argon2Mode;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedList;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicLong;
import java.util.Arrays;

import java.security.SecureRandom;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.generators.X448KeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
import org.bouncycastle.crypto.params.X448KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed448KeyGenerationParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.X448Agreement;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.crypto.SecretWithEncapsulation;

import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

public class Bencrypt {
    private static volatile Object DUMMY;

    private static void sclear(byte[] data) {
        java.util.Arrays.fill(data, (byte) 0);
        DUMMY = data;
    }

    public static void ClearDummy() {
        DUMMY = null;
    }

    // ========== Helpers ==========
    private static byte[] mkiv(byte[] g, long c) {
        byte[] iv = Arrays.copyOf(g, 12); // base IV 12B
        byte[] counterBytes = ByteBuffer.allocate(8) // counter 8B little endian
                .order(ByteOrder.LITTLE_ENDIAN)
                .putLong(c)
                .array();
        for (int i = 0; i < 8; i++) {
            iv[4 + i] ^= counterBytes[i]; // XOR
        }
        return iv;
    }

    private static byte[] decodeB64(String src) {
        String padded = src;
        int pad = src.length() % 4;
        if (pad > 0) {
            for (int i = 0; i < 4 - pad; i++)
                padded += "=";
        }
        return Base64.getDecoder().decode(padded);
    }

    // HMAC-SHA3-512
    public static byte[] genkey(byte[] data, String lbl, int size) {
        HMac hmac = new HMac(new SHA3Digest(512));
        byte[] key = lbl.getBytes(StandardCharsets.UTF_8);
        hmac.init(new KeyParameter(data)); // Key is data
        hmac.update(key, 0, key.length); // Message is label
        byte[] result = new byte[hmac.getMacSize()];
        hmac.doFinal(result, 0);
        if (size > result.length) {
            throw new IllegalArgumentException("key size too large");
        }
        return Arrays.copyOf(result, size);
    }

    // ========== Basic Functions ==========
    private final SecureRandom randSrc = new SecureRandom();

    public byte[] Random(int size) {
        byte[] bytes = new byte[size];
        this.randSrc.nextBytes(bytes);
        return bytes;
    }

    public static byte[] SHA3256(byte[] data) {
        SHA3Digest digest = new SHA3Digest(256);
        byte[] result = new byte[digest.getDigestSize()];
        digest.update(data, 0, data.length);
        digest.doFinal(result, 0);
        return result;
    }

    public static byte[] SHA3512(byte[] data) {
        SHA3Digest digest = new SHA3Digest(512);
        byte[] result = new byte[digest.getDigestSize()];
        digest.update(data, 0, data.length);
        digest.doFinal(result, 0);
        return result;
    }

    // ========== Data Masker ==========
    public static class Masker {
        private static volatile Masker instance = null; // singleton
        private static final int[] PRIME_CANDIDATES = {
                15485863, 32452843, 86028121, 104395301,
                179424673, 228017633, 236887691, 345098717,
                413158511, 481230491, 563117203, 693240851,
                715225741, 812349821, 882046271, 999999937
        };
        private int poolSize;
        private byte[] pool;
        private int prime;

        private Masker(int poolSizeMb) {
            this.poolSize = poolSizeMb * 1024 * 1024;
            Bencrypt rg = new Bencrypt();
            this.pool = rg.Random(this.poolSize);
            byte[] randByte = rg.Random(1);
            int randomIndex = Byte.toUnsignedInt(randByte[0]) % 16;
            this.prime = PRIME_CANDIDATES[randomIndex];
        }

        public static Masker GetMasker(int poolSizeMb) {
            if (instance == null) {
                synchronized (Masker.class) {
                    if (instance == null) {
                        instance = new Masker(poolSizeMb);
                    }
                }
            }
            return instance;
        }

        public static Masker GetMasker() {
            return GetMasker(8);
        }

        public byte[] XOR(byte[] data) {
            if (data == null) {
                return null;
            }
            int L = data.length;
            if (L == 0) {
                return data;
            }
            if (L == 1) {
                byte[] result = new byte[1];
                result[0] = (byte) (data[0] ^ this.pool[this.prime % this.poolSize]);
                return result;
            }
            if (L > this.poolSize) {
                throw new IllegalArgumentException("Data " + L + " exceeds Pool " + this.poolSize);
            }
            int mid = L / 2;
            byte[] left = java.util.Arrays.copyOfRange(data, 0, mid);
            byte[] right = java.util.Arrays.copyOfRange(data, mid, L);

            // 5-Round Feistel Network
            for (int round = 0; round < 5; round++) {
                long seed = 0;
                for (int i = 0; i < right.length; i++) {
                    int b = Byte.toUnsignedInt(right[i]);
                    seed = (seed + (long) b * (i + 1)) % this.poolSize;
                }

                byte[] newLeft = new byte[left.length];
                for (int i = 0; i < left.length; i++) {
                    int poolIdx = (int) ((seed + (long) i * this.prime) % this.poolSize);
                    newLeft[i] = (byte) (left[i] ^ this.pool[poolIdx]);
                }

                left = right;
                right = newLeft;
            }

            byte[] finalResult = new byte[L];
            System.arraycopy(right, 0, finalResult, 0, right.length);
            System.arraycopy(left, 0, finalResult, right.length, left.length);
            return finalResult; // re-order for odd length
        }
    }

    // ========== Hash Functions Master ==========
    public static class HashMaster {
        private String algo;
        private int hashSize;
        private int keySize;

        public HashMaster(String algo, int hashSize, int keySize) {
            if (!algo.equals("sha3") && !algo.equals("pbk2") && !algo.equals("arg2")) {
                throw new IllegalArgumentException("Unsupported algorithm: " + algo);
            }
            this.algo = algo;
            this.hashSize = hashSize;
            this.keySize = keySize;
        }

        public HashMaster(String algo) {
            this(algo, 32, 44); // default hashSize=32 bytes, keySize=44 bytes
        }

        public byte[][] KDF(byte[] pw, byte[] salt) {
            String lblStore = "", lblKeygen = "";
            byte[] master = null;

            if (this.algo.equals("sha3")) {
                lblStore = "PWHASH_SHA3";
                lblKeygen = "KEYGEN_SHA3";
                byte[] combined = new byte[salt.length + pw.length];
                System.arraycopy(salt, 0, combined, 0, salt.length);
                System.arraycopy(pw, 0, combined, salt.length, pw.length);
                master = Bencrypt.SHA3512(combined);
                sclear(combined);

            } else if (this.algo.equals("pbk2")) {
                lblStore = "PWHASH_PBK2";
                lblKeygen = "KEYGEN_PBK2";
                master = Bencrypt.pbkdf2(pw, salt, 1000000, 64);

            } else if (this.algo.equals("arg2")) {
                lblStore = "PWHASH_ARG2";
                lblKeygen = "KEYGEN_ARG2";
                master = Bencrypt.argon2(pw, salt);

            } else {
                return new byte[0][0];
            }

            byte[] pwStored = Bencrypt.genkey(master, lblStore, this.hashSize);
            byte[] keyGen = Bencrypt.genkey(master, lblKeygen, this.keySize);
            sclear(master);
            return new byte[][] { pwStored, keyGen };
        }
    }

    // ========== Hash Functions ==========
    public static byte[] pbkdf2(byte[] pw, byte[] salt, int iter, int outsize) {
        if (iter <= 0) // set iter, outsize to 0 for default (1000000, 64)
            iter = 1000000;
        if (outsize <= 0)
            outsize = 64;
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA512Digest());
        gen.init(pw, salt, iter);
        KeyParameter params = (KeyParameter) gen.generateDerivedParameters(outsize * 8); // byte -> bit
        return params.getKey();
    }

    private static final Argon2Kt argon2Kt = new Argon2Kt(); // dependency: com.lambdapioneer.argon2kt:argon2kt
    public static byte[] argon2(byte[] pw, byte[] salt) {
        Argon2KtResult result = argon2Kt.hash(Argon2Mode.ARGON2_ID, pw, salt, 3, 262144, 4, 48);
        byte[] hash = result.rawHashAsByteArray();

        // zerofill buffer
        ByteBuffer nativeBuffer = result.getRawHash();
        nativeBuffer.clear();
        while (nativeBuffer.hasRemaining()) {
            nativeBuffer.put((byte) 0);
        }
        return hash;
    }

    public String argon2Hash(byte[] pw, byte[] salt) {
        if (salt == null) { // Argon2 Parameters: Type=Argon2id, Time=3, Mem=262144(256MiB), Parallel=4,
                            // Len=48, Salt=16
            salt = this.Random(16);
        }
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(3)
                .withMemoryAsKB(262144)
                .withParallelism(4)
                .withSalt(salt);
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(builder.build());
        byte[] result = new byte[48];
        gen.generateBytes(pw, result, 0, result.length);

        // generate formatted string ( $argon2id$v=19$m=262144,t=3,p=4$saltB64$hashB64 )
        String b64Salt = Base64.getEncoder().withoutPadding().encodeToString(salt); // base64 without padding
        String b64Hash = Base64.getEncoder().withoutPadding().encodeToString(result);
        return String.format("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", 262144, 3, 4, b64Salt, b64Hash);
    }

    public boolean argon2Verify(String hashed, byte[] pw) {
        try {
            // make simple parser
            String[] parts = hashed.split("\\$");
            if (parts.length != 6)
                return false;
            if (!parts[1].equals("argon2id"))
                return false;

            // get parameters
            String[] params = parts[3].split(",");
            int memory = 0, iterations = 0, parallelism = 0;
            for (String p : params) {
                String[] kv = p.split("=");
                int val = Integer.parseInt(kv[1]);
                if (kv[0].equals("m"))
                    memory = val;
                else if (kv[0].equals("t"))
                    iterations = val;
                else if (kv[0].equals("p"))
                    parallelism = val;
            }
            byte[] salt = decodeB64(parts[4]);
            byte[] originalHash = decodeB64(parts[5]);

            // rehash
            Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withIterations(iterations)
                    .withMemoryAsKB(memory)
                    .withParallelism(parallelism)
                    .withSalt(salt);

            Argon2BytesGenerator gen = new Argon2BytesGenerator();
            gen.init(builder.build());
            byte[] newHash = new byte[originalHash.length];
            gen.generateBytes(pw, newHash, 0, newHash.length);
            return Arrays.equals(originalHash, newHash);

        } catch (Exception e) {
            return false;
        }
    }

    // ========== Symmetric Encryption Master ==========
    public static class SymMaster {
        private String algo;
        private byte[] key;
        private Masker mask;
        private Bencrypt.AES1 worker;

        /**
         * @param algo "gcm1" or "gcmx1"
         * @param key  44 bytes (12B IV + 32B Key)
         */
        public SymMaster(String algo, byte[] key) {
            if (!algo.equals("gcm1") && !algo.equals("gcmx1")) {
                throw new IllegalArgumentException("Unsupported algorithm: " + algo);
            }
            if (key.length != 44) {
                throw new IllegalArgumentException("Key length must be 44 bytes (12B IV + 32B Key)");
            }
            this.algo = algo;
            this.mask = Masker.GetMasker();
            this.key = this.mask.XOR(key); // saved as XOR masked
            this.worker = new Bencrypt.AES1();
        }

        // Calculate expected output size
        public long AfterSize(long size) {
            if (this.algo.equals("gcm1")) {
                return size + 16;
            } else if (this.algo.equals("gcmx1")) {
                long chunkSize = 1048576;
                long c = size / chunkSize + 1;
                if (size != 0 && size % chunkSize == 0) {
                    c -= 1;
                }
                return size + (16 * c);
            }
            return 0;
        }

        public long Processed() {
            return this.worker.Processed();
        }

        // Encrypt binary data (Memory)
        public byte[] EnBin(byte[] data) throws Exception {
            byte[] key = this.mask.XOR(this.key);
            if (this.algo.equals("gcm1")) {
                byte[] res = this.worker.enAESGCM(key, data);
                sclear(key);
                return res;
            } else {
                java.io.ByteArrayInputStream in = new java.io.ByteArrayInputStream(data);
                java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
                this.worker.enAESGCMx(key, in, data.length, out, 1048576);
                sclear(key);
                return out.toByteArray();
            }
        }

        // Decrypt binary data (Memory)
        public byte[] DeBin(byte[] data) throws Exception {
            byte[] key = this.mask.XOR(this.key);
            if (this.algo.equals("gcm1")) {
                byte[] res = this.worker.deAESGCM(key, data);
                sclear(key);
                return res;
            } else {
                java.io.ByteArrayInputStream in = new java.io.ByteArrayInputStream(data);
                java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
                this.worker.deAESGCMx(key, in, data.length, out, 1048576);
                sclear(key);
                return out.toByteArray();
            }
        }

        // Encrypt Stream/File
        public void EnFile(InputStream src, long size, OutputStream dst) throws Exception {
            byte[] key = this.mask.XOR(this.key);
            if (this.algo.equals("gcm1")) {
                byte[] buf = src.readNBytes((int) size);
                byte[] enc = this.worker.enAESGCM(key, buf);
                dst.write(enc);
            } else {
                this.worker.enAESGCMx(key, src, size, dst, 1048576);
            }
            sclear(key);
        }

        // Decrypt Stream/File
        public void DeFile(InputStream src, long size, OutputStream dst) throws Exception {
            byte[] key = this.mask.XOR(this.key);
            if (this.algo.equals("gcm1")) {
                byte[] buf = src.readNBytes((int) size);
                byte[] dec = this.worker.deAESGCM(key, buf);
                dst.write(dec);
            } else {
                this.worker.deAESGCMx(key, src, size, dst, 1048576);
            }
            sclear(key);
        }
    }

    // ========== AES Encryption ==========
    public static class AES1 {
        private final AtomicLong processed = new AtomicLong(0);

        private byte[] inlineEnc(byte[] key, byte[] iv, byte[] data) throws Exception {
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            return cipher.doFinal(data);
        }

        private byte[] inlineDec(byte[] key, byte[] iv, byte[] data) throws Exception {
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            return cipher.doFinal(data);
        }

        // get processed bytes
        public long Processed() {
            return this.processed.get();
        }

        // encrypt single block with 44B key, output: [Ciphertext][Tag 16B]
        public byte[] enAESGCM(byte[] key, byte[] data) throws Exception {
            this.processed.set(0);
            if (key.length != 44)
                throw new IllegalArgumentException("key size must be 44 bytes");
            byte[] iv = Arrays.copyOfRange(key, 0, 12);
            byte[] keyBytes = Arrays.copyOfRange(key, 12, 44);
            byte[] result = inlineEnc(keyBytes, iv, data);
            sclear(keyBytes);
            this.processed.set(data.length);
            return result;
        }

        // decrypt single block with 44B key
        public byte[] deAESGCM(byte[] key, byte[] data) throws Exception {
            this.processed.set(0);
            if (key.length != 44)
                throw new IllegalArgumentException("key size must be 44 bytes");
            if (data.length < 16)
                throw new IllegalArgumentException("data size must be at least 16 bytes");
            byte[] iv = Arrays.copyOfRange(key, 0, 12);
            byte[] keyBytes = Arrays.copyOfRange(key, 12, 44);
            byte[] result = inlineDec(keyBytes, iv, data);
            sclear(keyBytes);
            this.processed.set(data.length);
            return result;
        }

        // encrypt stream with 44B key, default chunkSize=1048576
        public void enAESGCMx(byte[] key, InputStream src, long size, OutputStream dst, int chunkSize)
                throws Exception {
            this.processed.set(0);
            if (key.length != 44)
                throw new IllegalArgumentException("key size must be 44 bytes");
            if (chunkSize <= 0)
                chunkSize = 1048576;
            byte[] globalIV = Arrays.copyOfRange(key, 0, 12);
            byte[] globalKey = Arrays.copyOfRange(key, 12, 44);

            // 1. Generate Thread x8 Pool
            ExecutorService executor = Executors.newFixedThreadPool(8);
            LinkedList<Future<byte[]>> futures = new LinkedList<>();
            long counter = 0;
            long remaining = size;

            try {
                while (true) {
                    // 2. Read Chunk
                    long toRead = Math.min(chunkSize, remaining);
                    byte[] buffer = src.readNBytes((int) toRead);
                    remaining -= toRead;

                    // 3. Submit Task
                    final long ctr = counter++;
                    Callable<byte[]> task = () -> {
                        byte[] iv = mkiv(globalIV, ctr); // make iv, add counter
                        return inlineEnc(globalKey, iv, buffer);
                    };
                    futures.add(executor.submit(task));

                    // 4. Writeback if task is more than 8
                    while (futures.size() > 8) {
                        byte[] result = futures.poll().get();
                        dst.write(result);
                        this.processed.addAndGet(result.length - 16);
                    }
                    if (remaining <= 0)
                        break;
                }

                // 5. Writeback remaining tasks
                while (futures.size() > 0) {
                    byte[] result = futures.poll().get();
                    dst.write(result);
                    this.processed.addAndGet(result.length - 16);
                }

            } finally { // 6. Close Thread x8 Pool
                executor.shutdown();
                sclear(globalKey);
            }
        }

        // decrypt stream with 44B key, default chunkSize=1048576
        public void deAESGCMx(byte[] key, InputStream src, long size, OutputStream dst, int chunkSize)
                throws Exception {
            this.processed.set(0);
            if (key.length != 44)
                throw new IllegalArgumentException("key size must be 44 bytes");
            if (size < 16)
                throw new IllegalArgumentException("cipher too short to decrypt");
            if (chunkSize <= 0)
                chunkSize = 1048576;
            byte[] globalIV = Arrays.copyOfRange(key, 0, 12);
            byte[] globalKey = Arrays.copyOfRange(key, 12, 44);

            // 1. Generate Thread x8 Pool
            ExecutorService executor = Executors.newFixedThreadPool(8);
            LinkedList<Future<byte[]>> futures = new LinkedList<>();
            long counter = 0;
            long remaining = size;

            try {
                while (remaining >= 16) {
                    // 2. Read Chunk
                    long toRead = Math.min(chunkSize + 16, remaining);
                    byte[] buffer = src.readNBytes((int) toRead);
                    remaining -= toRead;

                    // 3. Submit Task
                    final long ctr = counter++;
                    Callable<byte[]> task = () -> {
                        byte[] iv = mkiv(globalIV, ctr); // make iv, add counter
                        return inlineDec(globalKey, iv, buffer);
                    };
                    futures.add(executor.submit(task));

                    // 4. Writeback if task is more than 8
                    while (futures.size() > 8) {
                        byte[] result = futures.poll().get();
                        dst.write(result);
                        this.processed.addAndGet(result.length + 16);
                    }
                }

                // 5. Writeback remaining tasks
                while (futures.size() > 0) {
                    byte[] result = futures.poll().get();
                    dst.write(result);
                    this.processed.addAndGet(result.length + 16);
                }

            } finally { // 6. Close Thread x8 Pool
                executor.shutdown();
                sclear(globalKey);
            }
        }
    }

    // ========== Asymmetric Encryption Master ==========
    public static class AsymMaster {
        private String algo;
        private Bencrypt.RSA1 worker0;
        private Bencrypt.ECC1 worker1;
        private Bencrypt.PQC1 worker2;

        /**
         * @param algo "rsa1", "rsa2", "ecc1", "pqc1"
         */
        public AsymMaster(String algo) {
            switch (algo) {
                case "rsa1":
                case "rsa2":
                    this.algo = algo;
                    this.worker0 = new Bencrypt.RSA1();
                    break;
                case "ecc1":
                    this.algo = algo;
                    this.worker1 = new Bencrypt.ECC1();
                    break;
                case "pqc1":
                    this.algo = algo;
                    this.worker2 = new Bencrypt.PQC1();
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported algorithm: " + algo);
            }
        }

        // Generate key pair, {public, private}
        public byte[][] Genkey() throws Exception {
            if (this.algo.equals("rsa1")) {
                return this.worker0.genkey(2048);
            } else if (this.algo.equals("rsa2")) {
                return this.worker0.genkey(4096);
            } else if (this.algo.equals("ecc1")) {
                return this.worker1.genkey();
            } else if (this.algo.equals("pqc1")) {
                return this.worker2.genkey();
            }
            return null;
        }

        public void Loadkey(byte[] publicBuf, byte[] privateBuf) throws Exception {
            if (this.algo.equals("rsa1") || this.algo.equals("rsa2")) {
                this.worker0.loadkey(publicBuf, privateBuf);
            } else if (this.algo.equals("ecc1")) {
                this.worker1.loadkey(publicBuf, privateBuf);
            } else if (this.algo.equals("pqc1")) {
                this.worker2.loadkey(publicBuf, privateBuf);
            }
        }

        public byte[] Encrypt(byte[] data) throws Exception {
            if (this.algo.equals("rsa1") || this.algo.equals("rsa2")) {
                return this.worker0.encrypt(data);
            } else if (this.algo.equals("ecc1")) {
                return this.worker1.encrypt(data);
            } else if (this.algo.equals("pqc1")) {
                return this.worker2.encrypt(data);
            }
            return null;
        }

        public byte[] Decrypt(byte[] data) throws Exception {
            if (this.algo.equals("rsa1") || this.algo.equals("rsa2")) {
                return this.worker0.decrypt(data);
            } else if (this.algo.equals("ecc1")) {
                return this.worker1.decrypt(data);
            } else if (this.algo.equals("pqc1")) {
                return this.worker2.decrypt(data);
            }
            return null;
        }

        public byte[] Sign(byte[] data) throws Exception {
            if (this.algo.equals("rsa1") || this.algo.equals("rsa2")) {
                return this.worker0.sign(data);
            } else if (this.algo.equals("ecc1")) {
                return this.worker1.sign(data);
            } else if (this.algo.equals("pqc1")) {
                return this.worker2.sign(data);
            }
            return null;
        }

        public boolean Verify(byte[] data, byte[] signature) {
            if (this.algo.equals("rsa1") || this.algo.equals("rsa2")) {
                return this.worker0.verify(data, signature);
            } else if (this.algo.equals("ecc1")) {
                return this.worker1.verify(data, signature);
            } else if (this.algo.equals("pqc1")) {
                return this.worker2.verify(data, signature);
            }
            return false;
        }
    }

    // ========== RSA Encryption ==========
    public static class RSA1 {
        public PublicKey RSApub = null;
        public PrivateKey RSApri = null;

        // Generate RSA key (public, private), DER(PKIX, PKCS8) format
        public byte[][] genkey(int bits) throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(bits); // 2048, 3072, 4096
            KeyPair kp = kpg.generateKeyPair();
            this.RSApub = kp.getPublic();
            this.RSApri = kp.getPrivate();
            return new byte[][] {
                    this.RSApub.getEncoded(),
                    this.RSApri.getEncoded()
            };
        }

        // Load RSA key if not null (public, private), DER(PKIX, PKCS8) format
        public void loadkey(byte[] pubBytes, byte[] priBytes) throws Exception {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            if (pubBytes != null) {
                this.RSApub = kf.generatePublic(new X509EncodedKeySpec(pubBytes));
            }
            if (priBytes != null) {
                this.RSApri = kf.generatePrivate(new PKCS8EncodedKeySpec(priBytes));
            }
        }

        // RSA encrypt: OAEP-SHA-512
        public byte[] encrypt(byte[] data) throws Exception {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
                    "SHA-512",
                    "MGF1",
                    MGF1ParameterSpec.SHA512,
                    PSource.PSpecified.DEFAULT);
            cipher.init(Cipher.ENCRYPT_MODE, this.RSApub, oaepSpec);
            return cipher.doFinal(data);
        }

        // RSA decrypt: OAEP-SHA-512
        public byte[] decrypt(byte[] data) throws Exception {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
                    "SHA-512",
                    "MGF1",
                    MGF1ParameterSpec.SHA512,
                    PSource.PSpecified.DEFAULT); // set OAEP, MGF1 to SHA-512
            cipher.init(Cipher.DECRYPT_MODE, this.RSApri, oaepSpec);
            return cipher.doFinal(data);
        }

        // RSA sign: PKCS#1 v1.5 SHA-256
        public byte[] sign(byte[] data) throws Exception {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(this.RSApri);
            sig.update(data);
            return sig.sign();
        }

        // RSA verify: PKCS#1 v1.5 SHA-256
        public boolean verify(byte[] data, byte[] signature) {
            try {
                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initVerify(this.RSApub);
                sig.update(data);
                return sig.verify(signature);
            } catch (Exception e) {
                return false;
            }
        }
    }

    // ========== ECC Encryption ==========
    public static class ECC1 {
        public X448PublicKeyParameters pubX = null;
        public X448PrivateKeyParameters priX = null;
        public Ed448PublicKeyParameters pubEd = null;
        public Ed448PrivateKeyParameters priEd = null;

        // Generate ECC key (public, private), [X448 56B][Ed448 57B] format
        public byte[][] genkey() throws Exception {
            SecureRandom rnd = new SecureRandom();

            // 1. Generate X448
            X448KeyPairGenerator xGen = new X448KeyPairGenerator();
            xGen.init(new X448KeyGenerationParameters(rnd));
            AsymmetricCipherKeyPair xKp = xGen.generateKeyPair();
            this.pubX = (X448PublicKeyParameters) xKp.getPublic();
            this.priX = (X448PrivateKeyParameters) xKp.getPrivate();

            // 2. Generate Ed448
            Ed448KeyPairGenerator edGen = new Ed448KeyPairGenerator();
            edGen.init(new Ed448KeyGenerationParameters(rnd));
            AsymmetricCipherKeyPair edKp = edGen.generateKeyPair();
            this.pubEd = (Ed448PublicKeyParameters) edKp.getPublic();
            this.priEd = (Ed448PrivateKeyParameters) edKp.getPrivate();

            // 3. Get Raw Bytes & Concatenate
            byte[] xPubB = this.pubX.getEncoded(); // 56 bytes
            byte[] xPriB = this.priX.getEncoded(); // 56 bytes
            byte[] edPubB = this.pubEd.getEncoded(); // 57 bytes
            byte[] edPriB = this.priEd.getEncoded(); // 57 bytes

            byte[] pubFull = new byte[113];
            System.arraycopy(xPubB, 0, pubFull, 0, 56);
            System.arraycopy(edPubB, 0, pubFull, 56, 57);

            byte[] priFull = new byte[113];
            System.arraycopy(xPriB, 0, priFull, 0, 56);
            System.arraycopy(edPriB, 0, priFull, 56, 57);

            return new byte[][] { pubFull, priFull };
        }

        // Load ECC key if not null (public, private), [X448 56B][Ed448 57B] format
        public void loadkey(byte[] pubBytes, byte[] priBytes) throws Exception {
            if (pubBytes != null) {
                if (pubBytes.length != 113)
                    throw new IllegalArgumentException("Invalid Curve448 public key length");
                byte[] xPubB = Arrays.copyOfRange(pubBytes, 0, 56);
                byte[] edPubB = Arrays.copyOfRange(pubBytes, 56, 113);
                this.pubX = new X448PublicKeyParameters(xPubB, 0);
                this.pubEd = new Ed448PublicKeyParameters(edPubB, 0);
            }
            if (priBytes != null) {
                if (priBytes.length != 113)
                    throw new IllegalArgumentException("Invalid Curve448 private key length");
                byte[] xPriB = Arrays.copyOfRange(priBytes, 0, 56);
                byte[] edPriB = Arrays.copyOfRange(priBytes, 56, 113);
                this.priX = new X448PrivateKeyParameters(xPriB, 0);
                this.priEd = new Ed448PrivateKeyParameters(edPriB, 0);
            }
        }

        // ECC encrypt with public key, output: [1B KeyLen][PubKey][Ciphertext]
        public byte[] encrypt(byte[] data) throws Exception {
            // 1. Generate Temp Ephemeral Key
            X448KeyPairGenerator xGen = new X448KeyPairGenerator();
            xGen.init(new X448KeyGenerationParameters(new SecureRandom()));
            AsymmetricCipherKeyPair ephKp = xGen.generateKeyPair();
            X448PublicKeyParameters ephPub = (X448PublicKeyParameters) ephKp.getPublic();
            X448PrivateKeyParameters ephPri = (X448PrivateKeyParameters) ephKp.getPrivate();

            // 2. ECDH Agreement
            X448Agreement agreement = new X448Agreement();
            agreement.init(ephPri);
            byte[] sharedSecret = new byte[agreement.getAgreementSize()];
            agreement.calculateAgreement(this.pubX, sharedSecret, 0);

            // 3. KDF & Encrypt
            byte[] gcmKey = Bencrypt.genkey(sharedSecret, "KEYGEN_ECC1_ENCRYPT", 44);
            sclear(sharedSecret);
            Bencrypt.SymMaster worker = new Bencrypt.SymMaster("gcm1", gcmKey);
            byte[] enc = worker.EnBin(data);
            sclear(gcmKey);

            // 4. Pack
            byte[] ephPubRaw = ephPub.getEncoded(); // 56 bytes
            byte[] res = new byte[1 + ephPubRaw.length + enc.length];
            res[0] = (byte) ephPubRaw.length;
            System.arraycopy(ephPubRaw, 0, res, 1, ephPubRaw.length);
            System.arraycopy(enc, 0, res, 1 + ephPubRaw.length, enc.length);
            return res;
        }

        // ECC decrypt with my private key
        public byte[] decrypt(byte[] data) throws Exception {
            // 1. Parse
            int keyLen = data[0] & 0xFF;
            byte[] ephPubRaw = Arrays.copyOfRange(data, 1, 1 + keyLen);
            byte[] enc = Arrays.copyOfRange(data, 1 + keyLen, data.length);

            // 2. Load Eph Public Key
            X448PublicKeyParameters ephPub = new X448PublicKeyParameters(ephPubRaw, 0);

            // 3. ECDH Agreement
            X448Agreement agreement = new X448Agreement();
            agreement.init(this.priX);
            byte[] sharedSecret = new byte[agreement.getAgreementSize()];
            agreement.calculateAgreement(ephPub, sharedSecret, 0);

            // 4. KDF & Decrypt
            byte[] gcmKey = Bencrypt.genkey(sharedSecret, "KEYGEN_ECC1_ENCRYPT", 44);
            sclear(sharedSecret);
            Bencrypt.SymMaster worker = new Bencrypt.SymMaster("gcm1", gcmKey);
            byte[] res = worker.DeBin(enc);
            sclear(gcmKey);
            return res;
        }

        // ECC sign: Ed448
        public byte[] sign(byte[] data) throws Exception {
            Ed448Signer signer = new Ed448Signer(new byte[0]); // context empty
            signer.init(true, this.priEd);
            signer.update(data, 0, data.length);
            return signer.generateSignature();
        }

        // ECC verify: Ed448
        public boolean verify(byte[] data, byte[] signature) {
            try {
                Ed448Signer signer = new Ed448Signer(new byte[0]); // context empty
                signer.init(false, this.pubEd);
                signer.update(data, 0, data.length);
                return signer.verifySignature(signature);
            } catch (Exception e) {
                return false;
            }
        }
    }

    // ========== PQC1 Encryption ==========
    @SuppressWarnings("deprecation") // JCA Standards are not compatible with USAG-Lib Standards (Python)
    public static class PQC1 {
        // ECC Key Objects
        public X448PublicKeyParameters pubX = null;
        public X448PrivateKeyParameters priX = null;
        public Ed448PublicKeyParameters pubEd = null;
        public Ed448PrivateKeyParameters priEd = null;

        // PQC Raw Key Bytes
        public byte[] pubKEM = null;
        public byte[] priKEM = null;
        public byte[] pubDSA = null;
        public byte[] priDSA = null;

        // PQC keys will be unmasked and directly used in Lightweight PQC Key Objects
        private Masker mask = Masker.GetMasker();

        public byte[][] genkey() throws Exception {
            SecureRandom rnd = new SecureRandom();

            // 1. Curve448 key generation
            X448KeyPairGenerator xGen = new X448KeyPairGenerator();
            xGen.init(new X448KeyGenerationParameters(rnd));
            AsymmetricCipherKeyPair xKp = xGen.generateKeyPair();
            this.pubX = (X448PublicKeyParameters) xKp.getPublic();
            this.priX = (X448PrivateKeyParameters) xKp.getPrivate();

            Ed448KeyPairGenerator edGen = new Ed448KeyPairGenerator();
            edGen.init(new Ed448KeyGenerationParameters(rnd));
            AsymmetricCipherKeyPair edKp = edGen.generateKeyPair();
            this.pubEd = (Ed448PublicKeyParameters) edKp.getPublic();
            this.priEd = (Ed448PrivateKeyParameters) edKp.getPrivate();

            byte[] pub0 = this.pubX.getEncoded();
            byte[] pri0 = this.priX.getEncoded();
            byte[] pub1 = this.pubEd.getEncoded();
            byte[] pri1 = this.priEd.getEncoded();

            // 2. ML-KEM-1024 key generation
            MLKEMKeyPairGenerator kemKpg = new MLKEMKeyPairGenerator();
            kemKpg.init(new MLKEMKeyGenerationParameters(rnd, MLKEMParameters.ml_kem_1024));
            AsymmetricCipherKeyPair kemKp = kemKpg.generateKeyPair();
            MLKEMPublicKeyParameters kemPub = (MLKEMPublicKeyParameters) kemKp.getPublic();
            MLKEMPrivateKeyParameters kemPri = (MLKEMPrivateKeyParameters) kemKp.getPrivate();
            this.pubKEM = kemPub.getEncoded();
            this.priKEM = kemPri.getEncoded();

            // 3. ML-DSA-87 key generation
            MLDSAKeyPairGenerator dsaKpg = new MLDSAKeyPairGenerator();
            dsaKpg.init(new MLDSAKeyGenerationParameters(rnd, MLDSAParameters.ml_dsa_87));
            AsymmetricCipherKeyPair dsaKp = dsaKpg.generateKeyPair();
            MLDSAPublicKeyParameters dsaPub = (MLDSAPublicKeyParameters) dsaKp.getPublic();
            MLDSAPrivateKeyParameters dsaPri = (MLDSAPrivateKeyParameters) dsaKp.getPrivate();
            this.pubDSA = dsaPub.getEncoded();
            this.priDSA = dsaPri.getEncoded();

            // 4. Join keys (Public: 4273B, Private: 8177B)
            byte[] pubB = new byte[4273];
            System.arraycopy(pub0, 0, pubB, 0, 56);
            System.arraycopy(pub1, 0, pubB, 56, 57);
            System.arraycopy(this.pubKEM, 0, pubB, 113, 1568);
            System.arraycopy(this.pubDSA, 0, pubB, 1681, 2592);

            byte[] priB = new byte[8177];
            System.arraycopy(pri0, 0, priB, 0, 56);
            System.arraycopy(pri1, 0, priB, 56, 57);
            System.arraycopy(this.priKEM, 0, priB, 113, 3168);
            System.arraycopy(this.priDSA, 0, priB, 3281, 4896);

            // 5. Mask keys
            this.priKEM = this.mask.XOR(this.priKEM);
            this.priDSA = this.mask.XOR(this.priDSA);
            return new byte[][] { pubB, priB };
        }

        public void loadkey(byte[] publicBuf, byte[] privateBuf) throws Exception {
            if (publicBuf != null) {
                if (publicBuf.length != 4273)
                    throw new IllegalArgumentException("Invalid PQC1 public key length");
                this.pubX = new X448PublicKeyParameters(Arrays.copyOfRange(publicBuf, 0, 56), 0);
                this.pubEd = new Ed448PublicKeyParameters(Arrays.copyOfRange(publicBuf, 56, 113), 0);
                this.pubKEM = Arrays.copyOfRange(publicBuf, 113, 1681);
                this.pubDSA = Arrays.copyOfRange(publicBuf, 1681, 4273);
            }
            if (privateBuf != null) {
                if (privateBuf.length != 8177)
                    throw new IllegalArgumentException("Invalid PQC1 private key length");
                this.priX = new X448PrivateKeyParameters(Arrays.copyOfRange(privateBuf, 0, 56), 0);
                this.priEd = new Ed448PrivateKeyParameters(Arrays.copyOfRange(privateBuf, 56, 113), 0);
                this.priKEM = Arrays.copyOfRange(privateBuf, 113, 3281);
                this.priDSA = Arrays.copyOfRange(privateBuf, 3281, 8177);

                // mask keys
                this.priKEM = this.mask.XOR(this.priKEM);
                this.priDSA = this.mask.XOR(this.priDSA);
            }
        }

        public byte[] encrypt(byte[] data) throws Exception {
            SecureRandom rnd = new SecureRandom();

            // 1. Ephemeral X448 tempkey generation
            X448KeyPairGenerator xGen = new X448KeyPairGenerator();
            xGen.init(new X448KeyGenerationParameters(rnd));
            AsymmetricCipherKeyPair tempKp = xGen.generateKeyPair();
            X448PublicKeyParameters tempPub = (X448PublicKeyParameters) tempKp.getPublic();
            X448PrivateKeyParameters tempPri = (X448PrivateKeyParameters) tempKp.getPrivate();

            X448Agreement agreement = new X448Agreement();
            agreement.init(tempPri);
            byte[] ssvECC = new byte[agreement.getAgreementSize()];
            agreement.calculateAgreement(this.pubX, ssvECC, 0);

            // 2. ML-KEM-1024 Encapsulation
            MLKEMGenerator kemGen = new MLKEMGenerator(rnd);
            MLKEMPublicKeyParameters kemPub = new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_1024, this.pubKEM);
            SecretWithEncapsulation kemSec = kemGen.generateEncapsulated(kemPub);
            byte[] ssvKEM = kemSec.getSecret();
            byte[] kemEnc = kemSec.getEncapsulation();

            // 3. Hybrid KDF & Encryption
            byte[] combinedSecret = new byte[ssvECC.length + ssvKEM.length];
            System.arraycopy(ssvECC, 0, combinedSecret, 0, ssvECC.length);
            System.arraycopy(ssvKEM, 0, combinedSecret, ssvECC.length, ssvKEM.length);

            byte[] gcmKey = Bencrypt.genkey(combinedSecret, "KEYGEN_PQC1_ENCRYPT", 44);
            sclear(ssvECC);
            sclear(ssvKEM);
            sclear(combinedSecret);
            Bencrypt.SymMaster worker = new Bencrypt.SymMaster("gcm1", gcmKey);
            byte[] enc = worker.EnBin(data);
            sclear(gcmKey);

            byte[] tempPubB = tempPub.getEncoded();
            byte[] res = new byte[tempPubB.length + kemEnc.length + enc.length];
            System.arraycopy(tempPubB, 0, res, 0, tempPubB.length);
            System.arraycopy(kemEnc, 0, res, tempPubB.length, kemEnc.length);
            System.arraycopy(enc, 0, res, tempPubB.length + kemEnc.length, enc.length);
            return res;
        }

        public byte[] decrypt(byte[] data) throws Exception {
            // 1. Separate data
            byte[] tempPub = Arrays.copyOfRange(data, 0, 56);
            byte[] kemEnc = Arrays.copyOfRange(data, 56, 1624);
            byte[] enc = Arrays.copyOfRange(data, 1624, data.length);

            // 2. Shared Secret Value
            X448PublicKeyParameters tempXKey = new X448PublicKeyParameters(tempPub, 0);
            X448Agreement agreement = new X448Agreement();
            agreement.init(this.priX);
            byte[] ssvECC = new byte[agreement.getAgreementSize()];
            agreement.calculateAgreement(tempXKey, ssvECC, 0);

            // ML-KEM-1024 Decapsulation
            byte[] priKEMt = this.mask.XOR(this.priKEM);
            MLKEMPrivateKeyParameters kemPri = new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_1024, priKEMt);
            sclear(priKEMt);
            MLKEMExtractor kemExt = new MLKEMExtractor(kemPri);
            byte[] ssvKEM = kemExt.extractSecret(kemEnc);

            // 3. Hybrid KDF & Decryption
            byte[] combinedSecret = new byte[ssvECC.length + ssvKEM.length];
            System.arraycopy(ssvECC, 0, combinedSecret, 0, ssvECC.length);
            System.arraycopy(ssvKEM, 0, combinedSecret, ssvECC.length, ssvKEM.length);

            byte[] gcmKey = Bencrypt.genkey(combinedSecret, "KEYGEN_PQC1_ENCRYPT", 44);
            sclear(ssvECC);
            sclear(ssvKEM);
            sclear(combinedSecret);
            Bencrypt.SymMaster worker = new Bencrypt.SymMaster("gcm1", gcmKey);
            byte[] res = worker.DeBin(enc);
            sclear(gcmKey);
            return res;
        }

        public byte[] sign(byte[] data) throws Exception {
            SecureRandom rnd = new SecureRandom();

            // ECC-Ed448
            Ed448Signer edSigner = new Ed448Signer(new byte[0]);
            edSigner.init(true, this.priEd);
            edSigner.update(data, 0, data.length);
            byte[] edSgn = edSigner.generateSignature();

            // ML-DSA-87
            MLDSASigner mlSigner = new MLDSASigner();
            byte[] priDSAt = this.mask.XOR(this.priDSA);
            MLDSAPrivateKeyParameters dsaPri = new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_87, priDSAt);
            sclear(priDSAt);
            mlSigner.init(true, new ParametersWithRandom(dsaPri, rnd));
            mlSigner.update(data, 0, data.length);
            byte[] mlSgn = mlSigner.generateSignature();

            byte[] res = new byte[edSgn.length + mlSgn.length];
            System.arraycopy(edSgn, 0, res, 0, edSgn.length);
            System.arraycopy(mlSgn, 0, res, edSgn.length, mlSgn.length);
            return res;
        }

        public boolean verify(byte[] data, byte[] signature) {
            if (signature.length != 4741)
                return false;
            byte[] edSgn = Arrays.copyOfRange(signature, 0, 114);
            byte[] mlSgn = Arrays.copyOfRange(signature, 114, 4741);

            try {
                // ECC-Ed448 verify
                Ed448Signer edSigner = new Ed448Signer(new byte[0]);
                edSigner.init(false, this.pubEd);
                edSigner.update(data, 0, data.length);
                if (!edSigner.verifySignature(edSgn))
                    return false;

                // ML-DSA-87 verify
                MLDSASigner mlSigner = new MLDSASigner();
                MLDSAPublicKeyParameters dsaPub = new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_87, this.pubDSA);
                mlSigner.init(false, dsaPub);
                mlSigner.update(data, 0, data.length);
                return mlSigner.verifySignature(mlSgn);
            } catch (Exception e) {
                return false;
            }
        }
    }
}
