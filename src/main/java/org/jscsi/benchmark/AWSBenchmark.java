/**
 * 
 */
package org.jscsi.benchmark;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.filesystem.reference.FilesystemConstants;
import org.perfidix.Benchmark;
import org.perfidix.annotation.Bench;
import org.perfidix.ouput.CSVOutput;
import org.perfidix.ouput.TabularSummaryOutput;
import org.perfidix.result.BenchmarkResult;

import com.google.common.io.ByteStreams;

/**
 * @author Sebastian Graf, University osf Konstanz
 * 
 */
public class AWSBenchmark {

    private static final String ALGO = "AES";
    private static byte[] KEYVALUE = new byte[] {
        'k', 'k', 'k', 'k', 'k', 'k', 'k', 'k', 'k', 'k', 'k', 'k', 'k', 'k', 'k', 'k'
    };
    private static final Key KEY = new SecretKeySpec(KEYVALUE, "AES");

    private static final String BUCKETKEY = "KeyInTheBucket";
    private static final String CONTAINER = "grave9283708";
    private static final int RUNS = 100;
    private static final Cipher CIPHER;
    private static final Random RANDOM = new Random();

    static {
        try {
            CIPHER = Cipher.getInstance(ALGO);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] mData;

    private final BlobStoreContext mContext;

    private final BlobStore mStore;

    public AWSBenchmark() {
        String[] credentials = getCredentials();
        if (credentials.length == 0) {
            Properties properties = new Properties();
            properties.setProperty(FilesystemConstants.PROPERTY_BASEDIR, "/tmp/awsBenchmark");
            mContext =
                ContextBuilder.newBuilder("filesystem").overrides(properties).credentials("testUser",
                    "testPass").buildView(BlobStoreContext.class);
        } else {
            mContext =
                ContextBuilder.newBuilder("aws-s3").credentials(getCredentials()[0], getCredentials()[1])
                    .buildView(BlobStoreContext.class);
        }
        mStore = mContext.getBlobStore();
        mStore.createContainerInLocation(null, CONTAINER);
    }

    private byte[] createData(int pSize) {
        byte[] data = new byte[pSize];
        RANDOM.nextBytes(data);
        return data;
    }

    private void putBlob(final byte[] pData) {
        Blob blob = mStore.blobBuilder(BUCKETKEY).build();
        blob.setPayload(pData);
        mStore.putBlob(CONTAINER, blob);
    }

    private byte[] getBlob() {
        final Blob blob = mStore.getBlob(CONTAINER, BUCKETKEY);
        byte[] data;
        try {
            data = ByteStreams.toByteArray(blob.getPayload().getInput());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return data;
    }

    private void setUpPut() {
        try {
            CIPHER.init(Cipher.ENCRYPT_MODE, KEY);
            putBlob(mData);
            mStore.removeBlob(CONTAINER, BUCKETKEY);
            putBlob(mData);
            mStore.removeBlob(CONTAINER, BUCKETKEY);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void setUpGet(boolean pEnc) {
        if (pEnc) {
            try {
                CIPHER.init(Cipher.ENCRYPT_MODE, KEY);
                mData = CIPHER.doFinal(mData);
                CIPHER.init(Cipher.DECRYPT_MODE, KEY);
            } catch (Exception exc) {
                throw new RuntimeException(exc);
            }
        }
        putBlob(mData);
        mStore.removeBlob(CONTAINER, BUCKETKEY);
        putBlob(mData);
    }

    public void tearDown() {
        mStore.removeBlob(CONTAINER, BUCKETKEY);
    }

    // ////////////////////////////////
    // 256k Benches
    // ////////////////////////////////
    public void setUpPlainGet256k() {
        mData = createData(1024 * 256);
        setUpGet(false);
    }

    public void setUpEncGet256k() {
        mData = createData(1024 * 256);
        setUpGet(true);
    }

    public void setUpPut256k() {
        mData = createData(1024 * 256);
        setUpPut();
    }

    @Bench(beforeEachRun = "setUpPut256k", afterEachRun = "tearDown", runs = RUNS)
    public void plainPut256k() {
        putBlob(mData);
    }

    @Bench(beforeEachRun = "setUpPut256k", afterEachRun = "tearDown", runs = RUNS)
    public void encPut256k() {
        try {
            mData = CIPHER.doFinal(mData);
            putBlob(mData);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Bench(beforeEachRun = "setUpPlainGet256k", afterEachRun = "tearDown", runs = RUNS)
    public void plainGet256k() {
        getBlob();
    }

    @Bench(beforeEachRun = "setUpEncGet256k", afterEachRun = "tearDown", runs = RUNS)
    public void encGet256k() {
        byte[] data = getBlob();
        try {
            CIPHER.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ////////////////////////////////
    // 128k Benches
    // ////////////////////////////////
    public void setUpPlainGet128k() {
        mData = createData(1024 * 128);
        setUpGet(false);
    }

    public void setUpEncGet128k() {
        mData = createData(1024 * 128);
        setUpGet(true);
    }

    public void setUpPut128k() {
        mData = createData(1024 * 128);
        setUpPut();
    }

    @Bench(beforeEachRun = "setUpPut128k", afterEachRun = "tearDown", runs = RUNS)
    public void plainPut128k() {
        putBlob(mData);
    }

    @Bench(beforeEachRun = "setUpPut128k", afterEachRun = "tearDown", runs = RUNS)
    public void encPut128k() {
        try {
            mData = CIPHER.doFinal(mData);
            putBlob(mData);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Bench(beforeEachRun = "setUpPlainGet128k", afterEachRun = "tearDown", runs = RUNS)
    public void plainGet128k() {
        getBlob();
    }

    @Bench(beforeEachRun = "setUpEncGet128k", afterEachRun = "tearDown", runs = RUNS)
    public void encGet128k() {
        byte[] data = getBlob();
        try {
            CIPHER.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ////////////////////////////////
    // 64k Benches
    // ////////////////////////////////
    public void setUpPlainGet64k() {
        mData = createData(1024 * 64);
        setUpGet(false);
    }

    public void setUpEncGet64k() {
        mData = createData(1024 * 64);
        setUpGet(true);
    }

    public void setUpPut64k() {
        mData = createData(1024 * 64);
        setUpPut();
    }

    @Bench(beforeEachRun = "setUpPut64k", afterEachRun = "tearDown", runs = RUNS)
    public void plainPut64k() {
        putBlob(mData);
    }

    @Bench(beforeEachRun = "setUpPut64k", afterEachRun = "tearDown", runs = RUNS)
    public void encPut64k() {
        try {
            mData = CIPHER.doFinal(mData);
            putBlob(mData);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Bench(beforeEachRun = "setUpPlainGet64k", afterEachRun = "tearDown", runs = RUNS)
    public void plainGet64k() {
        getBlob();
    }

    @Bench(beforeEachRun = "setUpEncGet64k", afterEachRun = "tearDown", runs = RUNS)
    public void encGet64k() {
        byte[] data = getBlob();
        try {
            CIPHER.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ////////////////////////////////
    // 32k Benches
    // ////////////////////////////////
    public void setUpPlainGet32k() {
        mData = createData(1024 * 32);
        setUpGet(false);
    }

    public void setUpEncGet32k() {
        mData = createData(1024 * 32);
        setUpGet(true);
    }

    public void setUpPut32k() {
        mData = createData(1024 * 32);
        setUpPut();
    }

    @Bench(beforeEachRun = "setUpPut32k", afterEachRun = "tearDown", runs = RUNS)
    public void plainPut32k() {
        putBlob(mData);
    }

    @Bench(beforeEachRun = "setUpPut32k", afterEachRun = "tearDown", runs = RUNS)
    public void encPut32k() {
        try {
            mData = CIPHER.doFinal(mData);
            putBlob(mData);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Bench(beforeEachRun = "setUpPlainGet32k", afterEachRun = "tearDown", runs = RUNS)
    public void plainGet32k() {
        getBlob();
    }

    @Bench(beforeEachRun = "setUpEncGet32k", afterEachRun = "tearDown", runs = RUNS)
    public void encGet32k() {
        byte[] data = getBlob();
        try {
            CIPHER.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ////////////////////////////////
    // 16k Benches
    // ////////////////////////////////
    public void setUpPlainGet16k() {
        mData = createData(1024 * 16);
        setUpGet(false);
    }

    public void setUpEncGet16k() {
        mData = createData(1024 * 16);
        setUpGet(true);
    }

    public void setUpPut16k() {
        mData = createData(1024 * 16);
        setUpPut();
    }

    @Bench(beforeEachRun = "setUpPut16k", afterEachRun = "tearDown", runs = RUNS)
    public void plainPut16k() {
        putBlob(mData);
    }

    @Bench(beforeEachRun = "setUpPut16k", afterEachRun = "tearDown", runs = RUNS)
    public void encPut16k() {
        try {
            mData = CIPHER.doFinal(mData);
            putBlob(mData);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Bench(beforeEachRun = "setUpPlainGet16k", afterEachRun = "tearDown", runs = RUNS)
    public void plainGet16k() {
        getBlob();
    }

    @Bench(beforeEachRun = "setUpEncGet16k", afterEachRun = "tearDown", runs = RUNS)
    public void encGet16k() {
        byte[] data = getBlob();
        try {
            CIPHER.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ////////////////////////////////
    // 8k Benches
    // ////////////////////////////////
    public void setUpPlainGet8k() {
        mData = createData(1024 * 8);
        setUpGet(false);
    }

    public void setUpEncGet8k() {
        mData = createData(1024 * 8);
        setUpGet(true);
    }

    public void setUpPut8k() {
        mData = createData(1024 * 8);
        setUpPut();
    }

    @Bench(beforeEachRun = "setUpPut8k", afterEachRun = "tearDown", runs = RUNS)
    public void plainPut8k() {
        putBlob(mData);
    }

    @Bench(beforeEachRun = "setUpPut8k", afterEachRun = "tearDown", runs = RUNS)
    public void encPut8k() {
        try {
            mData = CIPHER.doFinal(mData);
            putBlob(mData);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Bench(beforeEachRun = "setUpPlainGet8k", afterEachRun = "tearDown", runs = RUNS)
    public void plainGet8k() {
        getBlob();
    }

    @Bench(beforeEachRun = "setUpEncGet8k", afterEachRun = "tearDown", runs = RUNS)
    public void encGet8k() {
        byte[] data = getBlob();
        try {
            CIPHER.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ////////////////////////////////
    // 4k Benches
    // ////////////////////////////////
    public void setUpPlainGet4k() {
        mData = createData(1024 * 4);
        setUpGet(false);
    }

    public void setUpEncGet4k() {
        mData = createData(1024 * 4);
        setUpGet(true);
    }

    public void setUpPut4k() {
        mData = createData(1024 * 4);
        setUpPut();
    }

    @Bench(beforeEachRun = "setUpPut4k", afterEachRun = "tearDown", runs = RUNS)
    public void plainPut4k() {
        putBlob(mData);
    }

    @Bench(beforeEachRun = "setUpPut4k", afterEachRun = "tearDown", runs = RUNS)
    public void encPut4k() {
        try {
            mData = CIPHER.doFinal(mData);
            putBlob(mData);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Bench(beforeEachRun = "setUpPlainGet4k", afterEachRun = "tearDown", runs = RUNS)
    public void plainGet4k() {
        getBlob();
    }

    @Bench(beforeEachRun = "setUpEncGet4k", afterEachRun = "tearDown", runs = RUNS)
    public void encGet4k() {
        byte[] data = getBlob();
        try {
            CIPHER.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ////////////////////////////////
    // 2k Benches
    // ////////////////////////////////
    public void setUpPlainGet2k() {
        mData = createData(1024 * 2);
        setUpGet(false);
    }

    public void setUpEncGet2k() {
        mData = createData(1024 * 2);
        setUpGet(true);
    }

    public void setUpPut2k() {
        mData = createData(1024 * 2);
        setUpPut();
    }

    @Bench(beforeEachRun = "setUpPut2k", afterEachRun = "tearDown", runs = RUNS)
    public void plainPut2k() {
        putBlob(mData);
    }

    @Bench(beforeEachRun = "setUpPut2k", afterEachRun = "tearDown", runs = RUNS)
    public void encPut2k() {
        try {
            mData = CIPHER.doFinal(mData);
            putBlob(mData);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Bench(beforeEachRun = "setUpPlainGet2k", afterEachRun = "tearDown", runs = RUNS)
    public void plainGet2k() {
        getBlob();
    }

    @Bench(beforeEachRun = "setUpEncGet2k", afterEachRun = "tearDown", runs = RUNS)
    public void encGet2k() {
        byte[] data = getBlob();
        try {
            CIPHER.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ////////////////////////////////
    // 1k Benches
    // ////////////////////////////////
    public void setUpPlainGet1k() {
        mData = createData(1024);
        setUpGet(false);
    }

    public void setUpEncGet1k() {
        mData = createData(1024);
        setUpGet(true);
    }

    public void setUpPut1k() {
        mData = createData(1024);
        setUpPut();
    }

    @Bench(beforeEachRun = "setUpPut1k", afterEachRun = "tearDown", runs = RUNS)
    public void plainPut1k() {
        putBlob(mData);
    }

    @Bench(beforeEachRun = "setUpPut1k", afterEachRun = "tearDown", runs = RUNS)
    public void encPut1k() {
        try {
            mData = CIPHER.doFinal(mData);
            putBlob(mData);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Bench(beforeEachRun = "setUpPlainGet1k", afterEachRun = "tearDown", runs = RUNS)
    public void plainGet1k() {
        getBlob();
    }

    @Bench(beforeEachRun = "setUpEncGet1k", afterEachRun = "tearDown", runs = RUNS)
    public void encGet1k() {
        byte[] data = getBlob();
        try {
            CIPHER.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        Benchmark bench = new Benchmark();
        bench.add(AWSBenchmark.class);
        BenchmarkResult res = bench.run();
        TabularSummaryOutput output = new TabularSummaryOutput();
        CSVOutput csv = new CSVOutput(new File("/Users/sebi/encbench"));
        output.visitBenchmark(res);
        csv.visitBenchmark(res);
    }

    /**
     * Getting credentials for aws from homedir/.credentials
     * 
     * @return a two-dimensional String[] with login and password
     */
    private static String[] getCredentials() {
        // return new String[0];
        File userStore =
            new File(System.getProperty("user.home"), new StringBuilder(".credentials")
                .append(File.separator).append("aws.properties").toString());
        if (!userStore.exists()) {
            return new String[0];
        } else {
            Properties props = new Properties();
            try {
                props.load(new FileReader(userStore));
                return new String[] {
                    props.getProperty("access"), props.getProperty("secret")
                };

            } catch (IOException exc) {
                throw new RuntimeException(exc);
            }
        }
    }

}
