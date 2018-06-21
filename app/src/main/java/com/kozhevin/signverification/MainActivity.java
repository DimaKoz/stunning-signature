package com.kozhevin.signverification;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.widget.TextView;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Example of a call to a native method
        TextView tv = (TextView) findViewById(R.id.sample_text);
        PackageInfo info = null;
        try {
            info = getPackageManager().getPackageInfo(getPackageName(), PackageManager.GET_SIGNATURES);
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        if (null != info && info.signatures.length > 0) {
            byte[] rawCertJava = info.signatures[0].toByteArray();
            byte[] rawCertNative = bytesFromJNI();
            String str = "From Java:\n"+getInfoFromBytes(rawCertJava) + "From native:\n"+getInfoFromBytes(rawCertNative);
            tv.setText(str);
        } else {
            tv.setText("No data");
        }

    }

    private String getInfoFromBytes(byte[] bytes) {
        if(null == bytes) {
            return "null";
        }

        /*
         * Get the X.509 certificate.
         */
        InputStream certStream = new ByteArrayInputStream(bytes);
        StringBuilder sb = new StringBuilder();
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X509");
            X509Certificate x509Cert = (X509Certificate) certFactory.generateCertificate(certStream);

            sb.append("Certificate subject: ").append(x509Cert.getSubjectDN()).append("\n");
            sb.append("Certificate issuer: ").append(x509Cert.getIssuerDN()).append("\n");
            sb.append("Certificate serial number: ").append(x509Cert.getSerialNumber()).append("\n");
            MessageDigest md;
            try {
                md = MessageDigest.getInstance("MD5");
                md.update(bytes);
                byte[] byteArray = md.digest();
                //String hash_key = new String(Base64.encode(md.digest(), 0));
                sb.append("MD5: ").append(bytesToString(byteArray)).append("\n");
                md.reset();
                md = MessageDigest.getInstance("SHA");
                md.update(bytes);
                byteArray = md.digest();
                //String hash_key = new String(Base64.encode(md.digest(), 0));
                sb.append("SHA1: ").append(bytesToString(byteArray)).append("\n");
                md.reset();
                md = MessageDigest.getInstance("SHA256");
                md.update(bytes);
                byteArray = md.digest();
                sb.append("SHA256: ").append(bytesToString(byteArray)).append("\n");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }


            sb.append("\n");
        } catch (CertificateException e) {
            // e.printStackTrace();
        }
        return sb.toString();
    }


    private String bytesToString(byte[] bytes) {
        StringBuilder md5StrBuff = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (Integer.toHexString(0xFF & bytes[i]).length() == 1) {
                md5StrBuff.append("0").append(Integer.toHexString(0xFF & bytes[i]));
            } else {
                md5StrBuff.append(Integer.toHexString(0xFF & bytes[i]));
            }
            if (bytes.length - 1 != i) {
                md5StrBuff.append(":");
            }
        }
        return md5StrBuff.toString();
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    private native byte[] bytesFromJNI();
}
