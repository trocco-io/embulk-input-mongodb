package org.embulk.input.mongodb;

import org.embulk.config.ConfigException;
import org.embulk.util.config.units.LocalFile;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SSLContextUtil
{
    private SSLContextUtil()
    {
        throw new UnsupportedOperationException();
    }

    public static SSLContext createContext(PluginTask task)
    {
        return createContext(
                toPath(task.getKeyStore().orElse(null)),
                task.getKeyStoreType().orElse(null),
                task.getKeyStorePassword().orElse(null),
                toPath(task.getTrustStore().orElse(null)),
                task.getTrustStoreType().orElse(null),
                task.getTrustStorePassword().orElse(null),
                task.getTlsInsecure()
        );
    }

    public static SSLContext createContext(Path keyStorePath, String keyStoreType, String keyStorePassword,
            Path trustStorePath, String trustStoreType, String trustStorePassword, Boolean trustAnyCerts)
    {
        try {
            KeyManager[] keyManagers = presence(createKeyManagers(keyStorePath, keyStoreType, keyStorePassword));
            List<TrustManager> trustManagerList = new ArrayList<>(Arrays.asList(createTrustManagers(trustStorePath, trustStoreType, trustStorePassword)));
            if (trustAnyCerts) {
                trustManagerList.add(createAllCertsTrustManager());
            }
            TrustManager[] trustManagers = presence(trustManagerList.toArray(new TrustManager[0]));
            if (keyManagers == null && trustManagers == null) {
               return null;
            }
            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(keyManagers, trustManagers, new java.security.SecureRandom());
            return sslContext;
        }
        catch (IOException | UnrecoverableKeyException | CertificateException | KeyStoreException |
                 NoSuchAlgorithmException | KeyManagementException e) {
            throw new ConfigException(e);
        }
    }

    private static TrustManager[] createTrustManagers(Path trustStorePath, String trustStoreType, String trustStorePassword) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException
    {
        if (trustStorePath == null) {
            return new TrustManager[0];
        }

        try (InputStream trustStoreInputStream = Files.newInputStream(trustStorePath)) {
            KeyStore trustStore = KeyStore.getInstance(trustStoreType != null ? trustStoreType : KeyStore.getDefaultType());
            trustStore.load(trustStoreInputStream, toCharArray(trustStorePassword));
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            return tmf.getTrustManagers();
        }
    }

    private static KeyManager[] createKeyManagers(Path keyStorePath, String keyStoreType, String keyStorePassword) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException
    {
        if (keyStorePath == null) {
            return new KeyManager[0];
        }

        try (InputStream keyStoreInputStream = Files.newInputStream(keyStorePath)) {
            KeyStore keyStore = KeyStore.getInstance(keyStoreType != null ? keyStoreType : KeyStore.getDefaultType());
            keyStore.load(keyStoreInputStream, toCharArray(keyStorePassword));
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, toCharArray(keyStorePassword));
            return kmf.getKeyManagers();
        }
    }

    private static TrustManager createAllCertsTrustManager()
    {
        return new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers()
            {
                return new X509Certificate[0];
            }

            public void checkClientTrusted(X509Certificate[] certs, String authType)
            {
            }

            public void checkServerTrusted(X509Certificate[] certs, String authType)
            {
            }
        };
    }

    private static <T> T[] presence(T[] arg)
    {
        return (arg != null && arg.length > 0) ? arg : null;
    }

    private static Path toPath(LocalFile localFile)
    {
        return localFile != null ? localFile.getPath() : null;
    }

    private static char[] toCharArray(String str)
    {
        return str != null ? str.toCharArray() : null;
    }
}
