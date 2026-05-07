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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.UnrecoverableKeyException;
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

    static TrustManager[] createTrustManagers(Path trustStorePath, String trustStoreType, String trustStorePassword) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException
    {
        if (trustStorePath == null) {
            return new TrustManager[0];
        }

        TrustManager[] defaultTrustManagers = createDefaultTrustManagers();
        try (InputStream trustStoreInputStream = Files.newInputStream(trustStorePath)) {
            KeyStore trustStore = KeyStore.getInstance(trustStoreType != null ? trustStoreType : KeyStore.getDefaultType());
            trustStore.load(trustStoreInputStream, toCharArray(trustStorePassword));
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            return mergeTrustManagers(defaultTrustManagers, tmf.getTrustManagers());
        }
    }

    static TrustManager[] createDefaultTrustManagers() throws NoSuchAlgorithmException, KeyStoreException
    {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
        return tmf.getTrustManagers();
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

    private static TrustManager[] mergeTrustManagers(TrustManager[] defaultTrustManagers, TrustManager[] customTrustManagers)
    {
        X509TrustManager mergedTrustManager = createMergedX509TrustManager(defaultTrustManagers, customTrustManagers);
        if (mergedTrustManager == null) {
            return customTrustManagers;
        }
        return new TrustManager[] { mergedTrustManager };
    }

    private static X509TrustManager createMergedX509TrustManager(TrustManager[] defaultTrustManagers, TrustManager[] customTrustManagers)
    {
        List<X509TrustManager> trustManagers = new ArrayList<>();
        trustManagers.addAll(extractX509TrustManagers(defaultTrustManagers));
        trustManagers.addAll(extractX509TrustManagers(customTrustManagers));
        if (trustManagers.isEmpty()) {
            return null;
        }
        return new X509TrustManager() {
            @Override
            public X509Certificate[] getAcceptedIssuers()
            {
                List<X509Certificate> issuers = new ArrayList<>();
                for (X509TrustManager trustManager : trustManagers) {
                    issuers.addAll(Arrays.asList(trustManager.getAcceptedIssuers()));
                }
                return issuers.toArray(new X509Certificate[0]);
            }

            @Override
            public void checkClientTrusted(X509Certificate[] certs, String authType) throws CertificateException
            {
                checkTrusted(trustManagers, certs, authType, true);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException
            {
                checkTrusted(trustManagers, certs, authType, false);
            }
        };
    }

    private static List<X509TrustManager> extractX509TrustManagers(TrustManager[] trustManagers)
    {
        List<X509TrustManager> x509TrustManagers = new ArrayList<>();
        for (TrustManager trustManager : trustManagers) {
            if (trustManager instanceof X509TrustManager) {
                x509TrustManagers.add((X509TrustManager) trustManager);
            }
        }
        return x509TrustManagers;
    }

    private static void checkTrusted(List<X509TrustManager> trustManagers, X509Certificate[] certs, String authType, boolean client) throws CertificateException
    {
        CertificateException lastException = null;
        for (X509TrustManager trustManager : trustManagers) {
            try {
                if (client) {
                    trustManager.checkClientTrusted(certs, authType);
                }
                else {
                    trustManager.checkServerTrusted(certs, authType);
                }
                return;
            }
            catch (CertificateException e) {
                lastException = e;
            }
        }
        if (lastException != null) {
            throw lastException;
        }
        throw new CertificateException("No X509TrustManager available");
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
