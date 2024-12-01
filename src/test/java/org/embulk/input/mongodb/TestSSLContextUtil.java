package org.embulk.input.mongodb;

import org.embulk.EmbulkTestRuntime;
import org.embulk.config.ConfigException;
import org.embulk.config.ConfigSource;
import org.embulk.util.config.ConfigMapperFactory;
import org.junit.Rule;
import org.junit.Test;

import javax.net.ssl.SSLContext;

import java.util.Objects;
import java.util.function.Function;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class TestSSLContextUtil
{
    private static final ConfigMapperFactory CONFIG_MAPPER_FACTORY = ConfigMapperFactory.builder().addDefaultModules().build();

    @Rule
    public EmbulkTestRuntime runtime = new EmbulkTestRuntime();

    @Test
    public void testDefault()
    {
        assertNotNull(create(null));
    }

    @Test
    public void testNoKeyStore()
    {
        assertNotNull(create(x -> x.set("key_store", null)));
    }

    @Test
    public void testNoTrustStore()
    {
        assertNotNull(create(x -> x.set("trust_store", null)));
    }

    @Test
    public void testNoKeyStoreAndTrustStore()
    {
        assertNull(create(x -> x.set("key_store", null).set("trust_store", null)));
    }

    @Test
    public void testNoKeyStoreAndTrustStoreButTlsInsecureTrue()
    {
        assertNotNull(create(x -> x.set("key_store", null).set("trust_store", null).set("tls_insecure", true)));
    }

    @Test(expected = ConfigException.class)
    public void testKeyStoreInvalid()
    {
        create(x -> x.set("key_store", "invalid"));
    }

    @Test(expected = ConfigException.class)
    public void testTrustStoreInvalid()
    {
        create(x -> x.set("trust_store", "invalid"));
    }

    @Test(expected = ConfigException.class)
    public void testKeyStoreTypeInvalid()
    {
        create(x -> x.set("key_store_type", "invalid"));
    }

    @Test(expected = ConfigException.class)
    public void testTrustStoreTypeInvalid()
    {
        create(x -> x.set("trust_store_type", "invalid"));
    }

    @Test(expected = ConfigException.class)
    public void testKeyStorePasswordInvalid()
    {
        create(x -> x.set("key_store_password", "invalid"));
    }

    @Test(expected = ConfigException.class)
    public void testTrustStorePasswordInvalid()
    {
        create(x -> x.set("trust_store_password", "invalid"));
    }

    private SSLContext create(Function<ConfigSource, ConfigSource> converter)
    {
        String p12FilePath = Objects.requireNonNull(getClass().getResource("/keystore.p12")).getPath();
        String jksFilePath = Objects.requireNonNull(getClass().getResource("/truststore.jks")).getPath();
        ConfigSource config = CONFIG_MAPPER_FACTORY.newConfigSource()
                .set("collection", "test")
                .set("key_store", p12FilePath)
                .set("key_store_type", "PKCS12")
                .set("key_store_password", "password")
                .set("trust_store", jksFilePath)
                .set("trust_store_type", "JKS")
                .set("trust_store_password", "password");
        if (converter != null) {
            config = converter.apply(config);
        }
        final PluginTask task = CONFIG_MAPPER_FACTORY.createConfigMapper().map(config, PluginTask.class);
        return SSLContextUtil.createContext(task);
    }
}
