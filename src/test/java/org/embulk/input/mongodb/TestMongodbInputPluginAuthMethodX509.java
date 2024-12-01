package org.embulk.input.mongodb;

import org.embulk.EmbulkTestRuntime;
import org.embulk.config.ConfigException;
import org.embulk.config.ConfigSource;
import org.embulk.spi.TestPageBuilderReader;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

import static org.embulk.input.mongodb.ConfigUtil.DEFAULT_DATABASE;
import static org.embulk.input.mongodb.ConfigUtil.DEFAULT_HOST;
import static org.embulk.input.mongodb.ConfigUtil.DEFAULT_HOSTS;
import static org.embulk.input.mongodb.ConfigUtil.DEFAULT_PORT;
import static org.embulk.input.mongodb.ConfigUtil.NO_KEY_AND_TRUST_STORE_FILE_PATH;
import static org.embulk.input.mongodb.MongoUtil.cleanup;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class TestMongodbInputPluginAuthMethodX509
{
    @Rule
    public EmbulkTestRuntime runtime = new EmbulkTestRuntime();

    private MongodbInputPlugin plugin;
    private TestPageBuilderReader.MockPageOutput output;
    private final String x509Uri = String.format("mongodb://%s:%s/%s?tls=true&authMechanism=MONGODB-X509",
            DEFAULT_HOST, DEFAULT_PORT, DEFAULT_DATABASE
    );

    @Before
    public void createResources() throws InvocationTargetException, NoSuchMethodException, IllegalAccessException
    {
        plugin = new MongodbInputPluginWithTimeout();
        output = new TestPageBuilderReader.MockPageOutput();

        cleanup();
    }

    @After
    public void dropResources() throws InvocationTargetException, NoSuchMethodException, IllegalAccessException
    {
        cleanup();
    }

    @Test
    public void testRunByUri() throws Exception
    {
        final ConfigSource config = baseConfigSource().set("uri", x509Uri);
        testRunSuccess(config);
    }

    @Test
    public void testRunByHost() throws Exception
    {
        final ConfigSource config = baseConfigSource()
                .set("hosts", DEFAULT_HOSTS)
                .set("database", DEFAULT_DATABASE)
                .set("tls", "true")
                .set("auth_method", "x-509");
        testRunSuccess(config);
    }

    @Test
    public void testInvalidKeyStore() throws Exception
    {
        testInvalidKeyOrTrustStore("key_store", "toDerInputStream");
    }

    @Test
    public void testInvalidTrustStore() throws Exception
    {
        testInvalidKeyOrTrustStore("trust_store", "Invalid keystore");
    }

    @Test
    public void testInvalidKeyStorePassword() throws Exception
    {
        testInvalidKeyOrTrustStorePassword("key_store_password");
    }

    @Test
    public void testInvalidTrustStorePassword() throws Exception
    {
        testInvalidKeyOrTrustStorePassword("trust_store_password");
    }

    private void testRunSuccess(ConfigSource config) throws Exception
    {
        MongoUtil.testRunSuccess(plugin, output, config);
    }

    private void testInvalidKeyOrTrustStore(String key, String messaage) throws Exception
    {
        final ConfigSource config = baseConfigSource()
                .set("uri", x509Uri)
                .set(key, NO_KEY_AND_TRUST_STORE_FILE_PATH);
        ConfigException e = assertThrows(ConfigException.class, () -> plugin.transaction(config, new MongoUtil.Control(plugin, output)));
        assertEquals(IOException.class, e.getCause().getClass());
        assertTrue(e.getCause().getMessage(), e.getCause().getMessage().contains(messaage));
    }

    private void testInvalidKeyOrTrustStorePassword(String key) throws Exception
    {
        final ConfigSource config = baseConfigSource()
                .set("uri", x509Uri)
                .set(key, "invalid");
        ConfigException e = assertThrows(ConfigException.class, () -> plugin.transaction(config, new MongoUtil.Control(plugin, output)));
        assertEquals(IOException.class, e.getCause().getClass());
        assertTrue(e.getCause().getMessage(), e.getCause().getMessage().contains("password"));
    }

    private ConfigSource baseConfigSource()
    {
        return ConfigUtil.trustAndKey(ConfigUtil.baseConfigSource());
    }
}
