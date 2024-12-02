package org.embulk.input.mongodb;

import org.embulk.EmbulkTestRuntime;
import org.embulk.config.ConfigSource;
import org.embulk.spi.TestPageBuilderReader;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.lang.reflect.InvocationTargetException;

import static org.embulk.input.mongodb.ConfigUtil.DEFAULT_DATABASE;
import static org.embulk.input.mongodb.ConfigUtil.DEFAULT_HOST;
import static org.embulk.input.mongodb.ConfigUtil.DEFAULT_PASSWORD;
import static org.embulk.input.mongodb.ConfigUtil.DEFAULT_PORT;
import static org.embulk.input.mongodb.ConfigUtil.DEFAULT_USER;
import static org.embulk.input.mongodb.ConfigUtil.baseConfigSource;
import static org.embulk.input.mongodb.ConfigUtil.buildHosts;
import static org.embulk.input.mongodb.ConfigUtil.concatUri;
import static org.embulk.input.mongodb.ConfigUtil.key;
import static org.embulk.input.mongodb.ConfigUtil.tls;
import static org.embulk.input.mongodb.ConfigUtil.trust;
import static org.embulk.input.mongodb.ConfigUtil.trustAndKey;

public class TestMongodbInputPluginTlsConnection
{
    @Rule
    public EmbulkTestRuntime runtime = new EmbulkTestRuntime();

    private MongodbInputPlugin plugin;
    private TestPageBuilderReader.MockPageOutput output;
    private String uri;

   protected String port()
    {
        return DEFAULT_PORT;
    }

    protected Boolean isCAFileValidation()
    {
        // Specified version mongo db server may skip peer certificate validation.
        // https://nvd.nist.gov/vuln/detail/CVE-2024-1351
        return true;
    }

    @Before
    public void createResources() throws InvocationTargetException, NoSuchMethodException, IllegalAccessException
    {
        plugin = new MongodbInputPluginWithTimeout();
        output = new TestPageBuilderReader.MockPageOutput();
        uri = String.format("mongodb://%s:%s@%s:%s/%s",
                DEFAULT_USER, DEFAULT_PASSWORD, DEFAULT_HOST, port(), DEFAULT_DATABASE
        );
        cleanup();
    }

    @After
    public void dropResources() throws InvocationTargetException, NoSuchMethodException, IllegalAccessException
    {
        cleanup();
    }

    @Test
    public void testSuccessTlsTrueByUri() throws Exception
    {
        ConfigSource config = trustAndKey(baseConfigSource()).set("uri", tls(uri, true));
        testRunSuccess(config);
    }

    @Test
    public void testSuccessTlsTrueByHost() throws Exception
    {
        ConfigSource config = host(trustAndKey(baseConfigSource())).set("tls", "true");
        testRunSuccess(config);
    }

    @Test
    public void testSuccessTlsFalseByUri() throws Exception
    {
        ConfigSource config = baseConfigSource().set("uri", tls(uri, false));
        testRunSuccess(config);
    }

    @Test
    public void testSuccessTlsFalseByHost() throws Exception
    {
        final ConfigSource config = host(baseConfigSource()).set("tls", "false");
        testRunSuccess(config);
    }

    @Test
    public void testErrorNoAuthWithTlsTrueByUri()
    {
        ConfigSource config = baseConfigSource().set("uri", tls(uri, true));
        testRunTimeout(config);
    }

    @Test
    public void testErrorNoAuthWithTlsTrueByHost()
    {
        ConfigSource config = host(baseConfigSource()).set("tls", "true");
        testRunTimeout(config);
    }

    @Test
    public void testErrorOnlyKeyWithTlsTrueByUri()
    {
        ConfigSource config = key(baseConfigSource()).set("uri", tls(uri, true));
        testRunTimeout(config);
    }

    @Test
    public void testErrorOnlyKeyWithTlsTrueByHost()
    {
        ConfigSource config = key(host(baseConfigSource())).set("tls", "true");
        testRunTimeout(config);
    }

    @Test
    public void testErrorOnlyTrustWithTlsTrueByUri() throws Exception
    {
        ConfigSource config = trust(baseConfigSource()).set("uri", tls(uri, true));
        testRunTimeoutOnlyCAFileValidation(config);
    }

    @Test
    public void testErrorOnlyTrustWithTlsTrueByHost() throws Exception
    {
        ConfigSource config = trust(host(baseConfigSource())).set("tls", "true");
        testRunTimeoutOnlyCAFileValidation(config);
    }

    @Test
    public void testSuccessTlsTrueAndTlsInsecureWithKeyByUri() throws Exception
    {
        ConfigSource config = key(baseConfigSource())
                .set("uri", tls(uri, true))
                .set("tls_insecure", "true");
        testRunSuccess(config);
    }

    @Test
    public void testSuccessTlsTrueAndTlsInsecureWithKeyByHost() throws Exception
    {
        ConfigSource config = key(host(baseConfigSource()))
                .set("tls", "true")
                .set("tls_insecure", "true");
        testRunSuccess(config);
    }

    @Test
    public void testErrorTlsTrueAndTlsInsecureWithTrustByUri() throws Exception
    {
        ConfigSource config = trust(baseConfigSource())
                .set("uri", tls(uri, true))
                .set("tls_insecure", "true");
        testRunTimeoutOnlyCAFileValidation(config);
    }

    @Test
    public void testErrorTlsTrueAndTlsInsecureWithTrustByHost() throws Exception
    {
        ConfigSource config = trust(host(baseConfigSource()))
                .set("tls", "true")
                .set("tls_insecure", "true");
        testRunTimeoutOnlyCAFileValidation(config);
    }

    @Test
    public void testErrorTlsTrueAndTlsInsecureWithoutAuthByUri() throws Exception
    {
        ConfigSource config = baseConfigSource()
                .set("uri", tls(uri, true))
                .set("tls_insecure", "true");
        testRunTimeoutOnlyCAFileValidation(config);
    }

    @Test
    public void testErrorTlsTrueAndTlsInsecureWithoutAuthByHost() throws Exception
    {
        ConfigSource config = host(baseConfigSource())
                .set("tls", "true")
                .set("tls_insecure", "true");
        testRunTimeoutOnlyCAFileValidation(config);
    }

    @Test
    public void testErrorByTlsInsecureInParamsByUri() throws Exception
    {
        ConfigSource config = key(baseConfigSource())
                .set("uri", concatUri(uri, "tls=true", "tlsInsecure=true"));
        testRunTimeout(config);
    }

    @Test
    public void testErrorTlsTrueAndNoTlsInsecureWithKeyByUri() throws Exception
    {
        ConfigSource config = key(baseConfigSource()).set("uri", tls(uri, true));
        testRunTimeout(config);
    }

    @Test
    public void testErrorTlsTrueAndNoTlsInsecureWithKeyByHost() throws Exception
    {
        ConfigSource config = key(host(baseConfigSource())).set("tls", "true");
        testRunTimeout(config);
    }

    private ConfigSource host(ConfigSource configSource)
    {
        return ConfigUtil.host(configSource).set("hosts", buildHosts(DEFAULT_HOST, port()));
    }

    private void testRunSuccess(ConfigSource config) throws Exception
    {
        MongoUtil.testRunSuccess(plugin, output, config);
    }

    private void testRunTimeout(ConfigSource config)
    {
        MongoUtil.testRunTimeout(plugin, output, config);
    }

    private void testRunTimeoutOnlyCAFileValidation(ConfigSource config) throws Exception
    {
        if (isCAFileValidation()) {
            testRunTimeout(config);
        }
        else {
            testRunSuccess(config);
        }
    }

    private void cleanup() throws InvocationTargetException, NoSuchMethodException, IllegalAccessException
    {
       MongoUtil.cleanup(host(baseConfigSource()));
    }
}
