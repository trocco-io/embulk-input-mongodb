package org.embulk.input.mongodb;

import com.google.common.collect.ImmutableMap;
import org.embulk.config.ConfigSource;
import org.embulk.util.config.ConfigMapperFactory;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import static java.util.Collections.singletonList;

public class ConfigUtil
{
    private static final ConfigMapperFactory CONFIG_MAPPER_FACTORY = ConfigMapperFactory.builder().addDefaultModules().build();

    private ConfigUtil()
    {
        throw new UnsupportedOperationException();
    }

    public static PluginTask toTask(ConfigSource configSource)
    {
        return CONFIG_MAPPER_FACTORY.createConfigMapper().map(configSource, PluginTask.class);
    }

    public static ConfigSource baseConfigSource()
    {
        return CONFIG_MAPPER_FACTORY.newConfigSource()
                .set("collection", DEFAULT_COLLECTION);
    }

    public static String DEFAULT_USER = "mongo_user";
    public static String DEFAULT_PASSWORD = "dbpass";
    public static String DEFAULT_HOST = "localhost";
    public static String DEFAULT_PORT = "27017";
    public static List<ImmutableMap<String, String>> DEFAULT_HOSTS = buildHosts(DEFAULT_HOST, DEFAULT_PORT);
    public static String DEFAULT_DATABASE = "mydb";
    public static String DEFAULT_COLLECTION = "my_collection";

    public static String CA_FILE_VULNERABILITY_PORT = "37017";

    public static String USER_PASSWORD_URI = String.format("mongodb://%s:%s@%s:%s/%s",
            DEFAULT_USER, DEFAULT_PASSWORD, DEFAULT_HOST, DEFAULT_PORT, DEFAULT_DATABASE
    );

    public static List<ImmutableMap<String, String>> buildHosts(String host, String port)
    {
        return singletonList(ImmutableMap.of("host", host, "port", port));
    }

    public static ConfigSource host(ConfigSource configSource)
    {
        return configSource
                .set("hosts", DEFAULT_HOSTS)
                .set("database", DEFAULT_DATABASE)
                .set("user", DEFAULT_USER)
                .set("password", DEFAULT_PASSWORD);
    }

    public static String KEY_STORE_FILE_PATH = Objects.requireNonNull(TestMongodbInputPlugin.class.getResource("/keystore.p12")).getPath();
    public static String TRUST_STORE_FILE_PATH = Objects.requireNonNull(TestMongodbInputPlugin.class.getResource("/truststore.jks")).getPath();
    public static String NO_KEY_AND_TRUST_STORE_FILE_PATH = Objects.requireNonNull(TestMongodbInputPlugin.class.getResource("/mongo.crt")).getPath();

    public static ConfigSource key(ConfigSource configSource)
    {
        return configSource
                .set("key_store", KEY_STORE_FILE_PATH)
                .set("key_store_type", "PKCS12")
                .set("key_store_password", "password");
    }

    public static ConfigSource trust(ConfigSource configSource)
    {
        return configSource
                .set("trust_store", TRUST_STORE_FILE_PATH)
                .set("trust_store_type", "JKS")
                .set("trust_store_password", "password");
    }

    public static ConfigSource trustAndKey(ConfigSource configSource)
    {
        return trust(key(configSource));
    }

    private static String _concatUri(String uri, String query)
    {
        return uri + (uri.contains("?") ? "&" : "?") + query;
    }

    public static String concatUri(String uri, String... queries)
    {
        return Arrays.stream(queries).reduce(uri, ConfigUtil::_concatUri);
    }

    public static String concatUri(String uri, String key, Boolean on)
    {
        return concatUri(uri, key + "=" +  (on ? "true" : "false"));
    }

    public static String tls(String uri, Boolean on)
    {
        return concatUri(uri, "tls", on);
    }
}
