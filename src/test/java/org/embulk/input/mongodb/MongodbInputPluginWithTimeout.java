package org.embulk.input.mongodb;

import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;

import java.util.concurrent.TimeUnit;

public class MongodbInputPluginWithTimeout extends MongodbInputPlugin
{
    @Override
    protected MongoClientSettings createMongoClientSettings(PluginTask task)
    {
        return MongoClientSettings.builder(super.createMongoClientSettings(task))
                .timeout(fetchTimeoutms(), TimeUnit.MILLISECONDS)
                .build();
    }

    @Override
    protected ConnectionString newConnectionString(PluginTask task)
    {
        return new ConnectionStringWithTimeout(task.getUri().get());
    }

    private static class ConnectionStringWithTimeout extends ConnectionString
    {
        public ConnectionStringWithTimeout(String connectionString)
        {
            super(connectionString);
        }

        @Override
        public Long getTimeout()
        {
            return fetchTimeoutms();
        }
    }

    public static long fetchTimeoutms()
    {
        String testTimeoutms = System.getenv("TEST_TIMEOUTMS");
        return Integer.parseInt(testTimeoutms != null ? testTimeoutms : "1000");
    }
}
