package org.embulk.input.mongodb;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mongodb.MongoOperationTimeoutException;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;
import org.embulk.config.ConfigException;
import org.embulk.config.ConfigSource;
import org.embulk.config.TaskReport;
import org.embulk.config.TaskSource;
import org.embulk.spi.Column;
import org.embulk.spi.InputPlugin;
import org.embulk.spi.Schema;
import org.embulk.spi.TestPageBuilderReader;
import org.embulk.spi.type.Types;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.TimeZone;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.embulk.input.mongodb.ConfigUtil.baseConfigSource;
import static org.embulk.input.mongodb.ConfigUtil.toTask;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class MongoUtil
{
    private MongoUtil()
    {
        throw new UnsupportedOperationException();
    }

    public static MongoDatabase fetchMongoDB(MongodbInputPlugin plugin, PluginTask task) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException
    {
        Method method = MongodbInputPlugin.class.getDeclaredMethod("connect", PluginTask.class);
        method.setAccessible(true);
        return (MongoDatabase) method.invoke(plugin, task);
    }

    public static void createCollection(MongodbInputPlugin plugin, PluginTask task, String collectionName) throws InvocationTargetException, NoSuchMethodException, IllegalAccessException
    {
        fetchMongoDB(plugin, task).createCollection(fetchCollectionName(task, collectionName));
    }

    public static void dropCollection(MongodbInputPlugin plugin, PluginTask task, String collectionName) throws InvocationTargetException, NoSuchMethodException, IllegalAccessException
    {
        fetchMongoDB(plugin, task).getCollection(fetchCollectionName(task, collectionName)).drop();
    }

    public static void insertDocuments(MongodbInputPlugin plugin, PluginTask task, String collectionName, List<Document> documents) throws Exception
    {
        fetchMongoDB(plugin, task).getCollection(fetchCollectionName(task, collectionName)).insertMany(documents);
    }

    public static void insertDocuments(MongodbInputPlugin plugin, PluginTask task, String collectionName, Document... documents) throws Exception
    {
        insertDocuments(plugin, task, collectionName, Arrays.asList(documents));
    }

    private static String fetchCollectionName(PluginTask task, String collectionName)
    {
        return Objects.requireNonNull(collectionName != null ? collectionName : task.getCollection());
    }

    public static List<JsonNode> fetchRecords(TestPageBuilderReader.MockPageOutput output)
    {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setDateFormat(MongoUtil.getUTCDateFormat());
        return Pages.toObjects(getFieldSchema(), output.pages).stream().map(x -> {
            try {
                return mapper.readTree(x[0].toString());
            }
            catch (IOException e) {
                throw new RuntimeException(e);
            }
        }).collect(Collectors.toList());
    }

    public static Schema getFieldSchema()
    {
        return new Schema(Collections.singletonList(new Column(0, "record", Types.JSON)));
    }

    private static DateFormat getUTCDateFormat()
    {
        DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", java.util.Locale.ENGLISH);
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        return dateFormat;
    }

    public static void testRunSuccess(MongodbInputPlugin plugin, TestPageBuilderReader.MockPageOutput output, ConfigSource config) throws Exception
    {
        MongoUtil.insertDocuments(plugin, ConfigUtil.toTask(config), null, new Document("data", "x509"));
        plugin.transaction(config, new MongoUtil.Control(plugin, output));
        final List<JsonNode> records = MongoUtil.fetchRecords(output);
        assertEquals(records.size(), 1);

        JsonNode node = records.get(0);
        assertEquals(2, node.size());
        assertTrue(node.has("_id"));
        assertEquals("x509", node.get("data").asText());
    }

    public static void testRunTimeout(MongodbInputPlugin plugin, TestPageBuilderReader.MockPageOutput output, ConfigSource config)
    {
        ConfigException e = assertThrows(ConfigException.class, () -> plugin.transaction(config, new MongoUtil.Control(plugin, output)));
        assertEquals(MongoOperationTimeoutException.class, e.getCause().getClass());
    }

    public static void cleanup(ConfigSource configSource) throws InvocationTargetException, NoSuchMethodException, IllegalAccessException
    {
        MongoUtil.dropCollection(new MongodbInputPluginWithTimeout(), toTask(configSource), null);
    }

    public static void cleanup() throws InvocationTargetException, NoSuchMethodException, IllegalAccessException
    {
        cleanup(baseConfigSource().set("uri", ConfigUtil.USER_PASSWORD_URI));
    }

    public static class Control implements InputPlugin.Control
    {
        final MongodbInputPlugin plugin;
        final TestPageBuilderReader.MockPageOutput output;

        public Control(MongodbInputPlugin plugin, TestPageBuilderReader.MockPageOutput output)
        {
            this.plugin = plugin;
            this.output = output;
        }

        @Override
        public List<TaskReport> run(TaskSource taskSource, Schema schema, int taskCount)
        {
            return IntStream.range(0, taskCount).mapToObj(i -> plugin.run(taskSource, schema, i, output)).collect(Collectors.toList());
        }
    }
}
