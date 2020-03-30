import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileTime;
import java.util.HashMap;
import java.util.Map;

import org.apache.kafka.common.security.auth.KafkaPrincipal;

import io.aiven.kafka.auth.AivenKafkaPrincipalBuilder;
import io.aiven.kafka.auth.utils.TimeWithTimer;
import io.aiven.kafka.auth.utils.Timer;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.anyLong;

@RunWith(MockitoJUnitRunner.class)
public class AivenKafkaPrincipalBuilderTest {
    static final String MAPPING_JSON = "["
        + "{\"subject_matcher\":\"^CN=test1-(.*)\","
        + "\"principal_name\":\"user1\",\"principal_type\":\"ServiceUser\"}"
        + "{\"subject_matcher\":\"^CN=test2-(.*)\"}"
        + "]";

    static final String MAPPING_JSON_USER_1 =
        "[{\"subject_matcher\":\"^CN=test1-(.*)\","
            + "\"principal_name\":\"user1\","
            + "\"principal_type\":\"ServiceUser\"}]";

    static final String MAPPING_JSON_USER_2 =
        "[{\"subject_matcher\":\"^CN=test1-(.*)\","
            + "\"principal_name\":\"user2\","
            + "\"principal_type\":\"ServiceUser\"}]";

    Path configFilePath;
    AivenKafkaPrincipalBuilder builder;
    @Mock
    TimeWithTimer time;
    @Mock
    Timer timer;

    /**
     * Set up test.
     */
    @Before
    public void setUp() throws IOException {
        final Path tempPath = Files.createTempDirectory("test-aiven-kafka-principal-builder");
        configFilePath = Paths.get(tempPath.toString(), "mapping.json");

        Mockito.doReturn(timer).when(time).timer(anyLong());
        Mockito.doNothing().when(timer).update();
        // Always expire the timer, apart from some particular test cases.
        Mockito.doReturn(true).when(timer).isExpired();

        builder = new AivenKafkaPrincipalBuilder(time);
        final Map<String, String> configs = new HashMap<>();
        configs.put("aiven.kafka.principal.builder.configuration", configFilePath.toString());
        builder.configure(configs);
    }

    @Test
    public void testAivenKafkaPrincipalBuilder() throws IOException {
        writeConfig(MAPPING_JSON);

        // basic mapping ops
        KafkaPrincipal result = builder.mapSslPrincipal("CN=test1-basic");
        assertNotNull(result);
        assertEquals("ServiceUser", result.getPrincipalType());
        assertEquals("user1", result.getName());

        result = builder.mapSslPrincipal("CN=test2-basic");
        assertNotNull(result);
        assertEquals("User", result.getPrincipalType());
        assertEquals("CN=test2-basic", result.getName());

        result = builder.mapSslPrincipal("CN=unknown");
        assertNotNull(result);
        assertEquals("Invalid", result.getPrincipalType());
    }

    @Test
    public void testConfigReloadedWhenTimestampAreDifferent() throws IOException {
        writeConfig(MAPPING_JSON_USER_1);
        final FileTime originalLastModified = Files.getLastModifiedTime(configFilePath);

        assertEquals("user1", builder.mapSslPrincipal("CN=test1-basic").getName());

        writeConfig(MAPPING_JSON_USER_2);
        Files.setLastModifiedTime(configFilePath,
            FileTime.fromMillis(originalLastModified.toMillis() + 1));

        assertEquals("user2", builder.mapSslPrincipal("CN=test1-basic").getName());

        // Go back in time.
        writeConfig(MAPPING_JSON_USER_1);
        Files.setLastModifiedTime(configFilePath,
            FileTime.fromMillis(originalLastModified.toMillis() - 1));

        assertEquals("user1", builder.mapSslPrincipal("CN=test1-basic").getName());
    }

    @Test
    public void testConfigNotReloadedWhenTimestampAreSame() throws IOException {
        writeConfig(MAPPING_JSON_USER_1);
        final FileTime originalLastModified = Files.getLastModifiedTime(configFilePath);

        assertEquals("user1", builder.mapSslPrincipal("CN=test1-basic").getName());

        writeConfig(MAPPING_JSON_USER_2);
        Files.setLastModifiedTime(configFilePath, originalLastModified);

        // We use the fact that it returns the old principal as an indicator that the
        // new file content hasn't been loaded.
        assertEquals("user1", builder.mapSslPrincipal("CN=test1-basic").getName());
    }

    @Test
    public void testConfigReloadTimeout() throws IOException {
        Mockito.doReturn(true).when(timer).isExpired();

        writeConfig(MAPPING_JSON_USER_1);
        final FileTime originalLastModified = Files.getLastModifiedTime(configFilePath);
        assertEquals("user1", builder.mapSslPrincipal("CN=test1-basic").getName());

        // We updated the config, but the timer hasn't expired yet.
        Mockito.doReturn(false).when(timer).isExpired();
        writeConfig(MAPPING_JSON_USER_2);
        Files.setLastModifiedTime(configFilePath,
            FileTime.fromMillis(originalLastModified.toMillis() + 1));
        assertEquals("user1", builder.mapSslPrincipal("CN=test1-basic").getName());

        // Finally timer expires.
        Mockito.doReturn(true).when(timer).isExpired();
        assertEquals("user2", builder.mapSslPrincipal("CN=test1-basic").getName());
    }

    private void writeConfig(final String config) throws IOException {
        Files.write(configFilePath, config.getBytes());
    }
}
