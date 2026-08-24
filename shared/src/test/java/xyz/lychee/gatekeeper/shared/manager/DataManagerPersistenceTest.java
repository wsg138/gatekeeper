package xyz.lychee.gatekeeper.shared.manager;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import xyz.lychee.gatekeeper.shared.objects.EnumAccess;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertTrue;

class DataManagerPersistenceTest {
    @TempDir
    Path tempDir;

    @Test
    void recreatesDeletedDataDirectoryBeforeSaving() throws Exception {
        DataManager manager = new DataManager();
        Path dataPath = this.tempDir.resolve("plugins/gatekeeper/data.json").toAbsolutePath().normalize();

        setField(manager, "dataPath", dataPath);
        setField(manager, "logger", Logger.getLogger("DataManagerPersistenceTest"));

        manager.updateNickname("ExamplePlayer", EnumAccess.WHITELIST.getType());
        assertTrue(Files.exists(dataPath));

        Path pluginFolder = dataPath.getParent();
        try (var paths = Files.walk(pluginFolder)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            });
        }

        manager.saveDataFile();

        assertTrue(Files.isDirectory(pluginFolder));
        assertTrue(Files.exists(dataPath));
        assertTrue(Files.readString(dataPath).contains("exampleplayer"));
    }

    private static void setField(DataManager manager, String fieldName, Object value) throws Exception {
        Field field = DataManager.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(manager, value);
    }
}
