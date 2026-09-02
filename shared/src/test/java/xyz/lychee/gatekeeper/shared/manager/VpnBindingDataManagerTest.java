package xyz.lychee.gatekeeper.shared.manager;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VpnBindingDataManagerTest {
    @TempDir
    Path tempDir;

    @Test
    void enforcesOneAccountPerEndpointAndAllowsOnlyExactMatches() {
        DataManager manager = new DataManager();

        assertEquals(
                DataManager.VpnBindingUpdateResult.ADDED,
                manager.bindVpn("PowerHamad", "203.0.113.42")
        );
        assertEquals(
                DataManager.VpnBindingStatus.MATCHED,
                manager.resolveVpnBinding("PowerHamad", "203.0.113.42")
        );
        assertEquals(
                DataManager.VpnBindingStatus.RESERVED_FOR_OTHER,
                manager.resolveVpnBinding("SomeOtherPlayer", "203.0.113.42")
        );
        assertEquals(
                DataManager.VpnBindingStatus.NONE,
                manager.resolveVpnBinding("PowerHamad", "203.0.113.43")
        );
        assertEquals(
                DataManager.VpnBindingUpdateResult.ADDRESS_IN_USE,
                manager.bindVpn("SomeOtherPlayer", "203.0.113.42")
        );
    }

    @Test
    void updatingBindingReleasesOldEndpoint() {
        DataManager manager = new DataManager();
        manager.bindVpn("PowerHamad", "203.0.113.42");

        assertEquals(
                DataManager.VpnBindingUpdateResult.UPDATED,
                manager.bindVpn("PowerHamad", "203.0.113.43")
        );
        assertEquals("203.0.113.43", manager.getVpnBindingAddress("POWERHAMAD"));
        assertNull(manager.getVpnBindingOwner("203.0.113.42"));
        assertEquals(
                DataManager.VpnBindingStatus.MATCHED,
                manager.resolveVpnBinding("powerhamad", "203.0.113.43")
        );
    }

    @Test
    void vpnBindingsPersistAndReload() throws Exception {
        Path dataPath = this.tempDir.resolve("plugins/gatekeeper/data.json").toAbsolutePath().normalize();

        DataManager writer = new DataManager();
        setStorage(writer, dataPath);
        writer.bindVpn("PowerHamad", "203.000.113.042");

        assertTrue(Files.exists(dataPath));
        String saved = Files.readString(dataPath);
        assertTrue(saved.contains("vpn_bindings"));
        assertTrue(saved.contains("powerhamad"));
        assertTrue(saved.contains("203.0.113.42"));

        DataManager reader = new DataManager();
        setStorage(reader, dataPath);
        reader.reload(null);

        assertEquals("203.0.113.42", reader.getVpnBindingAddress("PowerHamad"));
        assertEquals("powerhamad", reader.getVpnBindingOwner("203.0.113.42"));
    }

    private static void setStorage(DataManager manager, Path dataPath) throws Exception {
        setField(manager, "dataPath", dataPath);
        setField(manager, "logger", Logger.getLogger("VpnBindingDataManagerTest"));
    }

    private static void setField(DataManager manager, String fieldName, Object value) throws Exception {
        Field field = DataManager.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(manager, value);
    }
}
