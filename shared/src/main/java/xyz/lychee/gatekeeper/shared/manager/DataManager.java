package xyz.lychee.gatekeeper.shared.manager;

import com.grack.nanojson.JsonObject;
import com.grack.nanojson.JsonParser;
import com.grack.nanojson.JsonParserException;
import com.grack.nanojson.JsonWriter;
import it.unimi.dsi.fastutil.ints.Int2ByteMap;
import it.unimi.dsi.fastutil.ints.Int2ByteMaps;
import it.unimi.dsi.fastutil.ints.Int2ByteOpenHashMap;
import it.unimi.dsi.fastutil.objects.Object2ByteMap;
import it.unimi.dsi.fastutil.objects.Object2ByteMaps;
import it.unimi.dsi.fastutil.objects.Object2ByteOpenHashMap;
import lombok.Getter;
import xyz.lychee.gatekeeper.shared.Gatekeeper;
import xyz.lychee.gatekeeper.shared.objects.AbstractManager;
import xyz.lychee.gatekeeper.shared.objects.EnumAccess;
import xyz.lychee.gatekeeper.shared.objects.GeoConnection;
import xyz.lychee.gatekeeper.shared.util.AddressUtils;
import xyz.lychee.gatekeeper.shared.util.MathUtils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

@Getter
public class DataManager extends AbstractManager implements Runnable {
    public static final DataManager INSTANCE = new DataManager();

    private final Int2ByteMap addresses = Int2ByteMaps.synchronize(new Int2ByteOpenHashMap());
    private final Int2ByteMap asns = Int2ByteMaps.synchronize(new Int2ByteOpenHashMap());
    private final Object2ByteMap<String> nicknames = Object2ByteMaps.synchronize(new Object2ByteOpenHashMap<>());

    private Logger logger;
    private Path dataPath;

    public DataManager() {
        this.nicknames.defaultReturnValue((byte) 0);
        this.addresses.defaultReturnValue((byte) 0);
        this.asns.defaultReturnValue((byte) 0);
    }

    @Override
    public synchronized boolean load(Gatekeeper<?> plugin) throws IOException, JsonParserException {
        this.logger = plugin.logger();
        this.dataPath = new File(plugin.dataFolder(), "data.json").toPath().toAbsolutePath().normalize();
        this.ensureStorageDirectory();

        if (Files.exists(this.dataPath)) {
            this.applyLoadedData(this.readDataFile());
        } else {
            this.clearMemory();
        }
        return true;
    }

    @Override
    public synchronized boolean unload(Gatekeeper<?> plugin) {
        this.saveDataFile();
        return true;
    }

    @Override
    public synchronized boolean reload(Gatekeeper<?> plugin) throws IOException, JsonParserException {
        if (Files.exists(this.dataPath)) {
            LoadedData loaded = this.readDataFile();
            this.applyLoadedData(loaded);
        } else {
            this.clearMemory();
        }
        return true;
    }

    private LoadedData readDataFile() throws IOException, JsonParserException {
        Int2ByteOpenHashMap loadedAddresses = new Int2ByteOpenHashMap();
        Int2ByteOpenHashMap loadedAsns = new Int2ByteOpenHashMap();
        Object2ByteOpenHashMap<String> loadedNicknames = new Object2ByteOpenHashMap<>();

        try (InputStream is = Files.newInputStream(this.dataPath)) {
            JsonObject json = JsonParser.object().from(is);

            JsonObject addressesObj = json.getObject("addresses");
            if (addressesObj != null) {
                for (Map.Entry<String, Object> entry : addressesObj.entrySet()) {
                    try {
                        Object value = entry.getValue();
                        if (value instanceof Number) {
                            loadedAddresses.put(Integer.parseInt(entry.getKey()), ((Number) value).byteValue());
                        }
                    } catch (NumberFormatException ignored) {}
                }
            }

            JsonObject nicknamesObj = json.getObject("nicknames");
            if (nicknamesObj != null) {
                for (Map.Entry<String, Object> entry : nicknamesObj.entrySet()) {
                    Object value = entry.getValue();
                    if (value instanceof Number) {
                        loadedNicknames.put(normalizeNickname(entry.getKey()), ((Number) value).byteValue());
                    }
                }
            }

            JsonObject asnsObj = json.getObject("asns");
            if (asnsObj != null) {
                for (Map.Entry<String, Object> entry : asnsObj.entrySet()) {
                    try {
                        Object value = entry.getValue();
                        if (value instanceof Number) {
                            int asn = Integer.parseInt(entry.getKey());
                            if (asn > 0) loadedAsns.put(asn, ((Number) value).byteValue());
                        }
                    } catch (NumberFormatException ignored) {}
                }
            }
        }

        return new LoadedData(loadedAddresses, loadedAsns, loadedNicknames);
    }

    private void applyLoadedData(LoadedData loaded) {
        this.clearMemory();
        this.addresses.putAll(loaded.addresses);
        this.asns.putAll(loaded.asns);
        this.nicknames.putAll(loaded.nicknames);
    }

    private void clearMemory() {
        this.addresses.clear();
        this.nicknames.clear();
        this.asns.clear();
    }

    public synchronized void saveDataFile() {
        if (this.dataPath == null) return;

        JsonObject json = new JsonObject();
        json.put("addresses", this.addresses);
        json.put("asns", this.asns);
        json.put("nicknames", this.nicknames);

        try {
            this.writeDataFileWithRecovery(JsonWriter.string(json));
        } catch (IOException ex) {
            if (this.logger != null) {
                this.logger.log(Level.SEVERE, "Failed to save database file " + this.dataPath, ex);
            }
        }
    }

    private void writeDataFileWithRecovery(String contents) throws IOException {
        IOException firstMissingPathFailure = null;

        for (int attempt = 0; attempt < 2; attempt++) {
            Path tempPath = this.dataPath.resolveSibling(this.dataPath.getFileName() + ".tmp");
            try {
                this.ensureStorageDirectory();
                Files.writeString(tempPath, contents);
                this.moveIntoPlace(tempPath);
                return;
            } catch (NoSuchFileException ex) {
                this.deleteTempQuietly(tempPath);
                if (attempt == 0) {
                    firstMissingPathFailure = ex;
                    continue;
                }
                if (firstMissingPathFailure != null) ex.addSuppressed(firstMissingPathFailure);
                throw ex;
            } catch (IOException ex) {
                this.deleteTempQuietly(tempPath);
                throw ex;
            }
        }
    }

    private void ensureStorageDirectory() throws IOException {
        Path parent = this.dataPath.getParent();
        if (parent != null) Files.createDirectories(parent);
    }

    private void moveIntoPlace(Path tempPath) throws IOException {
        try {
            Files.move(
                    tempPath,
                    this.dataPath,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING
            );
        } catch (AtomicMoveNotSupportedException ignored) {
            Files.move(tempPath, this.dataPath, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private void deleteTempQuietly(Path tempPath) {
        try {
            Files.deleteIfExists(tempPath);
        } catch (IOException ignored) {}
    }

    public synchronized void updateAddress(int addressData, byte accessType) {
        if (accessType == 0) this.addresses.remove(addressData);
        else this.addresses.put(addressData, accessType);
        this.saveDataFile();
    }

    public synchronized void updateAsn(int asn, byte accessType) {
        if (asn <= 0) return;
        if (accessType == 0) this.asns.remove(asn);
        else this.asns.put(asn, accessType);
        this.saveDataFile();
    }

    public synchronized void updateNickname(String nickname, byte accessType) {
        String normalized = normalizeNickname(nickname);
        if (accessType == 0) this.nicknames.removeByte(normalized);
        else this.nicknames.put(normalized, accessType);
        this.saveDataFile();
    }

    public synchronized boolean updateAndCheckAccess(GeoConnection connection, EnumAccess targetAccess) {
        byte access = this.nicknames.getByte(normalizeNickname(connection.getName()));
        if (access == 0 && connection.isIpv4()) {
            access = this.addresses.get(connection.getAddressData());
        }
        if (access == 0 && connection.getAsn() > 0) {
            access = this.asns.get(connection.getAsn());
        }
        if (access != 0) {
            connection.setAccess(EnumAccess.getByType(access));
            return access == targetAccess.getType();
        }
        return false;
    }

    public synchronized byte resolveAccess(String target) {
        if (AddressUtils.isIpv4(target)) {
            int addressData = AddressUtils.ipv4ToInt(target);
            return this.addresses.getOrDefault(addressData, (byte) 0);
        } else if (MathUtils.isInteger(target)) {
            int asn = Integer.parseInt(target);
            return asn > 0 ? this.asns.getOrDefault(asn, (byte) 0) : 0;
        } else {
            return this.nicknames.getOrDefault(normalizeNickname(target), (byte) 0);
        }
    }

    @Override
    public void run() {
        this.saveDataFile();
    }

    private static String normalizeNickname(String nickname) {
        return nickname == null ? "" : nickname.toLowerCase(Locale.ROOT);
    }

    private static final class LoadedData {
        private final Int2ByteOpenHashMap addresses;
        private final Int2ByteOpenHashMap asns;
        private final Object2ByteOpenHashMap<String> nicknames;

        private LoadedData(
                Int2ByteOpenHashMap addresses,
                Int2ByteOpenHashMap asns,
                Object2ByteOpenHashMap<String> nicknames
        ) {
            this.addresses = addresses;
            this.asns = asns;
            this.nicknames = nicknames;
        }
    }
}
