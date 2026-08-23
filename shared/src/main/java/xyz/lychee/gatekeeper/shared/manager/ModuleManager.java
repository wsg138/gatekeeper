package xyz.lychee.gatekeeper.shared.manager;

import lombok.Getter;
import xyz.lychee.gatekeeper.shared.Gatekeeper;
import xyz.lychee.gatekeeper.shared.modules.*;
import xyz.lychee.gatekeeper.shared.objects.AbstractManager;
import xyz.lychee.gatekeeper.shared.objects.AbstractModule;
import xyz.lychee.gatekeeper.shared.util.TimingUtil;

import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

@Getter
public class ModuleManager extends AbstractManager {
    public static ModuleManager INSTANCE = new ModuleManager();

    private final Set<AbstractModule> allChecks = new LinkedHashSet<>();
    private final HashMap<Class<? extends AbstractModule>, AbstractModule> checksMap = new HashMap<>();
    private final ReentrantReadWriteLock lifecycleLock = new ReentrantReadWriteLock();
    private volatile List<AbstractModule> loadedChecks = Collections.emptyList();

    @Override
    public boolean load(Gatekeeper<?> plugin) {
        this.register(
                new AccountLimitModule(plugin),
                new BlacklistModule(plugin),
                new CountryFilterModule(plugin),
                new RateLimitModule(plugin),
                new ReputationModule(plugin),
                new AntiVpnModule(plugin),
                new IpFilterModule(plugin),
                new RiskModule(plugin)
        );
        this.reload(plugin);
        return true;
    }

    @Override
    public boolean unload(Gatekeeper<?> plugin) {
        Lock lock = this.lifecycleLock.writeLock();
        lock.lock();
        try {
            for (AbstractModule module : this.loadedChecks) {
                try {
                    module.unload();
                } catch (Exception ex) {
                    module.getGatekeeper().logger().info(" &8• &cSkipping module " + module.getName() + ", reason: " + ex.getMessage());
                }
                module.setLoaded(false);
            }
            this.loadedChecks = Collections.emptyList();
            this.allChecks.clear();
            this.checksMap.clear();
            return true;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public boolean reload(Gatekeeper<?> plugin) {
        Lock lock = this.lifecycleLock.writeLock();
        lock.lock();
        try {
            List<AbstractModule> nextLoaded = new ArrayList<>();
            for (AbstractModule module : this.allChecks) {
                try {
                    TimingUtil t = TimingUtil.startNew();
                    if (module.isLoaded()) module.unload();
                    boolean success = module.loadAllConfig();
                    if (success) {
                        nextLoaded.add(module);
                        module.getGatekeeper().logger().info(" &8• &rSuccessfully loaded module " + module.getName() + " in " + t.stop() + ".");
                    }
                    module.setLoaded(success);
                } catch (Exception ex) {
                    module.setLoaded(false);
                    module.getGatekeeper().logger().info(" &8• &cSkipping module " + module.getName() + ", reason: " + ex.getMessage());
                }
            }
            nextLoaded.sort(Comparator.comparingInt(AbstractModule::getPriority));
            this.loadedChecks = Collections.unmodifiableList(nextLoaded);
            return true;
        } finally {
            lock.unlock();
        }
    }

    public void register(AbstractModule... checks) {
        Lock lock = this.lifecycleLock.writeLock();
        lock.lock();
        try {
            this.checksMap.clear();
            this.allChecks.clear();
            for (AbstractModule check : checks) {
                this.checksMap.put(check.getClass(), check);
                this.allChecks.add(check);
            }
        } finally {
            lock.unlock();
        }
    }

    public Lock readLock() {
        return this.lifecycleLock.readLock();
    }

    public <T extends AbstractModule> T getCheck(Class<T> clazz) {
        return clazz.cast(this.checksMap.get(clazz));
    }
}
