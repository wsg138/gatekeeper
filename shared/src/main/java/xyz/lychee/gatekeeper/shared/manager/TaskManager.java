package xyz.lychee.gatekeeper.shared.manager;

import lombok.Getter;
import org.jetbrains.annotations.NotNull;
import xyz.lychee.gatekeeper.shared.Gatekeeper;
import xyz.lychee.gatekeeper.shared.objects.AbstractManager;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

@Getter
public class TaskManager extends AbstractManager {
    public static final TaskManager INSTANCE = new TaskManager();

    private ScheduledExecutorService scheduler;
    private ExecutorService callbackExecutor;
    private ExecutorService asyncExecutor;
    private HttpClient httpClient;

    @Override
    public boolean load(Gatekeeper<?> plugin) {
        int cores = Runtime.getRuntime().availableProcessors();

        this.callbackExecutor = new ThreadPoolExecutor(
                cores,
                128,
                60L, TimeUnit.SECONDS,
                new SynchronousQueue<>(),
                new SimpleThreadFactory("Gatekeeper-Callback"),
                new ThreadPoolExecutor.CallerRunsPolicy()
        );

        this.scheduler = new ScheduledThreadPoolExecutor(
                1,
                new SimpleThreadFactory("Gatekeeper-Scheduler")
        );

        this.asyncExecutor = new ThreadPoolExecutor(
                Math.max(1, cores / 2),
                Math.max(1, cores / 2),
                0, TimeUnit.MILLISECONDS,
                new SynchronousQueue<>(),
                new SimpleThreadFactory("Gatekeeper-Worker"),
                new ThreadPoolExecutor.CallerRunsPolicy()
        );

        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .executor(this.callbackExecutor)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();

        // Hard Tor exits are time-sensitive; refresh hourly. Broader reputation
        // data is scoring-only and can use a much slower cadence.
        this.scheduler.scheduleAtFixedRate(GeoipManager.INSTANCE, 1, 1, TimeUnit.HOURS);
        this.scheduler.scheduleAtFixedRate(ReputationManager.INSTANCE, 12, 12, TimeUnit.HOURS);
        this.scheduler.scheduleAtFixedRate(DataManager.INSTANCE, 1, 1, TimeUnit.MINUTES);
        return true;
    }

    @Override
    public boolean unload(Gatekeeper<?> plugin) {
        if (this.httpClient != null) {
            try {
                this.httpClient.close();
            } catch (Exception ignored) {}
            this.httpClient = null;
        }

        shutdown(this.scheduler);
        shutdown(this.asyncExecutor);
        shutdown(this.callbackExecutor);
        this.scheduler = null;
        this.asyncExecutor = null;
        this.callbackExecutor = null;
        return true;
    }

    private static void shutdown(ExecutorService executor) {
        if (executor == null) return;
        executor.shutdown();
        try {
            if (!executor.awaitTermination(2, TimeUnit.SECONDS)) {
                executor.shutdownNow();
                executor.awaitTermination(1, TimeUnit.SECONDS);
            }
        } catch (InterruptedException ex) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public boolean reload(Gatekeeper<?> gatekeeper) {
        return true;
    }

    private static class SimpleThreadFactory implements ThreadFactory {
        private final String namePrefix;
        private final AtomicInteger threadNumber = new AtomicInteger(1);

        public SimpleThreadFactory(String name) {
            this.namePrefix = name;
        }

        @Override
        public Thread newThread(@NotNull Runnable r) {
            Thread t = new Thread(r, this.namePrefix + "-" + this.threadNumber.getAndIncrement());
            t.setDaemon(true);
            return t;
        }
    }
}
