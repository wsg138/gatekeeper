package xyz.lychee.gatekeeper.shared.command.subcommand;

import org.jetbrains.annotations.NotNull;
import xyz.lychee.gatekeeper.shared.Gatekeeper;
import xyz.lychee.gatekeeper.shared.command.PermissibleCommand;
import xyz.lychee.gatekeeper.shared.manager.SecurityHistoryManager;
import xyz.lychee.gatekeeper.shared.objects.AbstractLang;
import xyz.lychee.gatekeeper.shared.objects.CommandPlayer;
import xyz.lychee.gatekeeper.shared.security.RiskSignal;
import xyz.lychee.gatekeeper.shared.security.SecuritySnapshot;
import xyz.lychee.gatekeeper.shared.util.AddressUtils;

import java.util.Collections;
import java.util.List;

public class RiskCommand<T> extends PermissibleCommand<T> {
    public RiskCommand(Gatekeeper<T> gatekeeper) {
        super(gatekeeper, "gatekeeper.command.risk");
    }

    @Override
    protected void handleExecution(CommandPlayer<T> player, String[] args) {
        AbstractLang<T> lang = this.getGatekeeper().language();
        if (args.length < 1) {
            player.sendMessage(lang, "messages.risk.usage");
            return;
        }

        if (AddressUtils.isIpv4(args[0]) && !player.canViewNetworkIdentifiers()) {
            player.sendMessage(lang, "messages.risk.network_identifier_console_only");
            return;
        }

        SecuritySnapshot snapshot = SecurityHistoryManager.INSTANCE.find(args[0]);
        if (snapshot == null) {
            player.sendMessage(lang, "messages.risk.error", args[0]);
            return;
        }

        long ageSeconds = Math.max(0L, (System.currentTimeMillis() - snapshot.getCreatedAtMillis()) / 1000L);
        String age = ageSeconds < 60 ? ageSeconds + "s ago" : (ageSeconds / 60L) + "m ago";

        send(player, lang, "&#54DAF4GateKeeper security result for &f" + snapshot.getName());
        if (player.canViewNetworkIdentifiers()) {
            send(player, lang, " &8» &7IP: &f" + snapshot.getAddress()
                    + " &8| &7ASN: &f" + snapshot.getAsn()
                    + " &8| &7Country: &f" + snapshot.getCountry());
        } else {
            send(player, lang, " &8» &7ASN: &f" + snapshot.getAsn()
                    + " &8| &7Country: &f" + snapshot.getCountry());
        }
        send(player, lang, " &8» &7Decision: &f" + snapshot.getAction()
                + " &8| &7Reason: &f" + snapshot.getReason()
                + " &8| &7Risk: &f" + snapshot.getScore());
        send(player, lang, " &8» &7Observed: &f" + age);

        if (!snapshot.getDetail().isBlank()) {
            send(player, lang, " &8» &7Detail: &f" + snapshot.getDetail());
        }

        if (snapshot.getSignals().isEmpty()) {
            send(player, lang, " &8» &7Risk signals: &fnone");
        } else {
            send(player, lang, " &8» &7Risk signals:");
            for (RiskSignal signal : snapshot.getSignals()) {
                String detail = signal.getDetail().isBlank() ? "" : " &8(" + signal.getDetail() + "&8)";
                send(player, lang, "    &8- &f" + signal.getType().getConfigKey()
                        + " &7+" + signal.getPoints() + detail);
            }
        }
    }

    private void send(CommandPlayer<T> player, AbstractLang<T> lang, String message) {
        player.sendMessage(lang.color(message, true));
    }

    @NotNull
    @Override
    protected List<String> handleSuggestion(CommandPlayer<T> player, String[] args) {
        return Collections.emptyList();
    }
}
