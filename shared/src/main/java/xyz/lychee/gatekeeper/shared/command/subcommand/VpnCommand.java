package xyz.lychee.gatekeeper.shared.command.subcommand;

import org.jetbrains.annotations.NotNull;
import xyz.lychee.gatekeeper.shared.Gatekeeper;
import xyz.lychee.gatekeeper.shared.command.PermissibleCommand;
import xyz.lychee.gatekeeper.shared.manager.DataManager;
import xyz.lychee.gatekeeper.shared.manager.SecurityHistoryManager;
import xyz.lychee.gatekeeper.shared.objects.AbstractLang;
import xyz.lychee.gatekeeper.shared.objects.CommandPlayer;
import xyz.lychee.gatekeeper.shared.security.SecuritySnapshot;
import xyz.lychee.gatekeeper.shared.util.AddressUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class VpnCommand<T> extends PermissibleCommand<T> {
    private static final List<String> ACTIONS = Arrays.asList("add", "remove", "info", "list");

    public VpnCommand(Gatekeeper<T> gatekeeper) {
        super(gatekeeper, "gatekeeper.command.vpn");
    }

    @Override
    protected void handleExecution(CommandPlayer<T> player, String[] args) {
        AbstractLang<T> lang = this.getGatekeeper().language();
        if (!player.canViewNetworkIdentifiers()) {
            player.sendMessage(lang, "messages.vpn.console_only");
            return;
        }

        if (args.length == 0) {
            player.sendMessage(lang, "messages.vpn.usage");
            return;
        }

        String action = args[0].toLowerCase(Locale.ROOT);
        switch (action) {
            case "add":
                this.handleAdd(player, lang, args);
                return;
            case "remove":
                this.handleRemove(player, lang, args);
                return;
            case "info":
                this.handleInfo(player, lang, args);
                return;
            case "list":
                this.handleList(player, lang, args);
                return;
            default:
                player.sendMessage(lang, "messages.vpn.usage");
        }
    }

    private void handleAdd(CommandPlayer<T> player, AbstractLang<T> lang, String[] args) {
        if (args.length != 3) {
            player.sendMessage(lang, "messages.vpn.usage");
            return;
        }

        String nickname = args[1];
        String address = AddressUtils.normalizeIpv4(args[2]);
        if (address == null) {
            player.sendMessage(lang, "messages.vpn.invalid_ip", args[2]);
            return;
        }

        DataManager dataManager = DataManager.INSTANCE;
        String conflictingOwner = dataManager.getVpnBindingOwner(address);
        if (conflictingOwner != null && !conflictingOwner.equalsIgnoreCase(nickname)) {
            player.sendMessage(lang, "messages.vpn.address_in_use", address, conflictingOwner);
            return;
        }

        String previousAddress = dataManager.getVpnBindingAddress(nickname);
        DataManager.VpnBindingUpdateResult result = dataManager.bindVpn(nickname, address);
        switch (result) {
            case ADDED:
                player.sendMessage(lang, "messages.vpn.added", nickname, address);
                return;
            case UPDATED:
                player.sendMessage(lang, "messages.vpn.updated", nickname, previousAddress, address);
                return;
            case UNCHANGED:
                player.sendMessage(lang, "messages.vpn.exists", nickname, address);
                return;
            case ADDRESS_IN_USE:
                String owner = dataManager.getVpnBindingOwner(address);
                player.sendMessage(lang, "messages.vpn.address_in_use", address, owner == null ? "another account" : owner);
                return;
            case INVALID_ADDRESS:
                player.sendMessage(lang, "messages.vpn.invalid_ip", args[2]);
                return;
            case INVALID_NAME:
            default:
                player.sendMessage(lang, "messages.vpn.invalid_player", nickname);
        }
    }

    private void handleRemove(CommandPlayer<T> player, AbstractLang<T> lang, String[] args) {
        if (args.length != 2) {
            player.sendMessage(lang, "messages.vpn.usage");
            return;
        }

        String removedAddress = DataManager.INSTANCE.removeVpnBinding(args[1]);
        if (removedAddress == null) {
            player.sendMessage(lang, "messages.vpn.missing", args[1]);
            return;
        }
        player.sendMessage(lang, "messages.vpn.removed", args[1], removedAddress);
    }

    private void handleInfo(CommandPlayer<T> player, AbstractLang<T> lang, String[] args) {
        if (args.length != 2) {
            player.sendMessage(lang, "messages.vpn.usage");
            return;
        }

        DataManager dataManager = DataManager.INSTANCE;
        String target = args[1];
        String normalizedAddress = AddressUtils.normalizeIpv4(target);
        if (normalizedAddress != null) {
            String owner = dataManager.getVpnBindingOwner(normalizedAddress);
            if (owner == null) {
                player.sendMessage(lang, "messages.vpn.missing", target);
                return;
            }
            player.sendMessage(lang, "messages.vpn.info", owner, normalizedAddress);
            return;
        }

        String address = dataManager.getVpnBindingAddress(target);
        if (address == null) {
            player.sendMessage(lang, "messages.vpn.missing", target);
            return;
        }
        player.sendMessage(lang, "messages.vpn.info", target, address);
    }

    private void handleList(CommandPlayer<T> player, AbstractLang<T> lang, String[] args) {
        if (args.length != 1) {
            player.sendMessage(lang, "messages.vpn.usage");
            return;
        }

        Map<String, String> bindings = DataManager.INSTANCE.getVpnBindingsSnapshot();
        if (bindings.isEmpty()) {
            player.sendMessage(lang, "messages.vpn.list_empty");
            return;
        }

        player.sendMessage(lang, "messages.vpn.list_header", Integer.toString(bindings.size()));
        for (Map.Entry<String, String> entry : bindings.entrySet()) {
            player.sendMessage(lang, "messages.vpn.list_entry", entry.getKey(), entry.getValue());
        }
    }

    @NotNull
    @Override
    protected List<String> handleSuggestion(CommandPlayer<T> player, String[] args) {
        if (!player.canViewNetworkIdentifiers()) return Collections.emptyList();

        if (args.length == 1) {
            return filter(ACTIONS, args[0]);
        }

        if (args.length == 2) {
            String action = args[0].toLowerCase(Locale.ROOT);
            if ("add".equals(action)) {
                Set<String> names = new LinkedHashSet<>(SecurityHistoryManager.INSTANCE.getRecentNames());
                names.addAll(DataManager.INSTANCE.getVpnBindingPlayers());
                return filter(names, args[1]);
            }
            if ("remove".equals(action)) {
                return filter(DataManager.INSTANCE.getVpnBindingPlayers(), args[1]);
            }
            if ("info".equals(action)) {
                return filter(DataManager.INSTANCE.getVpnBindingTargets(), args[1]);
            }
        }

        if (args.length == 3 && "add".equalsIgnoreCase(args[0])) {
            Set<String> addresses = new LinkedHashSet<>();
            String existingAddress = DataManager.INSTANCE.getVpnBindingAddress(args[1]);
            if (existingAddress != null) addresses.add(existingAddress);

            SecuritySnapshot recent = SecurityHistoryManager.INSTANCE.find(args[1]);
            if (recent != null) {
                String recentAddress = AddressUtils.normalizeIpv4(recent.getAddress());
                if (recentAddress != null) addresses.add(recentAddress);
            }
            return filter(addresses, args[2]);
        }

        return Collections.emptyList();
    }

    private static List<String> filter(Collection<String> candidates, String prefix) {
        String normalizedPrefix = prefix == null ? "" : prefix.toLowerCase(Locale.ROOT);
        List<String> results = new ArrayList<>();
        for (String candidate : candidates) {
            if (candidate.toLowerCase(Locale.ROOT).startsWith(normalizedPrefix)) {
                results.add(candidate);
            }
        }
        return results;
    }
}
