package xyz.lychee.gatekeeper.shared.objects;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;

class CommandPlayerPrivacyTest {
    @Test
    void networkIdentifiersAreHiddenUnlessPlatformExplicitlyOptsIn() {
        CommandPlayer<String> player = new CommandPlayer<>(new Object()) {
            @Override
            public boolean hasPermission(String permission) {
                return true;
            }

            @Override
            public void sendMessage(String message) {}

            @Override
            public void applyChange(String target, EnumAccess newAccess) {}
        };

        assertFalse(player.canViewNetworkIdentifiers());
    }
}
