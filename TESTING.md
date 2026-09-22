# Testing Gatekeeper

Gatekeeper is a multi-platform Gradle project. Most deterministic policy and persistence logic lives in `shared/`; platform modules (`paper`, `bukkit`, `bungee`, `velocity`, `sponge`) adapt that core to their server APIs.

Handwritten regression tests stay in this repository. The existing CI also builds the combined plugin and boots a real Paper server, which is stronger runtime evidence than a unit-only suite.

## Run locally

From the repository root:

```bash
./gradlew clean test shadowJar --no-daemon --stacktrace
```

On Windows:

```powershell
.\gradlew.bat clean test shadowJar --no-daemon --stacktrace
```

Run only shared tests:

```bash
./gradlew :shared:test --no-daemon
```

Run one suite:

```bash
./gradlew :shared:test --tests xyz.lychee.gatekeeper.shared.security.SecuritySnapshotTest
```

HTML results are under each module's `build/reports/tests/test/`; XML results are under `build/test-results/test/`.

## Current shared-core coverage

The regression suite protects:

- persistent data and VPN-binding storage behavior;
- reputation and whitelist policy;
- player/network identifier privacy;
- JSON/text/provider condition matching;
- anonymizer-provider consensus;
- risk assessment aggregation and risk policy;
- risk-signal point/detail/type metadata;
- immutable security-history snapshots;
- IP/address normalization helpers;
- integer recognition and rounding helpers.

`FullFeatureCoverageContractTest` is an inventory guard for these maintained shared-core suites. If one disappears or is renamed without an explicit update, tests fail rather than silently losing evidence.

### New hardening tests

This campaign adds:

- `MathUtilsTest` — signed integer recognition, malformed numeric strings and decimal rounding;
- `RiskSignalTest` — non-negative point clamping, null detail handling, and stable policy metadata;
- `SecuritySnapshotTest` — defensive copying, immutable signal exposure, null-detail normalization and audit-field preservation;
- `FullFeatureCoverageContractTest` — explicit shared-core regression inventory.

## CI and real Paper smoke evidence

`.github/workflows/ci.yml` already provides the canonical verification path on pull requests:

1. Java 25 compiles the full project and runs `./gradlew clean test shadowJar`;
2. the built Gatekeeper JAR is uploaded as an artifact;
3. a separate Java 21 job downloads stable Paper 1.21.11;
4. Paper boots with Gatekeeper installed;
5. CI requires the server to reach `Done` and Gatekeeper to be observed enabling;
6. Paper must stop cleanly.

A green PR therefore proves both deterministic regression tests and a real Paper enable/start/stop smoke test for that exact PR build.

## What the automated suite does not prove

The existing CI is strong, but it does not reproduce the entire production network. Additional controlled integration/manual evidence is still appropriate for:

- Bungee/Velocity/Sponge-specific connection interception and command behavior;
- live GeoIP/provider API responses, outages, quotas and latency;
- real multi-account/IP rate-limit traffic patterns;
- proxy-forwarding configuration and real client addresses;
- long-running reputation/history retention behavior;
- production database migration from every historical deployment state;
- interactions with other network/security plugins.

Never put production IP lists, API credentials, database dumps or identifiable player network history into test fixtures or CI logs.

## Reviewing failures

- **shared unit-test failure** — inspect the named class/assertion and confirm intended policy before changing it;
- **build/shadow failure** — packaging/module integration failed even if unit tests passed;
- **Paper smoke failure** — inspect the uploaded smoke console log; treat plugin enable or server startup errors as runtime evidence;
- **job with no executed steps** — runner/infrastructure failure, not a test result; rerun the unchanged head;
- **green build + green smoke** — current exact head passed both deterministic and real-Paper smoke gates.

## Maintenance rule

When a major shared policy/data/privacy feature changes, update or add its behavioral test in the same PR and keep the inventory contract accurate. Do not satisfy the inventory with empty/source-text-only tests. Platform-specific behavior should be tested in the corresponding module or through a real platform harness when the shared core cannot represent it honestly.

If a regression test exposes a product defect, keep the failing case and fix the owning production branch. Do not weaken security/privacy assertions merely to make CI green.
