# Verification record

Build host: Windows, Android Studio JBR 25.0.3, Android SDK 37.0,
build-tools 36.0.0, Gradle 9.6.0, Android Gradle Plugin 9.4.1,
Kotlin/Compose compiler 2.2.10. Core JVM toolchain: Java 17.
Recorded during implementation on 2026-10-01.

## Executed successfully

| Check | Observed result |
|---|---|
| Upstream C fixture generation | Actual extracted Stable hash/PACK functions compiled with clang and executed; 16 fixture entries generated |
| Protocol unit tests | 15 passed: hash/authentication, PACK, bounded malformed/fuzz inputs, HTTP, welcome validation, Ethernet batching/keepalive |
| IPv4/routing unit tests | 2 passed: masks, longest-prefix routes, packet/UDP bounds and checksums |
| Ethernet/ARP unit tests | 3 passed: wire layout, cache bounds/expiry, ARP-dependent outgoing and returning IPv4 packet flow |
| DHCP unit tests | 5 passed: options/overload, lease validation, DORA, renewal and malformed/fuzz inputs |
| TLS unit/integration tests | 4 passed: pin parsing, actual loopback TLS with matching/wrong pin, untrusted certificate, trusted hostname and hostname mismatch |
| App host unit tests | 5 passed: profile validation, bounded sanitized diagnostics, cancellation resource ownership/close races, and starter arithmetic test |
| Debug app assembly | `:app:assembleDebug` succeeded |
| Device-test assembly | `:app:assembleDebugAndroidTest` succeeded, including actual Android Keystore test code |
| Host integration runner | `:integration:installDist` succeeded |
| APK signature verification | Android SDK `apksigner verify --verbose` succeeded, one signer, APK Signature Scheme v2 |
| Packaged native dependencies | All packaged ELF PT_LOAD segments use 16 KiB alignment; `zipalign -c -P 16 -v 4` succeeded (device execution remains pending) |
| License packaging | APK contains the notice plus full Apache 2.0 and AOSP BSD license texts |

Total: **34 host tests, zero failures, zero errors, zero skipped**. Reports are
under each module's `build/test-results/` and `build/reports/tests/`.
Scripted in-memory protocol/DHCP peers and a loopback TLS server test specific
wire behavior. They are not stock SoftEther or Android end-to-end evidence.
The TLS fixture is an ephemeral test-only certificate generated with keytool;
it is ignored by Git and is not bundled with the app.

The C fixture generator ran against Stable revision
`ed17437af9719ac66acab30faa29e375d613c35f`. The recorded SHA-256 of its
`src/Cedar/Protocol.c` is
`e2cff892d23b56e1bc9e5981bb5080e774b9cf02d8c748fb0f2aea3fba5a1593`.

## Open checks

**Android lint did not run.** AGP tried to resolve
`com.android.tools.lint:lint-gradle:32.4.1`. Official Google Maven and Maven
Central returned 404. Retries with network enabled and official alternative
Google Maven URLs produced the same result. No lint findings were suppressed,
no baseline was created, and successful compilation is not a substitute for
lint. Re-run `:app:lintDebug` when this dependency is accessible.

**Device instrumentation did not run.** `adb devices -l` listed no devices.
The Android Keystore tests require the actual OS; they were compiled only.

**Stock-server integration did not run.** The prepared Docker server is pinned
to unmodified Stable source. Docker/Podman/WSL were unavailable on the build
host. No reachable existing-server settings or credentials were provided for
the host probe. The user's available server and phone will be used for the
required acceptance test. This record claims no native authentication,
DHCP lease, Internet traffic or DNS traffic observed against a real server.

**Production readiness remains pending.** Run and record every scenario in
`integration/ACCEPTANCE.md`, including real Android IPv4/DNS forwarding,
certificate failures, network transitions, cancellation, renewal, IPv6
blocking and sustained throughput. The generated APK is a development test
build, not a verified production release.

## Reproduce

```powershell
$env:JAVA_HOME = 'C:\Program Files\Android\Android Studio\jbr'
.\gradlew.bat test :app:assembleDebug :app:assembleDebugAndroidTest :integration:installDist
.\tools\package-apk.ps1
.\gradlew.bat :app:lintDebug
# Requires a connected phone/emulator:
.\gradlew.bat :app:connectedDebugAndroidTest
```

The packaged APK checksum is in `dist/SHA256SUMS.txt`. Server fixture and
manual phone procedures are in `integration/README.md` and README.md.
