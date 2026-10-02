# Third-party notices

The APK's Open-source licenses screen contains this notice and the full Apache
2.0 and AOSP BSD license texts. These texts are also in `licenses/`.

## SoftEther VPN Stable: native protocol and SHA-0 compatibility

Source: https://github.com/SoftEtherVPN/SoftEtherVPN_Stable
Revision: `ed17437af9719ac66acab30faa29e375d613c35f`
Release: v4.44-9807-rtm.

Copyright (c) Daiyuu Nobori.
Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
Copyright (c) SoftEther Corporation.
Copyright (c) all contributors on SoftEther VPN project in GitHub.

Licensed under the Apache License, Version 2.0. A copy is in
`licenses/Apache-2.0.txt`. Protocol serialization, negotiation and session
handling, additional connections, UDP acceleration and R-UDP/DNS were
implemented in Kotlin from the upstream behavior. `Sha0.kt` is
a Kotlin adaptation of the SHA-0 implementation in Mayaqua/Encrypt.c. The
upstream-C fixture generators extract selected hash/PACK and transport packet
writers into temporary test harnesses. The transport harness executes
SoftEther's embedded libsodium AEAD reference for fixtures only, preserving
its upstream ISC license text in the extracted code. No libsodium code is
bundled into the Android app; production v2 uses the platform JCA provider.
Changes include Kotlin types and bounds, correct
padding at block boundaries, temporary-buffer wiping and Android stream
integration. No SoftEther server/client executable, TAP driver, OpenSSL binary
or complete native source tree is distributed in the Android APK.

## Android Open Source Project SHA implementation

Copyright 2013 The Android Open Source Project.

SoftEther's internal SHA-0 implementation derives from AOSP libmincrypt:
https://android.googlesource.com/platform/system/core/+/81df1cc77722000f8d0025c1ab00ced123aa573c/libmincrypt/sha.c

The BSD redistribution conditions and disclaimer are reproduced in
`licenses/BSD-3-Clause-AOSP.txt` and in the APK license screen. Google Inc. and
contributors do not endorse this project.

## AndroidX

AndroidX Core, Activity, Lifecycle, SavedState, DataStore, Compose UI, Compose
Runtime, Compose Foundation, Compose Material3 and their transitive AndroidX
dependencies are copyright The Android Open Source Project and contributors,
licensed under Apache 2.0.

Source: https://android.googlesource.com/platform/frameworks/support/
Versions are pinned in `app/build.gradle.kts` and `gradle/libs.versions.toml`.

## Kotlin and kotlinx.coroutines

Kotlin standard library: Copyright 2010-2025 JetBrains s.r.o. and Kotlin
Programming Language contributors. Apache 2.0.
Source: https://github.com/JetBrains/kotlin

kotlinx.coroutines: Copyright 2016-2024 JetBrains s.r.o. and contributors.
Apache 2.0. Source: https://github.com/Kotlin/kotlinx.coroutines

JetBrains annotations are licensed under Apache 2.0.
Source: https://github.com/JetBrains/java-annotations

## Build and test dependencies

JUnit 4.13.2 is licensed under Eclipse Public License 1.0. Hamcrest 1.3 is
licensed under BSD 3-Clause. These are used by host/device tests; they are not
dependencies of the application APK. Their distributions include their own
license texts. Source: https://github.com/junit-team/junit4 and
https://github.com/hamcrest/JavaHamcrest.

Gradle, the Android Gradle Plugin and Kotlin build plugins are build-time
dependencies with licenses supplied by their respective distributions; they
are not bundled inside the application. Gradle wrapper files are Apache 2.0.

## Research references

Minimum-VPN-Client-for-SoftEther-VPN (Apache 2.0) and the Developer edition were
read as secondary compatibility references. No Minimum client code or assets
were copied into this application. The ignored research directories are not
part of this project's tracked source or its APK. SoftEther is a name of its
respective owners; no affiliation or endorsement is implied.
