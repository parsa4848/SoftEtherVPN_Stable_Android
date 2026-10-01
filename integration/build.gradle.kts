plugins { id("org.jetbrains.kotlin.jvm"); application }
kotlin { jvmToolchain(17) }
dependencies {
    implementation(project(":core-protocol"))
    implementation(project(":core-network"))
    implementation(project(":core-l2"))
    implementation(project(":core-dhcp"))
    implementation(project(":core-security"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
}
application { mainClass.set("com.blockto.sevpn.integration.ProbeKt") }
