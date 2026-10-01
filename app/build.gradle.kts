import org.jetbrains.kotlin.gradle.plugin.KotlinPlatformType
import org.gradle.api.attributes.java.TargetJvmEnvironment

plugins {
    alias(libs.plugins.android.application)
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.blockto.sevpn"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "com.blockto.sevpn"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"

        testInstrumentationRunner = "com.blockto.sevpn.PlatformTestRunner"
    }

    buildTypes {
        release {
            optimization {
                enable = false
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures { compose = true; buildConfig = true }
}

// AGP's lint jar discovery otherwise selects desktop/JVM stubs from these
// older multiplatform AndroidX publications. Keep the Android variant for lint.
configurations.matching { it.name.endsWith("LintChecksClasspath") }.configureEach {
    attributes {
        attribute(KotlinPlatformType.attribute, KotlinPlatformType.androidJvm)
        attribute(TargetJvmEnvironment.TARGET_JVM_ENVIRONMENT_ATTRIBUTE,
            objects.named(TargetJvmEnvironment::class.java, TargetJvmEnvironment.ANDROID))
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(project(":core-protocol"))
    implementation(project(":core-network"))
    implementation(project(":core-l2"))
    implementation(project(":core-dhcp"))
    implementation(project(":core-security"))
    implementation(platform("androidx.compose:compose-bom:2024.09.03"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.6")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.6")
    implementation("androidx.datastore:datastore-preferences:1.1.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    constraints {
        listOf("lifecycle-common", "lifecycle-runtime", "lifecycle-runtime-ktx",
            "lifecycle-viewmodel", "lifecycle-viewmodel-ktx", "lifecycle-viewmodel-savedstate")
            .forEach { implementation("androidx.lifecycle:$it:2.8.6") }
        implementation("androidx.annotation:annotation:1.8.1")
    }
    testImplementation(libs.junit)
    androidTestImplementation(libs.junit)
}
