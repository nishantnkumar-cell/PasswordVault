import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    // AGP 9 compiles Kotlin itself; the root project pins the Kotlin version.
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// One version for everything: [workspace.package] in the root Cargo.toml
// (docs/user-guide/11-versions-and-upgrades.md).
val repoRoot = rootDir.resolve("../..")
val vaultVersion: String = repoRoot.resolve("Cargo.toml").readLines()
    .dropWhile { it.trim() != "[workspace.package]" }
    .first { it.startsWith("version = ") }
    .substringAfter('"').substringBefore('"')
val vaultVersionCode = vaultVersion.split('.').map { it.toInt() }
    .let { (major, minor, patch) -> major * 10_000 + minor * 100 + patch }

android {
    namespace = "dev.passwordvault.app"
    compileSdk = 37

    defaultConfig {
        applicationId = "dev.passwordvault.app"
        minSdk = 28
        targetSdk = 36
        versionName = vaultVersion
        versionCode = vaultVersionCode
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Signed with the debug key unless a release key is configured,
            // so CI can build an installable APK.
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures { compose = true }

    // Written by buildRust below, which runs before every build.
    sourceSets["main"].java.directories.add("build/generated/uniffi")

    packaging { jniLibs.useLegacyPackaging = false }
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

// The Rust library and its Kotlin bindings (mobile/scripts/build-android.sh).
val buildRust = tasks.register<Exec>("buildRust") {
    group = "build"
    description = "Builds vault-mobile for Android and generates its Kotlin bindings."
    workingDir = repoRoot
    commandLine("bash", "mobile/scripts/build-android.sh", "release")
    inputs.dir(repoRoot.resolve("crates/vault-core/src"))
    inputs.dir(repoRoot.resolve("crates/vault-mobile/src"))
    inputs.file(repoRoot.resolve("Cargo.lock"))
    outputs.dir(projectDir.resolve("src/main/jniLibs"))
    outputs.dir(layout.buildDirectory.dir("generated/uniffi"))
}
tasks.named("preBuild") { dependsOn(buildRust) }

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.window)
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.compose.material3.navigation.suite)
    implementation(libs.compose.icons.extended)
    implementation(libs.adaptive)
    implementation(libs.adaptive.layout)
    implementation(libs.adaptive.navigation)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.code.scanner)
    // UniFFI's Kotlin bindings call into Rust through JNA.
    implementation("${libs.jna.get().module}:${libs.versions.jna.get()}@aar")
    debugImplementation(libs.compose.ui.tooling)
    testImplementation(libs.junit)
}
