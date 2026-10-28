import javax.inject.Inject
import org.gradle.process.ExecOperations
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

// The release key, when one is given (mobile/scripts/build-android-release.sh,
// docs/mobile.md#release-signing). Never kept in the repository.
val releaseKeystore: String? = System.getenv("VAULT_ANDROID_KEYSTORE")

android {
    namespace = "dev.passwordvault.app"
    compileSdk = 37

    defaultConfig {
        applicationId = "dev.passwordvault.app"
        minSdk = 28
        targetSdk = 36
        // A release build names its exact version, such as 0.2.0-beta.1.
        versionName = System.getenv("VAULT_VERSION") ?: vaultVersion
        versionCode = vaultVersionCode
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (releaseKeystore != null) {
            create("release") {
                storeFile = file(releaseKeystore)
                storePassword = System.getenv("VAULT_ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("VAULT_ANDROID_KEY_ALIAS") ?: "secret-vault"
                keyPassword = System.getenv("VAULT_ANDROID_KEY_PASSWORD") ?: storePassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Signed with the debug key unless a release key is configured,
            // so CI can build an installable APK.
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures { compose = true }

    packaging { jniLibs.useLegacyPackaging = false }
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

// The Rust library and its Kotlin bindings (mobile/scripts/build-android.sh),
// built for each variant into directories AGP adds as generated sources.
abstract class BuildRust : DefaultTask() {
    @get:Internal abstract val workspace: DirectoryProperty
    @get:InputFiles @get:PathSensitive(PathSensitivity.RELATIVE) abstract val rustSources: ConfigurableFileCollection
    @get:OutputDirectory abstract val bindings: DirectoryProperty
    @get:OutputDirectory abstract val jniLibs: DirectoryProperty
    @get:Inject abstract val execOps: ExecOperations

    @TaskAction
    fun build() {
        execOps.exec {
            workingDir(workspace.get().asFile)
            environment("VAULT_BINDINGS_OUT", bindings.get().asFile.absolutePath)
            environment("VAULT_JNILIBS_OUT", jniLibs.get().asFile.absolutePath)
            commandLine("bash", "mobile/scripts/build-android.sh", "release")
        }
    }
}

androidComponents {
    onVariants { variant ->
        val task = tasks.register<BuildRust>("buildRust${variant.name.replaceFirstChar { it.uppercase() }}") {
            group = "build"
            description = "Builds vault-mobile for Android and generates its Kotlin bindings."
            workspace.set(repoRoot)
            rustSources.from(
                repoRoot.resolve("crates/vault-core/src"),
                repoRoot.resolve("crates/vault-mobile/src"),
                repoRoot.resolve("Cargo.lock"),
            )
        }
        variant.sources.java?.addGeneratedSourceDirectory(task, BuildRust::bindings)
        variant.sources.jniLibs?.addGeneratedSourceDirectory(task, BuildRust::jniLibs)
    }
}

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
    androidTestImplementation(platform(libs.compose.bom))
    androidTestImplementation(libs.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    debugImplementation(libs.compose.ui.test.manifest)
}
