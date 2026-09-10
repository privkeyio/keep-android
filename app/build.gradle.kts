plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.devtools.ksp")
}

// Canonical connected/instrumented-test task names. Gradle lets any of these be
// abbreviated in camelCase on the command line (`cAT` -> connectedAndroidTest,
// `cC` -> connectedCheck, `cDAT` -> connectedDebugAndroidTest), and an abbreviation
// contains neither "connected" nor "AndroidTest", so a substring match alone misses
// a local `./gradlew cAT` and it silently keeps ABI splits enabled, still hitting #482.
val connectedTestTasks = listOf(
    "connectedCheck",
    "connectedAndroidTest",
    "connectedDebugAndroidTest",
    "assembleAndroidTest",
    "assembleDebugAndroidTest",
)

// True when the requested `name` is a Gradle camelCase abbreviation of `full`:
// same number of camel-hump segments, each a case-insensitive prefix of the
// corresponding segment of `full` (so `cAT` matches connectedAndroidTest but plain
// `cat` — a single lowercase hump — matches nothing multi-hump).
fun abbreviatesCamelCase(name: String, full: String): Boolean {
    val nameHumps = name.split(Regex("(?=\\p{Upper})"))
    val fullHumps = full.split(Regex("(?=\\p{Upper})"))
    return nameHumps.size == fullHumps.size &&
        nameHumps.indices.all { fullHumps[it].startsWith(nameHumps[it], ignoreCase = true) }
}

// True when the requested tasks include instrumented (connected) tests; used to
// disable per-ABI splits so a universal debug APK is built for the test device.
// Matches the explicit test tasks (connectedDebugAndroidTest, ...), the lifecycle
// wrappers (connectedCheck), and their camelCase abbreviations, so any connected-test
// entry point gets the universal APK, not just the one CI runs.
val runningInstrumentedTests = gradle.startParameter.taskNames.any { requested ->
    val name = requested.substringAfterLast(':')
    name.contains("AndroidTest", ignoreCase = true) ||
        name.contains("connected", ignoreCase = true) ||
        connectedTestTasks.any { abbreviatesCamelCase(name, it) }
}

// splits.abi is a global (non-per-variant) config, so disabling it for an
// instrumented-test run also strips the per-ABI release splits and their version
// codes, silently producing a universal release APK at the base versionCode.
// Refuse the mixed invocation rather than emit a broken F-Droid artifact (GH #482).
val assemblingRelease = gradle.startParameter.taskNames.any {
    it.contains("Release", ignoreCase = true) &&
        (it.contains("assemble", ignoreCase = true) || it.contains("bundle", ignoreCase = true))
}
if (runningInstrumentedTests && assemblingRelease) {
    throw GradleException(
        "Do not request instrumented tests and a release build in the same Gradle " +
            "invocation: disabling ABI splits for the universal test APK would also " +
            "strip the per-ABI release splits and their version codes. Run them separately."
    )
}

android {
    namespace = "io.privkey.keep"
    compileSdk = 37
    ndkVersion = "29.0.14206865"

    defaultConfig {
        applicationId = "io.privkey.keep"
        minSdk = 33
        targetSdk = 36
        versionCode = 28
        versionName = "1.2.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        // Reset the persisted kill switch to its disengaged baseline before every
        // instrumented test, so a switch left engaged by a process death mid-test
        // cannot fail-close signing tests in a later class (gh #397).
        testInstrumentationRunnerArguments["listener"] =
            "io.privkey.keep.KillSwitchResetRunListener"
        vectorDrawables {
            useSupportLibrary = true
        }
        // ABI selection is handled by the `splits { abi }` block below (which is
        // incompatible with ndk.abiFilters). splits.abi.include restricts the
        // packaged architectures to arm64-v8a and x86_64.
    }

    // Reproducible builds: strip non-reproducible Play dependency metadata blob
    // (contains signing timestamps) from APK and bundle outputs.
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    signingConfigs {
        create("release") {
            val ksFile = System.getenv("KEYSTORE_FILE")
            if (ksFile != null && file(ksFile).exists()) {
                storeFile = file(ksFile)
                storePassword = System.getenv("KEYSTORE_PASSWORD")
                keyAlias = System.getenv("KEY_ALIAS")
                keyPassword = System.getenv("KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // findByName (not getByName) so the build still works when F-Droid
            // strips the "release" signing config: fall back to debug signing.
            val releaseConfig = signingConfigs.findByName("release")
            signingConfig = if (releaseConfig?.storeFile != null) {
                releaseConfig
            } else {
                signingConfigs.getByName("debug")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
        jniLibs {
            excludes += listOf(
                "/lib/armeabi/**",
                "/lib/armeabi-v7a/**",
                "/lib/x86/**",
                "/lib/mips/**",
                "/lib/mips64/**",
            )
            useLegacyPackaging = false
        }
    }

    // Per-ABI APK splits for F-Droid: ship one APK per architecture instead of a
    // single universal APK. Each split gets a distinct versionCode assigned in
    // the androidComponents block below.
    //
    // Disabled while running instrumented (connected) tests: splits produce per-ABI
    // app APKs but the androidTest APK is universal, and the install path cannot
    // reconcile the two, so installPackages fails before any test runs and it is
    // misreported as failing tests (GH #482). A universal debug APK installs fine.
    splits {
        abi {
            isEnable = !runningInstrumentedTests
            reset()
            include("arm64-v8a", "x86_64")
            isUniversalApk = false
        }
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }

}

// Assign each per-ABI release split its own versionCode: 10 * base + abiCode.
// ABI codes follow F-Droid's required ordering (armeabi-v7a < arm64-v8a < x86 <
// x86_64), so e.g. base 26 yields 262 (arm64-v8a) and 264 (x86_64). The F-Droid
// recipe (VercodeOperation) and per-versionCode changelogs must match these.
val abiVersionCodes = mapOf("arm64-v8a" to 2, "x86_64" to 4)
androidComponents {
    onVariants(selector().withBuildType("release")) { variant ->
        variant.outputs.forEach { output ->
            val abi = output.filters
                .firstOrNull { it.filterType == com.android.build.api.variant.FilterConfiguration.FilterType.ABI }
                ?.identifier
            val abiCode = abiVersionCodes[abi]
            if (abiCode != null) {
                output.versionCode.set(10 * (android.defaultConfig.versionCode ?: 0) + abiCode)
            }
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        allWarningsAsErrors.set(true)
    }
}

tasks.named("preBuild") {
    dependsOn(rootProject.tasks.named("verifyKeepVersion"))
    dependsOn(rootProject.tasks.named("buildRust"))
}

// F-Droid / IzzyOnDroid eligibility guard: fail the build if proprietary Google
// coordinates reappear on the release runtime classpath. See issue #251.
val forbiddenDependencyGroups = setOf(
    "com.google.android.gms",
    "com.google.firebase",
    "com.google.android.datatransport",
    "com.google.mlkit",
    "com.google.android.odml",
    "com.google.android.play",
    "com.google.android.recaptcha",
    "com.android.billingclient",
    "com.google.ar",
    "com.google.android.libraries.places",
    "com.google.maps.android",
    "com.google.android.exoplayer",
    "com.google.android.youtube",
    "com.google.oauth-client",
)

tasks.register("verifyNoProprietaryDeps") {
    group = "verification"
    description = "Fails if release classpaths contain proprietary Google coordinates."
    doLast {
        val offenders = sortedMapOf<String, MutableSet<String>>()
        val visited = mutableSetOf<org.gradle.api.artifacts.component.ComponentIdentifier>()

        fun String.isForbidden() = forbiddenDependencyGroups.any { this == it || startsWith("$it.") }

        fun walk(component: org.gradle.api.artifacts.result.ResolvedComponentResult, path: List<String>) {
            if (!visited.add(component.id)) return
            val id = component.moduleVersion
            val coord = id?.let { "${it.group}:${it.name}:${it.version}" } ?: component.id.displayName
            val nextPath = path + coord
            if (id != null && id.group.isForbidden()) {
                offenders.getOrPut(coord) { mutableSetOf() }.add(nextPath.joinToString(" -> "))
            }
            component.dependencies
                .filterIsInstance<org.gradle.api.artifacts.result.ResolvedDependencyResult>()
                .forEach { walk(it.selected, nextPath) }
        }

        listOf("releaseRuntimeClasspath", "releaseCompileClasspath").forEach { name ->
            walk(configurations.getByName(name).incoming.resolutionResult.root, emptyList())
        }

        if (offenders.isNotEmpty()) {
            val details = offenders.entries.joinToString("\n  ") { (coord, paths) ->
                "$coord\n    via:\n      " + paths.sorted().joinToString("\n      ")
            }
            throw GradleException(
                "Proprietary dependencies detected on release classpaths " +
                    "(breaks F-Droid / IzzyOnDroid eligibility):\n  " + details
            )
        }
    }
}

dependencies {
    val roomVersion = "2.8.4"

    implementation(platform("androidx.compose:compose-bom:2026.08.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.navigation:navigation-compose:2.10.0")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.core:core-ktx:1.19.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    implementation("androidx.room:room-runtime:$roomVersion")
    implementation("androidx.room:room-ktx:$roomVersion")
    implementation("net.zetetic:sqlcipher-android:4.18.0")
    implementation("androidx.biometric:biometric:1.1.0")
    // biometric:1.1.0 drags in fragment 1.2.5, whose FragmentActivity still enforces
    // the legacy <=16-bit permission request-code validator and crashes the
    // activity-result permission launcher (large request codes). Align fragment with
    // the modern activity stack, where that validator is gone.
    implementation("androidx.fragment:fragment:1.9.0")
    implementation("androidx.security:security-crypto:1.1.0")
    implementation("androidx.camera:camera-camera2:1.6.1")
    implementation("androidx.camera:camera-lifecycle:1.6.1")
    implementation("androidx.camera:camera-view:1.6.1")
    implementation("com.google.zxing:core:3.5.4")
    implementation("net.java.dev.jna:jna:5.19.1@aar")

    ksp("androidx.room:room-compiler:$roomVersion")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    // Real org.json on the unit-test classpath; the android.jar stub is a no-op
    // under unitTests.isReturnDefaultValues, which would break JSON-parsing tests.
    testImplementation("org.json:json:20260814")

    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:core:1.7.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
    // Pin espresso-core over the 3.5.0 dragged in transitively by ui-test-junit4:
    // 3.5.0 reflects into the removed InputManager.getInstance and dies in Compose
    // test setup on Android 17. 3.7.0 uses getSystemService for SDK_INT >= 23 (gh #481).
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    androidTestImplementation("androidx.room:room-testing:$roomVersion")
    androidTestImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    androidTestImplementation(platform("androidx.compose:compose-bom:2026.08.00"))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    androidTestImplementation("fr.acinq.secp256k1:secp256k1-kmp-jni-android:0.24.0")

    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
