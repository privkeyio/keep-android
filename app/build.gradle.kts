plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.devtools.ksp")
}

android {
    namespace = "io.privkey.keep"
    compileSdk = 36
    ndkVersion = "29.0.14206865"

    defaultConfig {
        applicationId = "io.privkey.keep"
        minSdk = 33
        targetSdk = 36
        versionCode = 12
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
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
            val releaseConfig = signingConfigs.getByName("release")
            signingConfig = if (releaseConfig.storeFile != null) {
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

    testOptions {
        unitTests.isReturnDefaultValues = true
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
        val configNames = listOf("releaseRuntimeClasspath", "releaseCompileClasspath")
        val offenders = sortedMapOf<String, MutableSet<String>>()
        val visited = mutableSetOf<org.gradle.api.artifacts.component.ComponentIdentifier>()

        fun walk(component: org.gradle.api.artifacts.result.ResolvedComponentResult, path: List<String>) {
            if (!visited.add(component.id)) return
            val id = component.moduleVersion
            val coord = id?.let { "${it.group}:${it.name}:${it.version}" } ?: component.id.displayName
            val nextPath = path + coord
            if (id != null && forbiddenDependencyGroups.any { id.group == it || id.group.startsWith("$it.") }) {
                offenders.getOrPut(coord) { mutableSetOf() }.add(nextPath.joinToString(" -> "))
            }
            component.dependencies
                .filterIsInstance<org.gradle.api.artifacts.result.ResolvedDependencyResult>()
                .forEach { walk(it.selected, nextPath) }
        }

        configNames.forEach { name ->
            val root = configurations.getByName(name).incoming.resolutionResult.root
            walk(root, emptyList())
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

    implementation(platform("androidx.compose:compose-bom:2026.03.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.navigation:navigation-compose:2.9.7")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.core:core-ktx:1.18.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.10.0")
    implementation("androidx.room:room-runtime:$roomVersion")
    implementation("androidx.room:room-ktx:$roomVersion")
    implementation("net.zetetic:sqlcipher-android:4.14.1")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.security:security-crypto:1.1.0")
    implementation("androidx.camera:camera-camera2:1.6.0")
    implementation("androidx.camera:camera-lifecycle:1.6.0")
    implementation("androidx.camera:camera-view:1.6.0")
    implementation("com.google.zxing:core:3.5.4")
    implementation("net.java.dev.jna:jna:5.18.1@aar")

    ksp("androidx.room:room-compiler:$roomVersion")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")

    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:core:1.7.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.room:room-testing:$roomVersion")
    androidTestImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")

    debugImplementation("androidx.compose.ui:ui-tooling")
}
