plugins {
    id("com.android.application") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.1.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.1.21" apply false
    id("com.google.devtools.ksp") version "2.1.21-2.0.2" apply false
}

tasks.register("buildRust") {
    group = "rust"
    description = "Build Rust library for Android"
    doLast {
        exec {
            commandLine("bash", "build-rust.sh")
        }
    }
}
