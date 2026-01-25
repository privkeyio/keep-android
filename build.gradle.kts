plugins {
    id("com.android.application") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
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
