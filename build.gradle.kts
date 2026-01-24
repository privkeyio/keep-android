plugins {
    id("com.android.application") version "8.2.0" apply false
    id("org.jetbrains.kotlin.android") version "1.9.21" apply false
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
