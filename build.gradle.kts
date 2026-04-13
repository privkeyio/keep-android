plugins {
    id("com.android.application") version "9.1.0" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.3.20" apply false
    id("com.google.devtools.ksp") version "2.3.6" apply false
}

val keepRepo = file(System.getenv("KEEP_REPO") ?: "${rootDir}/keep")

tasks.register<Exec>("buildRust") {
    group = "rust"
    description = "Builds keep-mobile Rust native libraries and regenerates UniFFI Kotlin bindings."
    workingDir = rootDir
    commandLine("bash", "build-rust.sh")
    environment("KEEP_REPO", keepRepo.absolutePath)

    inputs.file("${rootDir}/build-rust.sh").withPathSensitivity(PathSensitivity.RELATIVE)
    if (keepRepo.exists()) {
        inputs.dir("${keepRepo}/keep-mobile/src").withPathSensitivity(PathSensitivity.RELATIVE)
        inputs.file("${keepRepo}/keep-mobile/Cargo.toml").withPathSensitivity(PathSensitivity.RELATIVE)
    }
    inputs.property("targets", System.getenv("TARGETS") ?: "")
    outputs.dir("${rootDir}/app/src/main/jniLibs")
    outputs.dir("${rootDir}/app/src/main/kotlin/io/privkey/keep/uniffi")

    doFirst {
        if (!keepRepo.exists()) {
            throw GradleException(
                "keep workspace not found at ${keepRepo.absolutePath}. " +
                "Clone it (e.g. `git clone https://github.com/privkeyio/keep ../keep`) " +
                "or set KEEP_REPO to its path."
            )
        }
    }
}
