plugins {
    id("com.android.application") version "9.1.0" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.3.20" apply false
    id("com.google.devtools.ksp") version "2.3.6" apply false
}

val expectedJavaMajor = 17
val runningJavaVersion = JavaVersion.current()
if (!runningJavaVersion.isCompatibleWith(JavaVersion.VERSION_17) ||
    runningJavaVersion.majorVersion.toInt() != expectedJavaMajor) {
    throw GradleException(
        "JDK $expectedJavaMajor is required but Gradle is running on ${System.getProperty("java.version")} " +
        "(java.home=${System.getProperty("java.home")}). " +
        "Fix: set JAVA_HOME to a JDK $expectedJavaMajor install (e.g. Temurin 17) and re-run."
    )
}

val expectedNdkVersion = "29.0.14206865"
val androidHome = System.getenv("ANDROID_HOME")
    ?: System.getenv("ANDROID_SDK_ROOT")
    ?: file("${System.getProperty("user.home")}/Android/Sdk").takeIf { it.exists() }?.absolutePath
if (androidHome != null) {
    val ndkDir = file("$androidHome/ndk/$expectedNdkVersion")
    if (!ndkDir.exists()) {
        throw GradleException(
            "Android NDK $expectedNdkVersion not found at ${ndkDir.absolutePath}. " +
            "Fix: sdkmanager --install \"ndk;$expectedNdkVersion\" " +
            "(or install via Android Studio SDK Manager)."
        )
    }
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
        inputs.files(
            fileTree(keepRepo) {
                include("**/*.rs", "**/Cargo.toml", "**/Cargo.lock")
                exclude("**/target/**", "**/.git/**")
            }
        ).withPathSensitivity(PathSensitivity.RELATIVE)
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
