plugins {
    id("com.android.application") version "9.1.0" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.3.20" apply false
    id("com.google.devtools.ksp") version "2.3.6" apply false
}

val expectedJavaMajor = 17
val expectedNdkVersion = "29.0.14206865"

fun validateSourceDateEpoch(sde: String): String {
    if (!sde.matches(Regex("^[0-9]+$"))) {
        throw GradleException(
            "SOURCE_DATE_EPOCH='$sde' is not a non-negative integer. " +
            "Fix: export SOURCE_DATE_EPOCH=\"\$(./scripts/derive-sde.sh)\"."
        )
    }
    return sde
}

fun resolveAndroidSdkDir(): String? {
    System.getenv("ANDROID_HOME")?.trim()?.takeIf { it.isNotBlank() }?.let { return it }
    System.getenv("ANDROID_SDK_ROOT")?.trim()?.takeIf { it.isNotBlank() }?.let { return it }
    val localProps = file("${rootDir}/local.properties")
    if (localProps.exists()) {
        val props = java.util.Properties()
        localProps.inputStream().use { props.load(it) }
        props.getProperty("sdk.dir")?.takeIf { it.isNotBlank() }?.let { return it }
    }
    return file("${System.getProperty("user.home")}/Android/Sdk").takeIf { it.exists() }?.absolutePath
}

gradle.taskGraph.whenReady {
    val buildTaskPatterns = listOf(
        Regex("(^|:)(assemble|bundle|compile|lint|buildRust|test|check)([A-Z0-9_].*)?$"),
        Regex("(^|:)connectedCheck[A-Z0-9_].*"),
        Regex("(^|:).*(AndroidTest|UnitTest)([A-Z0-9_].*)?$")
    )
    val needsAndroidBuild = allTasks.any { task ->
        buildTaskPatterns.any { it.containsMatchIn(task.path) }
    }
    if (!needsAndroidBuild) return@whenReady

    val runningJavaVersion = JavaVersion.current()
    if (runningJavaVersion.majorVersion.toInt() != expectedJavaMajor) {
        throw GradleException(
            "JDK $expectedJavaMajor is required but Gradle is running on ${System.getProperty("java.version")} " +
            "(java.home=${System.getProperty("java.home")}). " +
            "Fix: set JAVA_HOME to a JDK $expectedJavaMajor install (e.g. Temurin 17) and re-run."
        )
    }

    val androidHome = resolveAndroidSdkDir()
    if (androidHome == null) {
        logger.warn(
            "Android SDK not found (ANDROID_HOME, ANDROID_SDK_ROOT, local.properties sdk.dir, " +
            "and ~/Android/Sdk all unset/missing). Skipping NDK $expectedNdkVersion check; " +
            "Android build tasks will likely fail."
        )
        return@whenReady
    }
    val ndkDir = file("$androidHome/ndk/$expectedNdkVersion")
    if (!ndkDir.exists()) {
        throw GradleException(
            "Android NDK $expectedNdkVersion not found at ${ndkDir.absolutePath}. " +
            "Fix: sdkmanager --install \"ndk;$expectedNdkVersion\" " +
            "(or install via Android Studio SDK Manager)."
        )
    }

    val releaseTaskPattern = Regex("(^|:)(assemble|bundle|package)([A-Z0-9_].*)?Release([A-Z0-9_].*)?$")
    val buildingRelease = allTasks.any { task ->
        releaseTaskPattern.containsMatchIn(task.path)
    }
    if (buildingRelease) {
        val sde = System.getenv("SOURCE_DATE_EPOCH")
        if (sde.isNullOrBlank()) {
            throw GradleException(
                "SOURCE_DATE_EPOCH is not set. Release builds require it to be set in the " +
                "Gradle JVM environment so AGP's packaging and signing use a deterministic " +
                "timestamp. Fix: export SOURCE_DATE_EPOCH=\"\$(./scripts/derive-sde.sh)\" " +
                "before invoking Gradle."
            )
        }
        validateSourceDateEpoch(sde)
    }
}

val keepRepo = file(System.getenv("KEEP_REPO") ?: "${rootDir}/keep")

tasks.register("verifyKeepVersion") {
    group = "verification"
    description = "Verifies that the local keep checkout matches the pinned SHA in keep.version."
    val keepVersionFile = file("${rootDir}/keep.version")
    inputs.file(keepVersionFile).withPathSensitivity(PathSensitivity.RELATIVE)
    doLast {
        if (!keepVersionFile.exists()) {
            throw GradleException("keep.version not found at ${keepVersionFile.absolutePath}.")
        }
        val pinnedSha = keepVersionFile.readText().trim()
        if (!pinnedSha.matches(Regex("^[0-9a-f]{40}$"))) {
            throw GradleException(
                "keep.version at ${keepVersionFile.absolutePath} must be a 40-char lowercase hex SHA, got: '$pinnedSha'."
            )
        }
        val keepPath = keepRepo.absolutePath
        if (!keepRepo.isDirectory) {
            throw GradleException(
                "keep workspace not found at $keepPath. " +
                "Fix: git clone https://github.com/privkeyio/keep.git $keepPath && " +
                "git -C $keepPath checkout $pinnedSha"
            )
        }
        if (!file("$keepPath/.git").exists()) {
            throw GradleException(
                "keep workspace at $keepPath is not a git repository. " +
                "Fix: rm -rf $keepPath && git clone https://github.com/privkeyio/keep.git $keepPath && " +
                "git -C $keepPath checkout $pinnedSha"
            )
        }
        fun git(vararg args: String, onFailure: () -> String): String {
            val proc = ProcessBuilder(listOf("git", "-C", keepPath) + args)
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .start()
            val output = proc.inputStream.bufferedReader().use { it.readText() }
            if (proc.waitFor() != 0) {
                throw GradleException(onFailure())
            }
            return output
        }
        val actualSha = git("rev-parse", "HEAD") {
            "Failed to read HEAD of $keepPath. Fix: git -C $keepPath checkout $pinnedSha"
        }.trim()
        if (actualSha != pinnedSha) {
            throw GradleException(
                "keep checkout at $keepPath is at $actualSha but keep.version pins $pinnedSha. " +
                "Fix: git -C $keepPath checkout $pinnedSha"
            )
        }
        val statusOutput = git("status", "--porcelain") {
            "Failed to check worktree status of $keepPath. " +
            "Fix: git -C $keepPath reset --hard $pinnedSha && git -C $keepPath clean -fdx"
        }
        if (statusOutput.isNotBlank()) {
            throw GradleException(
                "keep checkout at $keepPath has a dirty worktree, which bypasses SHA pinning. " +
                "Fix: git -C $keepPath reset --hard $pinnedSha && git -C $keepPath clean -fdx"
            )
        }
    }
}

tasks.register<Exec>("buildRust") {
    group = "rust"
    description = "Builds keep-mobile Rust native libraries and regenerates UniFFI Kotlin bindings."
    dependsOn("verifyKeepVersion")
    workingDir = rootDir
    commandLine("bash", "build-rust.sh")
    environment("KEEP_REPO", keepRepo.absolutePath)
    System.getenv("SOURCE_DATE_EPOCH")?.takeIf { it.isNotBlank() }?.let { sde ->
        environment("SOURCE_DATE_EPOCH", validateSourceDateEpoch(sde))
    }

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
