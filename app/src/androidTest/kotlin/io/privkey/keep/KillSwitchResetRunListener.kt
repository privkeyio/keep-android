package io.privkey.keep

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.runner.Description
import org.junit.runner.notification.RunListener

/**
 * Forces the Rust-owned kill switch to its disengaged baseline before every
 * instrumented test (gh #397).
 *
 * The kill switch is persisted core state (it must survive a process restart). A
 * test that engages it and then suffers process death strictly between the engage
 * and its `@After` restore leaves the switch engaged on disk, which would then
 * fail-closed every signing test in a *subsequent* test class. Resetting it here,
 * before each test runs (`testStarted` fires before the test's own `@Before`),
 * neutralizes that cross-class leak without the module-wide blast radius of Android
 * Test Orchestrator + `clearPackageData`: a kill-switch-mutating class still engages
 * the switch in its own `@Before`, which runs after this reset.
 *
 * Registered via the `listener` instrumentation-runner argument in
 * `app/build.gradle.kts`. Best-effort: if the core is not yet initialized the reset
 * is skipped (the application's own `onCreate` establishes the disengaged default).
 */
class KillSwitchResetRunListener : RunListener() {
    override fun testStarted(description: Description) {
        val app = InstrumentationRegistry.getInstrumentation()
            .targetContext
            .applicationContext as? KeepMobileApp
        app?.getKeepMobile()?.setKillSwitch(false)
    }
}
