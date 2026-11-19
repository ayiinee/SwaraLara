package id.swaralara.app

import android.Manifest
import android.graphics.Bitmap
import android.graphics.Rect
import android.os.SystemClock
import android.view.MotionEvent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.rule.GrantPermissionRule
import id.swaralara.core.*
import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

/** Uses platform accessibility rather than Espresso idling on the user's physical device. */
class FrontendFlowTest {
    @get:Rule
    val permissions =
        GrantPermissionRule.grant(
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.POST_NOTIFICATIONS,
        )
    private val instrumentation
        get() = InstrumentationRegistry.getInstrumentation()

    private val context
        get() = instrumentation.targetContext

    private fun nodes(): List<AccessibilityNodeInfo> {
        val result = mutableListOf<AccessibilityNodeInfo>()
        fun visit(node: AccessibilityNodeInfo?) {
            if (node == null) return
            result += node
            repeat(node.childCount) { visit(node.getChild(it)) }
        }
        val root = instrumentation.uiAutomation.rootInActiveWindow
        if (root?.packageName?.toString() != context.packageName) return emptyList()
        visit(root)
        return result
    }

    private fun until(label: String, predicate: () -> Boolean) {
        val deadline = SystemClock.uptimeMillis() + 20000
        while (!predicate()) {
            check(SystemClock.uptimeMillis() < deadline) { "Timed out: $label" }
            SystemClock.sleep(100)
        }
    }

    private fun tap(text: String, last: Boolean = false) {
        until("visible $text") { nodes().any { it.text?.toString() == text } }
        val matches = nodes().filter { it.text?.toString() == text }
        var node: AccessibilityNodeInfo? = if (last) matches.last() else matches.first()
        while (node != null && !node.isClickable) node = node.parent
        assertNotNull("Clickable control: $text", node)
        assertTrue("Enabled control: $text", node!!.isEnabled)
        assertTrue(node.performAction(AccessibilityNodeInfo.ACTION_CLICK))
        SystemClock.sleep(250)
    }

    private fun screenshot(name: String) {
        SystemClock.sleep(250)
        until("SwaraLara in foreground") { nodes().isNotEmpty() }
        val folder = File(context.getExternalFilesDir(null), "frontend-preview").apply { mkdirs() }
        val bitmap = instrumentation.uiAutomation.takeScreenshot()
        File(folder, "$name.png").outputStream().use {
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, it)
        }
        bitmap.recycle()
    }

    private fun press(duration: Long) {
        val node = nodes().first { it.contentDescription?.toString() == "Tahan untuk merekam" }
        val bounds = Rect().also { node.getBoundsInScreen(it) }
        val down = SystemClock.uptimeMillis()
        fun event(action: Int) {
            val event =
                MotionEvent.obtain(
                    down,
                    SystemClock.uptimeMillis(),
                    action,
                    bounds.exactCenterX(),
                    bounds.exactCenterY(),
                    0,
                )
            event.source = android.view.InputDevice.SOURCE_TOUCHSCREEN
            try {
                assertTrue(instrumentation.uiAutomation.injectInputEvent(event, true))
            } finally {
                event.recycle()
            }
        }
        event(MotionEvent.ACTION_DOWN)
        SystemClock.sleep(duration)
        event(MotionEvent.ACTION_UP)
    }

    @Test
    fun navigationAndRealRecordingPlayback() {
        val core = CoreRuntime.get(context)
        instrumentation.uiAutomation.executeShellCommand(
            "am start -W -n id.swaralara.app/.MainActivity"
        ).use { descriptor ->
            android.os.ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { it.readBytes() }
        }
        until("Beranda") { nodes().any { it.text?.toString() == "SwaraLara" } }
        try {
            tap("Brankas", last = true)
            tap("Terpercaya", last = true)
            until("Token") { nodes().any { it.text?.toString() == "Token" } }
            screenshot("perangkat")
            tap("Akses", last = true)
            until("Muat ulang") { nodes().any { it.text?.toString() == "Muat ulang" } }
            screenshot("akses")
            tap("Pengaturan", last = true)
            until("Pengaturan") { nodes().any { it.text?.toString() == "Akun" } }
            screenshot("pengaturan")
            tap("Beranda", last = true)
            press(100)
            assertFalse(core.recorder.state.value.busy)
            press(1800)
            until("Merekam") { core.recorder.state.value.capture == CaptureState.RECORDING }
            until("segmen tersimpan") { core.recorder.state.value.savedSegments > 0 }
            screenshot("merekam")
            tap("Berhenti merekam")
            until("rekaman tersimpan") { !core.recorder.state.value.busy }
            until("Terbaru") { nodes().any { it.text?.toString() == "Terbaru" } }
            screenshot("beranda")
            tap("Brankas", last = true)
            tap("Kejadian")
            tap("Periksa")
            until("integritas") { nodes().any { it.text?.toString()?.replace(' ', '_') == "VERIFIED_PARTIAL" } }
            tap("Putar")
            until("player siap") { core.playback.state.value.phase == PlaybackPhase.PREPARED }
            screenshot("rekaman")
            tap("Putar", last = true)
            until("pemutaran") {
                core.playback.state.value.phase in
                    setOf(PlaybackPhase.PLAYING, PlaybackPhase.COMPLETED)
            }
            tap("Tutup")
            until("player ditutup") { core.playback.state.value.phase == PlaybackPhase.IDLE }
        } finally {
            runBlocking {
                core.recorder.stop()
                core.playback.release()
            }
        }
    }
}
