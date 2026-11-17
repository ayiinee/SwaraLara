package id.swaralara.coredemo

import android.Manifest
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.test.rule.GrantPermissionRule
import id.swaralara.core.*
import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.After

class LocalFlowTest {
    @get:Rule(order = 0) val permission: GrantPermissionRule = GrantPermissionRule.grant(Manifest.permission.RECORD_AUDIO)
    @get:Rule(order = 1) val compose = createAndroidComposeRule<MainActivity>()
    @After fun cleanup() = runBlocking {
        val core = CoreRuntime.get(compose.activity)
        try { if (core.recorder.state.value.busy) core.recorder.stop() }
        finally { core.playback.release() }
    }
    @Test fun holdRecordsOnceReleaseKeepsRecordingAndLocalRecoveryWorks() {
        val core = CoreRuntime.get(compose.activity)
        val hold = compose.onNodeWithContentDescription("Tahan untuk merekam")
        hold.performTouchInput { down(center); advanceEventTime(100); up() }
        compose.waitForIdle()
        assertFalse(core.recorder.state.value.busy)
        hold.performTouchInput { down(center) }
        compose.waitUntil(timeoutMillis = 10_000) { core.recorder.state.value.capture == CaptureState.RECORDING }
        val id = requireNotNull(core.recorder.state.value.id)
        hold.performTouchInput { up() }
        compose.waitForIdle()
        assertEquals(CaptureState.RECORDING,core.recorder.state.value.capture)
        // A second held interaction must leave the service session unchanged.
        hold.performTouchInput { down(center) }
        Thread.sleep(1700)
        hold.performTouchInput { up() }
        assertEquals(id,core.recorder.state.value.id)
        compose.waitUntil(timeoutMillis = 10_000) { core.recorder.state.value.savedSegments >= 1 }
        runBlocking { core.recorder.stop() }
        assertEquals(CaptureState.SEALED,core.recorder.state.value.capture)
        runBlocking {
            assertTrue(core.vault.inspect(id).passed)
            assertEquals(3,core.vault.demonstrateRecovery(id).pairsVerified)
            assertTrue(core.vault.testCorruptionOnCopy(id))
            assertTrue(core.playback.prepare(id))
            core.playback.play()
            withTimeout(20_000) {
                while (core.playback.state.value.phase !in setOf(PlaybackPhase.COMPLETED,PlaybackPhase.FAILED)) delay(50)
            }
            assertEquals(PlaybackPhase.COMPLETED,core.playback.state.value.phase)
            assertEquals(core.playback.state.value.totalFrames,core.playback.state.value.positionFrames)
            core.playback.release()
        }
    }
}
