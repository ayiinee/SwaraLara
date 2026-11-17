package id.swaralara.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import id.swaralara.core.CoreRuntime
import id.swaralara.core.RecorderPanel

// Scaffold handoff Orang 1. Recorder yang sama dengan core-demo, data sandbox terpisah.
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val core = CoreRuntime.get(applicationContext)
        setContent { MaterialTheme { Surface { RecorderPanel(core.recorder) } } }
    }
}
