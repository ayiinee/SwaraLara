package id.swaralara.app

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import id.swaralara.core.*
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

internal val Plum = Color(0xFF542044)
internal val Ink = Color(0xFF301C2B)
internal val Page = Color(0xFFFAF4FC)
internal val CardTint = Color(0xFFF5EDF8)
internal val Pink = Color(0xFFB33776)
internal val SoftPink = Color(0xFFF0CEE6)
internal val Muted = Color(0xFF8C8490)
internal val Hairline = Color(0xFFE3D7E7)

@Composable
internal fun SwaraTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme =
            lightColorScheme(
                primary = Plum,
                onPrimary = Color.White,
                primaryContainer = SoftPink,
                secondary = Pink,
                background = Page,
                surface = Page,
                onBackground = Ink,
                onSurface = Ink,
                outline = Plum,
                outlineVariant = Hairline,
                surfaceVariant = CardTint,
                onSurfaceVariant = Muted,
                error = Color(0xFFC9191D),
            ),
        content = content,
    )
}

internal enum class Destination(val label: String, val icon: String) {
    HOME("Beranda", "home"),
    VAULT("Brankas", "lock"),
    DEVICES("Terpercaya", "shield"),
    ACCESS("Akses", "inbox"),
    SETTINGS("Pengaturan", "settings"),
}

/** Small outlined icons share one stroke, matching the supplied reference screens. */
@Composable
internal fun SwaraIcon(name: String, modifier: Modifier = Modifier, tint: Color = Plum) {
    Canvas(modifier.size(24.dp)) {
        val s = size.width / 24f
        fun p(x: Float, y: Float) = Offset(x * s, y * s)
        val stroke = Stroke(1.65f * s, cap = StrokeCap.Round)
        fun line(x: Float, y: Float, x2: Float, y2: Float) =
            drawLine(tint, p(x, y), p(x2, y2), 1.65f * s, StrokeCap.Round)
        fun path(vararg points: Pair<Float, Float>, close: Boolean = false) {
            val path =
                Path().apply {
                    moveTo(points[0].first * s, points[0].second * s)
                    points.drop(1).forEach { lineTo(it.first * s, it.second * s) }
                    if (close) close()
                }
            drawPath(path, tint, style = stroke)
        }
        fun rect(x: Float, y: Float, w: Float, h: Float, r: Float = 1.5f) =
            drawRoundRect(tint, p(x, y), Size(w * s, h * s), CornerRadius(r * s), style = stroke)
        when (name) {
            "home" -> {
                path(3f to 10f, 12f to 3f, 21f to 10f)
                path(
                    6f to 9f,
                    6f to 21f,
                    10f to 21f,
                    10f to 14f,
                    14f to 14f,
                    14f to 21f,
                    18f to 21f,
                    18f to 9f,
                )
            }
            "lock" -> {
                rect(5f, 10f, 14f, 11f)
                drawArc(tint, 180f, 180f, false, p(8f, 3f), Size(8 * s, 12 * s), style = stroke)
                drawCircle(tint, 1.1f * s, p(12f, 15f))
                line(12f, 16f, 12f, 18f)
            }
            "shield" -> {
                path(
                    12f to 2f,
                    20f to 6f,
                    19f to 15f,
                    12f to 22f,
                    5f to 15f,
                    4f to 6f,
                    close = true,
                )
                path(8f to 12f, 11f to 15f, 16f to 9f)
            }
            "inbox" -> {
                rect(4f, 4f, 16f, 16f)
                path(4f to 14f, 9f to 14f, 10f to 16f, 14f to 16f, 15f to 14f, 20f to 14f)
            }
            "mic" -> {
                rect(9f, 3f, 6f, 12f, 3f)
                drawArc(tint, 0f, 180f, false, p(5f, 7f), Size(14 * s, 12 * s), style = stroke)
                line(12f, 19f, 12f, 23f)
            }
            "document" -> {
                path(6f to 2f, 15f to 2f, 20f to 7f, 20f to 22f, 6f to 22f, close = true)
                path(15f to 2f, 15f to 7f, 20f to 7f)
                line(10f, 12f, 16f, 12f)
                line(10f, 16f, 16f, 16f)
            }
            "back" -> {
                line(20f, 12f, 4f, 12f)
                path(10f to 5f, 3f to 12f, 10f to 19f)
            }
            "arrow" -> {
                line(4f, 12f, 20f, 12f)
                path(14f to 6f, 20f to 12f, 14f to 18f)
            }
            "copy" -> {
                rect(8f, 7f, 12f, 15f)
                path(15f to 3f, 4f to 3f, 4f to 17f)
            }
            "devices" -> {
                path(16f to 4f, 3f to 4f, 3f to 17f, 12f to 17f)
                line(1f, 20f, 12f, 20f)
                rect(15f, 8f, 7f, 12f)
            }
            "settings" -> {
                val path =
                    Path().apply {
                        for (i in 0..31) {
                            val a = i * Math.PI / 16
                            val r = if (i % 4 in 1..2) 10f else 8f
                            val x = (12 + kotlin.math.cos(a) * r).toFloat() * s
                            val y = (12 + kotlin.math.sin(a) * r).toFloat() * s
                            if (i == 0) moveTo(x, y) else lineTo(x, y)
                        }
                        close()
                    }
                drawPath(path, tint, style = stroke)
                drawCircle(tint, 3f * s, p(12f, 12f), style = stroke)
            }
        }
    }
}

@Composable
internal fun SwaraBottomBar(current: Destination, navigate: (Destination) -> Unit) {
    Row(
        Modifier.fillMaxWidth()
            .background(Plum)
            .navigationBarsPadding()
            .padding(top = 10.dp, bottom = 9.dp)
    ) {
        Destination.entries.forEach { item ->
            val selected = current == item
            Column(
                Modifier.weight(1f)
                    .clip(RoundedCornerShape(12.dp))
                    .clickable { navigate(item) }
                    .padding(vertical = 1.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Box(
                    Modifier.size(52.dp, 29.dp)
                        .clip(CircleShape)
                        .background(if (selected) Page else Color.Transparent),
                    contentAlignment = Alignment.Center,
                ) {
                    SwaraIcon(item.icon, Modifier.size(22.dp), if (selected) Plum else Page)
                }
                Text(
                    if (item == Destination.DEVICES && selected) "Perangkat" else item.label,
                    color = Page,
                    fontSize = 10.sp,
                    lineHeight = 16.sp,
                )
            }
        }
    }
}

@Composable
internal fun PageHeading(
    title: String,
    back: (() -> Unit)? = null,
    trailing: (@Composable () -> Unit)? = null,
) {
    Row(
        Modifier.fillMaxWidth().padding(top = 13.dp, bottom = 20.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (back != null) {
            IconButton(onClick = back, modifier = Modifier.size(36.dp).offset(x = (-5).dp)) {
                SwaraIcon("back", tint = Ink)
            }
            Spacer(Modifier.width(6.dp))
        }
        Text(
            title,
            Modifier.weight(1f),
            fontSize = 24.sp,
            color = if (title == "SwaraLara" || title == "Perangkat") Plum else Ink,
            fontWeight = if (title == "Perangkat") FontWeight.SemiBold else FontWeight.Normal,
        )
        trailing?.invoke()
    }
}

@Composable
internal fun SwaraCard(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Surface(
        modifier.fillMaxWidth(),
        shape = RoundedCornerShape(19.dp),
        color = CardTint.copy(alpha = .55f),
        border = BorderStroke(1.dp, Hairline),
    ) {
        Column(
            Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            content = content,
        )
    }
}

@Composable
internal fun Pill(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    filled: Boolean = false,
    enabled: Boolean = true,
    pink: Boolean = false,
) {
    val colors =
        ButtonDefaults.buttonColors(
            containerColor = if (pink) SoftPink else Plum,
            contentColor = if (pink) Plum else Color.White,
            disabledContainerColor = Hairline,
            disabledContentColor = Muted,
        )
    if (filled)
        Button(
            onClick,
            modifier.heightIn(min = 42.dp),
            enabled = enabled,
            shape = CircleShape,
            colors = colors,
            contentPadding = PaddingValues(horizontal = 22.dp, vertical = 8.dp),
        ) {
            Text(text, fontSize = 14.sp)
        }
    else
        OutlinedButton(
            onClick,
            modifier.heightIn(min = 42.dp),
            enabled = enabled,
            shape = CircleShape,
            border = BorderStroke(1.dp, if (enabled) Plum else Hairline),
            contentPadding = PaddingValues(horizontal = 20.dp, vertical = 8.dp),
        ) {
            Text(text, fontSize = 14.sp)
        }
}

@Composable
internal fun Badge(text: String) {
    Text(
        text,
        Modifier.clip(CircleShape).background(Plum).padding(horizontal = 10.dp, vertical = 5.dp),
        color = Color.White,
        fontSize = 10.sp,
        lineHeight = 12.sp,
    )
}

internal fun duration(frames: Long, sampleRate: Int): String {
    val seconds = frames / sampleRate.coerceAtLeast(1)
    return "%02d:%02d".format(seconds / 60, seconds % 60)
}

internal fun recordingName(r: RecordingSummary) =
    if (r.kind == "live_event") "Kejadian" else "Penuturan"

internal fun recordingDate(time: Long) =
    SimpleDateFormat("MM/dd/yy h:mm a", Locale.US).format(Date(time))

internal fun captureBadge(r: RecordingSummary) =
    when (r.capture) {
        CaptureState.SEALED -> "READY"
        CaptureState.INTERRUPTED -> "INTERRUPTED"
        else -> r.capture.name
    }

@Composable
internal fun RecordingRow(r: RecordingSummary, open: () -> Unit) {
    Surface(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(17.dp)).clickable(onClick = open),
        shape = RoundedCornerShape(17.dp),
        color = CardTint.copy(alpha = .55f),
        border = BorderStroke(1.dp, Hairline),
    ) {
        Row(
            Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                Modifier.size(40.dp).background(SoftPink.copy(alpha = .6f), CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                SwaraIcon(
                    if (r.kind == "live_event") "mic" else "document",
                    Modifier.size(22.dp),
                    Pink,
                )
            }
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(recordingName(r), color = Pink, fontSize = 14.sp)
                Text(
                    "${recordingDate(r.startedAtDevice)} · ${duration(r.frames,r.sampleRate)}",
                    fontSize = 11.sp,
                    color = Muted,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                    Badge(captureBadge(r))
                    Badge(r.integrity.name.replace('_', ' '))
                }
            }
            SwaraIcon("arrow", Modifier.size(18.dp), Muted)
        }
    }
}
