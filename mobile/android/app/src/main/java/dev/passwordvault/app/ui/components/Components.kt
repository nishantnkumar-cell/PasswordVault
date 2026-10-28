package dev.passwordvault.app.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.passwordvault.app.ui.theme.tileColors

/** The coloured letter tile used for items everywhere, as on the desktop. */
@Composable
fun LetterTile(title: String, size: Dp = 42.dp, shape: Shape = CircleShape) {
    val (bg, fg) = tileColors(title, isSystemInDarkTheme())
    Box(
        Modifier.size(size).clip(shape).background(bg),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            title.trim().firstOrNull()?.uppercase() ?: "?",
            color = fg,
            fontWeight = FontWeight.SemiBold,
            fontSize = (size.value * 0.42f).sp,
        )
    }
}

/** A ring that empties as the one-time code ages. */
@Composable
fun TotpRing(remaining: Int, period: Int, size: Dp = 44.dp, label: Boolean = false) {
    val track = MaterialTheme.colorScheme.primary.copy(alpha = 0.18f)
    val fill = MaterialTheme.colorScheme.primary
    val frac = if (period > 0) remaining.toFloat() / period else 0f
    Box(
        Modifier.size(size).semantics { contentDescription = "$remaining seconds left" },
        contentAlignment = Alignment.Center,
    ) {
        Canvas(Modifier.size(size)) {
            val w = this.size.minDimension * 0.13f
            val inset = w / 2
            val arcSize = androidx.compose.ui.geometry.Size(this.size.width - w, this.size.height - w)
            val tl = androidx.compose.ui.geometry.Offset(inset, inset)
            drawArc(track, 0f, 360f, false, tl, arcSize, style = Stroke(w))
            drawArc(fill, -90f, 360f * frac, false, tl, arcSize, style = Stroke(w, cap = StrokeCap.Round))
        }
        if (label) {
            Text("$remaining", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onPrimaryContainer)
        }
    }
}

/**
 * Material 3 Expressive grouped list: rows separated by small gaps, the
 * group's outer corners rounder than the inner ones.
 */
@Composable
fun SegmentedGroup(
    count: Int,
    modifier: Modifier = Modifier,
    row: @Composable (index: Int, shape: Shape) -> Unit,
) {
    Column(modifier, verticalArrangement = Arrangement.spacedBy(3.dp)) {
        for (i in 0 until count) row(i, segmentShape(i, count))
    }
}

fun segmentShape(index: Int, count: Int, outer: Dp = 22.dp, inner: Dp = 6.dp): Shape = when {
    count == 1 -> RoundedCornerShape(outer)
    index == 0 -> RoundedCornerShape(outer, outer, inner, inner)
    index == count - 1 -> RoundedCornerShape(inner, inner, outer, outer)
    else -> RoundedCornerShape(inner)
}

/** One labelled value in a detail group, with trailing actions. */
@Composable
fun FieldRow(
    label: String,
    shape: Shape,
    modifier: Modifier = Modifier,
    actions: @Composable RowScope.() -> Unit = {},
    value: @Composable ColumnScope.() -> Unit,
) {
    Surface(shape = shape, color = MaterialTheme.colorScheme.surfaceContainerLowest, modifier = modifier.fillMaxWidth()) {
        Row(
            Modifier.heightIn(min = 64.dp).padding(start = 20.dp, end = 8.dp, top = 10.dp, bottom = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(label, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
                value()
            }
            actions()
        }
    }
}

/** Small section heading in the primary colour, as in the mockups. */
@Composable
fun SectionLabel(text: String, modifier: Modifier = Modifier) {
    Text(
        text,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = modifier.padding(start = 16.dp, top = 16.dp, bottom = 8.dp),
    )
}

/**
 * The app icon, drawn like contrib/icons/secret-vault-small.svg: a white
 * keyhole on the signal-red tile, or on a green one while the vault is unlocked.
 */
@Composable
fun AppIcon(size: Dp = 88.dp, unlocked: Boolean = false, modifier: Modifier = Modifier) {
    val colors = if (unlocked) listOf(Color(0xFF2EB86B), Color(0xFF157542)) else listOf(Color(0xFFEE3B36), Color(0xFFB5161B))
    Canvas(
        modifier
            .size(size)
            .clip(RoundedCornerShape(size * (96f / 512f)))
            .background(Brush.linearGradient(colors)),
    ) {
        val s = this.size.width / 512f
        drawCircle(Color.White, radius = 86.8f * s, center = Offset(256f * s, 195.6f * s))
        val p = Path().apply {
            moveTo(216.8f * s, 237.6f * s); lineTo(186f * s, 411.2f * s)
            lineTo(326f * s, 411.2f * s); lineTo(295.2f * s, 237.6f * s); close()
        }
        drawPath(p, Color.White)
    }
}
