package dev.passwordvault.app.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// The desktop palette (crates/vault-gui/src/theme.rs) as a Material 3 scheme.
private val Accent = Color(0xFF2C55D4)

private val Light = lightColorScheme(
    primary = Accent,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFDCE1FF),
    onPrimaryContainer = Color(0xFF00164E),
    secondary = Color(0xFF4F5665),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFE3E6EE),
    onSecondaryContainer = Color(0xFF15171C),
    tertiary = Color(0xFF1F7A4D),
    tertiaryContainer = Color(0xFFC4EED0),
    onTertiaryContainer = Color(0xFF00210F),
    error = Color(0xFFB42318),
    errorContainer = Color(0xFFFDECEA),
    onErrorContainer = Color(0xFF5F120B),
    background = Color(0xFFF8F8FC),
    onBackground = Color(0xFF15171C),
    surface = Color(0xFFF8F8FC),
    onSurface = Color(0xFF15171C),
    surfaceVariant = Color(0xFFE9EAF1),
    onSurfaceVariant = Color(0xFF44474F),
    surfaceContainerLowest = Color.White,
    surfaceContainerLow = Color(0xFFF2F3F8),
    surfaceContainer = Color(0xFFEEEFF5),
    surfaceContainerHigh = Color(0xFFE9EAF1),
    surfaceContainerHighest = Color(0xFFE3E4EB),
    outline = Color(0xFF75777F),
    outlineVariant = Color(0xFFC5C6D0),
)

private val Dark = darkColorScheme(
    primary = Color(0xFFB4C5FF),
    onPrimary = Color(0xFF002A78),
    primaryContainer = Color(0xFF1D3FA8),
    onPrimaryContainer = Color(0xFFDCE1FF),
    secondary = Color(0xFFC1C6D6),
    secondaryContainer = Color(0xFF30343E),
    onSecondaryContainer = Color(0xFFE1E4EE),
    tertiary = Color(0xFF8BD8A6),
    tertiaryContainer = Color(0xFF0F5233),
    onTertiaryContainer = Color(0xFFC4EED0),
    error = Color(0xFFFFB4A9),
    errorContainer = Color(0xFF8C1D12),
    onErrorContainer = Color(0xFFFFDAD4),
    background = Color(0xFF0F1115),
    onBackground = Color(0xFFE6E8EE),
    surface = Color(0xFF0F1115),
    onSurface = Color(0xFFE6E8EE),
    surfaceVariant = Color(0xFF2A2D35),
    onSurfaceVariant = Color(0xFFC4C7D0),
    surfaceContainerLowest = Color(0xFF0A0B0E),
    surfaceContainerLow = Color(0xFF16181D),
    surfaceContainer = Color(0xFF1A1D23),
    surfaceContainerHigh = Color(0xFF23262D),
    surfaceContainerHighest = Color(0xFF2D3038),
    outline = Color(0xFF8E9099),
    outlineVariant = Color(0xFF44474F),
)

/** Colours outside the Material scheme: letter tiles and status. */
@Immutable
data class VaultColors(val ok: Color, val okContainer: Color, val warn: Color, val warnContainer: Color)

val LocalVaultColors = staticCompositionLocalOf {
    VaultColors(Color(0xFF1F7A4D), Color(0xFFC4EED0), Color(0xFFA84E06), Color(0xFFFBEEE2))
}

/** The monospace face for one-time codes, passwords and URLs. */
val Mono = FontFamily.Monospace

private val Expressive = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(24.dp),
    extraLarge = RoundedCornerShape(32.dp),
)

private val Type = Typography().let { t ->
    t.copy(
        displaySmall = t.displaySmall.copy(fontWeight = FontWeight.SemiBold),
        headlineMedium = t.headlineMedium.copy(fontWeight = FontWeight.SemiBold),
        headlineSmall = t.headlineSmall.copy(fontWeight = FontWeight.SemiBold),
        titleLarge = t.titleLarge.copy(fontWeight = FontWeight.SemiBold),
    )
}

val CodeStyle = TextStyle(fontFamily = Mono, fontWeight = FontWeight.SemiBold, fontSize = 30.sp, letterSpacing = 1.sp)

@Composable
fun VaultTheme(dynamicColor: Boolean = false, content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val context = LocalContext.current
    val scheme: ColorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
            if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        dark -> Dark
        else -> Light
    }
    val extra = if (dark) {
        VaultColors(Color(0xFF8BD8A6), Color(0xFF0F5233), Color(0xFFFFB77C), Color(0xFF5C2A00))
    } else {
        VaultColors(Color(0xFF1F7A4D), Color(0xFFC4EED0), Color(0xFFA84E06), Color(0xFFFBEEE2))
    }
    androidx.compose.runtime.CompositionLocalProvider(LocalVaultColors provides extra) {
        MaterialTheme(colorScheme = scheme, shapes = Expressive, typography = Type, content = content)
    }
}

/** Letter tile colours, picked from the title so an item keeps its colour. */
fun tileColors(title: String, dark: Boolean): Pair<Color, Color> {
    val light = listOf(
        Color(0xFFE5DEFF) to Color(0xFF1B0E5B),
        Color(0xFFCDE5FF) to Color(0xFF001D32),
        Color(0xFFC4EED0) to Color(0xFF00210F),
        Color(0xFFFFDBCB) to Color(0xFF341100),
        Color(0xFFDCE1FF) to Color(0xFF00164E),
        Color(0xFFFFD8E4) to Color(0xFF3E001D),
    )
    val darkTiles = listOf(
        Color(0xFF3A2F7A) to Color(0xFFE5DEFF),
        Color(0xFF0F4A70) to Color(0xFFCDE5FF),
        Color(0xFF0F5233) to Color(0xFFC4EED0),
        Color(0xFF6B2E0E) to Color(0xFFFFDBCB),
        Color(0xFF1D3FA8) to Color(0xFFDCE1FF),
        Color(0xFF6E1D3F) to Color(0xFFFFD8E4),
    )
    val list = if (dark) darkTiles else light
    val h = title.lowercase().fold(7) { acc, c -> acc * 31 + c.code }
    return list[Math.floorMod(h, list.size)]
}
