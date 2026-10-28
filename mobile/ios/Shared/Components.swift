import SwiftUI
import UIKit

/// The desktop palette (crates/vault-gui/src/theme.rs), adapting to dark mode.
enum Palette {
    static let accent = Color(light: 0x2C55D4, dark: 0x8FA8FF)
    static let ok = Color(light: 0x1F7A4D, dark: 0x5FC48D)
    static let warn = Color(light: 0xA84E06, dark: 0xFFB77C)
    static let ground = Color(light: 0xF2F3F6, dark: 0x0D0F13)
    static let card = Color(light: 0xFFFFFF, dark: 0x1A1D24)
    static let muted = Color(light: 0x4F5665, dark: 0xA9B0BD)
}

extension Color {
    init(light: UInt32, dark: UInt32) {
        self.init(uiColor: UIColor { t in
            let v = t.userInterfaceStyle == .dark ? dark : light
            return UIColor(
                red: CGFloat((v >> 16) & 0xFF) / 255,
                green: CGFloat((v >> 8) & 0xFF) / 255,
                blue: CGFloat(v & 0xFF) / 255,
                alpha: 1
            )
        })
    }
}

/// The coloured letter tile used for items everywhere, as on the desktop.
struct LetterTile: View {
    let title: String
    var size: CGFloat = 40

    private static let tiles: [(UInt32, UInt32, UInt32, UInt32)] = [
        (0xE6E3F7, 0x3B2F8F, 0x2A2550, 0xC9C1FF),
        (0xDCEAF2, 0x1D4C6B, 0x10334A, 0xB9DDF5),
        (0xDCEFE3, 0x1F5A3A, 0x123D27, 0xB4E6C6),
        (0xFBEEE2, 0x8A3F05, 0x4A2406, 0xFFCFA6),
        (0xE8EEFC, 0x1D3FA8, 0x1A2B5E, 0xBCCBFF),
        (0xFCE4EC, 0x8E1E4A, 0x4D1229, 0xFFBDD3),
    ]

    var body: some View {
        let h = title.lowercased().unicodeScalars.reduce(7) { ($0 &* 31 &+ Int($1.value)) }
        let t = Self.tiles[((h % Self.tiles.count) + Self.tiles.count) % Self.tiles.count]
        Text(String(title.trimmingCharacters(in: .whitespaces).prefix(1)).uppercased())
            .font(.system(size: size * 0.42, weight: .semibold))
            .foregroundStyle(Color(light: t.1, dark: t.3))
            .frame(width: size, height: size)
            .background(Color(light: t.0, dark: t.2), in: RoundedRectangle(cornerRadius: size * 0.3, style: .continuous))
            .accessibilityHidden(true)
    }
}

/// A ring that empties as the one-time code ages.
struct TotpRing: View {
    let remaining: Int
    let period: Int
    var size: CGFloat = 40

    var body: some View {
        ZStack {
            Circle().stroke(Palette.accent.opacity(0.18), lineWidth: size * 0.13)
            Circle()
                .trim(from: 0, to: period > 0 ? CGFloat(remaining) / CGFloat(period) : 0)
                .stroke(Palette.accent, style: StrokeStyle(lineWidth: size * 0.13, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 1), value: remaining)
        }
        .frame(width: size, height: size)
        .accessibilityLabel("\(remaining) seconds left")
    }
}

/// The app icon: white keyhole on the signal-red tile, or on a green one
/// while the vault is unlocked.
struct AppIconView: View {
    var size: CGFloat = 84
    var unlocked = false

    private var colors: [Color] {
        unlocked
            ? [Color(red: 0.18, green: 0.72, blue: 0.42), Color(red: 0.08, green: 0.46, blue: 0.26)]
            : [Color(red: 0.93, green: 0.23, blue: 0.21), Color(red: 0.71, green: 0.09, blue: 0.11)]
    }

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 96 / 512, style: .continuous)
                .fill(LinearGradient(colors: colors, startPoint: .topLeading, endPoint: .bottomTrailing))
            Keyhole().fill(.white)
        }
        .frame(width: size, height: size)
        .shadow(color: colors[1].opacity(size > 40 ? 0.25 : 0), radius: 14, y: 8)
        .accessibilityHidden(true)
    }
}

/// The keyhole of contrib/icons/secret-vault-small.svg, on its 512 grid.
struct Keyhole: Shape {
    func path(in r: CGRect) -> Path {
        let s = r.width / 512
        let at = { (x: CGFloat, y: CGFloat) in CGPoint(x: r.minX + x * s, y: r.minY + y * s) }
        var p = Path()
        p.addEllipse(in: CGRect(origin: at(256 - 86.8, 195.6 - 86.8), size: CGSize(width: 173.6 * s, height: 173.6 * s)))
        p.move(to: at(216.8, 237.6))
        p.addLine(to: at(186, 411.2))
        p.addLine(to: at(326, 411.2))
        p.addLine(to: at(295.2, 237.6))
        p.closeSubpath()
        return p
    }
}

/// "177810" as "177 810".
func groupCode(_ code: String) -> String {
    guard code.count == 6 else { return code }
    return String(code.prefix(3)) + " " + String(code.suffix(3))
}

/// Copies with an expiry and marks the item local-only, so Universal
/// Clipboard never sends a secret to the user's other devices.
enum SecureClipboard {
    static func copy(_ value: String, sensitive: Bool) {
        if sensitive {
            let expiry = Date().addingTimeInterval(TimeInterval(Prefs.clipboardSeconds))
            UIPasteboard.general.setItems([[UIPasteboard.typeAutomatic: value]],
                                          options: [.localOnly: true, .expirationDate: expiry])
        } else {
            UIPasteboard.general.string = value
        }
    }
}

extension Kind {
    var label: String {
        switch self {
        case .login: return "Login"
        case .note: return "Secure note"
        case .card: return "Card"
        case .identity: return "Identity"
        }
    }

    var symbol: String {
        switch self {
        case .login: return "key"
        case .note: return "note.text"
        case .card: return "creditcard"
        case .identity: return "person.text.rectangle"
        }
    }
}

extension ItemSummary: Identifiable {}
