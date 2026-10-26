# Bundled fonts

The app draws its text with Inter (body and headings) and JetBrains Mono
(passwords, codes, keys), so it looks the same on Linux, Windows and macOS.
Both are under the SIL Open Font License 1.1 (see the `*-OFL.txt` files).

The files here are subsets made with fontTools to keep the binary small
(Latin, Greek, Cyrillic, punctuation, arrows and common symbols). Characters
outside them fall back to egui's built-in fonts. To rebuild them:

    pip install fonttools
    U="U+0020-007E,U+00A0-024F,U+0300-036F,U+0370-03FF,U+0400-04FF,U+1E00-1EFF,U+2000-206F,U+20A0-20CF,U+2100-214F,U+2190-21FF,U+2200-22FF,U+2300-23FF,U+25A0-25FF,U+2713,U+2717,U+FFFD"
    pyftsubset Inter-Regular.otf  --unicodes="$U" --layout-features='kern,liga,calt,tnum,case,ss01' --output-file=Inter-Regular.otf
    pyftsubset Inter-SemiBold.otf --unicodes="$U" --layout-features='kern,liga,calt,tnum,case,ss01' --output-file=Inter-SemiBold.otf
    pyftsubset JetBrainsMono-Regular.ttf --unicodes="$U" --layout-features='kern' --output-file=JetBrainsMono-Regular.ttf

starting from Inter 4.0 (https://github.com/rsms/inter/releases) and
JetBrains Mono 2.304 (https://github.com/JetBrains/JetBrainsMono/releases).
