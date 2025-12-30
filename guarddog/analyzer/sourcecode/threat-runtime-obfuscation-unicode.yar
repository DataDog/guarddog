rule threat_runtime_obfuscation_unicode
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects unicode homoglyphs and uncommon characters used for obfuscation"
        identifies = "threat.runtime.obfuscation.unicode"
        severity = "medium"
        mitre_tactics = "defense-evasion"
        specificity = "medium"
        sophistication = "medium"

	path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go"
        max_hits = 1
    strings:
        // Mathematical Alphanumeric Symbols (specific examples of common homoglyphs)
        $unicode_math_bold = "\xf0\x9d\x90\x80" // 𝐀 (bold A)
        $unicode_math_italic = "\xf0\x9d\x90\xb4" // 𝐴 (italic A)
        $unicode_math_script = "\xf0\x9d\x92\x9c" // 𝒜 (script A)

        // Cyrillic lookalikes (UTF-8 encoded)
        $cyrillic_a = "\xd0\xb0" // а (Cyrillic a looks like Latin a)
        $cyrillic_e = "\xd0\xb5" // е (Cyrillic e looks like Latin e)
        $cyrillic_o = "\xd0\xbe" // о (Cyrillic o looks like Latin o)
        $cyrillic_p = "\xd1\x80" // р (Cyrillic r looks like Latin p)
        $cyrillic_c = "\xd1\x81" // с (Cyrillic s looks like Latin c)
        $cyrillic_y = "\xd1\x83" // у (Cyrillic u looks like Latin y)
        $cyrillic_x = "\xd1\x85" // х (Cyrillic h looks like Latin x)

        // Greek lookalikes (UTF-8 encoded)
        $greek_alpha = "\xce\xb1" // α
        $greek_beta = "\xce\xb2" // β
        $greek_omicron = "\xce\xbf" // ο (looks like Latin o)
        $greek_rho = "\xcf\x81" // ρ (looks like Latin p)

        // Zero-width characters (invisible, UTF-8 encoded)
        $zero_width_space = "\xe2\x80\x8b"
        $zero_width_non_joiner = "\xe2\x80\x8c"
        $zero_width_joiner = "\xe2\x80\x8d"

    condition:
        2 of them
}
