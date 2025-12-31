rule threat_runtime_obfuscation_steganography
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects steganography decode followed by code execution"
        identifies = "threat.runtime.obfuscation.steganography"
        severity = "high"
        mitre_tactics = "defense-evasion"
        specificity = "high"
        sophistication = "high"

        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"
    strings:
        // Python - steganography libraries
        $py_stego_decode = "steganography.decode(" nocase
        $py_lsb_reveal = "lsb.reveal(" nocase
        $py_stegano = "stegano" nocase
        $py_pil_image = "PIL.Image" nocase
        $py_exec = "exec(" nocase
        $py_eval = "eval(" nocase

        // JavaScript/Node.js - steganography
        $js_steggy = "steggy.reveal(" nocase
        $js_stego = "stego.decode(" nocase
        $js_jimp = "Jimp.read(" nocase
        $js_getpixel = "getPixelColor(" nocase
        $js_buffer_concat = "Buffer.concat(" nocase
        $js_eval = "eval(" nocase

        // Image file references in code
        $img_png = /\.(png|jpg|jpeg|gif|bmp)['"]/ nocase

    condition:
        (any of ($py_stego*, $py_lsb*, $py_stegano, $py_pil*) and $img_png and ($py_exec or $py_eval)) or
        (any of ($js_*) and $img_png and $js_eval)
}
