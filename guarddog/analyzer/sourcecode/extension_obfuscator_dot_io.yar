rule DETECT_FILE_obfuscator_dot_io
{
	meta:
	
		author = "T HAMDOUNI, Datadog"
		description = "Detects Javascript code obfuscated with obfuscator.io. Note that although malicious code is often obfuscated, there are legitimate use cases including protecting intellectual property or preventing reverse engineering."

	strings:
        $id1 = /(^|[^A-Za-z0-9])_0x[a-f0-9]{4,8}/ ascii
        $id2 = /(^|[^A-Za-z0-9])a0_0x[a-f0-9]{4,8}/ ascii

        $rot_push  = "['push'](_0x" ascii
        $rot_shift = "['shift']()" ascii
        $loop1     = /while\s*\(\!\!\[\]\)/

        $def1 = "Function('return\\x20(function()\\x20'+'{}.constructor(\\x22return\\x20this\\x22)(" ascii
        $def2 = "{}.constructor(\"return this\")(" ascii
        $def3 = "{}.constructor(\\x22return\\x20this\\x22)(\\x20)" base64

        $tok2 = /parseInt\(_0x[a-f0-9]{4,8}\(0x[a-f0-9]+\)\)/ ascii nocase  // strong indicator

    condition:
        filesize < 5MB and
        (
            ( (#id1 + #id2) >= 6 ) or
            ( ( $rot_push and $rot_shift ) or $loop1 )  or
            ( any of ($def*) or #tok2 > 5 )
        )
	
}
