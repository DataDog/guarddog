rule NK_InvisibleFerret
{
  meta:
    author = "mmmuir_dd"
    description = "InvisibleFerret obfuscated Python script"
    target_entity = "file"
  strings:
    $decode1 = "sk=temp[:8]"
    $decode2 = "chr(data[i]^ord(sk[k]));res+=c"
    $exec = "exec(res)"
    $const = "sType = "
  condition:
    3 of them
}
