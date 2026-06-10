# FALSE POSITIVE: a Unicode category data table (pygments-style unistring.py).
# Two long runs of \uXXXX escapes trip $unicode_1 (#unicode_1 >= 2), but this is
# declarative Unicode property data, not obfuscation.
Ll = "\u0101\u0103\u0105\u0107\u0109\u010b\u010d\u010f\u0111\u0113\u0115\u0117"
Lu = "\u0101\u0103\u0105\u0107\u0109\u010b\u010d\u010f\u0111\u0113\u0115\u0117"
