# Obfuscated with BlankOBF
# https://github.com/Blank-c/BlankOBF

def f():
    # ruleid: obfuscation
    _____=eval("\123\123\123\123")

def f():
    # ruleid: obfuscation
    _____ = eval("foo")

def f():
    # ok: obfuscation
    eval("foo")

def f():
    # ruleid: obfuscation
    cc = getattr(builtins, b'\x00\x00\x00\x00'.decode('cp1026'));cc(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfc]'.decode('cp1026'))

def f():
    # ruleid: obfuscation
    cc = __builtins__.getattr(__builtins__, b'\x85\xa5\x81\x93'.decode('cp1026'));cc(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfc'.decode('cp1026'))

def f():
    # ruleid: obfuscation
     i=0                                                                                                                                                                                                                                                                                                                             ;print("malicious code here");

def f():
    # ruleid: obfuscation
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfc'.decode('cp1026')

def f():
    """
     * Retrieves a list of up to 100 members and their membership status, given the provided paging and filtering.
     *
     * The queryMemberships function returns a Promise that resolves to a list of memberships.
     *
     * >**Note:** Site members can only query their own memberships.
     *
     // ok: obfuscation
     * | Property                    | Supported Filters & Sorting                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
     * | --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
     * | `status`                    | [`eq()`](#membershipsquerybuilder/eq), [`ne()`](#membershipsquerybuilder/ne)             |
     * | `role`                      | [`eq()`](#membershipsquerybuilder/eq), [`ne()`](#membershipsquerybuilder/ne)             |
     *
     * @public
     * @requiredField memberId
     * @param memberId - Site member ID.
     * @adminMethod
    """
    pass

def f():
    # ruleid: obfuscation
    exec(''.join(chr(c) for c in [0,0,0,0,0,0,0,0,0,0,0]))
    # ruleid: obfuscation
    exec(''.join(map(chr, [0,0,0,0,0,0,0,0,0,0,0])))
