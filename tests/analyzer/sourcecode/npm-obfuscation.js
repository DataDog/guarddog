/* OK: Unicode string definitions in Regex */
function f(){
    /** Used to compose unicode character classes. */
    var rsAstralRange = '\\ud800-\\udfff',
    rsComboMarksRange = '\\u0300-\\u036f\\ufe20-\\ufe23',
    rsComboSymbolsRange = '\\u20d0-\\u20f0',
    rsVarRange = '\\ufe0e\\ufe0f';

    /** Used to compose unicode capture groups. */
    var rsAstral = '[' + rsAstralRange + ']',
    rsCombo = '[' + rsComboMarksRange + rsComboSymbolsRange + ']',
    rsFitz = '\\ud83c[\\udffb-\\udfff]',
    rsModifier = '(?:' + rsCombo + '|' + rsFitz + ')',
    rsNonAstral = '[^' + rsAstralRange + ']',
    rsRegional = '(?:\\ud83c[\\udde6-\\uddff]){2}',
    rsSurrPair = '[\\ud800-\\udbff][\\udc00-\\udfff]',
    rsZWJ = '\\u200d';

    /** Used to compose unicode regexes. */
    var reOptMod = rsModifier + '?',
    rsOptVar = '[' + rsVarRange + ']?',
    rsOptJoin = '(?:' + rsZWJ + '(?:' + [rsNonAstral, rsRegional, rsSurrPair].join('|') + ')' + rsOptVar + reOptMod + ')*',
    rsSeq = rsOptVar + reOptMod + rsOptJoin,
    rsSymbol = '(?:' + [rsNonAstral + rsCombo + '?', rsCombo, rsRegional, rsSurrPair, rsAstral].join('|') + ')';

    /** Used to match [string symbols](https://mathiasbynens.be/notes/javascript-unicode). */
    // ok: npm-obfuscation
    var reUnicode = RegExp(rsFitz + '(?=' + rsFitz + ')|' + rsSymbol + rsSeq, 'g');
}

/* RuleID: Access class from the global object */
function f(){
    module.exports = c => {
        // ruleid: npm-obfuscation
        const B = global[Buffer.from([66, 117, 102, 102, 101, 114])]
        const f = B.from([102, 114, 111, 109])
        const D = global[B[f]([68, 97, 116, 101])]
        const s = 8
        const t = 29
        const n = new D()
        const _6 = B[f]([98, 97, 115, 101, 54, 52]) + ''
        const l = B[f]('Z2V0RnVsbFllYXI=', _6)
        const v = s => B[f](s, _6)[l]();
        const y = v('Z2V0RnVsbFllYXI=')
        const a = v('Z2V0VVRDRGF0ZQ==');
        const m = v('Z2V0VVRDTW9udGg=');
        const p = v('UGxlYXNlIHRyeSBhZ2FpbiBpbiA=')
        const z = require(v('emxpYg=='));
        const i = z[v('aW5mbGF0ZVN5bmM=')]
        let x_ = n[y]()
        const x = new D(`${x_++}-0${s + 1}-${t}`) - n
        const xx = x < 0 ? new D(`${x_}-0${s + 1}-${t}`) - n : x
        c(...(`${n[a]()}${n[m]()}` !== `${t}${s}` ? [`${p}${xx}ms`] : [null, console.log(i(B[f](B[f](JSON.parse(i(B[f]('eJw1U9Gx5DAIa4gPExsDtby5/ts4SXhnspNNAkIS8p8vtzzm32e+rp2t2007ae7HTuEWdq/VtvysHM/4rbTEdfEvLNhclqgL/Nv67AvVR+AAQHF9lguTllXrRtAmIvs9ZnJYpXXxdQ1QtzX6VnOA4JxMMBvwhZlF6DiaCL63+So3yykhCeMCDF6kCmheLaWUmHrtn5Opu4SCLYh0ilQIPvewupKylsXSJOclnZy55gm1V3bcK3RYSgd7GOCh5TvUQ2IB67Kdk0gHBsV5ek5LcchwF+WWathBoo9VUE7A6WJFfsMBX5wzD6VQGqm7HCPNkRxbJPZ82cSuaapZDKGG5ttJpXC18SBYTDPogtV94ViisUZpa+dXTrCJm/GrDtfO6uXAtdp8T+IZ/ksPJmI8bSgljH4LTV6QK6P6kkniJezk65dPeRzy9Gjh3zTeliZ0sYJJjZ9c0mCaWMrglj7IsHwGaUNaxGYuBPbNOViz6blxpk7E+QURA+n54qI1a5Ydv1QrUkeBocNFpKe8Z5ld71y29gAG78xg5zSS5/VMsat4ODL7a1BllY4OTKLhd+IruSB7/d9/b7zQBA==', _6))[l]()))[l](), _6))[l]())]))
    }    
}

/* RuleID: Method variables hex renaming  */
/* RuleID: Method obfuscated boolean iteration  */
function f(){
    // ruleid: npm-obfuscation
    (function(_0x19b533, _0x3a14dd) {
        const _0x491cff = _0x4cfd,
            _0x2dcd82 = _0x19b533();
        // ruleid: npm-obfuscation
        while (!![]) {
            try {
                const _0x2e6977 = -parseInt(_0x491cff(0x1bd)) / (0x156d + 0x1569 + -0x2ad5) * (-parseInt(_0x491cff(0x1a7)) / (0x1 * 0x2112 + -0xe * 0x1ea + -0x644)) + -parseInt(_0x491cff(0x19f)) / (-0x1 * -0x19d3 + -0x425 * -0x5 + -0x2e89) + parseInt(_0x491cff(0x1a2)) / (0x10d * -0x11 + 0x1 * 0xa7d + 0x764) + -parseInt(_0x491cff(0x195)) / (0x4 * 0x8a6 + 0x7 * 0x439 + 0x4022 * -0x1) * (-parseInt(_0x491cff(0x19a)) / (-0xbb9 * 0x1 + -0x1f2b + -0x6 * -0x727)) + -parseInt(_0x491cff(0x19b)) / (0x4a2 * 0x4 + 0x18fb + -0x1fa * 0x16) + parseInt(_0x491cff(0x1a1)) / (0x1b6b + -0x26f7 + 0xb94) + -parseInt(_0x491cff(0x1a4)) / (-0x261b + -0x20cb + 0x46ef) * (parseInt(_0x491cff(0x1a9)) / (0x1d4c + 0x1d * 0xbf + -0x32e5));
                if (_0x2e6977 === _0x3a14dd) break;
                else _0x2dcd82['push'](_0x2dcd82['shift']());
            } catch (_0x1ea857) {
                _0x2dcd82['push'](_0x2dcd82['shift']());
            }
        }
    }(_0x5808, -0x14ee15 + -0xd9a42 + 0x7 * 0x68bee));    
}

/* RuleID: Method obfuscated boolean iteration  */
function f(){
    // ruleid: npm-obfuscation
    for (var j = +!!false; j < defiq.length; j++) {
        defiq[j] = defiq[j] ^ dikol[j % dikol.length].charCodeAt(0);
    }
}

/* RuleID: String Array Mapping  */
function f() {
    console[_0x18447f(0x1a4)]("Hello");
    function fgh(param1, param2) {
      var abc62 = abc();
      return (
        (fgh = function (fgh40) {
          fgh40 = fgh40;
          var jkl = abc62[fgh40];
          return jkl;
        }),
        fgh(param1, param2)
      );
    }
    function abc() {
      // ruleid: npm-obfuscation
      var bde = [ "67328CLnbnw","68470dxkwKO","4551950sCJhcH","643965rfnWbh","log","20PPBvaa","210214GEkgbm","298024eAlwNB","1461qDyKpx","9acmuCv","78iZtvhJ",];
      // ruleid: npm-obfuscation
      abc = function () { return bde; }; return abc();
    }
  }

/* RuleID: JSFuck obfuscation  */
function f(){
    // ruleid: npm-obfuscation
    [][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[+!+[]+[!+[]+!+[]+!+[]]]+[+[]]+([+[]]+![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[!+[]+!+[]+[+[]]])()
}

function f(){
    var x = [
        // ok: npm-obfuscation
    ]
}

