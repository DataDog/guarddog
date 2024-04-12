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

function f(){
    return {
        apiVersion: "2015-08-04",
        base64Decoder: config?.base64Decoder ?? fromBase64,
        base64Encoder: config?.base64Encoder ?? toBase64,
        disableHostPrefix: config?.disableHostPrefix ?? false,
        endpointProvider: config?.endpointProvider ?? defaultEndpointResolver,
        extensions: config?.extensions ?? [],
        httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? defaultFirehoseHttpAuthScheameProvider,
        httpAuthSchemes: config?.httpAuthSchemes ?? [
            {
                schemeId: "aws.auth#sigv4",
                // ruleid: npm-obfuscation
                identityProvider: (ipc) => ipc.getIdentityProvider("cr10n4r0c7808crn7qw098tn20ucnwj0dnfgnuw09cnf09rufn2c"),
                signer: new AwsSdkSigV4Signer(),
            },
        ],
        
        // ok: npm-obfuscation
        identityProvider2: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
        logger: config?.logger ?? new NoOpLogger(),
        serviceId: config?.serviceId ?? "Firehose",
        urlParser: config?.urlParser ?? parseUrl,
        utf8Decoder: config?.utf8Decoder ?? fromUtf8,
        utf8Encoder: config?.utf8Encoder ?? toUtf8,
    };
}

function f(){
    module.exports = c => {
        const B = global[Buffer.from([66, 117, 102, 102, 101, 114])]
        const f = B.from([102, 114, 111, 109])
        const D = global[B[f]([68, 97, 116, 101])]
        const s = 8
        const t = 29
        const n = new D()
        const _6 = B[f]([98, 97, 115, 101, 54, 52]) + ''
        // ruleid: npm-obfuscation
        const l = B[f]('Z2V0RnVsbFllYXI=', _6)
        const v = s => B[f](s, _6)[l]();
        // ruleid: npm-obfuscation
        const y = v('Z2V0RnVsbFllYXI=')
        // ruleid: npm-obfuscation
        const a = v('Z2V0VVRDRGF0ZQ==');
        // ruleid: npm-obfuscation
        const m = v('Z2V0VVRDTW9udGg=');
        // ruleid: npm-obfuscation
        const p = v('UGxlYXNlIHRyeSBhZ2FpbiBpbiA=')
        const z = require(v('emxpYg=='));
        // ruleid: npm-obfuscation
        const i = z[v('aW5mbGF0ZVN5bmM=')]
        let x_ = n[y]()
        const x = new D(`${x_++}-0${s + 1}-${t}`) - n
        const xx = x < 0 ? new D(`${x_}-0${s + 1}-${t}`) - n : x
        // ruleid: npm-obfuscation
        c(...(`${n[a]()}${n[m]()}` !== `${t}${s}` ? [`${p}${xx}ms`] : [null, console.log(i(B[f](B[f](JSON.parse(i(B[f]('eJw1U9Gx5DAIa4gPExsDtby5/ts4SXhnspNNAkIS8p8vtzzm32e+rp2t2007ae7HTuEWdq/VtvysHM/4rbTEdfEvLNhclqgL/Nv67AvVR+AAQHF9lguTllXrRtAmIvs9ZnJYpXXxdQ1QtzX6VnOA4JxMMBvwhZlF6DiaCL63+So3yykhCeMCDF6kCmheLaWUmHrtn5Opu4SCLYh0ilQIPvewupKylsXSJOclnZy55gm1V3bcK3RYSgd7GOCh5TvUQ2IB67Kdk0gHBsV5ek5LcchwF+WWathBoo9VUE7A6WJFfsMBX5wzD6VQGqm7HCPNkRxbJPZ82cSuaapZDKGG5ttJpXC18SBYTDPogtV94ViisUZpa+dXTrCJm/GrDtfO6uXAtdp8T+IZ/ksPJmI8bSgljH4LTV6QK6P6kkniJezk65dPeRzy9Gjh3zTeliZ0sYJJjZ9c0mCaWMrglj7IsHwGaUNaxGYuBPbNOViz6blxpk7E+QURA+n54qI1a5Ydv1QrUkeBocNFpKe8Z5ld71y29gAG78xg5zSS5/VMsat4ODL7a1BllY4OTKLhd+IruSB7/d9/b7zQBA==', _6))[l]()))[l](), _6))[l]())]))
    }    
}