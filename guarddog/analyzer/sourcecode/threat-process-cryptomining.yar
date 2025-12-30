rule threat_process_cryptomining
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects cryptocurrency mining activity"
        identifies = "threat.process.cryptomining"
        severity = "high"
        mitre_tactics = "impact,resource-development"
        specificity = "high"
        sophistication = "medium"
        max_hits = 3

    strings:
        // Mining software
        $miner_xmrig = "xmrig" nocase
        $miner_ethminer = "ethminer" nocase
        $miner_cgminer = "cgminer" nocase
        $miner_bfgminer = "bfgminer" nocase
        $miner_cpuminer = "cpuminer" nocase
        $miner_ccminer = "ccminer" nocase

        // Mining pools
        $pool_monero = /(pool\.)?[a-z0-9-]+\.monero/ nocase
        $pool_generic = /[a-z0-9-]+pool\.(com|net|org|io)/ nocase
        $pool_supportxmr = "supportxmr.com" nocase
        $pool_minexmr = "minexmr.com" nocase
        $pool_nanopool = "nanopool.org" nocase

        // Mining protocols/ports
        $stratum = "stratum+tcp://" nocase
        $stratum_ssl = "stratum+ssl://" nocase
        $port_3333 = ":3333" // Common mining port
        $port_4444 = ":4444" // Common mining port
        $port_5555 = ":5555" // Common mining port

        // Cryptocurrency addresses (Monero, Bitcoin)
        $monero_address = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ nocase
        $bitcoin_address = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ nocase

        // Mining-related terms in combination
        $mining_hashrate = "hashrate" nocase
        $mining_difficulty = "difficulty" nocase
        $mining_shares = "shares" nocase
        $mining_worker = "worker" nocase

    condition:
        any of ($miner_*) or
        any of ($pool_*) or
        2 of ($stratum*, $port_*) or
        any of ($monero_address, $bitcoin_address) or
        3 of ($mining_*)
}
