rule threat_network_outbound
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects URLs to suspicious domains often used for exfiltration or C2"
        identifies = "threat.network.outbound"
        severity = "high"
        mitre_tactics = "exfiltration"
        specificity = "medium"
        sophistication = "medium"

        max_hits = 5
    strings:
        // Webhook/tunneling services
        $webhook1 = "webhook.site" nocase
        $webhook2 = "webhook.cool" nocase
        $webhook3 = "oastify.com" nocase
        $webhook4 = "burpcollaborator.net" nocase
        $webhook5 = "burpcollaborator.me" nocase
        $webhook6 = "pipedream.net" nocase
        $webhook7 = "beeceptor.com" nocase

        // Tunneling services
        $tunnel1 = "ngrok.io" nocase
        $tunnel2 = "ngrok-free.app" nocase
        $tunnel3 = "trycloudflare.com" nocase
        $tunnel4 = "localhost.run" nocase

        // Paste/file sharing services
        $paste1 = "pastebin.com" nocase
        $paste2 = "hastebin.com" nocase
        $paste3 = "ghostbin.site" nocase
        $paste4 = "transfer.sh" nocase
        $paste5 = "filetransfer.io" nocase

        // Communication platforms (when used for exfil)
        $comm1 = "api.telegram.org" nocase
        $comm2 = "discord.com/api/webhooks" nocase

        // Suspicious TLDs in URLs (with http/https)
        $tld1 = /https?:\/\/[^\s\/]+\.(xyz|tk|ml|ga|cf|gq)/
        $tld2 = /https?:\/\/[^\s\/]+\.(pw|top|club|bid|icu)/
        $tld3 = /https?:\/\/[^\s\/]+\.(zip|stream|link|quest)/

        // Direct IP addresses in URLs
        $ip = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/

    condition:
        any of them
}
