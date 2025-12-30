rule threat_network_outbound_shady_links
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects URLs to URL shorteners, file sharing, and suspicious services"
        identifies = "threat.network.outbound.shady_links"
        severity = "medium"
        mitre_tactics = "command-and-control,exfiltration"
        specificity = "medium"
        sophistication = "low"

        max_hits = 5
    strings:
        // URL shorteners
        $short_bitly = "bit.ly" nocase
        $short_tinyurl = "tinyurl.com" nocase
        $short_goo_gl = "goo.gl" nocase
        $short_ow_ly = "ow.ly" nocase
        $short_is_gd = "is.gd" nocase
        $short_buff_ly = "buff.ly" nocase

        // Tunneling/forwarding services
        $tunnel_ngrok = "ngrok.io" nocase
        $tunnel_ngrok_free = "ngrok-free.app" nocase
        $tunnel_localhost = "localhost.run" nocase
        $tunnel_serveo = "serveo.net" nocase

        // File sharing / paste services
        $paste_pastebin = "pastebin.com" nocase
        $paste_hastebin = "hastebin.com" nocase
        $paste_ghostbin = "ghostbin.com" nocase
        $paste_dpaste = "dpaste.com" nocase
        $file_transfer = "transfer.sh" nocase
        $file_anonfiles = "anonfiles.com" nocase
        $file_fileio = "file.io" nocase

        // Temporary email
        $tempmail = "temp-mail.org" nocase
        $guerrilla = "guerrillamail.com" nocase
        $tenmin = "10minutemail.com" nocase

        // Suspicious TLDs
        $tld_xyz = /https?:\/\/[^\s\/]+\.xyz/ nocase
        $tld_tk = /https?:\/\/[^\s\/]+\.tk/ nocase
        $tld_ml = /https?:\/\/[^\s\/]+\.ml/ nocase
        $tld_ga = /https?:\/\/[^\s\/]+\.ga/ nocase
        $tld_cf = /https?:\/\/[^\s\/]+\.cf/ nocase
        $tld_gq = /https?:\/\/[^\s\/]+\.gq/ nocase
        $tld_pw = /https?:\/\/[^\s\/]+\.pw/ nocase
        $tld_top = /https?:\/\/[^\s\/]+\.top/ nocase

        // Communication platforms (when used from server-side code)
        $discord_webhook = "discord.com/api/webhooks" nocase
        $telegram_bot = "api.telegram.org/bot" nocase
        $slack_webhook = "hooks.slack.com" nocase

    condition:
        any of them
}
