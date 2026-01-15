# Tests for rubygems-serialize-environment rule

# ok: rubygems-serialize-environment
ENV['HOME']

# ok: rubygems-serialize-environment
{ foo: "bar" }.to_json

# ruleid: rubygems-serialize-environment
ENV.to_h.to_json

# ruleid: rubygems-serialize-environment
ENV.to_hash.to_json

# ruleid: rubygems-serialize-environment
JSON.dump(ENV)

# ruleid: rubygems-serialize-environment
JSON.dump(ENV.to_h)

# ruleid: rubygems-serialize-environment
JSON.generate(ENV)

# ruleid: rubygems-serialize-environment
JSON.generate(ENV.to_hash)

# ruleid: rubygems-serialize-environment
ENV.to_h.to_yaml

# ruleid: rubygems-serialize-environment
YAML.dump(ENV)

# ruleid: rubygems-serialize-environment
YAML.dump(ENV.to_h)

# ruleid: rubygems-serialize-environment
Marshal.dump(ENV)

# ruleid: rubygems-serialize-environment
Marshal.dump(ENV.to_h)

# ruleid: rubygems-serialize-environment
ENV.to_h.inspect

# ruleid: rubygems-serialize-environment
ENV.inspect
