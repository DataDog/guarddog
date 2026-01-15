# Tests for rubygems-exec-base64 rule

# ok: rubygems-exec-base64
eval("puts 'hello'")

# ok: rubygems-exec-base64
instance_eval("@foo = 1")

# ruleid: rubygems-exec-base64
eval(Base64.decode64("cHV0cyAnaGVsbG8n"))

# ruleid: rubygems-exec-base64
instance_eval(Base64.decode64("QGZvbyA9IDE="))

# ruleid: rubygems-exec-base64
class_eval(Base64.strict_decode64("cHV0cyAnaGVsbG8n"))

# ruleid: rubygems-exec-base64
module_eval(Base64.urlsafe_decode64("cHV0cyAnaGVsbG8n"))

code = Base64.decode64("cHV0cyAnaGVsbG8n")
# ruleid: rubygems-exec-base64
eval(code)

# ruleid: rubygems-exec-base64
Kernel.eval(Base64.decode64("cHV0cyAnaGVsbG8n"))

# ruleid: rubygems-exec-base64
binding.eval(Base64.decode64("cHV0cyAnaGVsbG8n"))
