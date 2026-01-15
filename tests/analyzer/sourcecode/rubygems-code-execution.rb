# Tests for rubygems-code-execution rule

# ok: rubygems-code-execution
puts "hello"

# ok: rubygems-code-execution
File.read("config.yml")

# ruleid: rubygems-code-execution
system("ls -la")

# ruleid: rubygems-code-execution
exec("whoami")

# ruleid: rubygems-code-execution
spawn("background_job")

# ruleid: rubygems-code-execution
Kernel.system("rm -rf /tmp/foo")

# ruleid: rubygems-code-execution
`ls -la`

# ruleid: rubygems-code-execution
%x{whoami}

# ruleid: rubygems-code-execution
%x[uname -a]

# ruleid: rubygems-code-execution
%x(cat /etc/passwd)

# ruleid: rubygems-code-execution
IO.popen("ls")

# ruleid: rubygems-code-execution
Open3.capture3("ls", "-la")

# ruleid: rubygems-code-execution
Open3.popen3("bash")

# ruleid: rubygems-code-execution
Process.spawn("sleep 10")

cmd = params[:cmd]
# ruleid: rubygems-code-execution
eval(cmd)

user_input = gets
# ruleid: rubygems-code-execution
instance_eval(user_input)
