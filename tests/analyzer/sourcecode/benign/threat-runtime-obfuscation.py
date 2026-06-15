# Benign regression test for threat-runtime-obfuscation.
# 1. Long URLs in comments and long generated identifiers are not base64
#    payloads (none are quoted base64 blobs over the length threshold).
# 2. ALLCAPS words (license text, constants) plus ordinary string
#    concatenation must not be read as obfuscated variable names.
# (FPs from npm 'requests', mistralai, mypy-boto3, pytensor.)

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub/paginator/ListConfigurationPolicyAssociations
# https://github.com/numpy/numpy/blob/6f6be042c6208815b15b90ba87d04159bfa25fd3/numpy/random/src/distributions/distributions.c

# Generated SDK identifiers can be very long but are plain CamelCase code.
request = GetChatCompletionFieldOptionsCountsV1ObservabilityChatCompletionFieldsFieldNameOptionsCountsPostRequest()

# ALL-CAPS constants and license boilerplate.
BigPipe_LOADING = 1
BigPipe_INTERACTIVE = 2
BigPipe_COMPLETE = 3
LICENSE = "THE SOFTWARE IS PROVIDED AS IS WITHOUT WARRANTY OF MERCHANTABILITY"

# Ordinary string concatenation, repeated many times.
parts = ('a' + 'b') + ('c' + 'd') + ('e' + 'f') + ('g' + 'h') + ('i' + 'j')
more = ('k' + 'l') + ('m' + 'n') + ('o' + 'p') + ('q' + 'r') + ('s' + 't')
even_more = ('u' + 'v') + ('w' + 'x') + ('y' + 'z') + ('1' + '2') + ('3' + '4')
last = ('5' + '6') + ('7' + '8') + ('9' + '0') + ('A' + 'B') + ('C' + 'D')
