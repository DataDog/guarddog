# FALSE POSITIVE: the requests library defines the standard netrc filenames as a
# constant. $netrc matches the bare ".netrc" substring; this is documented HTTP
# auth support, not credential theft.
NETRC_FILES = (".netrc", "_netrc")
