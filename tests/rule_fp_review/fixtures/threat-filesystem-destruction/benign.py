# FALSE POSITIVE: a Pygments lexer keyword list (Qlik builtins). $drop_table
# matches the highlighter vocabulary string, which is never executed SQL.
KEYWORDS = ["Drop table", "Drop database", "Truncate table", "Load"]
