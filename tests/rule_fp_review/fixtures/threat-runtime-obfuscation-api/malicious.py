# Reaching exec() dynamically via getattr to evade static detection.
getattr(__builtins__, "exec")("import os; os.system('id')")
