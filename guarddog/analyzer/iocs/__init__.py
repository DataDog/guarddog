import os
import pathlib

current_dir = pathlib.Path(__file__).parent.resolve()
rule_file_names = list(
    filter(
        lambda x: x.endswith('yar'),
        os.listdir(current_dir)
    )
)

IOC_RULES: set[str] = set()

for file_name in rule_file_names:
    IOC_RULES.add(pathlib.Path(file_name).stem)
