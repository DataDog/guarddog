import os
import multiprocessing

"""
This parameter specifies the amount of threads to use while requiring parallelism
- Default: Number of CPUs available
"""
PARALLELISM: int = int(
    os.environ.get("GUARDDOG_PARALLELISM", multiprocessing.cpu_count())
)

"""
This flag specifies if an analysis of all posible versions is required
- True: All possible versions are analyzed
- False [default]: Only best match is analyzed
"""
VERIFY_EXHAUSTIVE_DEPENDENCIES: bool = (
    os.environ.get("GUARDDOG_VERIFY_EXHAUSTIVE_DEPENDENCIES", "false").lower() == "true"
)

"""
This parameter specifies the location of the top packages cache
- Default: guarddog/analyzer/metadata/resources
"""
TOP_PACKAGES_CACHE_LOCATION: str = os.environ.get(
    "GUARDDOG_TOP_PACKAGES_CACHE_LOCATION",
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../analyzer/metadata/resources")
    ),
)

"""
This parameter specifies comman separated file extentions that YARA rules will not run against
- Default: ini,md,rst,txt,lock,json,yaml,yml,toml,xml,html,rst,csv,sql,pdf,doc,docx,ppt,
           pptx,xls,xlsx,odt,changelog,readme,makefile,dockerfile,pkg-info,d.ts
"""
YARA_EXT_EXCLUDE: list[str] = os.environ.get(
    "GUARDDOG_YARA_EXT_EXCLUDE",
    "ini,md,rst,txt,lock,json,yaml,yml,toml,xml,html,rst,csv,sql,pdf,doc,docx,ppt,"
    "pptx,xls,xlsx,odt,changelog,readme,makefile,dockerfile,pkg-info,d.ts",
).split(",")

"""
This parameter specifies the maximum uncompressed size allowed for archive extraction
- Default: 2 GB in bytes
"""
MAX_UNCOMPRESSED_SIZE: int = int(
    os.environ.get("GUARDDOG_MAX_UNCOMPRESSED_SIZE", 2 * 1024 * 1024 * 1024)
)

"""
This parameter specifies the maximum compression ratio allowed for archive extraction
- Default: 100 (100:1 ratio)
"""
MAX_COMPRESSION_RATIO: float = float(
    os.environ.get("GUARDDOG_MAX_COMPRESSION_RATIO", 100)
)

"""
This parameter specifies the maximum number of files allowed in an archive
- Default: 100000
"""
MAX_FILE_COUNT: int = int(os.environ.get("GUARDDOG_MAX_FILE_COUNT", 100000))
