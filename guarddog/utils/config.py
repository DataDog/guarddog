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
           pptx,xls,xlsx,odt,changelog,readme,makefile,dockerfile,pkg-info
"""
YARA_EXT_EXCLUDE: list[str] = os.environ.get(
    "GUARDDOG_YARA_EXT_EXCLUDE",
    "ini,md,rst,txt,lock,json,yaml,yml,toml,xml,html,rst,csv,sql,pdf,doc,docx,ppt,"
    "pptx,xls,xlsx,odt,changelog,readme,makefile,dockerfile,pkg-info",
).split(",")
