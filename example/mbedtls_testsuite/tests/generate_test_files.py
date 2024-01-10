import sys
import math
import pathlib
import re
import subprocess
import argparse
from littlefs import LittleFS

script_path = pathlib.Path(__file__).resolve().absolute()
output_dir_path = script_path.parent

mbedtls_dir_path = script_path.joinpath("../../../../").resolve()
mbedtls_testsuites_dir_path = mbedtls_dir_path.joinpath("tests/suites").resolve()

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--testsuite", dest="testsuite_path", required=True, type=pathlib.Path,
                    help="The testsuite to generate files for. This shall be a name of a test data file (*.data) "
                         "found in the mbedtls/tests/suites folder. (e.g. -t test_suite_aes.cbc.data)")
args = parser.parse_args()

if not args.testsuite_path.is_file():
    args.testsuite_path = mbedtls_testsuites_dir_path.joinpath(args.testsuite_path)
if not args.testsuite_path.is_file():
    print("Unable to find testsuite file.")
    exit(1)

output_source_path = output_dir_path.joinpath(f"test_suite_postprocessed.c")
output_littlefs_path = output_dir_path.joinpath(f"test_suite_postprocessed.datax.littlefs.bin")

lfs_block_size = 4096

# Delete old files from previous runs.
output_source_path.unlink(missing_ok=True)
output_littlefs_path.unlink(missing_ok=True)

data_name = args.testsuite_path.name
data_name = re.sub(r"\.data$", "", data_name)
data_name = data_name.replace("test_suite_", "")
suite_name = re.search("([^.]*)", data_name).group(1)

print(f"Generating test files for {data_name}")

# Invoke the generation script from mbedtls
gen_script_path = mbedtls_dir_path.joinpath("tests/scripts/generate_test_code.py")
subprocess.run(["python", gen_script_path,
                "-f", mbedtls_testsuites_dir_path.joinpath(f"test_suite_{suite_name}.function"),
                "-d", mbedtls_testsuites_dir_path.joinpath(f"test_suite_{data_name}.data"),
                "-t", mbedtls_testsuites_dir_path.joinpath("main_test.function"),
                "-p", mbedtls_dir_path.joinpath("port/test_littlefs/host_test.function"),
                "-s", mbedtls_testsuites_dir_path,
                "--helpers-file", mbedtls_testsuites_dir_path.joinpath("helpers.function"),
                "-o", "."], cwd=output_dir_path)

datax_path = pathlib.Path(output_dir_path.joinpath(f"test_suite_{data_name}.datax"))
lfs_block_count = math.ceil(datax_path.stat().st_size * 1.10 / lfs_block_size) + 2

# Some postprocessing of the generated c code file is required:
input_source_path = output_dir_path.joinpath(f"test_suite_{data_name}.c")
with open(input_source_path, "r") as fc:
    lines = fc.readlines()

# The generated test file does set the path to the datax file as "./filename.datax". Littlefs 
# is not happy with that, the ./ prefix has to be removed so that the file can be found.
lines = map(lambda l: l.replace("default_filename = \".\\\\test_suite", "default_filename = \"test_suite"), lines)

# The generated file contains references to the original source locations like #line filename:linenr
# This allows for the compiler to reference errors in the original source instead of the generated 
# source. However, this does not play well with debugging, so here is a method to strip all of those 
# from the file. 
lines = filter(lambda l: not l.startswith("#line"), lines)

# The number of blocks that is required depends on the size of the test data. In order not to have to accomodate 
# for the biggest possible test set and to have to copy a large amount of data everytime, the block count is 
# dynamically calculated and inserted into the code.
lines = map(lambda l: l.replace(".block_count = 256,  // ## POST-PROCESSING",
                                f".block_count = {lfs_block_count},  // ## POST-PROCESSED"), lines)

# Write back the post-processed file. Also, we save it under a different name - always the same one, so it becomes 
# more straightforward to switch test suite.
with open(output_source_path, "w") as fc:
    fc.writelines(lines)

# Generate a littlefs image from the test data
fs = LittleFS(block_size=lfs_block_size, block_count=lfs_block_count)
with open(datax_path, "r") as fi:

    # Open a file and write some content
    with fs.open(datax_path.name, 'w') as fh:
        for line in fi:
            fh.write(line)

# Dump the filesystem content to a file
with open(output_littlefs_path, 'wb') as fh:
    fh.write(fs.context.buffer)
