import os
import pefile
import shutil
import argparse
from typing import Dict
from pathlib import Path

TEMPLATE_DIR = "template"
VARIABLES = [
    "PROXY_TARGET_DLL",
    "EXPORT_STUBS",
    "REAL_FUNCTION_DECLS",
    "REAL_FUNCTION_ASSIGNMENTS"
]

def copy_template(output_dir):
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    shutil.copytree(TEMPLATE_DIR, output_dir)

def parse_exports(dll_path):
    pe = pefile.PE(dll_path)
    exported_functions = []
    for exp in getattr(pe, 'DIRECTORY_ENTRY_EXPORT', []).symbols:
        if exp.name is not None:
            name = exp.name.decode()
            ordinal = exp.ordinal
            exported_functions.append((name, ordinal))
    return exported_functions

def replace_variable(contents: str, name: str, value: str) -> str:
    variable_reference = f"%{name}%"
    return contents.replace(variable_reference, value)

def replace_variables(contents, variables: Dict[str, str]) -> str:
    result = contents
    for name, value in variables.items():
        result = replace_variable(result, name, value)
    return result

def parse_arguments():
    parser = argparse.ArgumentParser(description="Generate a DLL proxy Visual Studio project.")

    parser.add_argument("-s", "--source_dll", required=True, type=Path, help="Path to the source DLL to proxy")
    parser.add_argument("-d", "--worker_dll", required=True, type=Path, help="Name of the DLL to load on startup")
    parser.add_argument("-o", "--output_dir", required=True, type=Path, help="Directory where the new project will be generated")

    return parser.parse_args()

def format_code_path(path: Path) -> str:
    return path.absolute().as_posix()


def main():
    args = parse_arguments()

    source_dll = args.source_dll
    output_dir = args.output_dir
    worker_dll = args.worker_dll

    copy_template(output_dir)
    exports = parse_exports(source_dll)

    export_stubs = [
        f"#pragma comment(linker,\"/export:{name}={format_code_path(source_dll)}.{name},@{ordinal}\")"
        for (name, ordinal) in exports
    ]

    files = {
        "Main.cpp": {
            "WORKER_PATH": format_code_path(worker_dll),
            "EXPORT_STUBS": "\n".join(export_stubs)
        },
        "Source.def": {
            "LIBRARY_NAME": source_dll.name
        }
    }

    for file, variables in files.items():
        path = output_dir / file
        contents = path.read_text()
        updated_contents = replace_variables(contents, variables)
        path.write_text(updated_contents)

    print(f"Proxy DLL project generated at \"{output_dir.absolute()}\"")

if __name__ == "__main__":
    main()
