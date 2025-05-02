import os
import tempfile
import pefile
import shutil
import argparse
from typing import Dict
from pathlib import Path
from importlib.resources import files

TEMPLATE_DIR = files("dllproxy").joinpath("template")
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

def format_code_path(path: Path) -> str:
    return path.absolute().as_posix()

def build(solution_path: Path, configuration: str, platform: str):
    os.system(f"msbuild {solution_path.as_posix()} /p:Configuration={configuration} /p:Platform={platform}")


def parse_arguments():
    parser = argparse.ArgumentParser(description="Generate a DLL proxy Visual Studio project.")

    parser.add_argument("-s", "--source-dll", required=True, type=Path, help="Path to the source DLL to proxy")
    parser.add_argument("-d", "--worker-dll", required=True, type=Path, help="Name of the DLL to load on startup")
    parser.add_argument("-o", "--output", required=False, type=Path, help="If building, the output path. If generating, the directory where the new project will be generated")
    parser.add_argument("-b", "--build", action="store_true", help="Build the project using msbuild instead of generating project files")
    parser.add_argument("-p", "--platform", required=False, default="x64", type=str, help="Target platform")

    return parser.parse_args()

def main():
    args = parse_arguments()

    source_dll = args.source_dll
    output = args.output
    worker_dll = args.worker_dll
    platform = args.platform

    CONFIGURATION = "Release"

    if args.build:
        directory = tempfile.TemporaryDirectory()
        project_dir = Path(directory.name)
        if output is None:
            output = source_dll.name
    else:
        project_dir = output
        if output is None:
            raise ValueError("Provide an output directory when generating a project")

    copy_template(project_dir)
    exports = parse_exports(source_dll)

    export_stubs = [
        f"#pragma comment(linker,\"/export:{name}={format_code_path(source_dll)}.{name},@{ordinal}\")"
        for (name, ordinal) in exports
    ]

    files = {
        "Main.cpp": {
            "EXPORT_STUBS": "\n".join(export_stubs)
        },
        "Config.hpp": {
            "WORKER_PATH": format_code_path(worker_dll)
        },
        "Source.def": {
            "LIBRARY_NAME": source_dll.name
        }
    }

    for file, variables in files.items():
        path = project_dir / file
        contents = path.read_text()
        updated_contents = replace_variables(contents, variables)
        path.write_text(updated_contents)

    print(f"Proxy DLL project generated at \"{project_dir.absolute()}\"")

    if args.build:
        build(project_dir / "DllProxy.sln", CONFIGURATION, platform)
        shutil.copy(project_dir / platform / CONFIGURATION / "DllProxy.dll", output)
        print(f"Build completed successfully, target is at \"{output}\"")

if __name__ == "__main__":
    main()
