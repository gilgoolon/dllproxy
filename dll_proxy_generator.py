import os
import shutil
import pefile
import argparse

TEMPLATE_DIR = "template"
VARIABLES = [
    "PROXY_TARGET_DLL",
    "EXPORT_STUBS",
    "REAL_FUNCTION_DECLS",
    "REAL_FUNCTION_ASSIGNMENTS"
]

def parse_exports(dll_path):
    pe = pefile.PE(dll_path)
    exported_functions = []
    for exp in getattr(pe, 'DIRECTORY_ENTRY_EXPORT', []).symbols:
        if exp.name is not None:
            name = exp.name.decode()
            ordinal = exp.ordinal
            exported_functions.append((name, ordinal))
    return exported_functions

def copy_template(output_dir):
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    shutil.copytree(TEMPLATE_DIR, output_dir)

def render_template_file(file_path, substitutions):
    with open(file_path, "rt", encoding="utf-8") as f:
        content = f.read()
    for key, value in substitutions.items():
        content = content.replace("${" + key + "}", value)
    with open(file_path, "wt", encoding="utf-8") as f:
        f.write(content)

def fill_all_templates(output_dir, substitutions):
    # Only replace in .cpp, .h, .vcxproj, .sln, .filters, etc.
    for root, _, files in os.walk(output_dir):
        for filename in files:
            ext = os.path.splitext(filename)[-1].lower()
            if ext in (".cpp", ".h", ".vcxproj", ".sln", ".filters", ".txt", ".def"):
                path = os.path.join(root, filename)
                render_template_file(path, substitutions)

def generate_stubs(exports):
    """Returns (EXPORT_STUBS, REAL_FUNCTION_DECLS, REAL_FUNCTION_ASSIGNMENTS)"""
    decls = []
    assigns = []
    stubs = []
    for name, _ in exports:
        decls.append(f"static FARPROC _real_{name} = nullptr;")
        assigns.append(f'_real_{name} = _load_real_function(kProxyTarget, "{name}");')
        stubs.append(f'''
extern "C" __declspec(naked) void {name}()
{{
    __asm {{
        pushad
        pushfd
        mov eax, offset _real_{name}
        test eax, eax
        jz load_real_functions
        jmp eax
    load_real_functions:
        push offset kProxyTarget
        call _load_real_functions
        mov eax, offset _real_{name}
        jmp eax
        popfd
        popad
    }}
}}
''')
    return ("\n".join(stubs), "\n".join(decls), "\n    ".join(assigns))

def main():
    parser = argparse.ArgumentParser(description="Generate a DLL proxy Visual Studio project from a template.")
    parser.add_argument("source_dll", help="Path to the source DLL to proxy")
    parser.add_argument("output_dir", help="Directory where the new project will be generated")
    parser.add_argument("--dll-name", help="Name of the DLL to forward functions to (defaults to source DLL name)")
    args = parser.parse_args()

    source_dll = os.path.abspath(args.source_dll)
    output_dir = os.path.abspath(args.output_dir)
    dll_name = args.dll_name or os.path.basename(args.source_dll)

    # 1. Copy template project
    copy_template(output_dir)

    # 2. Parse PE exports
    exports = parse_exports(source_dll)
    if not exports:
        print(f"No exports found in '{source_dll}'.")
        return

    # 3. Produce stub section as per template's expected variable names
    export_stubs, real_function_decls, real_function_assigns = generate_stubs(exports)

    # 4. Prepare variables for placeholders
    substitutions = {
        "PROXY_TARGET_DLL": f'L"{dll_name}"',
        "EXPORT_STUBS": export_stubs,
        "REAL_FUNCTION_DECLS": real_function_decls,
        "REAL_FUNCTION_ASSIGNMENTS": real_function_assigns,
    }

    # 5. Replace variables in all text/code files in the copied template
    fill_all_templates(output_dir, substitutions)

    print(f"Proxy DLL project generated at: {output_dir}")

if __name__ == "__main__":
    main()
