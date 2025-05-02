# DLL Proxy Generator

A tool for generating Windows DLL proxies with automatic export forwarding.

## Overview

The DLL Proxy Generator creates fully functional Visual Studio C++ projects that can intercept calls to any Windows DLL. This enables various scenarios including:

- Function call interception and monitoring
- API hooking and modification
- DLL replacement without changing application code
- Debugging and reverse engineering

## How It Works

DLL proxying works by creating a DLL with the same name and exports as the original, but which forwards calls to the actual implementation DLL (renamed or relocated). The proxy sits between the application and the real DLL, allowing you to:

1. Intercept function calls
2. Modify parameters or return values
3. Log API usage
4. Forward calls to the original implementation

## Requirements

- **Windows operating system**
- **Python 3.7+** with the `pefile` module
- **Visual Studio** (for building the generated projects)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/dll-proxy-generator.git
cd dll-proxy-generator

# Install required Python packages
pip install pefile
```

## Usage

### Basic Usage

```bash
python generate_dll_proxy.py -s <source_dll> -d <worker_dll> -o <output_directory>
```

Where:
- `<source_dll>` is the path to the DLL you want to proxy
- `<worker_dll>` is the path where the original DLL will be relocated
- `<output_directory>` is where the proxy project will be generated

### Example

```bash
# Generate a proxy for kernel32.dll
python generate_dll_proxy.py -s C:\Windows\System32\kernel32.dll -d C:\Windows\System32\kernel32_original.dll -o .\KernelProxy
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-s`, `--source-dll` | Path to the DLL to proxy (required) |
| `-d`, `--worker-dll` | Path to the actual implementation DLL (required) |
| `-o`, `--output` | Output directory for the generated project |
| `-b`, `--build` | Build the project after generation |
| `-p`, `--platform` | Target platform (x86 or x64, default: x64) |

## Project Structure

The generated proxy project includes:

- **Visual Studio solution and project files**
- **Exports definition file** with all the original DLL's exports
- **Source code** for the proxy implementation
- **Configuration header** for customization

## Customizing the Proxy

You can modify the generated proxy to add custom logic:

1. Open the generated project in Visual Studio
2. Edit the function implementations in the source files
3. Add your custom code before/after forwarding calls to the original DLL

## Advanced Usage

### Logging Function Calls

The template includes hooks for adding logging to all function calls:

```cpp
// Example of adding logging to a proxied function
BOOL WINAPI CreateProcessW_Proxy(/* parameters */) {
    // Log the call
    LogFunctionCall("CreateProcessW", /* parameters */);
    
    // Forward to original implementation
    return Original_CreateProcessW(/* parameters */);
}
```

### Deployment

To deploy your proxy:

1. Build the proxy DLL
2. Rename the original DLL to match your worker DLL path
3. Place your proxy DLL in the original location
4. The application will now load your proxy instead

## Troubleshooting

- **Missing exports**: Ensure the proxy exports all functions from the original DLL
- **DLL loading issues**: Check that the worker DLL path is correct and accessible
- **Build errors**: Verify Visual Studio and required components are installed

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgements

- [pefile](https://github.com/erocarrera/pefile) for PE file parsing
