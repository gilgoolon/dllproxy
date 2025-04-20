# DLL Proxy Main.cpp Generation

This script generates a C++ file for a proxy DLL which dynamically loads an original DLL and forwards all exported functions using inline assembly.

## Approach

- All exports from the source DLL are stubbed with global functions.
- On first call, the real function address is loaded from the target DLL using `GetProcAddress` and cached in a function pointer.
- Subsequent calls jump directly to the real function's address using `__declspec(naked)` and `__asm { jmp ... }`.

## Example of Generated Stub

```cpp
extern "C" __declspec(naked) void ExportedFunction()
{
    __asm {
        mov eax, offset _real_ExportedFunction
        jmp eax
    }
}
```

Real function pointers are initialized at `DLL_PROCESS_ATTACH` in `DllMain` using:
```cpp
_real_ExportedFunction = _load_real_function(kProxyTarget, "ExportedFunction");
```

The script ensures this structure is repeated for each discovered export in the DLL, automating the tedious process of making a fully functional proxy DLL.