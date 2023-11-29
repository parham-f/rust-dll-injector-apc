# Rust DLL Injector with APC

This is a DLL injection tool written in Rust that uses the 'QueueUserAPC' Windows API.

## Build
```bash
cargo build --release
```

## Usage

To use this tool, run it from the command line with the following syntax:

```bash
./dll_injector <pid> <DLL Full Path>
```
Example
```bash
./dll_injector 1234 C:\Users\Public\mal.dll
```

- `<pid>`: The process ID of the target process.
- `<DLL Full Path>`: The full path to the DLL that you want to inject.

#### If your process has more than one PID, it's better to use the first one.

## DISCLAIMER

Please only use this tool on systems you have permission to access! Ethical use only.

Any actions and or activities related to the tools I have created is solely your responsibility.The misuse of the tools I have created can result in criminal charges brought against the persons in question. I will not be held responsible in the event any criminal charges be brought against any individuals misusing the tools I have made to break the law.

You are responsible for your own actions.

## License

This project is licensed under the [MIT License](LICENSE).

Feel free to use, modify, and distribute this code in accordance with the license terms.
