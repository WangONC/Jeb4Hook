# Jeb4Hook
Generate Frida/Xposed hooks directly from JEB!

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Original Project License

The original project is licensed under the MIT License. See the [LICENSE_ORIGINAL](LICENSE_ORIGINAL) file for details.

## How to use

1. **Copy the Scripts:** Copy the `Jeb4frida_ts.py` and the `Jeb4Xposed.py` python script in JEB's scripts folder.
2. **Open the Target APK:** Open the target APK in JEB GUI (Command line usage is not supported).
3. **Analyze the APK:** After analysis of the APK, look for a target to generate hooks for.
4. **Select Target:** Put the cursor a class or a method you want to create a hook for. This can be done in the disassembly view or decompiler view.
5. **Run the script:**
   - Press `f` to run `Jeb4Frida_ts.py` .
   - Press `alt` + `x` to run `Jeb4Xposed.py` . 
6. **Generate Hooks:**
   - If the cursor is set on a method, a hook is created for that method alone.
   - If the cursor is set on a class, hooks are generated for each method in that class.

## Note
- The code generated by `jeb4frida_ts.py` is based on the TypeScript code from [frida-agent-example](https://github.com/oleavr/frida-agent-example). You need to insert the generated code into the project and compile it before use.
- If you want to generate JavaScript hook code, please use the original project: [jeb4frida](https://github.com/Hamz-a/jeb4frida).

## Acknowledgments
This project is adapted from the original work by [Hamz-a](https://github.com/Hamz-a) and his project [jeb4frida](https://github.com/Hamz-a/jeb4frida). We would like to express our gratitude for the foundational work that made this project possible.

