# -*- coding: utf-8 -*-
#?description=Helper JEB script to generate Frida hooks
#?shortcut= f

from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit, IApkUnit
from com.pnfsoftware.jeb.core.units.code.android.dex import DexPoolType
from com.pnfsoftware.jeb.core.units.code.java import IJavaSourceUnit, IJavaMethod
from com.pnfsoftware.jeb.core.units import INativeCodeUnit
from com.pnfsoftware.jeb.core.units.code.asm.decompiler import INativeSourceUnit
from com.pnfsoftware.jeb.core.units import UnitUtil
from java.awt.datatransfer import StringSelection
from java.awt.datatransfer import Clipboard
from java.awt import Toolkit

import re

"""
Helper JEB script to generate Frida hooks
"""
class Jeb4frida_ts(IScript):
    def run(self, ctx):
        print(u"🔥 Jeb4frida...")
        # Require script to be run in JEB GUI
        if not isinstance(ctx, IGraphicalClientContext):
            print(u"❌ This script must be run within a graphical client.")
            return

        view = ctx.getFocusedView()
        unit = view.getUnit()

        if isinstance(unit, IJavaSourceUnit) or isinstance(unit, IDexUnit):
            print(u"IJavaSourceUnit / IDexUnit detected")
            # Both IJavaSourceUnit and IDexUnit have getDecompiler()
            dexdec = unit.getDecompiler()
            self.handle_java_dex(ctx, dexdec)
            return

        if isinstance(unit, INativeSourceUnit) or isinstance(unit, INativeCodeUnit):
            print(u"INativeSourceUnit / INativeCodeUnit detected...")
            self.handle_native(ctx, unit)
            return

        return 

    def handle_java_dex(self, ctx, dexdec):
        f = ctx.getFocusedFragment()
        assert f, 'Need a focused fragment'

        # a DEX-style address: TYPENAME->METHODNAME(PARAMTYPES)RETTYPE+OFFSET
        dex_addr = f.getActiveAddress()

        # strip the offset if present
        dex_addr = dex_addr.split('+')[0]

        # we won't be looping through inner classes, for now...
        class_dex_addr = dex_addr.split('->')[0]
        java_class = dexdec.getClass(class_dex_addr, True) # True to decompile if not done yet

        if ";->" in dex_addr: # single method
            java_methods = [dexdec.getMethod(dex_addr, True)] # True to decompile if not done yet
        else: # all methods                
            java_methods = java_class.getMethods()
        
        print(u"🔥 Here\'s a fresh Frida hook...")
        print('-' * 100)
        print(self.gen_how_to(ctx))
        print(self.gen_java_hook(java_class, java_methods))
    
    def to_canonical_name(self, dalvik_name):
        dalvik_name = dalvik_name.replace('/', '.')
        type_name = {
            'C': "char",
            'I': "int",
            'B': "byte",
            'Z': "boolean",
            'F': "float",
            'D': "double",
            'S': "short",
            'J': "long",
            'V': "void",
            'L': dalvik_name[1:-1],
            '[': dalvik_name
        }
        return type_name.get(dalvik_name[0], "unknown")
    
    def gen_java_hook(self, java_class, java_methods):
        class_name = java_class.getType().toString()
        class_name_var = class_name.split('.')[-1]
        if not class_name_var[0].isalpha() and class_name_var[0] != '_':
            class_name_var = '_' + class_name_var
        frida_hook = u"var {} = Java.use('{}');".format(class_name_var, class_name)

        for idx, java_method in enumerate(java_methods):
            method_name = java_method.getName().strip('<>')
            method_name_var = u"{}_{}_{:x}".format(class_name_var, method_name, idx)
            if not method_name[0].isalpha() and method_name[0] != '_':
                method_name = '_' + method_name
            method_name = '$init' if method_name == "init" else method_name
            if method_name == "clinit": 
                print(u"//❌ Encountered <clinit>, skipping...\n//\tPS: Send PR if you know how to fix this.")
                continue
            method_parameters = java_method.getParameters()
            if len(method_parameters) > 0 and method_parameters[0].getIdentifier().toString() == "this":  # pop "this"
                method_parameters = method_parameters[1:]

            method_arguments = []
            method_overload_parameters = []

            for p in method_parameters:
                arg_name = p.getIdentifier().toString()
                if not arg_name[0].isalpha() and arg_name[0] != '_':
                    arg_name = '_' + arg_name
                method_arguments.append(arg_name)
                method_overload_parameters.append(u'"{}"'.format(self.to_canonical_name(p.getType().getSignature())))
            
            # Build method_arguments_with_types string
            if method_arguments:
                method_arguments_with_types = ', '.join([arg + ': any' for arg in method_arguments])
            else:
                method_arguments_with_types = ''

            args_passing = ', ' + ', '.join(method_arguments) if method_arguments else ''

            # 修改这里：添加参数值字符串的条件判断
            method_arguments_values = ''
            if method_arguments:
                method_arguments_values = ' -> (${' + '}, ${'.join(method_arguments) + '})'
            else:
                method_arguments_values = ' -> ()'

            frida_hook += u"""
var {method_name_var} = {class_name_var}.{method_name}.overload({method_overload});
{method_name_var}.implementation = function({method_arguments_with_types}) {{
    console.log(`Hooked {class_name}.{method_name}({method_arguments}){method_arguments_values}`);
    var retval = {method_name_var}.call(this{args_passing});
    return retval;
}};""".format(
        class_name_var=class_name_var,
        class_name=class_name,
        method_name_var=method_name_var,
        method_name=method_name,
        method_overload=', '.join(method_overload_parameters),
        method_arguments_with_types=method_arguments_with_types,
        method_arguments=', '.join(method_arguments),
        method_arguments_values=method_arguments_values,
        args_passing=args_passing)

        return frida_hook
    

    def handle_native(self, ctx, unit):
        f = ctx.getFocusedFragment()
        assert f, 'Need a focused fragment'
        active_address = f.getActiveAddress()
        assert active_address, 'Put cursor somewhere else...'
        active_address = active_address.split('+')[0]  # strip offset

        # Get decompiler and code unit
        if isinstance(unit, INativeSourceUnit):
            decompiler = unit.getDecompiler()
            code_unit = decompiler.getCodeUnit()
        elif isinstance(unit, INativeCodeUnit):
            code_unit = unit
        else:
            print(u"❌ Unsupported native unit type.")
            return

        elf = code_unit.getCodeObjectContainer()
        lib_name = elf.getName()

        code_method = code_unit.getMethod(active_address)  # ICodeMethod -> INativeMethodItem
        method_real_name = code_method.getName(False)  # we need the real name instead of renamed one
        func_address = code_method.getMemoryAddress()
        func_offset = func_address - code_unit.getVirtualImageBase()
        func_offset_hex = hex(func_offset)

        func_retval_type = code_method.getReturnType().getName(True) if code_method.getReturnType() is not None else "void"
        func_parameter_names = code_method.getParameterNames()
        func_parameter_types = code_method.getParameterTypes()

        func_args = ""
        for idx, func_parameter_name in enumerate(func_parameter_names):
            arg_name = func_parameter_name
            if not arg_name[0].isalpha() and arg_name[0] != '_':
                arg_name = '_' + arg_name
            func_args += u"            var {arg_name} = args[{idx}]; // {arg_type}\n".format(
                arg_name=arg_name,
                idx=idx,
                arg_type=func_parameter_types[idx].getName()
            )

        # Determine how to get the function pointer
        if method_real_name.startswith("Java_"):
            print("Java native method detected...")
            native_pointer = u"Module.getExportByName('{}', '{}')".format(lib_name, method_real_name)
        elif method_real_name.startswith(u"→"):
            print("Trampoline detected...")
            native_pointer = u"Module.getExportByName('{}', '{}')".format(lib_name, method_real_name.lstrip(u"→"))
        elif re.match(r'sub_[A-Fa-f0-9]+', method_real_name):
            print("Need to calculate offset...")
            native_pointer = u"Module.findBaseAddress('{}').add({})".format(lib_name, func_offset_hex)
        else:
            print("Assuming export...")
            native_pointer = u"Module.getExportByName('{}', '{}')".format(lib_name, method_real_name)

        frida_hook = u"""
var interval = setInterval(function() {{
    if (Module.findBaseAddress("{lib_name}")) {{
        clearInterval(interval);

        Interceptor.attach({native_pointer}, {{ // offset {func_offset_hex}
            onEnter: function(args) {{
{func_args}            }},
            onLeave: function(retval) {{ // return type: {func_retval_type}
                console.log(`Hooked {lib_name}[{method_real_name}]() -> ${{retval}}`);
                // You can modify the return value here
            }}
        }});

        return;
    }}
}}, 0);""".format(
            lib_name=lib_name,
            method_real_name=method_real_name,
            native_pointer=native_pointer,
            func_offset_hex=func_offset_hex,
            func_retval_type=func_retval_type,
            func_args=func_args)

        print(u"🔥 Here's a fresh Frida hook...")
        print('-' * 100)
        print(self.gen_how_to_native(ctx, lib_name))
        print(frida_hook)

    def gen_how_to(self, ctx):
        project = ctx.getMainProject()
        assert project, "Need a project..."

        # Find the first IApkUnit in the project
        apk = project.findUnit(IApkUnit)
        assert apk, "Need an apk unit"

        return u"// Insert this code into your TypeScript Frida code's Java.perform method.".format(apk.getPackageName())
    
    def gen_how_to_native(self, ctx, lib_name):
        return u"// Insert this code into your TypeScript Frida code's Java.perform method.\n// Make sure the library '{}' is loaded before hooking.".format(lib_name)
