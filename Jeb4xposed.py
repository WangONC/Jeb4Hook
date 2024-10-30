# -*- coding: utf-8 -*-
#?description=Helper JEB script to generate Xposed hooks
#?shortcut= alt+x

from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit, IApkUnit
from com.pnfsoftware.jeb.core.units.code.java import IJavaSourceUnit, IJavaMethod
import re

"""
Helper JEB script to generate Xposed hooks
"""
class Jeb4xposed(IScript):
    def run(self, ctx):
        print(u"🔥 Jeb4xposed...")
        # Require script to be run in JEB GUI
        if not isinstance(ctx, IGraphicalClientContext):
            print(u"❌ This script must be run within a graphical client.")
            return

        view = ctx.getFocusedView()
        unit = view.getUnit()

        if isinstance(unit, IJavaSourceUnit) or isinstance(unit, IDexUnit):
            print(u"IJavaSourceUnit / IDexUnit detected")
            dexdec = unit.getDecompiler()
            self.handle_java_dex(ctx, dexdec)
            return

        return 

    def handle_java_dex(self, ctx, dexdec):
        f = ctx.getFocusedFragment()
        assert f, 'Need a focused fragment'

        dex_addr = f.getActiveAddress()
        dex_addr = dex_addr.split('+')[0]
        class_dex_addr = dex_addr.split('->')[0]
        java_class = dexdec.getClass(class_dex_addr, True)

        if ";->" in dex_addr:
            java_methods = [dexdec.getMethod(dex_addr, True)]
        else:
            java_methods = java_class.getMethods()
        
        print(u"🔥 Here\'s a fresh Xposed hook...")
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
        xposed_hook = ""

        for idx, java_method in enumerate(java_methods):
            method_name = java_method.getName().strip('<>')
            if method_name in ("<init>", "init"):
                method_name = "constructor"
            if method_name == "<clinit>":
                print(u"//❌ Encountered <clinit>, skipping...\n//\tPS: Send PR if you know how to fix this.")
                continue

            method_parameters = java_method.getParameters()
            if len(method_parameters) > 0 and method_parameters[0].getIdentifier().toString() == "this":
                method_parameters = method_parameters[1:]

            method_arguments = []
            method_param_types = []

            for p in method_parameters:
                arg_name = p.getIdentifier().toString()
                if not arg_name[0].isalpha() and arg_name[0] != '_':
                    arg_name = '_' + arg_name
                method_arguments.append(arg_name)
                param_type = self.to_canonical_name(p.getType().getSignature())
                if param_type in ['int', 'boolean', 'char', 'byte', 'float', 'double', 'long', 'short']:
                    param_type_class = param_type + '.class'
                else:
                    param_type_class = 'Class.forName("%s")' % param_type
                method_param_types.append(param_type_class)

            args_list = ['"%s"' % class_name, 'lpparam.classLoader', '"%s"' % method_name]
            args_list.extend(method_param_types)
            args_code = ', '.join(args_list)

            xposed_hook += u"""
try {
    XposedHelpers.findAndHookMethod({args_code}, new XC_MethodHook() {{
        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {{
            super.beforeHookedMethod(param);
            // Your code here
        }}
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {{
            super.afterHookedMethod(param);
            // Your code here
        }}
    }});
} catch (ClassNotFoundException e) {
    throw new RuntimeException(e);
}""".format(args_code=args_code)

        return xposed_hook

    def gen_how_to(self, ctx):
        return u"// Insert this code into your Xposed module's handleLoadPackage method."
