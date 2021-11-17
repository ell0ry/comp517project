import re
import typing
import os


RAW = """BOOL CreateProcessW(
  [in, optional]      LPCWSTR               lpApplicationName,
  [in, out, optional] LPWSTR                lpCommandLine,
  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
  [in]                BOOL                  bInheritHandles,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCWSTR               lpCurrentDirectory,
  [in]                LPSTARTUPINFOW        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);
"""

format_io_sig = {
    "in": "_In_",
    "in, optional": "_In_opt_",
    "in, out, optional": "_Inout_opt_",
    "in, out": "_Inout_",
    "out": "_Out_",
    "out, optional": "_Out_opt_"
    }

class function_declaration():

    def __init__(self, raw_declaration: str):
        self.raw_declaration = raw_declaration
        self.lines = raw_declaration.splitlines()
        self.arguments = []
        self.function_name = ""
        self.return_type = ""
        self.lowercase_function_name = ""

    def parse_function_signature(self):
        # Parse header
        header = re.match(r"(?P<return_type>\S+) (?P<function_name>\S+)\(", self.lines[0])
        self.return_type = header.group("return_type")
        self.function_name = header.group("function_name")

        arguments = []

        # Parse arguments
        for line in self.lines[1: -1]:
            # \s+(?P<argument_type>\S+)\s+(?P<argument_name>)
            #argument = re.match(r"\[(?P<io_signature>.*)\]", line)
            argument = re.match(r".*\[(?P<io_signature>.*)\]\s+(?P<argument_type>\S+)\s+(?P<argument_name>\S+)\b", line)
            arguments.append((argument.group("io_signature"), argument.group("argument_type"), argument.group("argument_name")))

        self.arguments = arguments

        # Parse last line
        last_line = re.match(r"\);", line[-1])

    def dump_signatures(self):
        arguments_no_io_signature = ", ".join([f"{argument[1]} {argument[2]}" for argument in self.arguments])
        self.lowercase_function_name = "_".join([str.lower(word) for word in re.findall('[A-Z][^A-Z]*', self.function_name)])
        
        # print the lambda function
        print(f"std::function<void({ arguments_no_io_signature })>\n"
              f"{ self.lowercase_function_name } = []({ arguments_no_io_signature}) {{\n"
              f"\t tracingStream << \"{ self.function_name }\" << endl;\n}};")

        # convert function wrapper parameters
        signature_with_formatted_io = ", ".join([f"{ format_io_sig[argument[0]] } { argument[1] } { argument[2] }" for argument in self.arguments])

        # print the full function signature wrapper
        print()
        print(f"void\n"
              f"WINAPI\n"
              f"hook{self.function_name}({ signature_with_formatted_io }) {{\n"
              f"\t{self.lowercase_function_name}({ ', '.join([argument[2] for argument in self.arguments]) });\n"
              f"}}\n")
        print()




"""
def print_replace(header):
    stripped = header.replace("[in]", "_In_").replace("[in, optional]", "_In_opt_").replace("[in, out, optional]", "_Inout_opt_")
    stripped = stripped.replace("[out]", "_Out_")
    stripped = re.sub(r"\s+", " ", stripped)
    
    no_api_includes = re.sub(r"\s+", " ", re.sub("(\[.*\])", "", header))
    
    print(stripped)
    
print_replace(RAW)
"""

file = open("function_signatures.txt", "r")
#print(file.read())


win_api_helper_constructor = []
win_api_func_pointers = [] 
win_api_hook_install = []


# Split on empty lines
functions = file.read().split("\n\n")
for func in functions:
    x = function_declaration(func)
    x.parse_function_signature()
    x.dump_signatures()

    # Create the extra boilerplate code for the Windows API Helper class
    win_api_helper_constructor.append(f"_{x.function_name} = m_dll[\"{x.function_name}\"];")
    win_api_func_pointers.append(f"decltype({x.function_name})* _{x.function_name};")
    win_api_hook_install.append(f"hookList.push_back(CreateHookingEnvironment(windowsHelper._{x.function_name}, { x.function_name }, { x.lowercase_function_name }));")

for cons_line in win_api_helper_constructor:
    print(cons_line)

print()

for pointer in win_api_func_pointers:
    print(pointer) 

print()

for hook in win_api_hook_install:
    print(hook)

"""
replacement = function_declaration(RAW)
replacement.parse_function_signature()
replacement.dump_signatures()
"""