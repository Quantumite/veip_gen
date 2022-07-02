import random
import string
import argparse

BASIC_TYPES = ["int", "float", "char", "double", "long", "long long", "short"]

class VEIPStackVariable():
    """A class that produces a well-formed stack variable for a C program."""
    def __init__(self, type=None, name=None, value=None):
        self.type = type
        self.name = name
        self.value = value

    def __repr__(self):
        return f"{self.type} {self.name} = {self.value};"

class StrcpyVuln():
    """Produces a line of code using strcpy() that is vulnerable."""
    def __init__(self, buf_name='buf'):
        self.buf_name = buf_name

    def __repr__(self):
        return f"(void)strcpy({self.buf_name}, argv[1]);\n"

class StrncpyVuln():
    """Produces a line of code using strncpy() that is vulnerable."""
    def __init__(self, buf_name='buf'):
        self.buf_name = buf_name

    def __repr__(self):
        return f"(void)strncpy({self.buf_name}, argv[1], strlen(argv[1]));\n"

class GetsVuln():
    """Produces a line of code using gets() that is vulnerable."""
    def __init__(self, buf_name='buf'):
        self.buf_name = buf_name

    def __repr__(self):
        return f"(void)gets({self.buf_name});\n"

class SprintfVuln():
    """Produces a line of code using sprintf() that is vulnerable."""
    def __init__(self, buf_name="buf"):
        self.buf_name = buf_name

    def __repr__(self):
        return f"(void)sprintf({self.buf_name}, \"%s\", argv[1]);\n"

class StrcatVuln():
    """Produces a line of code using strcat() that is vulnerable."""
    def __init__(self, buf_name="buf"):
        self.buf_name = buf_name

    def __repr__(self):
        return f"(void)strcat({self.buf_name}, argv[1]);\n"


class VanillaEIPBufferOverflowExample():
    def __init__(self, number_stack_variables=3, buffer_name="buf", buffer_size=16, random_vuln=False, specific_vuln_string=None, verbose=False):
        self.number_stack_variables = number_stack_variables
        self.buffer_name = buffer_name
        self.buffer_size = buffer_size
        self.random_vuln = random_vuln
        self.specific_vuln = None
        self.specific_vuln_string = specific_vuln_string
        self.verbose = verbose

        if self.specific_vuln_string is not None:
            if self.verbose:
                print(f"[*] Specific vulnerable function was specified: {self.specific_vuln_string}\n")

            if self.specific_vuln_string.lower() == "strcpy":
                self.specific_vuln = StrcpyVuln()
            elif self.specific_vuln_string == "strncpy":
                self.specific_vuln = StrncpyVuln()
            elif self.specific_vuln_string == "gets":
                self.specific_vuln = GetsVuln()
            elif self.specific_vuln_string == "strcat":
                self.specific_vuln = StrcatVuln()
            elif self.specific_vuln_string == "sprintf":
                self.specific_vuln = SprintfVuln()
            else:
                print("[!] Unknown type of vulnerability. Quitting...\n")
                quit()

    def produce_random_name(self, length=5):
        name = ""
        for i in range(length):
           name += f"{string.ascii_letters[random.randint(0,len(string.ascii_letters)-1)]}" 

        if self.verbose:
            print(f"[*] Random variable name: {name}\n")

        return name

    @staticmethod
    def produce_beginning(data=None):
        if data is None:
            content = ""
            content += "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\n"
            content += "int main(int argc, char** argv) {\n"
            return content
        else:
            return data

    @staticmethod
    def produce_ending(data=None, return_value=0):
        if data is None:
            content = ""
            content += f"\treturn {return_value};\n"
            content += "}"
            return content
        else:
            return data

    @staticmethod
    def produce_blank_line(num=1):
        return "\n"*num

    def produce_buffer(self,): 
        return f"\tchar {self.buffer_name}[{self.buffer_size}];\n"

    def produce_stack_variables(self):
        stack_vars_string = ""
        tmp_stack_variable = ""
        for i in range(self.number_stack_variables):
           tmp_stack_variable = "\t" + str(VEIPStackVariable(BASIC_TYPES[random.randint(0,len(BASIC_TYPES)-1)], self.produce_random_name(), random.randint(0,255))) + "\n"
           if self.verbose:
               print(f"[*] Stack Variable: {tmp_stack_variable}\n")

           stack_vars_string += tmp_stack_variable

        return stack_vars_string

    def create(self):
        file_contents = VanillaEIPBufferOverflowExample.produce_beginning()
        file_contents += self.produce_stack_variables()
        file_contents += self.produce_buffer()
        file_contents += VanillaEIPBufferOverflowExample.produce_blank_line()
        if self.random_vuln:
            idx = random.randint(0,2)
            vulns = [StrcpyVuln(), StrncpyVuln(), GetsVuln(), SprintfVuln(), StrcatVuln()]
            vuln = vulns[idx]
            if self.verbose:
                print(f"[*] Randomly selected vulnerability: {vuln}\n")
            file_contents += "\t"+str(vuln)
        elif self.specific_vuln is not None:
            file_contents += "\t" + str(self.specific_vuln)
        else:
            if self.verbose:
                print("[*] Default vulnerability (strcpy) used.\n")
            file_contents += "\t"+str(StrcpyVuln())
        file_contents += VanillaEIPBufferOverflowExample.produce_ending()
        return file_contents

def main():
    arg_parse = argparse.ArgumentParser()
    arg_parse.add_argument("-v", "--verbose", help="Print out additional information about the vulnerable code being generated.", action="store_true")
    arg_parse.add_argument("-s", "--specific", help="Specify a specific vulnerable function to use. Options: strcpy, strncpy, strcat, sprintf, gets.", default="strcpy", type=str)
    arg_parse.add_argument("-r", "--random", help="Pick a random vulnerable function.", default=False, action="store_true")
    arg_parse.add_argument("-n", "--number-stack-variables", help="How many stack variables would you like in the main() function. This will move the buffer address around on the stack to make vulnerable programs different.", default=3, type=int)
    arg_parse.add_argument("-b", "--buffer-size", help="Set the size of the buffer to be used for overflows.", default=16, type=int)
    arg_parse.add_argument("-g", "--generate", help="Generate a number of vulnerable programs.", type=int, default=1)
    arg_parse.add_argument("-f", "--file", help="Write code to a file rather than stdout. Ex. '-f test' produces 'test.c'. If the -g (--generate) flag is used, a number will be appended to the file name given before the '.c' extension is added. Ex. '-g 2 -f test' produces 'test_1.c' and 'test_2.c'.", type=str, default=None)
    args = arg_parse.parse_args()

    for i in range(args.generate):
        example = VanillaEIPBufferOverflowExample(number_stack_variables=args.number_stack_variables, buffer_size=args.buffer_size, random_vuln=args.random, specific_vuln_string=args.specific, verbose=True if args.verbose else False)

        if args.file is not None:
            if args.generate > 1:
                file_name = f"{args.file}_{i+1}.c"
            else:
                file_name = f"{args.file}.c"

            with open(file_name, "w") as f:
                f.write(example.create())
        else:
            print(example.create(), end="\n\n")

if __name__ == "__main__":
    main()