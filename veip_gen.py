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
            content += "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <stdbool.h>\n\n"
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
        """Creates the vulnerable code."""
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

class ConditionalEIPBufferOverflowExample(VanillaEIPBufferOverflowExample):
    """Adds conditional code that must be satisfied before the EIP overflow vulnerability is exposed."""
    def __init__(self, number_stack_variables=3, buffer_name="buf", buffer_size=16, random_vuln=False, 
                specific_vuln_string=None, verbose=False, condition_type=None, condition="true", 
                bytes_value=b"ABCD", numargs_value=3):
        super().__init__(number_stack_variables = number_stack_variables, buffer_name = buffer_name, 
                        buffer_size = buffer_size, random_vuln=random_vuln, specific_vuln_string=specific_vuln_string,
                        verbose = verbose)
        self.condition = condition
        self.condition_type = condition_type
        self.bytes_value = bytes_value
        self.numargs_value = numargs_value
        self.bytes_value_string = ""

        if self.condition_type is not None:
            self.create_condition()

        if self.condition_type == "bytes":
            self.bytes_value_string = f"\tchar bytes_value[{len(self.bytes_value)}] = {{"
            for b in self.bytes_value:
                if isinstance(b, bytes):
                    self.bytes_value_string += f"{b},"
                elif isinstance(b, str):
                    self.bytes_value_string += f"{ord(b)},"
                else:
                    print("[!] Unknown type for bytes conditional!\n")
                    quit()
            self.bytes_value_string = self.bytes_value_string[:-1]
            self.bytes_value_string += "};"

    def create_conditional(self, vuln):
        """Creates a conditional wrapper around a vuln."""
        conditional_code_string = f"if({self.condition}){{\n"
        conditional_code_string += "\t\t"+str(vuln)+"\n"
        conditional_code_string += "\t}\n"
        return conditional_code_string

    def create_condition(self):
        if self.condition_type == "numargs":
            self.condition = f"argc == {self.numargs_value}"
        elif self.condition_type == "bytes":
            self.condition=f"memcmp(argv[1], bytes_value, {len(self.bytes_value)}) == 0"
        else:
            print(f"[!] Using unvalidated condition: {self.condition} in code!\n");
        

    def create(self):
        """Creates the vulnerable code."""
        file_contents = ConditionalEIPBufferOverflowExample.produce_beginning()
        file_contents += self.produce_stack_variables()
        file_contents += self.produce_buffer()
        if self.condition_type == "bytes":
            file_contents += self.bytes_value_string
        file_contents += ConditionalEIPBufferOverflowExample.produce_blank_line()
        if self.random_vuln:
            idx = random.randint(0,2)
            vulns = [StrcpyVuln(), StrncpyVuln(), GetsVuln(), SprintfVuln(), StrcatVuln()]
            vuln = vulns[idx]
            if self.verbose:
                print(f"[*] Randomly selected vulnerability: {vuln}\n")
            file_contents += "\t"+self.create_conditional(str(vuln))
        elif self.specific_vuln is not None:
            file_contents += "\t" + self.create_conditional(str(self.specific_vuln))
        else:
            if self.verbose:
                print("[*] Default vulnerability (strcpy) used.\n")
            file_contents += "\t"+self.create_conditional(str(StrcpyVuln()))
        file_contents += ConditionalEIPBufferOverflowExample.produce_ending()
        return file_contents


def main():
    arg_parse = argparse.ArgumentParser()
    arg_parse.add_argument("-v", "--verbose", help="Print out additional information about the vulnerable code being generated.", action="store_true")
    arg_parse.add_argument("-s", "--specific", help="Specify a specific vulnerable function to use. Options: strcpy, strncpy, strcat, sprintf, gets.", default="strcpy", type=str)
    arg_parse.add_argument("-t", "--type", help="Type of vulnerability -- Currently supports 'vanilla' or 'conditional'.\n\nVanilla EIP overflows are always guaranteed to have the vulnerability present. Conditional EIP vulnerabilities have a condition that must be satisifed before the vulnerable code is reached.", default='vanilla')
    arg_parse.add_argument("--num-args", help="Only relevant to conditional EIP vulnerable code. Specify the number of args that should be given to expose the vulnerable code. Default: 3", type=int, default=None)
    arg_parse.add_argument("--bytes", help="Only relevant to conditional EIP vulnerable code. Specify the bytes to be searched for at the beginning of the first argument in order to satisfy the condition.", default=None)
    arg_parse.add_argument("-r", "--random", help="Pick a random vulnerable function.", default=False, action="store_true")
    arg_parse.add_argument("-n", "--number-stack-variables", help="How many stack variables would you like in the main() function. This will move the buffer address around on the stack to make vulnerable programs different.", default=3, type=int)
    arg_parse.add_argument("-b", "--buffer-size", help="Set the size of the buffer to be used for overflows.", default=16, type=int)
    arg_parse.add_argument("-g", "--generate", help="Generate a number of vulnerable programs.", type=int, default=1)
    arg_parse.add_argument("-f", "--file", help="Write code to a file rather than stdout. Ex. '-f test' produces 'test.c'. If the -g (--generate) flag is used, a number will be appended to the file name given before the '.c' extension is added. Ex. '-g 2 -f test' produces 'test_1.c' and 'test_2.c'.", type=str, default=None)
    args = arg_parse.parse_args()

    for i in range(args.generate):
        if args.type == 'vanilla' or args.type[0].lower() == 'v':
            example = VanillaEIPBufferOverflowExample(number_stack_variables=args.number_stack_variables, buffer_size=args.buffer_size, random_vuln=args.random, specific_vuln_string=args.specific, verbose=True if args.verbose else False)
        elif args.type == 'conditional' or args.type[0].lower() == 'c':
            if args.num_args is not None:
                condition_type = 'numargs'
            elif args.bytes is not None:
                condition_type = 'bytes'
            example = ConditionalEIPBufferOverflowExample(number_stack_variables=args.number_stack_variables, buffer_size=args.buffer_size, random_vuln=args.random, specific_vuln_string=args.specific, verbose=True if args.verbose else False, condition_type=condition_type, condition=None, bytes_value=args.bytes, numargs_value = args.num_args)

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