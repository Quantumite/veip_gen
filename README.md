# veip_gen README
## General Information
- Author: Austin Norby
- Date 7/2/2022
- Description: Generate programs with vanilla EIP overwrite vulnerabilities.
- Tested on Windows 11 with Python 3.8.10

## Video Link
- [Link](https://www.youtube.com/watch?v=RQN9wAHBHdY)

## Installation
- This was not turned into a python module so there is no installation. Place the script in a directory and run using Python 3.

## Help Menu
```bash
usage: veip_gen.py [-h] [-v] [-s SPECIFIC] [-t TYPE] [--num-args NUM_ARGS] [--bytes BYTES] [-r] [-n NUMBER_STACK_VARIABLES] [-b BUFFER_SIZE] [-g GENERATE] [-f FILE]

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Print out additional information about the vulnerable code being generated.
  -s SPECIFIC, --specific SPECIFIC
                        Specify a specific vulnerable function to use. Options: strcpy, strncpy, strcat, sprintf, gets.
  -t TYPE, --type TYPE  Type of vulnerability -- Currently supports 'vanilla' or 'conditional'. Vanilla EIP overflows are always guaranteed to have the vulnerability present. Conditional     
                        EIP vulnerabilities have a condition that must be satisifed before the vulnerable code is reached.
  --num-args NUM_ARGS   Only relevant to conditional EIP vulnerable code. Specify the number of args that should be given to expose the vulnerable code. Default: 3
  --bytes BYTES         Only relevant to conditional EIP vulnerable code. Specify the bytes to be searched for at the beginning of the first argument in order to satisfy the condition.       
  -r, --random          Pick a random vulnerable function.
  -n NUMBER_STACK_VARIABLES, --number-stack-variables NUMBER_STACK_VARIABLES
                        How many stack variables would you like in the main() function. This will move the buffer address around on the stack to make vulnerable programs different.
  -b BUFFER_SIZE, --buffer-size BUFFER_SIZE
                        Set the size of the buffer to be used for overflows.
  -g GENERATE, --generate GENERATE
                        Generate a number of vulnerable programs.
  -f FILE, --file FILE  Write code to a file rather than stdout. Ex. '-f test' produces 'test.c'. If the -g (--generate) flag is used, a number will be appended to the file name given        
                        before the '.c' extension is added. Ex. '-g 2 -f test' produces 'test_1.c' and 'test_2.c'.
```

## Examples
- Single file, specific vulnerable function
```
python3 veip_gen.py -s strcpy
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
        char WdqfH = 35;
        double IEAXs = 103;
        double VQCzY = 185;
        char buf[16];

        (void)strcpy(buf, argv[1]);
        return 0;
}
```
- single file, verbose, random vulnerable function, and a buffer size of 32 bytes
```
python3 veip_gen.py -v -r -b 32
[*] Specific vulnerable function was specified: strcpy

[*] Random variable name: SCIAR

[*] Stack Variable:     short SCIAR = 4;


[*] Random variable name: eeiSl

[*] Stack Variable:     short eeiSl = 115;


[*] Random variable name: REOJJ

[*] Stack Variable:     int REOJJ = 133;


[*] Randomly selected vulnerability: (void)strncpy(buf, argv[1], strlen(argv[1]));


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
        short SCIAR = 4;
        short eeiSl = 115;
        int REOJJ = 133;
        char buf[32];

        (void)strncpy(buf, argv[1], strlen(argv[1]));
        return 0;
}
```
- multiple (10) files, random vulnerabilities, 12 stack variables, and a buffer size of 128 bytes written to files starting with 'demo'
```
python3 veip_gen.py -g 10 -r -n 12 -b 128 -f demo
...
Produces 10 files, 'demo_{1..10}.c
...
Ex.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
	char uNhRe = 238;
	int kGKps = 157;
	int zXAer = 4;
	short cwHwk = 61;
	long long kMEfX = 10;
	long nnCWV = 70;
	int ABoVB = 16;
	long long VMuKN = 93;
	short csiuD = 164;
	float VEaZz = 161;
	char OxbGJ = 220;
	char UHDGn = 116;
	char buf[128];

	(void)gets(buf);
	return 0;
}
```
- Create a conditional EIP Buffer Overflow vulnerability with a check for the number of arguments.
```
python3 veip_gen.py -t conditional --num-args 2 -r -n 5 -b 32
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

int main(int argc, char** argv) {
        short fqNcY = 175;
        int LQatX = 204;
        int ZfuvY = 86;
        long long MYSEs = 97;
        long long psAZi = 86;
        char buf[32];

        if(argc == 2){
                (void)strcpy(buf, argv[1]);

        }
        return 0;
}
```
- Create a conditional EIP Buffer Overflow vulnerability with a check for a byte sequence at the beginning of the first argument.
```
python3 veip_gen.py -t conditional --bytes DEFG -r -n 7 -b 8
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

int main(int argc, char** argv) {
        short puGXU = 198;
        float rndkZ = 186;
        float orhUm = 50;
        int LNGgd = 43;
        double tnUlT = 86;
        double SbJil = 31;
        long zRPnM = 83;
        char buf[8];
        char bytes_value[4] = {68,69,70,71};
        if(memcmp(argv[1], bytes_value, 4) == 0){
                (void)strcpy(buf, argv[1]);

        }
        return 0;
}
```

## Additional Resources
- [Updated Banned API Documentation](https://www.microsoft.com/security/blog/2011/06/23/updated-banned-api-documentation-available/#:~:text=The%20most%20common%20examples%20of,%2C%20MD4%20and%20SHA%2D1)

- [Discouraged of forbidden C functions](https://libreswan.org/wiki/Discouraged_or_forbidden_C_functions)