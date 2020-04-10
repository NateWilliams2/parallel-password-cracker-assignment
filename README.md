# Parallel Password Cracker
Parallel password cracker assignment for CSC-213 Operating Systems at Grinnell College. Assignment is to implement a simple brute-force password cracker that can run on parallel threads.

Code below "provided code" section provided as part of assignment. All code above this line by Nate Williams. Code under "part A" written collaboratively by Nate Williams and Evan Holt.

### Executing Code
Brute-force a single password by passing the md5 hash as an argument:  
``./password-cracker single 8d5f88b71d679934fdcdaf2ab4af0812``
Crack a list of passwords with 4 threads running in parallel:
``./password-cracker list inputs/input1.txt``
