# Assignment 2
This repository contains example code and test scripts for Assignment 2

## Example Certificate Code
certexample.c contains example code for opening a certificate file using OpenSSL, as well as extracting some values from it.

## Test Scripts and Certificates
Inside sample\_certs you will find a testscript.sh file. Copy the contents of sample\_certs to the directory where your certcheck program is, and then run ./testscript.sh It will call your program, passing sample_input.csv as the input file parameter, and wait for it to finish. It will then compare the output.csv with the expected output.

### Sample Certificate Explanation
An additional file output\_explanation.csv has also been included. This is a CSV file with an additional column explaining why a certificate and domain pairing is considered VALID or INVALID.
