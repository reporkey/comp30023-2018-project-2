#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

typedef struct{
    char* certPath;
    char* URL;
    int isDN;
    int isDate;
    int isKeyLen;
    int isExtn;
} Web;

void readCSV(Web*** queues, char* CSVpath, int* length);
void verifyCert(Web* queues);
int checkDN(X509 *cert, char* DN);
int compareDN(char* CN, char* DN);
int checkDate(X509 *cert);
int checkKeyLen(X509 *cert);
int checkExtn(X509 *cert);
void writeCSV(Web** queues, int length);
void freeCSV(Web*** queues, int length);