#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <inttypes.h>

#include <openssl/bio.h>
#define DATE_LEN 128

typedef struct{
    char* certPath;
    char* URL;
    int isSubj;
    int isDate;
    int isKeyLen;
    int isExtn;
} Web;

void readCSV(Web*** queues, char* CSVpath, int* length);
void verifyCert(Web* queues);
int checkCN(X509 *cert, char* DN);
int checkDate(X509 *cert);
int checkKeyLen(X509 *cert);
int checkExtn(X509 *cert);
void freeCSV(Web*** queues, int* length);

/*======================TEMP======================*/

int convert_ASN1TIME(ASN1_TIME *t, char* buf, size_t len)
{
    int rc;
    BIO *b = BIO_new(BIO_s_mem());
    rc = ASN1_TIME_print(b, t);
    if (rc <= 0) {
//        log_error("fetchdaemon", "ASN1_TIME_print failed or wrote no data.\n");
        BIO_free(b);
        return EXIT_FAILURE;
    }
    rc = BIO_gets(b, buf, len);
    if (rc <= 0) {
//        log_error("fetchdaemon", "BIO_gets call failed to transfer contents to buf");
        BIO_free(b);
        return EXIT_FAILURE;
    }
    BIO_free(b);
    return EXIT_SUCCESS;
}
/*====================main========================*/

void main(int argc, char **argv) {

    int length = 0;
    Web** queues = NULL;

    if (argc != 2){
        fprintf(stderr, "Error: Incorrect num of arguments.\n");
        exit(EXIT_FAILURE);
    }

    readCSV(&queues, argv[1], &length);
    for(int j=0; j<length; j++){

    }

    for(int i=0; i<length; i++){
        verifyCert(queues[i]);
    }

    freeCSV(&queues, &length);

}

/*===================functions==================*/
void readCSV(Web*** queues, char* CSVpath, int* length){

    FILE *fp = NULL;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    fp = fopen(CSVpath, "r");
    if (fp == NULL){
        fprintf(stderr, "unable to open: %s\n", CSVpath);
        exit(EXIT_FAILURE);
    }

    while ((nread = getline(&line, &len, fp)) > 0) {

        /* create a pair of cert in queues */

        Web* web = (Web*) malloc(sizeof(Web));

        // cert path
        char* temp = strtok(line, ",");
        web->certPath = (char*) malloc(sizeof(char) * strlen(temp));
        if (web->certPath == NULL){
            perror("malloc web->certPath");
            exit(EXIT_FAILURE);
        }
        strcpy(web->certPath, temp);

        // URL
        temp = strtok(NULL, ",");
        web->URL = (char*) malloc(sizeof(char) * strlen(temp));
        if (web->URL == NULL){
            perror("malloc web->URL");
            exit(EXIT_FAILURE);
        }
        temp[(strlen(temp) -1)] = '\0';
        strcpy(web->URL, temp);

        // put into queues
        *queues = (Web**) realloc(*queues, (*length+1)*sizeof(Web*));
        if (*queues == NULL){
            perror("realloc queues");
            exit(EXIT_FAILURE);
        }
        (*queues)[*length] = web;
        (*length)++;
    }
    fclose(fp);
    free(line);
};

void verifyCert(Web* web){

//    printf("%s\n%s\n", web->certPath, web->URL);

    char* path = web->certPath;
    web->isSubj = 0;
    web->isDate = 0;
    web->isKeyLen = 0;
    web->isExtn = 0;

    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Unable to open: %s\n", path);
        exit(EXIT_FAILURE);
    }

    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (!cert) {
        fprintf(stderr, "Unable to parse certificate in: %s\n", path);
        fclose(fp);
        exit(EXIT_FAILURE);
    }

    /* check domain name validation (including Subject Alternative Name (SAN)
     * extension) and wildcards */
    web->isSubj = checkCN(cert, web->URL);

    /* validation of dates, both the Not Before and Not After dates */
    web->isDate = checkDate(cert);

    /* minimum key length of 2048 bits for RSA */
    web->isKeyLen = checkKeyLen(cert);

    /* correct key usage, including extensions */
    web->isExtn = checkExtn(cert);

//    printf("isSubj = %d\n", web->isSubj);
//    printf("isDate = %d\n", web->isDate);
//    printf("isKeyLen = %d\n", web->isKeyLen);
//    printf("isExtn = %d\n", web->isExtn);
    printf("%d\n", web->isSubj && web->isDate && web->isKeyLen && web->isExtn);
    X509_free(cert);
    fclose(fp);

}

int checkCN(X509 *cert, char* DN){
    return X509_check_host(cert, DN, strlen(DN), 0, NULL);
}

int checkDate(X509 *cert){
    int isDate = 0;
    ASN1_TIME* not_before = X509_get_notBefore(cert);
    ASN1_TIME* not_after = X509_get_notAfter(cert);
    /*============================================*/
    // given display time function
    char not_after_str[DATE_LEN];
    char not_before_str[DATE_LEN];
    convert_ASN1TIME(not_after, not_after_str, DATE_LEN);
    convert_ASN1TIME(not_before, not_before_str, DATE_LEN);
//    printf("%s\n%s\n\n", not_before_str, not_after_str);
    /*============================================*/
    // mine own check time
    int day = -1;
    int sec = -1;
    if (ASN1_TIME_diff(&day, &sec, not_before, NULL)) {
        if (day < 0 || sec < 0){
//            printf("Now is Earlier than not_before\n");
            return 0;
        }else{
//            printf("Now is Later than not_before\n");
            isDate = 1;
        }
    } else{
        fprintf(stderr, "Passed-in time structure has invalid syntax\n");
        exit(EXIT_FAILURE);
    }
    day = 1;
    sec = 1;
    if (ASN1_TIME_diff(&day, &sec, not_after, NULL)) {
        if (day > 0 || sec > 0){
//            printf("Now is Later than not_after\n");
            return 0;
        }else{
//            printf("Now is Earlier than not_after\n");
            isDate = 1;
        }
    } else{
        fprintf(stderr, "Passed-in time structure has invalid syntax\n");
        exit(EXIT_FAILURE);
    }
    return isDate;
}

int checkKeyLen(X509 *cert){
    EVP_PKEY * public_key = X509_get_pubkey(cert);
    RSA *rsa_key = EVP_PKEY_get1_RSA(public_key);
    if (RSA_size(rsa_key)*8 >= 2048){
        RSA_free(rsa_key);
        return 1;
    }else{
        RSA_free(rsa_key);
        return 0;
    }
}

int checkExtn(X509 *cert){
    int isCA = 0;
    // BasicConstraints includes “CA:FALSE”
    if (cert->ex_flags & EXFLAG_BCONS){
        if (cert->ex_flags & EXFLAG_CA){
            isCA = 1;
        }

    }
//    printf("my: %d\n", isCA);

    // Enhanced Key Usage includes “TLS Web Server Authentication”
    // 2 is the index of "ssl server" in purpose list
    int isServer = X509_check_purpose(cert, 2, 0);
//    printf("%d\n\n", isServer);
    return (isCA==0) && (isServer==1);
}

void freeCSV(Web*** queues, int* length){
    for(int i=0; i<*length; i++){
        free((*queues)[i]->certPath);
        free((*queues)[i]->URL);
        free((*queues)[i]);
    }
    free(*queues);
}