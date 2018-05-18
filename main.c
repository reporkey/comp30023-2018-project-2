#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include <openssl/bio.h>
#define DATE_LEN 128

typedef struct{
    char* certPath;
    char* URL;
} Web;

void readCSV(Web*** queues, char* CSVpath, int* length);
void readCert(Web*** queues);
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
/*============================================*/

void main(int argc, char **argv) {

    int length = 0;
    Web** queues = NULL;

    if (argc != 2){
        fprintf(stderr, "Error: Incorrect num of arguments.\n");
        exit(EXIT_FAILURE);
    }

    readCSV(&queues, argv[1], &length);
    for(int j=0; j<length; j++){
        printf("%s\n%s\n", queues[j]->certPath, queues[j]->URL);
    }
    
    readCert(&queues);

    freeCSV(&queues, &length);

}

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

        Web* queue = (Web*) malloc(sizeof(Web));

        // cert path
        char* temp = strtok(line, ",");
        queue->certPath = (char*) malloc(sizeof(char) * strlen(temp));
        if (queue->certPath == NULL){
            perror("malloc queue->certPath");
            exit(EXIT_FAILURE);
        }
        strcpy(queue->certPath, temp);

        // URL
        temp = strtok(NULL, ",");
        queue->URL = (char*) malloc(sizeof(char) * strlen(temp));
        if (queue->URL == NULL){
            perror("malloc queue->URL");
            exit(EXIT_FAILURE);
        }
        temp[(strlen(temp) -1)] = '\0';
        strcpy(queue->URL, temp);

        // put into queues
        *queues = (Web**) realloc(*queues, (*length+1)*sizeof(Web*));
        if (*queues == NULL){
            perror("realloc queues");
            exit(EXIT_FAILURE);
        }
        (*queues)[*length] = queue;
        (*length)++;
    }
    fclose(fp);
    free(line);
};

void readCert(Web*** queues){

    char* path = (*queues)[1]->certPath;
    char* DN = (*queues)[1]->URL;
    int isSubj = 0;
    int isDate = 0;
    int isKeyLen = 0;

    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "unable to open: %s\n", path);
        exit(EXIT_FAILURE);
    }

    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (!cert) {
        fprintf(stderr, "unable to parse certificate in: %s\n", path);
        fclose(fp);
        exit(EXIT_FAILURE);
    }

    /* check domain name validation (including Subject Alternative Name (SAN)
     * extension) and wildcards */

    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    isSubj = X509_check_host(cert, DN, strlen(DN), 0, NULL);
    printf("\n%s\n%s\nisSubj = %d\n\n", subj, DN, isSubj);

    /* validation of dates, both the Not Before and Not After dates */

    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);
    // mine own check time
    int day = -1;
    int sec = -1;
    if (ASN1_TIME_diff(&day, &sec, not_before, NULL)) {
        if (day < 0 || sec < 0){
            printf("Now is Earlier than not_before\n");
            return;
        }else{
            printf("Now is Later than not_before\n");
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
            printf("Now is Later than not_after\n");
            return;
        }else{
            printf("Now is Earlier than not_after\n");
            isDate = 1;
        }
    } else{
        fprintf(stderr, "Passed-in time structure has invalid syntax\n");
        exit(EXIT_FAILURE);
    }
    // given display time function
    char not_after_str[DATE_LEN];
    char not_before_str[DATE_LEN];
    convert_ASN1TIME(not_after, not_after_str, DATE_LEN);
    convert_ASN1TIME(not_before, not_before_str, DATE_LEN);
    printf("%s\n%s\nisDate = %d\n\n", not_before_str, not_after_str, isDate);

    /* minimum key length of 2048 bits for RSA */
    EVP_PKEY * public_key = X509_get_pubkey(cert);
    RSA *rsa_key = EVP_PKEY_get1_RSA(public_key);
    int key_length = RSA_size(rsa_key)*8;
    if (key_length >= 2048){
        isKeyLen = 1;
    }else{
        RSA_free(rsa_key);
        return;
    }
    printf("%d\n", key_length);
    RSA_free(rsa_key);

    X509_free(cert);
    fclose(fp);

}

void freeCSV(Web*** queues, int* length){
    for(int i=0; i<*length; i++){
        free((*queues)[i]->certPath);
        free((*queues)[i]->URL);
        free((*queues)[i]);
    }
    free(*queues);
}