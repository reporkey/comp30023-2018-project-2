#include <certcheck.h>
int main(int argc, char **argv) {

    int length = 0;
    Web** queues = NULL;

    if (argc != 2){
        fprintf(stderr, "Error: Incorrect num of arguments.\n");
        exit(EXIT_FAILURE);
    }

    readCSV(&queues, argv[1], &length);

    for(int i=0; i<length; i++){
        verifyCert(queues[i]);
    }

    writeCSV(queues, length);

    freeCSV(&queues, length);
    return 0;
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

        /* create each web in queues */

        Web* web = (Web*) malloc(sizeof(Web));
        web->isCN = 0;
        web->isDate = 0;
        web->isKeyLen = 0;
        web->isExtn = 0;

        // cert path
        char* temp = strtok(line, ",");
        web->certPath = (char*) malloc(sizeof(char) * strlen(temp)+1);
        if (web->certPath == NULL){
            perror("malloc web->certPath");
            exit(EXIT_FAILURE);
        }
        strcpy(web->certPath, temp);

        // URL
        temp = strtok(NULL, ",");
        temp[(strlen(temp) -1)] = '\0';
        web->URL = (char*) malloc(sizeof(char) * strlen(temp)+1);
        if (web->URL == NULL){
            perror("malloc web->URL");
            exit(EXIT_FAILURE);
        }
        strcpy(web->URL, temp);

        // put into queues
        *queues = (Web**) realloc(*queues, (*length+1)*sizeof(web));
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

    char* path = web->certPath;

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

    /* check domain name validation and its wildcards */
    web->isCN = checkCN(cert, web->URL);

    /* check validation of dates */
    web->isDate = checkDate(cert);

    /* check length of RSA */
    web->isKeyLen = checkKeyLen(cert);

    /* check extensions */
    web->isExtn = checkExtn(cert);

    X509_free(cert);
    fclose(fp);
}

int checkCN(X509 *cert, char* DN){
    int isCN = 0;
    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char* splitCN = "/CN=";
    char* CN = strstr(subj, splitCN) + strlen(splitCN) * sizeof(char);

    if (CN[0] == '*'){
        CN = CN + 2 * sizeof(char);
        DN = strstr(DN, ".") + sizeof(char);
    }
    if (strcmp(CN,DN) == 0){
        isCN = 1;
    }
    OPENSSL_free(subj);
    return isCN;
}

int checkDate(X509 *cert){
    int isDate = 0;
    ASN1_TIME* not_before = X509_get_notBefore(cert);
    ASN1_TIME* not_after = X509_get_notAfter(cert);
    int day = -1;
    int sec = -1;
    if (ASN1_TIME_diff(&day, &sec, not_before, NULL)) {
        if (day < 0 || sec < 0){
            return 0;
        }else{
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
            return 0;
        }else{
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
        EVP_PKEY_free(public_key);
        return 1;
    }else{
        RSA_free(rsa_key);
        EVP_PKEY_free(public_key);
        return 0;
    }

}

int checkExtn(X509 *cert){
    int isCA = 0;
    int isServer = 0;

    // Enhanced Key Usage includes “TLS Web Server Authentication”
    // 2 is the index of "ssl server" in purpose list
    isServer = X509_check_purpose(cert, 2, 0);

    // BasicConstraints includes “CA:FALSE”
    X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_basic_constraints, -1));
    BUF_MEM *bptr = NULL;
    char *buff = NULL;
    BIO *bio = BIO_new(BIO_s_mem());
    if (!X509V3_EXT_print(bio, ex, 0, 0)) {
        fprintf(stderr, "Error in reading extensions");
    }
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    buff = (char *)malloc((bptr->length + 1) * sizeof(char));
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = '\0';
    if(strstr(buff, "CA:FALSE") == NULL) {
        isCA = 1;
    }
    BIO_free_all(bio);
    free(buff);

    return (isCA==0) && (isServer==1);
}

void writeCSV(Web** queues, int length){
    FILE *f = fopen("output.csv", "w");
    if (f == NULL) {
        fprintf(stderr, "Error write file!\n");
        exit(EXIT_FAILURE);
    }

    for (int i=0; i<length; i++){
        fprintf(f, "%s,", queues[i]->certPath);
        fprintf(f, "%s,", queues[i]->URL);
        fprintf(f, "%d\n", queues[i]->isCN && queues[i]->isDate && queues[i]->isKeyLen && queues[i]->isExtn);
    }

    fclose(f);
}

void freeCSV(Web*** queues, int length) {
    for (int i = 0; i < length; i++) {
        free((*queues)[i]->certPath);
        free((*queues)[i]->URL);
        free((*queues)[i]);
    }
    free(*queues);
}