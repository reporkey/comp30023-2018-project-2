#include <certcheck.h>
int main(int argc, char **argv) {

    int length = 0;
    Web** queues = NULL;

    if (argc != 2){
        fprintf(stderr, "Error: Incorrect numbers of arguments.\n");
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
        fprintf(stderr, "Unable to open: %s\n", CSVpath);
        exit(EXIT_FAILURE);
    }

    while ((nread = getline(&line, &len, fp)) > 0) {

        /* create each web in queues */

        Web* web = (Web*) malloc(sizeof(Web));
        if (web == NULL) {
            fprintf(stderr, "Failed to malloc the %dth web\n", *length+1);
            return;
        }
        web->isDN = 0;
        web->isDate = 0;
        web->isKeyLen = 0;
        web->isExtn = 0;

        // cert path
        char* temp = strtok(line, ",");
        web->certPath = (char*) malloc(sizeof(char) * strlen(temp)+1);
        if (web->certPath == NULL){
            fprintf(stderr, "Failed to malloc certPath in the %dth web\n", *length+1);
            return;
        }
        strcpy(web->certPath, temp);

        // URL
        temp = strtok(NULL, ",");
        temp[(strlen(temp) -1)] = '\0';
        web->URL = (char*) malloc(sizeof(char) * strlen(temp)+1);
        if (web->URL == NULL){
            fprintf(stderr, "Failed to malloc URL in the %dth web\n", *length+1);
            return;
        }
        strcpy(web->URL, temp);

        // put into queues
        *queues = (Web**) realloc(*queues, (*length+1)*sizeof(web));
        if (*queues == NULL){
            fprintf(stderr, "Failed to reallocate queues in the %dth web\n", *length+1);
            return;
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
        fprintf(stderr, "Unable to open %s\n", path);
        return;
    }
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (!cert) {
        fprintf(stderr, "Unable to parse certificate in: %s\n", path);
        fclose(fp);
        return;
    }

    /* check domain name validation and SAN, and their wildcards */
    web->isDN = checkDN(cert, web->URL);
    if (web->isDN == 0){
        X509_free(cert);
        fclose(fp);
        return;
    }
    /* check validation of dates */
    web->isDate = checkDate(cert);
    if (web->isDate == 0){
        X509_free(cert);
        fclose(fp);
        return;
    }
    /* check length of RSA */
    web->isKeyLen = checkKeyLen(cert);
    if (web->isKeyLen == 0){
        X509_free(cert);
        fclose(fp);
        return;
    }
    /* check extensions */
    web->isExtn = checkExtn(cert);

    X509_free(cert);
    fclose(fp);
}

int checkDN(X509 *cert, char* DN) {

    /* check CN*/

    int isCN = 0;
    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char *splitCN = "/CN=";
    char *CN = strstr(subj, splitCN) + strlen(splitCN) * sizeof(char);

    isCN = compareDN(CN, DN);
    OPENSSL_free(subj);
    if(isCN == 1) return isCN;

    /* check SAN */

    int isSAN = 0;
    X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_subject_alt_name, -1));
    if (ex != NULL) {
        BUF_MEM *bptr = NULL;
        char *buff = NULL;
        BIO *bio = BIO_new(BIO_s_mem());
        if (!X509V3_EXT_print(bio, ex, 0, 0)) {
            fprintf(stderr, "Error in reading extensions");
            return -1;
        }
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &bptr);

        buff = (char *)malloc((bptr->length + 1) * sizeof(char));
        if (buff == NULL){
            fprintf(stderr, "Failed to malloc buff at %d\n", __LINE__);
            return -1;
        }
        memcpy(buff, bptr->data, bptr->length);
        buff[bptr->length] = '\0';
        printf("%s\n", buff);
        char* SAN = buff;
        char* SANnext = NULL;
        char *splitSAN = "DNS:";
        while ((isSAN != 1) && (SAN != NULL) && (SAN = strstr(SAN, splitSAN)) != NULL){
            SAN += sizeof(char)*strlen(splitSAN);
            SANnext = strstr(SAN, splitSAN);
            if (SANnext != NULL){
                *(SANnext-sizeof(char)) = '\0';
            }
            printf("%s\n", SAN);
            isSAN = compareDN(SAN, DN);
            SAN = SANnext;
        }
        BIO_free_all(bio);
        free(buff);
    }
    return isCN || isSAN;
}

int compareDN(char* CN, char* DN){
    int isSame = 0;
    int CNlen = strlen(CN);
    int DNlen = strlen(DN);

    if (CNlen > 2) {

        // if example.example.com
        if (strcmp(CN, DN) == 0) isSame = 1;

        // if example*.example.com
        for (int i = 0; i < DNlen && i < CNlen; i++) {
            if ((CN[i] != DN[i]) && (CN[i] == '*') && (i+1 < CNlen)) {
                i += 1;
                printf("CN: %s\n DN:%s\n", &CN[i], &DN[i]);
                for (int j = i; j < DNlen-i; j++) {
                    if (strcmp(&CN[i], &DN[j]) == 0) isSame = 1;
                    if (DN[j] == '.') break;
                }
                break;
            }
        }
    }
    return isSame;
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
        fprintf(stderr, "Passed-in time structure has invalid syntax at %d\n", __LINE__);
        return -1;
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
        fprintf(stderr, "Passed-in time structure has invalid syntax at %d\n", __LINE__);
        return -1;
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
    if (buff == NULL){
        fprintf(stderr, "Failed to malloc buff at %d\n", __LINE__);
        return -1;
    }
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
        fprintf(stderr, "Error to open file at %d\n", __LINE__);
        return;
    }

    for (int i=0; i<length; i++){
        fprintf(f, "%s,", queues[i]->certPath);
        fprintf(f, "%s,", queues[i]->URL);
        fprintf(f, "%d\n", queues[i]->isDN && queues[i]->isDate && queues[i]->isKeyLen && queues[i]->isExtn);
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