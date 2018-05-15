#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

typedef struct{
    char* certPath;
    char* URL;
} Pair;

void readCSV(Pair*** queues, char* CSVpath, int* length);
void freeCSV(Pair*** queues, int* length);

void main(int argc, char **argv) {

    int length = 0;
    Pair** queues = NULL;

    if (argc != 2){
        fprintf(stderr, "Error: Incorrect num of arguments.\n");
        exit(EXIT_FAILURE);
    }

    readCSV(&queues, argv[1], &length);

    for(int j=0; j<length; j++){
        printf("%s\n%s\n", queues[j]->certPath, queues[j]->URL);
    }

    freeCSV(&queues, &length);

}

void readCSV(Pair*** queues, char* CSVpath, int* length){

    FILE *fp = NULL;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    fp = fopen(CSVpath, "r");
    if (fp == NULL){
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    while ((nread = getline(&line, &len, fp)) > 0) {

        /* create a pair of cert in queues */

        Pair* queue = (Pair*) malloc(sizeof(Pair));

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
        *queues = (Pair**) realloc(*queues, (*length+1)*sizeof(Pair*));
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


void freeCSV(Pair*** queues, int* length){
    for(int i=0; i<*length; i++){
        free((*queues)[i]->certPath);
        free((*queues)[i]->URL);
        free((*queues)[i]);
    }
    free(*queues);
}