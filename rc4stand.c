#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/rc4.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define BUFFER_SIZE 4000000

//global variables
int argv_cnt = 1;
char *input_file_name; //hold input name
char *output_file_name; //hold output name
bool salt_status= true; //by default salt option selected
bool encrypt; //hold to encrypt/decrypt
char *eKey; // hold key 
int eKeyLength; //keylength



void print_help(char **argv)
{

    printf("usage: %s -e|-d -k key -in input -out output\n", argv[0]);
    exit(1);
}

void handle_option(int argc, char **argv)
{
    switch(argv[argv_cnt][0]) {
    case '-':
        if (strcmp(argv[argv_cnt]+1,"e") == 0 ) {
            encrypt=true;
        }
        else if (strcmp(argv[argv_cnt]+1,"d") == 0 ) {

            encrypt=false;
        }
        else if (strcmp(argv[argv_cnt]+1,"k") == 0 ) {
            argv_cnt++;
            if (argv_cnt == argc)
                print_help(argv);
            eKey=argv[argv_cnt];
            eKeyLength=strlen(eKey);
        }
        else if (strcmp(argv[argv_cnt]+1,"in") == 0 ) {
            argv_cnt++;
            if ( argv_cnt == argc ) {
                printf("no input is specified\n");
                print_help(argv);
            }
            input_file_name=argv[argv_cnt];
        }
        else if (strcmp(argv[argv_cnt]+1,"out") == 0 ) {
            argv_cnt++;
            if ( argv_cnt == argc ) {
                printf("no output is specified\n");
                print_help(argv);
            }
            output_file_name=argv[argv_cnt];
        }
        else if (strcmp(argv[argv_cnt]+1,"salt") == 0 )  {
            salt_status=true;
        }
        else if (strcmp(argv[argv_cnt]+1,"nosalt") == 0 )  {
            salt_status=false;
        }
        else if (strcmp(argv[argv_cnt]+1,"help") == 0 ) {
            print_help(argv);
        }
        else {
            printf("%s: unknown option\n", argv[argv_cnt]);
            print_help(argv);
        }

        argv_cnt++;
        break;
    default:
        printf("%s: unknown option\n", argv[argv_cnt]);
        print_help(argv);
        break;
    }
    return;

}


int main(int argc, char **argv)
{

    if (argc == 1 )
        print_help(argv);

    while( argv_cnt < argc )
        handle_option(argc, argv);


    //test args passed correctly
    /*printf("ARGS\n");
    printf("-------------------------------------\n");
    printf("ENC STATUS: %d\n" , encrypt);
    printf("Salt STATUS: %d\n" , salt_status);
    printf("Key : %s\n" , eKey);
    printf("Key length: %d\n" , eKeyLength);
    printf("Input File : %s\n" , input_file_name);
    printf("Output File : %s\n" , output_file_name);
    printf("-------------------------------------\n");
    */

    //file read stuff
    int input_file;
    int output_file;
    ssize_t numRead;
    char input_b[BUFFER_SIZE];
    char output_b[BUFFER_SIZE];
    char s_check[8];


    //rc4 stuff
    RC4_KEY key;
    const EVP_CIPHER *cipher;
    const EVP_MD *dgst = NULL;
    unsigned char rKey[EVP_MAX_KEY_LENGTH];
    unsigned char salt[8];
    char full_salt[16];
    bool salt_rc4;  //checks to see the status of what encrypt of key to generate


    cipher = EVP_get_cipherbyname("rc4");
    dgst=EVP_get_digestbyname("sha256");
    if(!cipher){fprintf(stderr, "no such cipher\n"); return 1;}
    if(!dgst){fprintf(stderr, "no such digest\n"); return 1;}


    //input file
    input_file = open(input_file_name, O_RDONLY );
    if(input_file == -1) {
        perror("Error opening input file");
        return 1;
    }


    //output file
    output_file = open(output_file_name, O_CREAT | O_WRONLY, 0644);
    if(output_file == -1) {
        perror("Error with output file");
        return 1;
    }


    //determine input file size
    int offset = lseek(input_file, 0, SEEK_END);
    lseek(input_file, 0, SEEK_SET);
    //printf("*Input File size is: %d bytes\n", offset);

    // determine what encryption of key to generate water with salt or no salt
    // also checks if encryption or decryption option selected
    // for decryption checks if file is salted
    if (encrypt && salt_status)// if encrypting with salt
    {
        //printf("SALTING\n");
        RAND_bytes(salt, 8); //generate 8 random bytes
        sprintf(full_salt, "Salted__%s", salt); //append 8 rand bytes generated to Salted__ to create the full_salt string
        //printf("Salt is : %s\n", full_salt);
        write(output_file, &full_salt, 16); //write full_salt to beginning of output file
        salt_rc4=true; //salt encryption/decryption
    }
    else if (!encrypt || !encrypt && salt_status) { // if decrypt option chosen with salt
        //printf("CHECK SALTING\n");
        lseek(input_file, 8, 16);
        read(input_file, s_check, 8);
        //printf("%s\n", s_check);
        if(strcmp(s_check, "Salted__") == 0) { //extra check to see if file contains salt
            lseek(input_file, 8, SEEK_SET); //read/write file offset to read saltString
            read(input_file, salt, 8); //read salt chars into salt
            //printf("FILE CONTAINS SALT \n SALT VALUE IS: %s\n", salt);
            salt_rc4=true; //salt encryption/decryption
        }
        else {
            //printf("NO SALT DECODE\n");
            salt_rc4=false;//no salt decryption
        }
    }
    else {
        salt_rc4=false; //no salt encryption
    }

    //generate key depending on if there was salt or not
    if(salt_rc4) {
        //printf("SALT ENCODING/DECODING\n");
        if(!EVP_BytesToKey(cipher, dgst, (const unsigned char*)salt, (const unsigned char*)eKey, eKeyLength, 1, rKey, NULL)) //salt key
        {
            fprintf(stderr, "EVP_BytesToKey failed\n");
            return 1;
        }
    }
    else if(!salt_rc4) {
        //printf("NO SALT ENCODING/DECODING\n");
        if (!EVP_BytesToKey(cipher, dgst, NULL, (const unsigned char*)eKey, eKeyLength, 1, rKey, NULL)) //nosalt key
        {
            fprintf(stderr, "EVP_BytesToKey failed\n"); //if BytesToKey fails.
            return 1;
        }
    }
    else {
        printf("Unable to identify if option for salt or no salt was selected! Not able to generate RC4 Key!");
        return 1;
    }
    RC4_set_key(&key, 16, rKey); //set key
   

    //get position of input file
    if(salt_rc4 &&  !encrypt) {
        lseek(input_file, 16, SEEK_SET); //start input file after first 16 bytes
    }
    else {
        lseek(input_file, 0, SEEK_SET); //default input file from beginning of file
    }


    //write to file
    while ((numRead = read(input_file, input_b, BUFFER_SIZE)) > 0) {
        RC4(&key, numRead, input_b, output_b);
        //printf("%s", output_b);
        if (write(output_file, output_b, numRead) != numRead)
            printf("write() returned error or partial write occurred");
    }

    //output file size
    offset = lseek(output_file, 0, SEEK_END);
    lseek(output_file, 0, SEEK_SET);
    //printf("*Output File size is: %d bytes\n", offset);


    if (numRead == -1){
         perror("Error with reading file");
        return 1;
    }
    if (close(input_file) == -1){
         perror("Error closing input file");
        return 1;
    }
    if (close(output_file) == -1){
         perror("Error closing output file");
        return 1;
    }
    return(0);

}



