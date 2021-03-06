#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <mpi.h>


/* BruteForceMPI.c    November 2018
 * Program using distributed memory parallelization (MPI)to generate a series of potential keys
 * using nested if statements, of length 6 (padded to 16B) from an alphabet of length n.
 * Keys are then successively tried using AES-128-CBC encryption with known IV and plaintext to produce ciphertext
 * which is tested for match against original ciphertext.
 */


/* initialise global variables*/
int len;
int ciphertext_len;
unsigned char ciphertext[64];


/* ***************************************************************
 * error handling function
 *****************************************************************/
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


/* ********************************************************************************************
 *  ENCRYPTION FUNCTION
 *  Takes plaintext and encrypts it using a 128b IV and a 128b key
 *  Returns ciphertext.
 *  Code based on: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
 **********************************************************************************************/

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the encryption operation.*/
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

/* ***********************************************************************
 *  Main function
 *************************************************************************/

int main(int argc, char *argv[])
{

  /*Initialize MPI environment */
    int id, procs;
    MPI_Init(&argc, &argv);
    MPI_Comm_rank (MPI_COMM_WORLD, &id);
    MPI_Comm_size (MPI_COMM_WORLD, &procs);

    if (id ==0)
    {
        printf("\n********************************************************\n");
        printf("*************Cipher Cracker  MPI version****************\n");
        printf("********************************************************\n");
    }

    /* initialize variables */
    unsigned long count = 0;
    int i,j,k,l,m,n,q, posn;
    char key[18];
    double start1, start2, end1;

    /* Hardcoding the IV, Ciphertext and Plaintext.
     * Ciphertext previously obtained by encrypting the plaintext using command line AES cbc encryption.
     * Program could be modified to be taken as user inputs.
     */
    unsigned char *iv = (unsigned char *)"\xaa\xbb\xcc\xdd\xee\xff\x00\x99\x88\x77\x66\x55\x44\x33\x22\x11";
    unsigned char *cipherorig = "\x5f\x44\x29\xbb\xed\x0c\xbb\xa0\x46\x2f\x1e\xfa\x19\xbd\x7a\x2e\xea\x19\x3f\x50\x35\xb9\xba\x91\xa2\x7e\x85\x37\xb6\x5f\x95\x35";
    unsigned char *plaintext = (unsigned char *)"This is a secret message.";
   
    /*Iniitalise alphabet arrays where user can input choice of position of the first char of the key.*/
    char alphabetMax[] = "abcdefghijklmnoqrstuvwxyz0123456789p";
    char alphabet8[] = "abcdefgphijklmnoqrstuvwxyz0123456789";
    char alphabet4[] = "abcpdefghijklmnoqrstuvwxyz0123456789";
    char alphabet3[] = "abpcdefghijklmnoqrstuvwxyz0123456789";
    char alphabet2[] = "apbcdefghijklmnoqrstuvwxyz0123456789";
    char alphabet1[] = "pabcdefghijklmnoqrstuvwxyz0123456789";
    char alphabet0[] = "abcdefghijklmnopqrstuvwxyz0123456789"; // default order
    char alphabetF[] = "abcdefghijklmnoqrstuvwxyz0123456789A"; // key can't be found using this alphabet (no 'p')

    char alphabet[40];

    if(id ==0)  //only want once process to take the user input
    {
        printf("In the search alphabet, what is the position of the first char of the key?\n");
        printf("Please enter 1,2,3,4,8 or 36 (36 is last posn of alphabet order and will take max search time\n");
        printf("If position not known, enter 0 for standard alphabet order: a-z,0-9  or 99 for 'no success' search \n" );
        scanf("%d", &posn);
    }
    MPI_Bcast(&posn, 1, MPI_INT, 0, MPI_COMM_WORLD); // 'posn' is then broadcast to all processes

    start1 = MPI_Wtime();

    if (posn ==1)
    {
        strcpy(alphabet, alphabet1);
    }
    else if (posn ==2)
    {
        strcpy(alphabet, alphabet2);
    }
    else if (posn ==3)
    {
        strcpy(alphabet, alphabet3);
    }
    else if (posn ==4)
    {
        strcpy(alphabet, alphabet4);
    }
    else if (posn ==8)
    {
        strcpy(alphabet, alphabet8);
    }
    else if (posn ==36)
    {
        strcpy(alphabet, alphabetMax);
    }
    else if (posn ==0)
    {
        strcpy(alphabet, alphabet0);
    }
    else if (posn == 99)
    {
        strcpy(alphabet, alphabetF);
    }
    else
    {
        if (id ==0)
        {
            printf ("Not a valid input. Run program again\n");
        }
        return 1; //exit program
    }

    int s = strlen(alphabet); // can now initialise alphabet length

    if(id==0)
    {
        printf("\nalphabet: %s\n", alphabet);  // print chosen alphabet
        printf("length of alphabet: %d\n",s);
        printf("No. of processes is %d\n", procs);
        printf("timer started...\n\n");
    }

    start2 = MPI_Wtime();

    // divide outer loop between no. of processes
    for (i = id; i < s; i = i+procs)
    {
        for (j = 0; j< s; j++)
        {
            for (k = 0; k< s; k++)
            {
                for (l = 0; l< s; l++)
                {
                    for (m = 0; m< s; m++)
                    {
                        for (n = 0; n< s; n++)
                        {
                            key[0] = alphabet[i];   // assign elements to alphabet array
                            key[1] = alphabet[j];
                            key[2] = alphabet[k];
                            key[3] = alphabet[l];
                            key[4] = alphabet[m];
                            key[5] = alphabet[n];
                            for (q = 6; q < 16; q++) // add padding to key to make 16B in total
                            {
                                key[q] = '#';
                            }
                            key[16] = '\0';        // add null terminator for end of string
                            count++;

                           // if (id == 0 && count%25000000 == 0)  // print certain attempts for process 0 only
                            if (count%25000000 == 0) // print certain attempts for all processes
                            {
                                printf("Process %d  trying key  %s\n", id, key);
                            }

                            /* *************************************************************************************************************
                            * Use generated key in encryption function to produce new ciphertext, then check for match with orig ciphertext
                            ****************************************************************************************************************/
                            ciphertext_len = encrypt(plaintext, strlen ((char *)plaintext), key, iv, ciphertext);

                            /* Compare the original ciphertext with new ciphertext, exit if a match */
                            int result;
                            result = strncmp(cipherorig, ciphertext,32);
                            if (result == 0)
                            {
                                printf("Count %lu Cipherorig and Ciphertext match\n", count);
                                printf("***************************************************\n\n");
                                printf("Success!! The key is  %s\n\n", key);
                                printf("Key found by process %d, Total processes used = %d\n", id, procs);
                                printf("***************************************************\n");

                                end1 = MPI_Wtime();
                                printf( "\nMain prog elapsed time is %f\n", end1 - start1 );
                                printf("Parallel section elapsed time is %f\n\n", end1 - start2 );
                                printf("**************end of program*******************\n\n");

                                return(0);  // exit the for loops
                            }
                        }
                    }
                }
            }
        }
    }

    end1 = MPI_Wtime();
    if(id == 0)
    {
        printf("Sorry, no solutions found :(");
        printf( "\nMain prog elapsed time is %f\n", end1 - start1 );
        printf("Process 1's count is %lu ", count);
    }
    MPI_Finalize();

    return 0;
} // end of main
