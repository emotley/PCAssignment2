#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <omp.h>
#include <errno.h>
#define CHUNKSIZE 1


/* BruteForceIfOMP.c    November 2018
 * Program using shared memory parallelization (OpenMP)to generate a series of potential keys
 * using nested if statements, of length 6 (padded to 16B)from an alphabet of length n.
 * Keys are then successively tried using AES-128-CBC encryption with known IV and plaintext to 
 * produce ciphertext which is tested for match against original ciphertext.
 */


/* initialise global variables*/
int len;
int ciphertext_len;
unsigned char ciphertext[64];


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

/* *********************************************************************************************
 *  ENCRYPTION FUNCTION
 *  Takes plaintext and encrypts it using a 128b IV and a 128b key
 *  Returns ciphertext
 *  Code based on: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
 ***********************************************************************************************/

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

    /* Finalise the encryption. 
     *  Further ciphertext bytes may be written at this stage.
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

int main()
{
    printf("\n*******************************************************************************\n");
    printf("***************Cipher Key Cracker (Parallel Version using OMP)*****************\n");
    printf("*******************************************************************************\n");

    /* Initialise variables */
    int i,j,k,l,m,n,q, thread_id, nthreads,nt, count = 0;
    char key[18];
    //float time_used1 = 0, time_used2 = 0;
    int chunk = CHUNKSIZE;
    double end, start1, start2;

    /* Hardcoding the IV, Ciphertext and Plaintext.
     * Ciphertext previously obtained by encrypting the plaintext using command line AES cbc encryption.
     * Program could be modified to be taken as user inputs.
     */
    unsigned char *iv = (unsigned char *)"\xaa\xbb\xcc\xdd\xee\xff\x00\x99\x88\x77\x66\x55\x44\x33\x22\x11";
    unsigned char *cipherorig = "\x5f\x44\x29\xbb\xed\x0c\xbb\xa0\x46\x2f\x1e\xfa\x19\xbd\x7a\x2e\xea\x19\x3f\x50\x35\xb9\xba\x91\xa2\x7e\x85\x37\xb6\x5f\x95\x35";
    unsigned char *plaintext = (unsigned char *)"This is a secret message.";

    /*Iniitalise alphabet arrays where user can input choice of position of the first char of the key.
     * Also take user input for no. of threads
     */
    char alphabetMax[] = "abcdefghijklmnoqrstuvwxyz0123456789p";
    char alphabet8[] = "abcdefgphijklmnoqrstuvwxyz0123456789";
    char alphabet4[] = "abcpdefghijklmnoqrstuvwxyz0123456789";
    char alphabet3[] = "abpcdefghijklmnoqrstuvwxyz0123456789";
    char alphabet2[] = "apbcdefghijklmnoqrstuvwxyz0123456789";
    char alphabet1[] = "pabcdefghijklmnoqrstuvwxyz0123456789";
    char alphabet0[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    char alphabetF[] = "abcdefghijklmnoqrstuvwxyz0123456789A";
    char alphabet[40];
    int posn;

    printf("How many threads?\n");
    scanf("%d", &nt);
     printf("In the search alphabet, what is the position of the first char of the key?\n");
     printf("Please enter 1,2,3,4,8 or 36 (36 is last posn of alphabet order and will take max search time\n");
     printf("If position not known, enter 0 for standard alphabet order: a-z,0-9   or 99 for 'no success' search\n" );
     scanf("%d", &posn);

    start1 = omp_get_wtime( );
    printf("Timer1 started...\n");


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
    else if (posn ==99)
    {
        strcpy(alphabet, alphabetF);
    }
    else
    {
        printf ("Not a valid input. Run program again\n");
        return 1; //exit program
    }
    int s = strlen(alphabet);
    printf("\nalphabet: %s\tLength is %d\n", alphabet, s);

    #pragma omp parallel shared(alphabet,count,chunk,start2, start1) private(i,j,k,l,m,n,key,ciphertext,thread_id, end) num_threads(nt)
    {
        omp_set_dynamic(0);
        //omp_set_num_threads();
        thread_id = omp_get_thread_num();

        if (thread_id ==0)  // get info from master thread
        {
            nthreads = omp_get_num_threads();
            printf("Total threads = %d\n\n\n", nthreads);
        }

        start2 = omp_get_wtime( ); // time the parallel region
        if(thread_id == 0) // only want to print this once
        {
            printf("Timer2 started...\n");
        }

        #pragma omp for schedule(dynamic, chunk) nowait

        for (i = 0; i< s; ++i)
        {
            for (j = 0; j< s; ++j)
            {
                for (k = 0; k< s; ++k)
                {
                    for (l = 0; l< s; ++l)
                    {
                        for (m = 0; m< s; ++m)
                        {
                            for (n = 0; n< s; ++n)
                            {
                                key[0] = alphabet[i];
                                key[1] = alphabet[j];
                                key[2] = alphabet[k];
                                key[3] = alphabet[l];
                                key[4] = alphabet[m];
                                key[5] = alphabet[n];
                                for (q = 6; q < 16; q++)
                                {
                                    key[q] = '#';
                                }
                                key[16] = '\0';

                                count++;

                                if (count%25000000 == 0)
                                {
                                    printf("count %d  Thread %d is trying key  %s\n", count, thread_id, key);
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
                                    printf("\nCount %d Cipherorig and Ciphertext match\n", count);
                                    printf("Alphabet searched is '%s'  Length: %d\n", alphabet, s);
                                    printf("******************************************************************************\n\n");
                                    printf("           Success!! The key is  %s\n\n", key);
                                    printf("           Found by thread %d.   No of threads: %d\n", thread_id, nthreads);
                                    printf("******************************************************************************\n");

                                    end = omp_get_wtime( );
                                    printf("OMP start time = %.11g\tOMP end time= %.11g\nOMP exe time = %.5g\n\n", start2, end, end - start2);
                                    printf("Main prog start time = %.11g\tEnd time= %.11g\nProg exe time = %.5g\n\n", start1, end, end - start1);
                                    printf("**************************End of program**************************************\n\n");
                                    exit(0);  // can't use return statements in OMP, so have to exit
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    printf("Sorry, no key found :((  \n");
    double end2 = omp_get_wtime( );
    printf("Main prog start time = %.11g\nEnd time= %.11g\nProg exe time = %.5g\n\n", start1, end2, end2 - start1);
    printf("**************************End of program**************************************\n\n");

    return 0;
}
