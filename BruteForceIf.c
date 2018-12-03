#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>


/* BruteForceIf.c    November 2018
 * Serial Program to generate a series of potential keys using nested if statements,
 * of length 6 (padded to 16B)from an alphabet of length s.
 * Keys are then successively tried using AES-128-CBC encryption with known IV and plaintext
 * to produce ciphertext which is tested for match against original ciphertext. */


/* Global variables initialised first*/
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


/* *****************************************************************************************
 *  ENCRYPTION FUNCTION
 *  Takes plaintext and encrypts it using a 128b IV and a 128b key
 *  Returns ciphertext
 *  Code based on: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
 ********************************************************************************************/

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

int main()
{
    printf("\n********************************************************\n");
    printf("******************Cipher Cracker**********************\n");
    printf("********************************************************\n\n");

    // First clock started
    clock_t start1 = clock(); // start the timer
    printf("timer1 started...\n\n");

    /* Initialise most of the variables */
    unsigned long count = 0;
    int i,j,k,l,m,n,q,posn;
    char key[18];


    /* Hardcoding the IV, Ciphertext and Plaintext.
     * Ciphertext previously obtained by encrypting the plaintext using command line AES cbc encryption.
     * Program could be modified to be taken as user inputs.
     */
    unsigned char *iv = (unsigned char *)"\xaa\xbb\xcc\xdd\xee\xff\x00\x99\x88\x77\x66\x55\x44\x33\x22\x11";
    unsigned char *cipherorig = "\x5f\x44\x29\xbb\xed\x0c\xbb\xa0\x46\x2f\x1e\xfa\x19\xbd\x7a\x2e\xea\x19\x3f\x50\x35\xb9\xba\x91\xa2\x7e\x85\x37\xb6\x5f\x95\x35";
    unsigned char *plaintext = (unsigned char *)"This is a secret message.";

    /* Selection of alphabets for user selection for testing purposes. Position of first character of key changes in each. */
    char alphabet8[] = "abcdefgphijklmnoqrstuvwxyz0123456789";
    char alphabet4[] = "abcpdefghijklmnoqrstuvwxyz0123456789";
    char alphabet3[] = "abpcdefghijklmnoqrstuvwxyz0123456789";
    char alphabet2[] = "apbcdefghijklmnoqrstuvwxyz0123456789";
    char alphabet1[] = "pabcdefghijklmnoqrstuvwxyz0123456789";
    char alphabet0[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    char alphabetMax[] = "abcdefghijklmnoqrstuvwxyz0123456789p";
    char alphabetF[] = "abcdefghijklmnoqrstuvwxyz0123456789A";
    char alphabet[40];

    printf("In the search alphabet, what is the position of the first char of the key?\n");
    printf("Please enter 1,2,3,4,8 or 36 (36 is last posn of alphabet order and will take max search time\n");
    printf("If position not known, enter 0 for standard alphabet order: a-z0-9, or 99  for a 'no success' search \n" );
    scanf("%d", &posn);

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
    else if (posn ==99)
    {
        strcpy(alphabet, alphabetF);
    }
    else if (posn ==0)
    {
        strcpy(alphabet, alphabet0);
    }

    else
    {
        printf ("Not a valid input. Run program again\n");
        return 1; //exit program
    }

    int s = strlen(alphabet); // now alphabet is chosen can initialise s.
    printf("\nalphabet: %s", alphabet);  // print chosen alphabet
    printf("\nlength of alphabet: %d\n",s);

    clock_t start2 = clock(); // start the timer for execution time of main process
    printf("timer2 started...\n\n");

    /* Everything is now initialised, so the process of generating keys and encryption with those keys can begin */

    for (i = 0; i< s; i++)
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
                            key[0] = alphabet[i];
                            key[1] = alphabet[j];
                            key[2] = alphabet[k];
                            key[3] = alphabet[l];
                            key[4] = alphabet[m];
                            key[5] = alphabet[n];
                            for (q = 6; q < 16; q++) // add padding
                            {
                                key[q] = '#';
                            }
                            key[16] = '\0';  // add null terminator for end of string
                            count++;

                            if (count%25000000 == 0) // only print certain attempts
                            {
                                printf("count %lu  trying key  %s\n", count, key);
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
                                printf("***************************************************\n");

                                clock_t end = clock(); // stop the timer
                                float time_used1 = (float)(end - start1)/ CLOCKS_PER_SEC;
                                float time_used2 = (float)(end - start2)/ CLOCKS_PER_SEC;

                                printf("Execution time of full program = %.4lf seconds\n", time_used1);
                                printf("Execution time of logical process = %.4lf seconds\n\n", time_used2);
                                printf("*************End of Program************\n\n");

                                return(0);
                            }
                        }
                    }
                }
            }
        }
    }
    printf("Sorry, no matching key found.\n");
    clock_t end = clock(); // stop the timer
    float time_used = (float)(end - start1)/ CLOCKS_PER_SEC;
    printf("Execution time = %.4lf seconds. Total count = %lu\n\n", time_used, count);
    printf("*************End of Program************\n\n");
    return 0;
}
