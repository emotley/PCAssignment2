#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <mpi.h.>
//#define MAXCHAR 1000


/* BruteforceRecMPI.c    November 2018
*  Program to generate a series of potential keys using a recursive function, of up to length k 
*  from an alphabet of length n, then padded to a total of 16 Bytes, where it can then be used 
*   to crack a ciphertext by Brute Force using  AES-128-CBC encryption, where the IV is known. */


/* initialise global variables*/
int len;
int ciphertext_len;
unsigned char ciphertext[64];



void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

/* ***************************************************************
 *  ENCRYPTION FUNCTION
 *  Takes plaintext and encrypts it using a 128b IV and a 128b key
 *  Returns ciphertext
 *****************************************************************/

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


/* ************************************************************************************************
*   genKeys function
*   Generates all the possible permutations (keys) up to length k from a given alphabet of size n
*   then uses each generated key in turn in the encrypt function. Each new ciphertext is then tested
*   against the original for a match. Function exits when a match is found.
*****************************************************************************************************/


static unsigned long count=0;

int genKeys(char alphabet[], char prefix[], int n, int k)

{
    int i,j,len=strlen(prefix);
    char newprefix[len+2];
    char key [20]; 	// keys is only 16B, but set larger to accommodate null terminating character


    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"\xaa\xbb\xcc\xdd\xee\xff\x00\x99\x88\x77\x66\x55\x44\x33\x22\x11";
    /* Original CipherText */
    unsigned char *cipherorig = "\x5f\x44\x29\xbb\xed\x0c\xbb\xa0\x46\x2f\x1e\xfa\x19\xbd\x7a\x2e\xea\x19\x3f\x50\x35\xb9\xba\x91\xa2\x7e\x85\x37\xb6\x5f\x95\x35";
    /* Message to be encrypted */
    unsigned char *plaintext = (unsigned char *)"This is a secret message.";


    if (k==0)
    {
        return 1; 	// returns unsuccessful if key is of length 0.
    }

    for(i=0; i<n; i++)  // loop through alphabet array (ideal place for openMPI parallisation)
    {
        /*Concatenation of currentPrefix + alphabet[i] = newPrefix*/
        for(j=0; j<len; j++)
        {
            newprefix[j] = prefix[j];
        }
        newprefix[len] = alphabet[i];
        newprefix[len+1] = '\0'; // add null terminator

        strcpy(key, newprefix); // copy to new string, so that newprefix is unaltered for next iteration

        /* add padding to generated keys to make 16B in total*/
        int q;
        for (q =strlen(key); q<16; q++)
        {
            key[q] = '#';
        }
        key[q] = '\0'; 		// add null terminator for printing correctly
        count++;
        //  printf("%lu  Trying key   %s\n", count, key);

	if (count%10000000 == 0)
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
            // printf("The original plaintext is  \"%s\"\n", decryptedtext);
            printf("***************************************************\n\n");
            printf("Success!! The key is  %s\n\n", key);
            printf("***************************************************\n");
            return(0);
        }

       else
        {
           if (genKeys(alphabet, newprefix, n, k-1) == 0)  // continue with recursion if no match
            {
                return 0;
            }
        }
    }           //end of for loop
    return 1;  	// needs to be 1 to go to next letter of alphabet
}  		        // end of function


/* ***********************************************************************
 *  Main function
 *************************************************************************/


int main(int argc, char *argv[])
{
    int k=6;
    char alphabet[] = "abcpdefghijkjlmnoqrstuvwxyz0123456789"; // if 1st char of key is known, can posn this at beg of alphabet.
    //char alphabet4[] = "abcpdefghijklmnoqrstuvwxyz0123456789";
    //char alphabet3[] = "abpcdefghijklmnoqrstuvwxyz0123456789";
    //char alphabet2[] = "apbcdefghijklmnoqrstuvwxyz0123456789";
    //char alphabet1[] = "pabcdefghijklmnoqrstuvwxyz0123456789";
    //char alphabet0[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    //char alphabet[40];
    //int posn;
    int n = strlen(alphabet);
	int solutions =0;
	
    int id, procs;
    MPI_Init(&argc, &argv);
    MPI_Comm_rank (MPI_COMM_WORLD, &id);
    MPI_Comm_size (MPI_COMM_WORLD, &procs);
	
	if (id==0)
	{
    printf("\n********************************************************\n");
    printf("******************Cipher Key Cracker********************\n");
    printf("********************************************************\n");
    printf("\nalphabet: %s", alphabet);  // print chosen alphabet	
    printf("\ntimer started...\n\n");	
		
	}


   clock_t start = clock(); // start the timer
    
   for (v= id; v< 2176782336; v = v+ procs)
	
	//lutions += genKeys(id,v);
    genKeys(alphabet,"",n,k); // calls the generate keys function and tries to match input string
    // note that initial prefix is an empty string ""

    clock_t end = clock(); // stop the timer

    float time_used = (float)(end - start)/ CLOCKS_PER_SEC;
    printf("Execution time = %.4lf seconds\n\n", time_used);
	MPI_Finalize();

    return 0;
}
