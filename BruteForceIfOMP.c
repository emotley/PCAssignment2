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


/* BruteForceOMP.c    November 2018
*  Program to generate a series of potential keys of up to length k from an alphabet of length n,
*  then padded to a total of 16 Bytes, where it can then be used to Brute Force a ciphertext using
*  AES-128-CBC encryption, where the IV is known. */


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



/* ***********************************************************************
 *  Main function
 *************************************************************************/

int main()
{
    int i,j,k,l,m,n,q, thread_id, nthreads,nt, count = 0;
    char key[18];
    float time_used1 = 0, time_used2 = 0;
    int chunk = CHUNKSIZE;
    double end;
	
	clock_t start1 = clock(); // note clock reading
        printf("timer1 started...\n");



    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"\xaa\xbb\xcc\xdd\xee\xff\x00\x99\x88\x77\x66\x55\x44\x33\x22\x11";
    /* Original CipherText */
    unsigned char *cipherorig = "\x5f\x44\x29\xbb\xed\x0c\xbb\xa0\x46\x2f\x1e\xfa\x19\xbd\x7a\x2e\xea\x19\x3f\x50\x35\xb9\xba\x91\xa2\x7e\x85\x37\xb6\x5f\x95\x35";
    /* Message to be encrypted */
    unsigned char *plaintext = (unsigned char *)"This is a secret message.";
    
    char alphabet8[] = "abcdefgphijklmnoqrstuvwxyz0123456789";
    char alphabet4[] = "abcpdefghijklmnoqrstuvwxyz0123456789";
    char alphabet3[] = "abpcdefghijklmnoqrstuvwxyz0123456789";
    char alphabet2[] = "apbcdefghijklmnoqrstuvwxyz0123456789";
    char alphabet1[] = "pabcdefghijklmnoqrstuvwxyz0123456789";
    char alphabet0[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    char alphabet[40];
    int posn;
 

    printf("\n*******************************************************************************\n");
    printf("******************************Cipher Key Cracker*******************************\n");
    printf("*******************************************************************************\n");

    // Take user input for choice of position of the first char of the key and no. of threads
	
	printf("how many threads?\n");
	scanf("%d", &nt);
    printf("In the search alphabet, what is the position of the first char of the key?\n");
    printf("Please enter 1,2,3,4 or 8\n");
    printf("If position not known, enter 0 for standard alphabet order: a-z,0-9 \n" );
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
    else if (posn ==0)
    {
        strcpy(alphabet, alphabet0);
    }

    else
    {
        printf ("Not a valid input. Run program again\n");
        return 1; //exit program
    }
	
	
    int s = strlen(alphabet);
    printf("\nalphabet: %s\tLength is %d\n", alphabet, s);  
    
	clock_t start2 = clock(); // note clock reading
        printf("timer2 started...\n");

     #pragma omp parallel shared(alphabet,count,chunk,start2) private(i,j,k,l,m,n,key,ciphertext,thread_id, end) num_threads(nt)
    {
	  omp_set_dynamic(0);
	  omp_set_num_threads(2);   
	  thread_id = omp_get_thread_num();
       
	if (thread_id ==0)  // get info from master thread
        {
          nthreads = omp_get_num_threads();
          printf("Total threads - %d\n", nthreads);
        }

	    double start = omp_get_wtime( );  
      
   
	    
	    
#pragma omp for schedule(dynamic, chunk) nowait
        
   for (i = 0; i< s; ++i)
    {
        for (j = 0; j< s; ++j)
        {
            for (k = 0; k< s;++k)
            {
                for (l = 0; l< s;++l)
                {
                    for (m = 0; m< s;++m)
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
 				
				double end = omp_get_wtime( );    
    				printf("OMP start time = %.11g\nOMP end time= %.11g\nOMP exe time = %.5g\n", start, end, end - start);  
				
				
				end = clock(); // stop the timer
				time_used2 = (double)(end - start2)/ CLOCKS_PER_SEC;
    				printf("Execution time = %.4lf seconds\n\n", time_used2);
				    
				time_used1 = (double)(end - start1)/ CLOCKS_PER_SEC;
    				printf("Execution time = %.4lf seconds\n\n", time_used1);    
				 
				    
				    
				    
				    
				exit(0);
                             }
		 }
		}
		 }
		
                }
    		    
		}
   
		}

		}

  //  clock_t end2 = clock(); // stop the timer

  //  float time_used2 = (float)(end2 - start)/ CLOCKS_PER_SEC;
    //printf("Execution time = %.4lf seconds\n\n", time_used2);

  //  printf("No key found\n");

    return 0;
}
