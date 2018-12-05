# PCAssignment2
Parallel Computing Assignment 2 - Brute Force attacks

BruteForceIf.c  serial version of bruteforce attack using nested if statements

BruteForceIf2.c serial version of bruteforce attack using recursive function call

BruteForceIfOMP.c  OMP parallelization using outer loop of nested if statements

BruteForceIfMPI.c  MPI parallalization using outer loop of nested if statements


makefiles are included for compilation of the programs. 
Please execute the makefiles and run as follows:

1. Serial program using nested if statements:

make -f Serial
./BruteSerial


2. Serial program using recursive function call:

make -f Serial2
./BruteSerial2

3. OpenMP parallelized version of nested if serial version:

make -f OMP
./BruteSerial

4. MPI parallelized version of nested if serial version:

make -f MPI
mpirun -quiet -np x BruteMPI

  (x is no of processors, please enter appropriate values)
  


