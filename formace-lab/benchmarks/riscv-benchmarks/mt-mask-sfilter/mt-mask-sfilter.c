// See LICENSE for license details.

//**************************************************************************
// Masked Gaussian Blur benchmark
//--------------------------------------------------------------------------

// to print out arrays, etc.
#define DEBUG

//--------------------------------------------------------------------------
// Includes 

#include <string.h>
#include <stdlib.h>
#include <stdio.h>


//--------------------------------------------------------------------------
// Input/Reference Data

#include "dataset2.h"
 
  
//--------------------------------------------------------------------------
// Basic Utilities and Multi-thread Support

#include "util.h"
   
 
//--------------------------------------------------------------------------
// vvadd function

extern void __attribute__((noinline)) mask_sfilter(int coreid, int ncores, 
        const data_t* input, const data_t* output, short* mask, int input_sz,
        data_t m0, data_t m1, data_t m2, data_t m3, data_t m4, data_t m5, 
        data_t m6, data_t m7, data_t m8);

//--------------------------------------------------------------------------
// Main
//
// all threads start executing thread_entry(). Use their "coreid" to
// differentiate between threads (each thread is running on a separate core).
  
void thread_entry(int cid, int nc)
{
   // static allocates data in the binary, which is visible to both threads
   static data_t results_data[DATA_SIZE*DATA_SIZE];
   float m0 = 1.0;
   float m1 = 1.0;
   float m2 = 1.0;
   float m3 = 1.0;
   float m4 = 1.0;
   float m5 = 1.0;
   float m6 = 1.0;
   float m7 = 1.0;
   float m8 = 1.0;


   printf("IN CORE %d/%d\n", cid, nc);

   // First do out-of-place vvadd
   barrier(nc);
   stats(mask_sfilter(cid, nc, input, results_data, mask, DATA_SIZE, 
               m0, m1, m2, m3, m4, m5, m6, m7, m8); barrier(nc), DATA_SIZE);
 
   if(cid == 0) {
     printFloatArray("result: ", DATA_SIZE*DATA_SIZE, results_data);
     printFloatArray("verify: ", DATA_SIZE*DATA_SIZE, verify_data);
     // we assume that results_data edges are zeroed out to start with
     int res = verifyFloat(DATA_SIZE*DATA_SIZE, results_data, verify_data);
     if(res) exit(res);
   }

   barrier(nc);
   exit(0);
}
