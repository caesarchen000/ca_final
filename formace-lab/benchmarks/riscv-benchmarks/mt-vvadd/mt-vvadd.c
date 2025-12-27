// See LICENSE for license details.

//**************************************************************************
// Vector-vector add benchmark
//--------------------------------------------------------------------------
// Author  : Andrew Waterman
// TA      : Christopher Celio
// Student : 
//
// This benchmark adds two vectors and writes the results to a
// third vector. The input data (and reference data) should be
// generated using the vvadd_gendata.pl perl script and dumped
// to a file named dataset.h 

// to print out arrays, etc.
//#define DEBUG

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

extern void __attribute__((noinline)) vvadd(int coreid, int ncores, size_t n, const data_t* x, const data_t* y, data_t* z);


//--------------------------------------------------------------------------
// Main
//
// all threads start executing thread_entry(). Use their "coreid" to
// differentiate between threads (each thread is running on a separate core).
  
void thread_entry(int cid, int nc)
{
   // static allocates data in the binary, which is visible to both threads
   static data_t results_data[DATA_SIZE];
  
   printf("IN CORE %d/%d\n", cid, nc);

   // First do out-of-place vvadd
   barrier(nc);
   stats(vvadd(cid, nc, DATA_SIZE, input_data_X, input_data_Y, results_data); barrier(nc), DATA_SIZE);
 
   if(cid == 0) {
//#ifdef DEBUG
     printFloatArray("out-of-place results: ", DATA_SIZE, results_data);
     printFloatArray("out-of-place verify : ", DATA_SIZE, verify_data_Z);
//#endif
     int res = verifyFloat(DATA_SIZE, results_data, verify_data_Z);
     if(res) exit(res);
   }

   // Second do in-place vvadd
   // Copying input
   size_t i;
   if(cid == 0) {
     for (i = 0; i < DATA_SIZE; i++)
           results_data[i] = input_data_X[i];
   }
   barrier(nc);
   stats(vvadd(cid, nc, DATA_SIZE, results_data, input_data_Y, results_data); barrier(nc), DATA_SIZE);
 
   if(cid == 0) {
//#ifdef DEBUG
     printFloatArray("in-place results: ", DATA_SIZE, results_data);
     printFloatArray("in-place verify : ", DATA_SIZE, verify_data_Z);
//#endif
     int res = verifyFloat(DATA_SIZE, results_data, verify_data_Z);
     if(res) exit(res);
   }
   
   barrier(nc);
   exit(0);
}
