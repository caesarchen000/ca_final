// See LICENSE for license details.

//**************************************************************************
// Vector SAXPY benchmark for Hwacha v4
//--------------------------------------------------------------------------
//
#include <stdbool.h>
#include <stdlib.h>
#include "util.h"
#include "mt-csaxpy.h"

//--------------------------------------------------------------------------
// Input/Reference Data

#include "dataset1.h"


//--------------------------------------------------------------------------
// Main

int thread_entry(int cid, int nc)
{
  if (cid == 0) {
    // Print the input array
    printFloatArray("inputX", DATA_SIZE, input_data_X);
    printFloatArray("inputY", DATA_SIZE, input_data_Y);
    printFloatArray("verify", DATA_SIZE, verify_data);
  }
  barrier(nc);

  // Do SAXPY
  stats(mt_csaxpy(cid, nc, DATA_SIZE, input_data_a, input_data_X, input_data_Y, cond_data); barrier(nc), DATA_SIZE);

  if (cid == 0) {
    // Print out the result
    printFloatArray("results", DATA_SIZE, input_data_Y);

    // Check the results
    int res = verifyFloat(DATA_SIZE, input_data_Y, verify_data);
    if (res) exit(res);
  }
  barrier(nc);
  exit(0);
}
