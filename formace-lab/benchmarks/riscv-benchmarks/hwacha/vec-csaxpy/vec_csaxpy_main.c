// See LICENSE for license details.

//**************************************************************************
// Vector SAXPY benchmark for Hwacha v4
//--------------------------------------------------------------------------
//
#include <stdbool.h>
#include "util.h"
#include "vec_csaxpy.h"

//--------------------------------------------------------------------------
// Input/Reference Data

#include "dataset1.h"


//--------------------------------------------------------------------------
// Main

int main( int argc, char* argv[] )
{
  // Print the input array
  printFloatArray("inputX", DATA_SIZE, input_data_X);
  printFloatArray("inputY", DATA_SIZE, input_data_Y);
  printFloatArray("verify", DATA_SIZE, verify_data);

  // Do the csaxpy
  setStats(1);
  vec_csaxpy_asm(DATA_SIZE, input_data_a, input_data_X, input_data_Y, cond_data);
  setStats(0);

  // Print out the result
  printFloatArray("results", DATA_SIZE, input_data_Y);

  // Check the results
  return verifyFloat(DATA_SIZE, input_data_Y, verify_data);
}
