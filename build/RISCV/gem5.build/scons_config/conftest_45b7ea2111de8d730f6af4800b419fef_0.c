

#include "execinfo.h"

int main(void) {
  backtrace_symbols_fd((void *)1, 0, 0);
return 0;
}
