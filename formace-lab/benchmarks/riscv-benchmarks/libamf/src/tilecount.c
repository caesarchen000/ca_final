/* Copyright 2016 Palmer Dabbelt <palmer@dabbelt.com> 
 * Modifications by Eric Love <io@ericlove.me> from original lookup.c
 */

#include "amf.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

int main()
{
  char *config_string;
  size_t config_string_size;
  size_t config_string_used;
  int ntiles;

  config_string_size = 1024;
  config_string_used = 0;
  config_string = malloc(config_string_size);
  while (!feof(stdin)) {
    ssize_t readed;

    readed = fread(&config_string[config_string_used],
                   1,
                   config_string_size - config_string_used - 1,
                   stdin);

    if (readed < 0)
      continue;

    config_string_used += readed;
    if (config_string_used > config_string_size / 2) {
      char *new_config_string;
      config_string_size *= 2;
      new_config_string = realloc(config_string, config_string_size);
      memcpy(new_config_string, config_string, config_string_used);
      config_string = new_config_string;
    }
  }

  config_string[config_string_used] = '\0';

  ntiles = amf_ntiles(config_string);
  if (ntiles < 0)
    return 1;

  printf("%d\n", ntiles);

  return 0;
}
