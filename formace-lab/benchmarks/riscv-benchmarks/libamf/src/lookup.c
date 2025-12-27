/* Copyright 2016 Palmer Dabbelt <palmer@dabbelt.com> */

#include "amf.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

int main(int argc, char **argv)
{
  char *config_string;
  size_t config_string_size;
  size_t config_string_used;
  const char *found;
  const char *end;

  if ((argc != 2) || (strcmp(argv[1], "--help") == 0)) {
    printf("amf-lookup <path>: Searches for a path in a AMF-formatted stdin\n");
    exit(2);
  }

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

  found = amf_lookup(config_string, argv[1]);
  if (found == NULL)
    return 1;

  end = strchr(found, ';');
  if (end == NULL)
    return 1;

  printf("%.*s\n", (int)(end - found), found);

  return 0;
}
