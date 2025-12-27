/* Copyright 2016 Palmer Dabbelt <palmer@dabbelt.com> */

#ifndef AMF_H
#define AMF_H

/* libamf has one single public function: amf_lookup(config_string, path).
 * "config_string" is an AMF-formatted string, and "path" is the path to look
 * up in the AMF string.  The return value is a pointer into the original AMF
 * string that points to the start of the value that cooresponds to the given
 * path.  You can determine the end of this value by looking for a ';'
 * character.  Paths are seperated by a slash.  For example, given the
 * following AMF string:
 *   parentA {
 *     childA 0x1;
 *     childB 0x2;
 *   }
 *   parentB {
 *     childA 0x3;
 *     childB 0x4;
 *   }
 * amf_lookup(s, "parentA/childA") returns "0x1;\n "...
 * amf_lookup(s, "parentA/childB") returns "0x2;\n "...
 * amf_lookup(s, "parentB/childB") returns "0x3;\n "...
 * amf_lookup(s, "parentB/childB") returns "0x4;\n "...
 */
static __inline__
const char *amf_lookup(const char *amf_string, const char *path);

/* Returns the number of tiles implied in the given AMF-formatted string,
 * or -1 if unable to find. */
static __inline__ 
int amf_ntiles (const char *amf_string);

/* Everything below here is part of the AMF implementation.  For ease of use,
 * this is all stored in a single header file. */

/* When in debug mode, we need printf. */
#ifdef AMF_DEBUG
struct _IO_FILE;
extern struct _IO_FILE *stderr;
int fprintf(struct _IO_FILE *f, const char *format, ...);
#endif

/* A simple implementation of the C "isspace()" function.  This doesn't exist
 * in stand-alone environments, so I just went ahead and implemented it here
 * because it's simple. */
static __inline__
int _amf__isspace(int c)
{
  if (c == ' ')  return 1;
  if (c == '\t') return 1;
  if (c == '\n') return 1;
  if (c == '\r') return 1;
  return 0;
}

/* Searches for the next "/" character in the given string, returning a pointer
 * to the character after that. */
static __inline__
const char *_amf__advance_until_slash(const char *path)
{
  while ((*path != '\0') && (*path != '/'))
    path++;
  if (*path == '/')
    path++;

  return path;
}

/* Moves past the header of an AMF block (the part that looks like "parent {").
 * This returns a pointer to the character after the opening "{". */
static __inline__
const char *_amf__advance_until_entered(const char *config_string)
{
  while ((*config_string != '\0') && (*config_string != '{'))
    config_string++;

  if (*config_string == '{')
    config_string++;

  return config_string;
}

/* Moves past a whole AMF block, returning a pointer to the character after the
 * closing "}".  If config_string points to a leaf (so something like "childA
 * 1; childB 2;"), this will advance just past the first leaf node (so it'll
 * return "childB 2;"). */
static __inline__
const char *_amf__advance_until_over(const char *config_string)
{
  int open;

  while ((*config_string != '\0') && (*config_string != '{') && (*config_string != ';'))
    config_string++;

  if (*config_string == ';') {
    config_string++;
    return config_string;
  }

  if (*config_string == '{')
    config_string++;

  open = 1;
  while ((*config_string != '\0') && (open > 0)) {
    if (*config_string == '{') open++;
    if (*config_string == '}') open--;
    config_string++;
  }
  if (*config_string == ';')
    config_string++;

  return config_string;
}

/* Like strcmp, but stops at a '/' character in the "path" string.  This is
 * used to compare a path like "parentA/childB" to an AMF string like "parentA
 * { childA: 1; }", matching the "parentA" section on the first call. */
static __inline__
int _amf__compare_until_slash(const char *config_string, const char *path)
{
  while (_amf__isspace(*config_string)) config_string++;
  while ((*path != '\0') && (*path != '/') && (*config_string != '\0')) {
    if (*path != *config_string)
      return 0;
    path++;
    config_string++;
  }

  if (!_amf__isspace(*config_string))
    return 0;

  return 1;
}

/* The public library function.  See above. */
static __inline__
const char *amf_lookup(const char *config_string, const char *path)
{
  while (*path != '\0' && *config_string != '\0') {
#ifdef AMF_DEBUG
    fprintf(stderr, "Looking for '%s' in '%s'\n", path, config_string);
#endif
    if (_amf__compare_until_slash(config_string, path)) {
      path = _amf__advance_until_slash(path);
      if (*path != '\0')
        config_string = _amf__advance_until_entered(config_string);
    } else {
      config_string = _amf__advance_until_over(config_string);
    }
  }

  /* Remove any whitespace from the config string, then strip off the key. */
  while (*config_string != '\0' &&  _amf__isspace(*config_string)) config_string++;
  while (*config_string != '\0' && !_amf__isspace(*config_string)) config_string++;
  while (*config_string != '\0' &&  _amf__isspace(*config_string)) config_string++;

  return config_string;
}

/* Returns the number of tiles implied in the given AMF-formatted string,
 * or -1 if unable to find. */
static __inline__
int amf_ntiles(const char *config_string)
{
  int ntiles;

  config_string = amf_lookup(config_string, "core");
  if (*config_string == '\0')
    return -1;

  config_string = _amf__advance_until_entered(config_string);
  if (*config_string == '\0')
    return -1;

  ntiles = 0;
  while (*config_string != '\0') {
    config_string = _amf__advance_until_over(config_string);
    while (*config_string != '\0' && _amf__isspace(*config_string))
      config_string++;

#ifdef AMF_DEBUG
    fprintf(stderr, "Looking for tile '%d', in '%s'\n", ntiles, config_string);
#endif
    if (*config_string == '}') {
      return ++ntiles;
    } else if (*config_string != '\0') {
      ntiles++;
    } else {
      return ntiles;
    }
  }

  return ntiles;
}


#endif
