#!/usr/bin/python

DIM = 128

preamble = """
#ifndef DATASET_H
#define DATASET_H

"""

def emit_matrix(name, matrix):
  res = "static double " + name + "[] = {\n"
  a_dim = len(matrix)
  b_dim = len(matrix[0])
  for i in range(0, a_dim):
    res += "  { "
    for j in range(0, b_dim):
      res += str(matrix[i][j])
      if j < b_dim:
        res += ", "
    res += " }"
    if i < a_dim:
      res += ","
    res += "\n"
  res += "};\n"


test_mat = [
