#include <stdio.h>
#include <stdlib.h>
#include <smack.h>
#include <smack-contracts.h>

// @skip
// @expect error

int g[10];

int main(void) {
  ensures(g[0] == 1);
  return 0;
}