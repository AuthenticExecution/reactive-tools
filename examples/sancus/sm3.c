#include <sancus/reactive.h>

#include <stdio.h>

SM_INPUT(sm3, input, data, len)
{
  puts("SM3 input!");

  unsigned int val = *(unsigned int*) data;

  if(val == 33) {
    puts("SM3 input Correct!");
  }
  else {
    puts("SM3 input Wrong");
  }
}

SM_INPUT(sm3, input2, data, len)
{
  puts("SM3 input2!");

  unsigned int val = *(unsigned int*) data;

  if(val == 33) {
    puts("SM3 input2 Correct!");
  }
  else {
    puts("SM3 input2 Wrong");
  }
}

SM_ENTRY(sm3) void init(uint8_t* input_data, size_t len)

{
    (void) input_data;
    (void) len;
     puts("hello from sm3");
}