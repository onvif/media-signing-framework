#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char *argv[])
{
  char *filename_i = argv[1];
  char *filename_o = argv[2];
  FILE *fi = fopen(filename_i, "rb");
  FILE *fo = fopen(filename_o, "wb");

  // obtain file size:
  fseek(fi, 0, SEEK_END);
  long lSize = ftell(fi);
  rewind(fi);
  printf("%s is %ld Bytes\n", filename_i, lSize);

  // allocate memory to contain the whole file:
  char *buffer = (char *)malloc(sizeof(char) * lSize);
  if (buffer == NULL) {
    fputs("Memory error", stderr);
    exit(2);
  }

  // copy the file into the buffer:
  size_t result = fread(buffer, 1, lSize, fi);
  if (result != lSize) {
    printf("Read %zu bytes\n", result);
  }
  fclose(fi);

  // modify one byte in the middle
  // buffer[lSize / 2] ^= 0xff;
  if (buffer[lSize / 2] == 0xff)
    buffer[lSize / 2] = 0x05;
  else
    buffer[lSize / 2] = 0xff;

  // write to file
  printf("writing modified buffer to %s\n", filename_o);
  result = fwrite(buffer, sizeof(char), lSize, fo);
  if (result != lSize) {
    printf("Wrote %zu bytes\n", result);
  }
  fclose(fo);
}
