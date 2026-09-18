#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char *argv[])
{
  if (argc != 3) {
    fprintf(stderr, "Usage: %s INPUT OUTPUT\n", argv[0]);
    return 1;
  }

  char *filename_i = argv[1];
  char *filename_o = argv[2];
  int exit_code = 1;
  unsigned char *buffer = NULL;
  FILE *fi = NULL;
  FILE *fo = NULL;

  fi = fopen(filename_i, "rb");
  if (!fi) {
    perror(filename_i);
    goto cleanup;
  }

  fo = fopen(filename_o, "wb");
  if (!fo) {
    perror(filename_o);
    goto cleanup;
  }

  if (fseek(fi, 0, SEEK_END) != 0) {
    perror(filename_i);
    goto cleanup;
  }
  long file_size_long = ftell(fi);
  if (file_size_long <= 0) {
    fprintf(stderr, "%s is empty or its size could not be determined\n", filename_i);
    goto cleanup;
  }
  rewind(fi);
  size_t file_size = (size_t)file_size_long;
  printf("%s is %zu Bytes\n", filename_i, file_size);

  buffer = malloc(file_size);
  if (buffer == NULL) {
    fputs("Memory error\n", stderr);
    goto cleanup;
  }

  size_t result = fread(buffer, 1, file_size, fi);
  if (result != file_size) {
    fprintf(stderr, "Read %zu of %zu bytes\n", result, file_size);
    goto cleanup;
  }

  if (buffer[file_size / 2] == 0xff)
    buffer[file_size / 2] = 0x05;
  else
    buffer[file_size / 2] = 0xff;

  printf("writing modified buffer to %s\n", filename_o);
  result = fwrite(buffer, 1, file_size, fo);
  if (result != file_size) {
    fprintf(stderr, "Wrote %zu of %zu bytes\n", result, file_size);
    goto cleanup;
  }

  exit_code = 0;

cleanup:
  free(buffer);
  if (fi)
    fclose(fi);
  if (fo)
    fclose(fo);
  return exit_code;
}
