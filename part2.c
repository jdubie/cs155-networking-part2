#include <stdio.h>
#include <pcap.h>

int
main (int argc, char *argv[])
{
  if (argc > 2)
    {
      printf("incorrect number of args\n");
      return 1;
    }
  int arg_no;
  if (argc == 1) arg_no = 1; /* default to file 1 */
  else arg_no = atoi (argv[1]);
  char file[100]; /* filenames are all less than 10 characters */
  sprintf (file, "traces/attack%d", arg_no);

  printf ("hello %s\n",file);
  return 0;
}
