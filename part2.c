#include <stdio.h>
#include <pcap.h>

int main (int argc, char *argv[]);
//int open_ (int argc, char *argv[]);

int
main (int argc, char *argv[])
{
  if (argc > 2)
    {
      printf("incorrect number of args\n");
      return 1;
    }
  int arg_no;
  if (argc == 1) arg_no = 1; /* default to attack1 */
  else arg_no = atoi (argv[1]);
  char filename[100]; /* filenames are all less than 10 characters */
  sprintf (filename, "traces/attack%d", arg_no);

  pcap_open_offline (filename, NULL);

  return 0;
}
