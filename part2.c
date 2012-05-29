#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>

int main (int argc, char *argv[]);
//int open_ (int argc, char *argv[]);

int
main (int argc, char *argv[])
{
  /*if (argc > 2)
    {
      printf("incorrect number of args\n");
      return 1;
    }
  int arg_no;
  if (argc == 1) arg_no = 1; // default to attack1
  else arg_no = atoi (argv[1]);
  char filename[100]; // filenames are all less than 10 characters
  sprintf (filename, "./traces/attack%d", arg_no);
  */

  /* read in pcap file */
  char err[1000];
  char *filename = "./traces/part2Trace.pcap";
  pcap_t *dump   = pcap_open_offline (filename, err);
  printf("%s", err);

  while (1)
    {
      /*struct pcap_pkthdr **header;
      const u_char **data;
      int next = pcap_next_ex (dump, header, data);
      if (next == 1) break;*/

      struct pcap_pkthdr *header = malloc (sizeof (struct pcap_pkthdr));
      const u_char *ret = pcap_next (dump, header);
      if (ret == NULL) break;
    }

  printf ("**** DONE *****\n");

  /* iterate through packets */
  
  

  return 0;
}
