#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>

#include "sr_protocol.h"

int main (int argc, char *argv[]);

void
print_ip (uint32_t addr)
{
  struct in_addr ia;
  ia.s_addr = addr;
  printf ("%s\n", inet_ntoa (ia));
}

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

  /* create hash table to keep track of connections */

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
      const u_char *p = pcap_next (dump, header);
      if (p == NULL) break;

      /* cast to ip packet header */
      sr_ethernet_hdr_t *eth_packet = (sr_ethernet_hdr_t *)p; 
      char *_ip = ((char *)p) + sizeof (sr_ethernet_hdr_t);
      sr_ip_hdr_t *ip = (sr_ip_hdr_t *)_ip;

      print_ip (ip->ip_src);

    }

  printf ("**** DONE *****\n");

  /* iterate through packets */
  
  

  return 0;
}
