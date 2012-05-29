#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>

#include "sr_protocol.h"
#include "hash.h"

int main (int argc, char *argv[]);

void
print_ip (uint32_t addr)
{
  struct in_addr ia;
  ia.s_addr = addr;
  printf ("%s\n", inet_ntoa (ia));
}

struct pk_entry {
  uint32_t ip;
  uint32_t port;
  struct hash_elem elem;
};

unsigned pk_hash_func (const struct hash_elem *e, void *aux)
{
  struct pk_entry *entry = hash_entry (e, struct pk_entry, elem);
  // TODO: better hash function
  return (unsigned) entry->port + entry->ip; /* not unique but hopfully goodneogh */
}

bool pk_less_func (const struct hash_elem *a,
                     const struct hash_elem *b,
                     void *aux) {
  uint32_t a_ip = hash_entry (a, struct pk_entry, elem)->ip;
  uint32_t b_ip = hash_entry (b, struct pk_entry, elem)->ip;
  uint32_t a_port = hash_entry (a, struct pk_entry, elem)->port;
  uint32_t b_port = hash_entry (b, struct pk_entry, elem)->port;
  if (a_ip < b_ip)         return true;
  else if (a_ip == b_ip)
    {
      if (a_port < b_port) return true;
      else                 return false;
    }
  else                     return false;
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
  struct hash *hash;
  hash_init (hash, pk_hash_func, pk_less_func, NULL);  

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
