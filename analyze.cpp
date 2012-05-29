/* C Declarations */
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

/* C++ Declarations */
#include <string>
#include <map>
#include <iostream>

#include "sr_protocol.h"

using namespace std; /* for vector */

#define SCAN_RATIO   3 
#define MIN_REQUESTS 5 

int main (int argc, char *argv[]);

void
print_ip (uint32_t addr)
{
  struct in_addr ia;
  ia.s_addr = addr;
  printf ("%s\n", inet_ntoa (ia));
}

bool
is_scanning (string key, map<string, int>requests,
                        map<string, int>responses)
{
  /* someone who only scans a few ports isn't a scanner */
  if (requests[key] < MIN_REQUESTS)
    return false;

  if (SCAN_RATIO * responses[key] / requests[key] < 1)
    return true;

  return false;
}

bool
is_response (struct tcphdr *tcp)
{
  if (tcp->syn && tcp->ack) return true;
  return false;
}

bool
is_request (struct tcphdr *tcp)
{
  if (tcp->syn && !tcp->ack) return true;
  return false;
}

string
port_to_s (unsigned short port)
{
  char buffer[6];
  sprintf (buffer, "%d", port);
  return string (buffer);
}

string
ip_to_s (uint32_t addr)
{
  struct in_addr ia;
  ia.s_addr = addr;
  char *result = inet_ntoa (ia);
  return string(result);
}

string
src_to_s (sr_ip_hdr_t *ip, struct tcphdr *tcp)
{
  //return ip_to_s (ip->ip_src) + ":" + port_to_s (tcp->source);
  return ip_to_s (ip->ip_src);
}

string
dst_to_s (sr_ip_hdr_t *ip, struct tcphdr *tcp)
{
  //return ip_to_s (ip->ip_dst) + ":" + port_to_s (tcp->dest);
  return ip_to_s (ip->ip_dst);
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
  map<string, int> requests;
  map<string, int> responses;

  /* read in pcap file */
  char err[1000];
  const char *filename = "./traces/part2Trace.pcap";
  pcap_t *dump   = pcap_open_offline (filename, err);
  printf("%s", err);

  while (1)
    {
      /*struct pcap_pkthdr **header;
      const u_char **data;
      int next = pcap_next_ex (dump, header, data);
      if (next == 1) break;*/
      

      struct pcap_pkthdr *header =
        (struct pcap_pkthdr *)malloc (sizeof (struct pcap_pkthdr));
      const u_char *p = pcap_next (dump, header);
      if (p == NULL) break;

      /* cast to ip packet header */
      sr_ethernet_hdr_t *eth_packet = (sr_ethernet_hdr_t *)p; 
      char *_ip = ((char *)p) + sizeof (sr_ethernet_hdr_t);
      sr_ip_hdr_t *ip = (sr_ip_hdr_t *)_ip;
      char *_tcp = ((char *)ip) + sizeof (sr_ip_hdr_t);
      struct tcphdr *tcp = (struct tcphdr *)_tcp;

      if (is_request (tcp))
        requests[src_to_s (ip, tcp)]++;
        
      if (is_response (tcp)) 
        responses[dst_to_s (ip, tcp)]++;
    }

  cout << "\n**** START ****" << endl;

  map<string, int>::iterator iter;
  for (iter = requests.begin(); iter != requests.end(); iter++)
    {
      if (is_scanning (iter->first,requests,responses))
        cout << "SCANER!\t";

      cout << iter->first << "\t: (" << iter->second << "," << responses[iter->first] << ")" << endl;
    }

  printf ("**** DONE ****\n");


  return 0;
}
