/* C Declarations */
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

/* C++ Declarations */
#include <string>
#include <map>
#include <vector>
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
  //return ip_to_s (ip->ip_src);
  return ip_to_s (ip->ip_src) + "\t" + ip_to_s (ip->ip_dst);
}

string
dst_to_s (sr_ip_hdr_t *ip, struct tcphdr *tcp)
{
  //return ip_to_s (ip->ip_dst) + ":" + port_to_s (tcp->dest);
  return ip_to_s (ip->ip_dst) + "\t" + ip_to_s (ip->ip_src);
}

int
main (int argc, char *argv[])
{
  /* create hash table to keep track of connections */
  map<string, int>    requests;
  map<string, int>    responses;
  vector<string>      scanners;
  map<string, string> scanning;

  /* read in pcap file */
  char err[1000];
  const char *filename = "./traces/part2Trace.pcap";
  pcap_t *dump   = pcap_open_offline (filename, err);
  printf("%s", err);

  while (1)
    {
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

  cout << "**** START *****" << endl;
  cout << "<Source-IP>\t<Destination-IP>" << endl;

  map<string, int>::iterator iter;
  for (iter = requests.begin(); iter != requests.end(); iter++)
    {
      /*if (is_scanning (iter->first,requests,responses))
        {
          scanners.push_back (iter->first);
          cout << "SCANER!\t";
        }

      cout << iter->first << "\t: (" << iter->second << "," << responses[iter->first] << ")" << endl;*/

      if (is_scanning (iter->first,requests,responses))
        cout << iter->first << endl;
    }

  printf ("**** FINISH ****\n");


  return 0;
}
