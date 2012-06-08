/* C Declarations */
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

/* C++ Declarations */
#include <string>
#include <map>
#include <vector>
#include <iostream>

//#include "sr_protocol.h"
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace std; /* for vector */

#define SCAN_RATIO   3 
#define MIN_REQUESTS 2 

int main (int argc, char *argv[]);

/*void
print_ip (uint32_t addr)
{
  struct in_addr ia;
  ia.s_addr = addr;
  printf ("%s\n", inet_ntoa (ia));
}*/

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

/*string
ip_to_s (uint32_t addr)
{
  struct in_addr ia;
  //ia.s_addr = ntohl (addr);
  //ia.s_addr = ntohs (addr);
  ia.s_addr = addr;
  char *result = inet_ntoa (ia);
  return string(result);
}*/

string
ip_to_s (struct in_addr addr)
{
  return string(inet_ntoa(addr));
  /* from http://stackoverflow.com/questions/1680365/integer-to-ip-address-c */
  /*unsigned char bytes[4];
  bytes[0] = addr & 0xFF;
  bytes[1] = (addr >> 8) & 0xFF;
  bytes[2] = (addr >> 16) & 0xFF;
  bytes[3] = (addr >> 24) & 0xFF;       
  char result[17];
  sprintf(result, "%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);*/
}

  string
src_to_s (struct ip *ip, struct tcphdr *tcp)
{
  //return ip_to_s (ip->ip_src) + ":" + port_to_s (tcp->source);
  //return ip_to_s (ip->ip_src);
  return ip_to_s (ip->ip_src) + "\t" + ip_to_s (ip->ip_dst);
}

  string
dst_to_s (struct ip *ip, struct tcphdr *tcp)
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
    char *eth_packet = (char *) p; 
    char *_ip = (char *)(p + 14);
    struct ip *ip = (struct ip *)_ip;

    char *_tcp = ((char *)ip) + sizeof (struct ip);
    struct tcphdr *tcp = (struct tcphdr *)_tcp;

    if (is_request (tcp))
      requests[src_to_s (ip, tcp)]++;

    if (is_response (tcp)) 
      responses[dst_to_s (ip, tcp)]++;
  }

  //cout << "**** START *****" << endl;
  cout << "<Source-IP>\t<Destination-IP>" << endl;

  map<string, int>::iterator iter;
  for (iter = requests.begin(); iter != requests.end(); iter++)
  {
    /*if (is_scanning (iter->first,requests,responses))
      {
      scanners.push_back (iter->first);
      cout << "SCANER!\t";
      }

      cout << iter->first << "\t: (" << iter->second << "," << responses[iter->first] << ")" << endl;
      */


    if (is_scanning (iter->first,requests,responses))
      cout << iter->first << endl;
  }

  //printf ("**** FINISH ****\n");


  return 0;
}
