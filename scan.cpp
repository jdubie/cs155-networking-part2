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
ip_to_s (struct in_addr addr)
{
  return string(inet_ntoa(addr));
}

string
src_to_s (struct ip *ip, struct tcphdr *tcp)
{
  return ip_to_s (ip->ip_src) + "\t" + ip_to_s (ip->ip_dst);
}

string
dst_to_s (struct ip *ip, struct tcphdr *tcp)
{
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

  /* print results */
  cout << "<Source-IP>\t<Destination-IP>" << endl;
  map<string, int>::iterator iter;
  for (iter = requests.begin(); iter != requests.end(); iter++)
    if (is_scanning (iter->first,requests,responses))
      cout << iter->first << endl;

  return 0;
}
