/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  struct sr_if* iface = 0;
  iface = sr_get_interface(sr,interface);
  sr_print_if(iface);
 
  /* Ensure the packet is long enough */
  if (len < sizeof(struct sr_ethernet_hdr))
    return;

  /* Handle Packet */
  sr_ethernet_hdr_t *ehdr = (struct sr_ethernet_hdr *)packet;
  
  if (ntohs(ehdr->ether_type) == ethertype_arp){
    arp_handlepacket(sr,packet,len,interface);
  } else {
    ip_handlepacket(packet);
  }

}/* end sr_ForwardPacket */

void arp_handlepacket(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
  printf("** Recieved ARP packet");
  /* Initialization */
  sr_arp_hdr_t *arp_hdr = arp_header(packet);
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));

  if (ntohs(arp_hdr->ar_op) == arp_op_request)
    {
      printf("** ARP packet request to me");
	/*how to define that fuction??*/
      if(sr_arp_req_not_for_us(sr,packet,len,interface))
	{return;}

      /* build the arp reply packet  */
      sr_arp_hdr_t *arp_packet;
      unsigned int arplen =  sizeof(sr_arp_hdr_t);
      arp_packet = (sr_arp_hdr_t *)malloc(arplen);
      assert(arp_packet);  

      /* set value of arp packet  */
      arp_packet->ar_hrd= arp_hdr->ar_hrd;  /*same as received packet*/
      arp_packet->ar_pro= arp_hdr->ar_pro;  /*same as received packet*/
      arp_packet->ar_hln= arp_hdr->ar_hln;  /*same as received packet*/
      arp_packet->ar_pln= arp_hdr->ar_pln;  /*same as received packet*/
      arp_packet->ar_op = arp_op_reply;     /*ARP opcode--ARP reply */


      /*get hardware address of router*/
      struct sr_if* iface;
      iface = sr_get_interface(sr,interface);
      char iface_name[sr_IFACE_NAMELEN];
      memcpy(iface_name,iface->name,sr_IFACE_NAMELEN); 
      unsigned char iface_addr[ETHER_ADDR_LEN];
      memcpy(iface_addr,iface->addr,ETHER_ADDR_LEN); 


      memcpy(arp_packet->ar_sha, iface_addr, ETHER_ADDR_LEN); /* flip sender hardware address*/
      arp_packet->ar_sip=arp_hdr->ar_tip;   /* flip sender IP address */
      memcpy(arp_packet->ar_tha,arp_hdr->ar_sha, ETHER_ADDR_LEN); /* flip target hardware address*/
      arp_packet->ar_tip=arp_hdr->ar_sip;   /* flip target IP address */

 
      /* encap the arp reply into ethernet frame and then send it*/
      sr_ethernet_hdr_t *sr_ether_pkt;
      unsigned int len = sizeof(arp_packet);
      unsigned int total_len = len + (sizeof(sr_ethernet_hdr_t));
      sr_ether_pkt = (sr_ethernet_hdr_t *)malloc(len + sizeof(sr_ethernet_hdr_t));
      assert(sr_ether_pkt);  

      memcpy(sr_ether_pkt->ether_dhost,arp_packet->ar_tha, ETHER_ADDR_LEN);
      memcpy(sr_ether_pkt->ether_shost,arp_packet->ar_sha, ETHER_ADDR_LEN);
      sr_ether_pkt-> ether_type = ethertype_arp;

      uint8_t *packet_rpy = (uint8_t *)sr_ether_pkt;

      /* send the reply*/
      sr_send_packet(sr,packet_rpy,total_len,iface_name);

	
    
    } else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {

    printf("** ARP packet reply to me");
  

  
  }
}

void ip_handlepacket(uint8_t * packet) {
  printf("** Recieved IP packet");

  sr_ip_hdr_t * ip_hdr = ip_header(packet);
    if (ntohs(ip_hdr->ar_op) == arp_op_request)
}


