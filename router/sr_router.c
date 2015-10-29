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
 ***********************************************************************/

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

int sr_packet_is_for_me(struct sr_instance* sr, uint32_t ip_dst);

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

void sr_handlepacket(struct sr_instance *sr,
        uint8_t *packet/* lent */,
        unsigned int len,
        char *interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);
   
    /* Ensure the packet is long enough */
    if (len < sizeof(struct sr_ethernet_hdr)){
      return;
    }
    
    if (ethertype(packet) == ethertype_arp){
      arp_handlepacket(sr, packet, len, interface);
    } else {
      ip_handlepacket(sr, packet, len, interface);
    }

}/* end sr_ForwardPacket */

void arp_handlepacket(struct sr_instance *sr,
        uint8_t *packet,
        unsigned int len,
        char *interface) 
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("** Recieved ARP packet\n");

    /* Initialization */
    sr_arp_hdr_t *arp_hdr = arp_header(packet);
    struct sr_if* r_iface = sr_get_interface(sr,interface);

    struct sr_arpentry *arp_entry;
    struct sr_arpreq *arp_req;

    /* Ensure the packet is long enough */
    if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr)){
      return ;
    }

    /* Ensure the arp header setting is correct*/
    if (ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet){
      return ;
    }
    if (ntohs(arp_hdr->ar_pro) != arp_pro_ip){
      return ;
    }
    if (r_iface->ip != arp_hdr->ar_tip){
      return;
    }

    /* Check ARP cache  */
    arp_entry = sr_arpcache_lookup(&sr->cache, arp_hdr->ar_sip);
    if (arp_entry != 0){
      free(arp_entry);
    }else {
      arp_req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
      /* Check ARP request queue, if not empty send out packets on it*/
      if (arp_req != 0) {
        struct sr_packet *pkt_wait = arp_req->packets;

        while (pkt_wait != 0) {
          /*some universal function to encap and send out packet*/
          pkt_wait = pkt_wait->next;
        }
      } 
    }   

    if (ntohs(arp_hdr->ar_op) == arp_op_request){
    	/*how to define that fuction??
      if(sr_arp_req_not_for_us(sr,packet,len,interface))
        return;*/
      printf("** ARP packet request to me \n");   
   
      /* build the arp reply packet  */
      struct sr_arp_hdr arp_packet_reply;
      /* set value of arp packet  */
      arp_packet_reply.ar_hrd= htons(arp_hrd_ethernet);         /*same as received packet*/
      arp_packet_reply.ar_pro= htons(arp_pro_ip);         /*same as received packet*/
      arp_packet_reply.ar_hln= ETHER_ADDR_LEN;         /*same as received packet*/
      arp_packet_reply.ar_pln= sizeof(uint32_t);         /*same as received packet*/
      arp_packet_reply.ar_op = htons(arp_op_reply);     /*ARP opcode--ARP reply */
      arp_packet_reply.ar_sip= r_iface->ip;   /* flip sender IP address */
      arp_packet_reply.ar_tip= arp_hdr->ar_sip;   /* flip target IP address */
      memcpy(arp_packet_reply.ar_sha, r_iface->addr, ETHER_ADDR_LEN); /* insert router interface hardware address*/
      memcpy(arp_packet_reply.ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN); /* flip target hardware address*/
      
      /* Build the Ethernet Packet */
      struct sr_ethernet_hdr sr_ether_pkt;
      memcpy(sr_ether_pkt.ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      memcpy(sr_ether_pkt.ether_shost, r_iface->addr, ETHER_ADDR_LEN);
      sr_ether_pkt.ether_type = htons(ethertype_arp);

      /* Copy the Packet into the sender buf */
      uint8_t *send_packet;
      unsigned int eth_pkt_len;
      eth_pkt_len = sizeof(arp_packet_reply) + sizeof(sr_ether_pkt)
      send_packet = malloc(eth_pkt_len)
      memcpy(send_packet, &sr_ether_pkt, sizeof(sr_ether_pkt));
      memcpy(send_packet + sizeof(sr_ether_pkt), arp_packet_reply, sizeof(arp_packet_reply));

      /* send the reply*/
      sr_send_packet(sr, send_packet, eth_pkt_len, r_iface->name);
      free(packet_rpy);
    } else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
        printf("** ARP packet reply to me\n");
        /* all need to do is done when manipulating the arp_req, this part only prints the message */
    }
}

void ip_handlepacket(struct sr_instance *sr,
        uint8_t *packet,
        unsigned int len,
        char *interface) 
{ 
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("** Recieved IP packet\n");

    /* Initialization */
    sr_ip_hdr_t * ip_hdr = ip_header(packet);
    uint16_t c_cksum = 0, r_cksum = ip_hdr->ip_sum;
    unsigned int hdr_len = ip_hdr->ip_hl * 4;

    /* Ensure the packet is long enough */
    if (len < sizeof(struct sr_ethernet_hdr) + hdr_len){
      return ;
    }
    
    /* Check cksum */
    ip_hdr->ip_sum = 0;
    c_cksum = cksum(ip_hdr, hdr_len);
    if (c_cksum != r_cksum){
      return ;
    }

    /* Check interface IP to determine whether this IP packet is for me */
    if (sr_packet_is_for_me(sr, ip_hdr->ip_dst)) {
    
      /* Check whether ICMP echo request or TCP/UDP */
      if (ntohs(ip_hdr->ip_p) == ip_protocol_icmp){
        
        /* Deal with icmp echo request */

      } else {

          /* Send icmp */
                    
        }
    } else {
       
        struct sr_arpentry *arp_entry;
        struct sr_if *s_interface;
        
        /* Find longest prefix match in routing table. */

        struct sr_rt* ip_walker;
        struct sr_rt* lpmatch = 0;
        unsigned long lpmatch_len = 0;
        struct in_addr dst_ip;
        
        dst_ip.s_addr = ip_hdr->ip_dst;  
        ip_walker = sr->routing_table;
        
        /* If there is a longer match ahead replace it */
        while(ip_walker != 0) {
          if (((ip_walker->dest.s_addr & ip_walker->mask.s_addr) == (dst_ip.s_addr & ip_walker->mask.s_addr)) && 
            (lpmatch_len <= ip_walker->mask.s_addr)) {          
            lpmatch_len = ip_walker->mask.s_addr;
            lpmatch = ip_walker;
          }
          ip_walker = ip_walker->next;
        }
    
        /* If cannot find dst_ip in routing table, send ICMP host unreachable */
        if (lpmatch == 0) {
        
        /* Send ICMP */

        return;
        }
      
        /* Get the corresponding interface of the destination IP. */
        s_interface = sr_get_interface(sr, lpmatch->interface);
      
        /* Check ARP cache */
        arp_entry = sr_arpcache_lookup(&sr->cache, lpmatch->gw.s_addr);



      /* *************IF miss APR cache, Send APR request packet************** */
      sr_arp_hdr_t *arp_packet_request;
      unsigned int arplen =  sizeof(sr_arp_hdr_t);
      arp_packet_request = (sr_arp_hdr_t *)malloc(arplen);
      assert(arp_packet_request);  

      /* set value of arp packet  */
      arp_packet_request->ar_hrd = htons(arp_hrd_ethernet);    
      arp_packet_request->ar_pro = htons(arp_pro_ip);        
      arp_packet_request->ar_hln = ETHER_ADDR_LEN;        
      arp_packet_request->ar_pln = ARP_PLEN;       
      arp_packet_request->ar_op  = htons(arp_op_request);     /*ARP opcode--ARP request */
      /*get hardware address of router*/  
      /*use s_interface as the struct member of sr_if that send the packet out*/

      memcpy(arp_packet_request->ar_sha, s_interface->addr, ETHER_ADDR_LEN); /* insert router interface hardware address*/
      arp_packet_request->ar_sip= ip_hdr->ip_src;   /* same as the sent IP or another? */
      arp_packet_request->ar_tip= ip_hdr->ip_dst;   /* flip target IP address */
  
      /* encap the arp request into ethernet frame and then send it    */
      sr_ethernet_hdr_t *sr_ether_pkt;
      unsigned int len = sizeof(arp_packet_request);
      unsigned int total_len = len + sizeof(sr_ethernet_hdr_t);
      sr_ether_pkt = (sr_ethernet_hdr_t *)malloc(total_len);
      assert(sr_ether_pkt);  

      memcpy(sr_ether_pkt->ether_dhost, arp_packet_request->ar_tha, ETHER_ADDR_LEN);
      memcpy(sr_ether_pkt->ether_shost, arp_packet_request->ar_sha, ETHER_ADDR_LEN);
      sr_ether_pkt->ether_type = htons(ethertype_arp);

      uint8_t *packet_rqt = (uint8_t*)sr_ether_pkt;

      /* send the reply*/
      sr_send_packet(sr, packet_rqt, total_len, s_interface->name);
      free(packet_rqt);

      /* ********************IF hit the cache, Send IP packet (TTL-1; )************************** */

      }
}

int sr_packet_is_for_me(struct sr_instance* sr, uint32_t ip_dst)
{
    /* -- REQUIRES -- */
    assert(sr);

    struct sr_if* if_walker = sr->if_list;
    while(if_walker) {
      if(ip_dst == if_walker->ip){
        return 1;
      }
      if_walker = if_walker->next;
    }
    return 0;
}
