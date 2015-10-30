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

/*--------------------------------------------------------------------
* Reply Definations
*----------------------------------------------------------------------*/
#define ICMP_ECHO 0
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
    
    uint8_t *r_packet;
    r_packet = malloc(len);
    memcpy(r_packet, packet, len);

    if (ethertype(r_packet) == ethertype_arp){
      arp_handlepacket(sr, r_packet, len, interface);
    } else {
      ip_handlepacket(sr, r_packet, len, interface);
    }

}/* end sr_ForwardPacket */

void arp_handlepacket(struct sr_instance *sr,
        uint8_t *packet,
        unsigned int len,
        char *interface) 
{
    printf("** Recieved ARP packet\n");

    /* Initalize ARP header and Input Interface */
    struct sr_arp_hdr *arp_hdr = arp_header(packet);
    struct sr_if *r_iface = sr_get_interface(sr,interface);

    if (r_iface->ip != arp_hdr->ar_tip){
      return;
    }

    if (!arp_validpacket(packet, len))
      return;

    if (ntohs(arp_hdr->ar_op) == arp_op_request){

      if(sr_arp_req_not_for_us(sr, packet, len, interface))
        return;

      printf("** ARP packet request to me \n");   
   
      /* build the arp reply packet  */
      struct sr_arp_hdr arp_packet_reply;
      arp_packet_reply = build_arp_reply(arp_hdr, r_iface);
      
      /* Build the Ethernet Packet */
      struct sr_ethernet_hdr sr_ether_pkt;
      memcpy(sr_ether_pkt.ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      memcpy(sr_ether_pkt.ether_shost, r_iface->addr, ETHER_ADDR_LEN);
      sr_ether_pkt.ether_type = htons(ethertype_arp);

      /* Copy the Packet into the sender buf */
      uint8_t *send_packet;
      unsigned int eth_pkt_len;
      eth_pkt_len = sizeof(arp_packet_reply) + sizeof(sr_ether_pkt);
      send_packet = malloc(eth_pkt_len);
      memcpy(send_packet, &sr_ether_pkt, sizeof(sr_ether_pkt));
      memcpy(send_packet + sizeof(sr_ether_pkt), &arp_packet_reply, sizeof(arp_packet_reply));

      /* send the reply*/
      sr_send_packet(sr, send_packet, eth_pkt_len, r_iface->name);
      free(send_packet);
    } else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
        printf("** ARP packet reply to me\n");

        struct sr_arpentry *arp_entry;
        struct sr_arpreq *arp_req;

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
    }
}

struct sr_arp_hdr build_arp_reply(struct sr_arp_hdr *arp_hdr, struct sr_if *r_iface)
{
      /* Initalize ARP header and Input Interface */
      struct sr_arp_hdr build_arp;

      /* set value of arp packet  */
      build_arp.ar_hrd= htons(arp_hrd_ethernet);
      build_arp.ar_pro= htons(arp_pro_ip);
      build_arp.ar_hln= ETHER_ADDR_LEN;
      build_arp.ar_pln= ARP_PLEN;
      build_arp.ar_op = htons(arp_op_reply);
      build_arp.ar_sip= r_iface->ip;
      build_arp.ar_tip= arp_hdr->ar_sip;
      memcpy(build_arp.ar_sha, r_iface->addr, ETHER_ADDR_LEN); 
      memcpy(build_arp.ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);

      return build_arp;
}

void ip_handlepacket(struct sr_instance *sr,
        uint8_t *packet,
        unsigned int len,
        char *interface) 
{ 
    printf("** Recieved IP packet\n");

    /*struct sr_if *r_iface = sr_get_interface(sr,interface);*/
    /*arp_boardcast(sr, r_iface);*/

    /* Initialization */
    struct sr_ip_hdr *ip_hdr = ip_header(packet);

    if (!ip_validpacket(packet, len))
      return;

    /* Check interface IP to determine whether this IP packet is for me */
    if (sr_packet_is_for_me(sr, ip_hdr->ip_dst)) {
    
        /* Check whether ICMP echo request or TCP/UDP */
        if (ip_hdr->ip_p == ip_protocol_icmp){

            /* send ICMP echo reply Packet */
		        struct sr_icmp_hdr icmp_echo_reply = icmp_send_reply_packet();

        } else if(ip_hdr->ip_p == ip_protocol_tcp||ip_hdr->ip_p == ip_protocol_udp){

            /* Send ICMP unreachable */
                    
        }
    } else {
        ip_hdr->ip_ttl --;

        /* If TTL reaches 0, send  ICMP time exceeded and return */
        if (ip_hdr->ip_ttl == 0) {
              
          /* Send ICMP time exceeded */

          return;
        }

        /* update checksum */
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

        uint8_t *ip_pkt;
        ip_pkt = malloc(len);
        memcpy(ip_pkt, ip_hdr, len);

        /* Find longest prefix match in routing table. */
        struct sr_rt* lpmatch = 0;

        lpmatch = longest_prefix_matching(sr, ip_hdr->ip_dst);
        
        /* If cannot find dst_ip in routing table, send ICMP host unreachable */
        if (lpmatch == 0) {
        
        /* Send ICMP */

        return;
        }
        
        struct sr_arpentry *arp_entry;
        struct sr_if *s_interface;

        /* Get the corresponding interface of the destination IP. */
        s_interface = sr_get_interface(sr, lpmatch->interface);
      
        /* Check ARP cache */
        arp_entry = sr_arpcache_lookup(&sr->cache, lpmatch->gw.s_addr);

        if (arp_entry == 0){

          /* IF miss APR cache, add the packet to ARP request queue */
          struct sr_arpreq *req;  

          req = sr_arpcache_queuereq(&sr->cache, lpmatch->gw.s_addr, ip_pkt, len, lpmatch->interface);
          sr_handle_arpreq(sr, req);
          free(ip_pkt);
        } else{

            /* Hit ARP cache, send out the packet right away */

            /* Encap the arp request into ethernet frame and then send it */
            sr_ethernet_hdr_t *sr_ether_pkt = 0;

            memcpy(sr_ether_pkt->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN); /*address from routing table*/
            memcpy(sr_ether_pkt->ether_shost, s_interface->addr, ETHER_ADDR_LEN); /*hardware address of the outgoing interface*/
            sr_ether_pkt->ether_type = htons(ethertype_ip);

            uint8_t *packet_rqt;
            unsigned int total_len = len + sizeof(struct sr_ethernet_hdr);
            packet_rqt = malloc(total_len);
            memcpy(packet_rqt, &sr_ether_pkt, sizeof(sr_ether_pkt));
            memcpy(packet_rqt + sizeof(sr_ether_pkt), ip_pkt, len);

            sr_ether_pkt = (sr_ethernet_hdr_t *)malloc(total_len);
            assert(sr_ether_pkt);  

            /* forward the IP packet*/
            sr_send_packet(sr, packet_rqt, total_len, s_interface->name);
            free(packet_rqt);
          }
      }
}

void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req) 
{
    if (difftime(time(0), req->sent) > 1.0) {
    
      /* Host is not reachable */
      if (req->times_sent >= 5) {

        /* Send ICMP host unreachable*/

        sr_arpreq_destroy(&sr->cache, req);
      } else {
          struct sr_if *s_interface;

          s_interface = sr_get_interface(sr, req->packets->iface);
          arp_boardcast(sr, s_interface);
          req->sent = time(0);
          req->times_sent ++;
        }
    }
}

int arp_validpacket(uint8_t *packet, unsigned int len){

    /* Ensure the packet is long enough */
    if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr)){
      return 0;
    }

    struct sr_arp_hdr *arp_hdr = arp_header(packet);

    /* Ensure the arp header setting is correct */
    if (ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet){
      return 0;
    }
    if (ntohs(arp_hdr->ar_pro) != arp_pro_ip){
      return 0;
    }

    return 1;
}

int ip_validpacket(uint8_t *packet, unsigned int len){

    /* Initialization */
    struct sr_ip_hdr * ip_hdr = ip_header(packet);
    uint16_t c_cksum = 0;
    uint16_t r_cksum = ip_hdr->ip_sum;
    unsigned int hdr_len = ip_hdr->ip_hl * 4;

    /* Ensure the packet is long enough */
    if (len < sizeof(struct sr_ethernet_hdr) + hdr_len){
      return 0;
    }
    
    /* Check cksum */
    ip_hdr->ip_sum = 0;
    c_cksum = cksum(ip_hdr, hdr_len);
    if (c_cksum != r_cksum){
      return 0;
    }

    return 1;
}

int icmp_validpacket(struct sr_ip_hdr *ip_hdr){

    /* Initialization */
    uint8_t *icmp_hdr_ptr;
    sr_icmp_hdr_t *icmp_hdr;
    uint16_t c_cksum;
    uint16_t r_cksum;

    /* Location ICMP header */
    icmp_hdr_ptr = (uint8_t *)(ip_hdr)+(ip_hdr->ip_hl * 4);
    icmp_hdr = (struct sr_icmp_hdr *)icmp_hdr_ptr;

    /* Check cksum */
    r_cksum = icmp_hdr->icmp_sum;
    icmp_hdr->icmp_sum = 0;
    c_cksum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len)-(ip_hdr->ip_hl * 4));
    if(c_cksum != r_cksum){
      return 0;
    }

    return 1;
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

void arp_boardcast(struct sr_instance* sr, struct sr_if *s_interface)
{
      /* Initalize ARP header and Input Interface */
      struct sr_arp_hdr arp_boarcast;

      /* set value of arp packet  */
      arp_boarcast.ar_hrd = htons(arp_hrd_ethernet);
      arp_boarcast.ar_pro = htons(arp_pro_ip);
      arp_boarcast.ar_hln = ETHER_ADDR_LEN;
      arp_boarcast.ar_pln = ARP_PLEN;
      arp_boarcast.ar_op = htons(arp_op_reply);
      arp_boarcast.ar_sip = s_interface->ip;
  
      memcpy(arp_boarcast.ar_sha, s_interface->addr, ETHER_ADDR_LEN); 
      memset(arp_boarcast.ar_tha, 255, ETHER_ADDR_LEN);

      /* Build the Ethernet Packet */
      struct sr_ethernet_hdr sr_ether_pkt;
      memcpy(sr_ether_pkt.ether_shost, s_interface->addr, ETHER_ADDR_LEN);
      memset(sr_ether_pkt.ether_dhost, 255, ETHER_ADDR_LEN);
      sr_ether_pkt.ether_type = htons(ethertype_arp);

      /* Copy the Packet into the sender buf */
      uint8_t *send_packet;
      unsigned int eth_pkt_len;
      eth_pkt_len = sizeof(arp_boarcast) + sizeof(sr_ether_pkt);
      send_packet = malloc(eth_pkt_len);
      memcpy(send_packet, &sr_ether_pkt, sizeof(sr_ether_pkt));
      memcpy(send_packet + sizeof(sr_ether_pkt), &arp_boarcast, sizeof(arp_boarcast));

      print_hdrs(send_packet, eth_pkt_len);
      /* send the reply*/
      sr_send_packet(sr, send_packet, eth_pkt_len, s_interface->name);
}

struct sr_rt* longest_prefix_matching(struct sr_instance *sr, uint32_t IP_dest)
{
    /* Find longest prefix match in routing table. */

    struct sr_rt* ip_walker;
    struct sr_rt* lpmatch = 0;
    unsigned long lpmatch_len = 0;
    struct in_addr dst_ip;
        
    dst_ip.s_addr = IP_dest;  
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

    return lpmatch;
}

struct sr_icmp_hdr icmp_send_reply_packet()
{

	struct sr_icmp_hdr icmp_echo_reply;
        
  icmp_echo_reply.icmp_type = htons(type_echo_reply);
  icmp_echo_reply.icmp_code = htons(code_echo_reply);
	icmp_echo_reply.icmp_sum = cksum(&icmp_echo_reply, sizeof(icmp_echo_reply));

	return icmp_echo_reply;
}

struct sr_icmp_t3_hdr* icmp_send_error_packet(struct sr_ip_hdr *ip_hdr, int code_num)
{
	struct sr_icmp_t3_hdr *icmp_error_reply;
        icmp_error_reply->icmp_type = htons(type_dst_unreach);
	switch (code_num)
	{
		case 0:
			icmp_error_reply->icmp_code = htons(code_net_unreach);
			break;
		case 1:
			icmp_error_reply->icmp_code = htons(code_port_unreach);
			break;
		case 3:
			icmp_error_reply->icmp_code = htons(code_host_unreach);
			break;
	}
	
	icmp_error_reply->next_mtu = htons(MTU);
  /****************************encap the received ip header and the first 8 bytes ********************/
  memcpy(icmp_error_reply->data, &ip_hdr, ICMP_DATA_SIZE);
	return icmp_error_reply;
}




