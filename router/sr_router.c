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
#define ICMP_IP_HDR_LEN 5
#define ICMP_ECHO_REPLY_LEN 56
#define ICMP_TYPE3_LEN 36
#define ICMP_COPY_DATAGRAM_LEN 8
#define ICMP_IP_HDR_LEN_BYTE 20
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

    printf("** -> Received packet of length %d \n",len);
   
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
    printf("** Recieved ARP packet\n");

    /* Initalize ARP header from the Packet */
    struct sr_arp_hdr *arp_hdr = arp_header(packet);
    /* Interface the packet arrived in */
    struct sr_if *r_iface = sr_get_interface(sr,interface);

    /* Check if interface->ip = arp header->ip */
    if (r_iface->ip != arp_hdr->ar_tip){
        return;
    }

    /* validate ARP packet */
    if (!arp_validpacket(packet, len))
        return;

    if (ntohs(arp_hdr->ar_op) == arp_op_request){

        if(sr_arp_req_not_for_us(sr, packet, len, interface))
            return;

        printf("** ARP packet request to me \n");   
        /* build and send ARP packet  */
        build_arp_reply(sr, arp_hdr, r_iface);
      
    } else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
        printf("** ARP packet reply to me\n");

        struct sr_arpentry *arp_entry;
        struct sr_arpreq *arp_req;
        struct sr_if *s_interface;
        struct sr_packet *pkt_wait;
        struct sr_packet *temp;
        uint8_t *send_packet;
        unsigned int eth_pkt_len;

        /* Check ARP cache  */
        arp_entry = sr_arpcache_lookup(&sr->cache, arp_hdr->ar_sip);
        if (arp_entry != 0){
            free(arp_entry);
        }else {
            arp_req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

            /* Check ARP request queue, if not empty send out packets on it*/
            if (arp_req != 0) {
                pkt_wait = arp_req->packets;

                while (pkt_wait != 0) {
                    /* Send the packets out */
                    s_interface = sr_get_interface(sr, pkt_wait->iface);

                    struct sr_ethernet_hdr sr_ether_hdr;

                    /* Construct the Ethernet Packet */
                    sr_ether_hdr.ether_type = htons(ethertype_ip);
                    memcpy(sr_ether_hdr.ether_shost, s_interface->addr, ETHER_ADDR_LEN);
                    memcpy(sr_ether_hdr.ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);

                    /* Copy the Packet into the sender buf */
                    eth_pkt_len = pkt_wait->len + sizeof(struct sr_ethernet_hdr);
                    send_packet = malloc(eth_pkt_len);
                    memcpy(send_packet, &sr_ether_hdr, sizeof(struct sr_ethernet_hdr));
                    memcpy(send_packet + sizeof(struct sr_ethernet_hdr), 
                        pkt_wait->buf, pkt_wait->len);

                    sr_send_packet(sr, send_packet, eth_pkt_len, s_interface->name);

                temp = pkt_wait;
                pkt_wait = pkt_wait->next;
                free(temp);
                }
            } 
        }   
    }
}

void sr_add_ethernet_send(struct sr_instance *sr,
        uint8_t *packet,
        unsigned int len,
        uint32_t dip,
        enum sr_ethertype type) 
{
    struct sr_rt *rt;
    struct sr_if *r_iface;
    struct sr_ethernet_hdr sr_ether_pkt;
    struct sr_arp_hdr * arp_pkt;
    uint8_t *send_packet;
    unsigned int eth_pkt_len;
    struct sr_arpentry *arp_entry;

    rt = longest_prefix_matching(sr, dip);
    r_iface = sr_get_interface(sr, rt->interface);

    if (type == ethertype_arp) { 
        arp_pkt = (struct sr_arp_hdr *)packet;

        /* Broadcast Request */
        if (arp_pkt->ar_op == htons(arp_op_request))
            memset(sr_ether_pkt.ether_dhost, 255, ETHER_ADDR_LEN);
        /* Build reply packet */
        else if (arp_pkt->ar_op == htons(arp_op_reply))
            memcpy(sr_ether_pkt.ether_dhost, arp_pkt->ar_tha, ETHER_ADDR_LEN);

        memcpy(sr_ether_pkt.ether_shost, r_iface->addr, ETHER_ADDR_LEN);
        sr_ether_pkt.ether_type = htons(type);

        /* Copy the Packet into the sender buf */
        eth_pkt_len = sizeof(struct sr_arp_hdr) + sizeof(struct sr_ethernet_hdr);
        send_packet = malloc(eth_pkt_len);
        memcpy(send_packet, &sr_ether_pkt, sizeof(struct sr_ethernet_hdr));
        memcpy(send_packet + sizeof(struct sr_ethernet_hdr), 
            packet, sizeof(struct sr_arp_hdr));

        /* send the reply*/
        sr_send_packet(sr, send_packet, eth_pkt_len, r_iface->name);
        free(send_packet);

    } else {
        arp_entry = sr_arpcache_lookup(&sr->cache, dip);

        /* Set the Ethernet Header */
        memcpy(sr_ether_pkt.ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        memcpy(sr_ether_pkt.ether_shost, r_iface->addr, ETHER_ADDR_LEN);
        sr_ether_pkt.ether_type = htons(type);

        /* Copy the Packet into the sender buf */
        eth_pkt_len = len + sizeof(struct sr_ethernet_hdr);
        send_packet = malloc(eth_pkt_len);
        memcpy(send_packet, &sr_ether_pkt, sizeof(struct sr_ethernet_hdr));
        memcpy(send_packet + sizeof(struct sr_ethernet_hdr), 
            packet, len);

        /* send the reply*/
        sr_send_packet(sr, send_packet, eth_pkt_len, r_iface->name);
        free(send_packet);
    }

}

void build_arp_reply(struct sr_instance *sr, struct sr_arp_hdr *arp_hdr, struct sr_if *r_iface)
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

      sr_add_ethernet_send(sr, (uint8_t *)&build_arp, 
              sizeof(struct sr_arp_hdr), arp_hdr->ar_sip, ethertype_arp);
}

void ip_handlepacket(struct sr_instance *sr,
        uint8_t *packet,
        unsigned int len,
        char *interface) { 
    printf("** Recieved IP packet\n");

    /* Test Broadcast */
    struct sr_ip_hdr *ip_hdr = ip_header(packet);
    struct sr_if *r_interface = sr_get_interface(sr,interface);
    struct sr_arpreq *req;
    struct sr_arpentry *arp_entry;
    uint8_t *cache_packet;
    uint16_t total_len;
    uint16_t icmp_len;
    uint32_t dst;
    struct sr_icmp_t3_hdr icmp_error_packet;
    
    if (!ip_validpacket(packet, len))
      return;

    /* Check interface IP to determine whether this IP packet is for me */
    if (sr_packet_is_for_me(sr, ip_hdr->ip_dst)) {
    
        /* Check whether ICMP echo request or TCP/UDP */
        if (ip_hdr->ip_p == ip_protocol_icmp){

            dst = ip_hdr->ip_src;
            ip_hdr->ip_src = ip_hdr->ip_dst;
            ip_hdr->ip_dst = dst;

            /* Modify the ICMP reply packet */
            sr_icmp_hdr_t *icmp_hdr_ptr = icmp_header(ip_hdr);
            icmp_hdr_ptr->icmp_sum = 0;
            icmp_hdr_ptr->icmp_type = htons(type_echo_reply);
            icmp_hdr_ptr->icmp_code = htons(code_echo_reply);
	          icmp_len = ntohs(ip_hdr->ip_len)-ip_hdr->ip_hl*4;
            /* Copy the packet over */

            total_len = ip_len(ip_hdr);
            cache_packet = malloc(total_len);
            memcpy(cache_packet, ip_hdr, total_len);

            icmp_hdr_ptr = icmp_header((struct sr_ip_hdr *)cache_packet);
            icmp_hdr_ptr->icmp_sum = cksum(icmp_hdr_ptr, icmp_len);
            struct sr_ip_hdr *ip_hdr_csum = (struct sr_ip_hdr *)cache_packet;
            ip_hdr_csum->ip_sum = cksum(ip_hdr_csum, sizeof(sr_ip_hdr_t));

            /*Check if we should send immediately or wait */
            arp_entry = sr_arpcache_lookup(&sr->cache, dst);

            if (arp_entry != 0){
                /* Entry Exists, we can send it out right now */
                sr_add_ethernet_send(sr, cache_packet, total_len, dst, ethertype_ip);
            } else {
                req = sr_arpcache_queuereq(&(sr->cache), dst, cache_packet, 
                  total_len, interface);
            }

        } else if(ip_hdr->ip_p == ip_protocol_tcp||ip_hdr->ip_p == ip_protocol_udp){

            /* Send ICMP net unreachable */
            struct sr_ip_hdr send_ip_hdr;
            send_ip_hdr.ip_hl = 5;
            send_ip_hdr.ip_v = ip_hdr->ip_v;
            send_ip_hdr.ip_tos = 0;
            send_ip_hdr.ip_id = ip_hdr->ip_id;
            send_ip_hdr.ip_off = htons(IP_DF);
            send_ip_hdr.ip_ttl = 64;
            send_ip_hdr.ip_p = ip_protocol_icmp;
            send_ip_hdr.ip_sum = 0;
            send_ip_hdr.ip_dst = ip_hdr->ip_src;
            send_ip_hdr.ip_src = r_interface->ip;
            dst = ip_hdr->ip_src;

            icmp_len = sizeof(struct sr_icmp_t3_hdr);
            total_len = ICMP_IP_HDR_LEN_BYTE + icmp_len;

            send_ip_hdr.ip_len = htons(total_len);
            send_ip_hdr.ip_sum = cksum(&send_ip_hdr, ICMP_IP_HDR_LEN_BYTE);
            /* Modify the ICMP error packet */
	          icmp_error_packet = icmp_send_error_packet(ip_hdr, 3); 

            icmp_len = sizeof(struct sr_icmp_t3_hdr);
            total_len = ICMP_IP_HDR_LEN_BYTE + icmp_len;
            cache_packet = malloc(total_len);
            memcpy(icmp_error_packet.data, ip_hdr, ICMP_DATA_SIZE);

            memcpy(cache_packet, &(send_ip_hdr), ICMP_IP_HDR_LEN_BYTE);
            memcpy(cache_packet + ICMP_IP_HDR_LEN_BYTE, &(icmp_error_packet), 
               sizeof(sr_icmp_t3_hdr_t));

            /*Check if we should send immediately or wait */
            arp_entry = sr_arpcache_lookup(&sr->cache, dst);

            if (arp_entry != 0){
                /* Entry Exists, we can send it out right now */
                sr_add_ethernet_send(sr, cache_packet, total_len, dst, ethertype_ip);
            } else {
                req = sr_arpcache_queuereq(&(sr->cache), dst, cache_packet, 
                  total_len, interface);
            }
                    
        }
    } else {
        /* Packet is not for you */
        ip_hdr->ip_ttl --;

        /* update checksum */
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

        uint8_t *ip_pkt;
        ip_pkt = malloc(len);
        memcpy(ip_pkt, ip_hdr, len);

        /* Find longest prefix match in routing table. */
        struct sr_rt* lpmatch = 0;
        lpmatch = longest_prefix_matching(sr, ip_hdr->ip_dst);
        
        /* If cannot find destination IP in routing table, send ICMP net unreachable */
        /* OR TTL = 0 */
        if (lpmatch == 0 || ip_hdr->ip_ttl == 0) {
        
            /* Send ICMP net unreachable */
            struct sr_ip_hdr send_ip_hdr;
            send_ip_hdr.ip_hl = 5;
            send_ip_hdr.ip_v = ip_hdr->ip_v;
            send_ip_hdr.ip_tos = 0;
            send_ip_hdr.ip_id = ip_hdr->ip_id;
            send_ip_hdr.ip_off = htons(IP_DF);
            send_ip_hdr.ip_ttl = 64;
            send_ip_hdr.ip_p = ip_protocol_icmp;
            send_ip_hdr.ip_sum = 0;
            send_ip_hdr.ip_dst = ip_hdr->ip_src;
            send_ip_hdr.ip_src = r_interface->ip;
            dst = ip_hdr->ip_src;

            struct sr_icmp_t3_hdr error_packet;
          	/* Modify the ICMP error packet */
            if (lpmatch == 0) {
              error_packet.icmp_type = 3;
              error_packet.icmp_code = 0;
            } else {
              error_packet.icmp_type = 11;
              error_packet.icmp_code = 0;             
            }
            error_packet.icmp_sum = 0;
            error_packet.unused = 0;
            error_packet.next_mtu = htons(MTU);

            icmp_len = sizeof(struct sr_icmp_t3_hdr);
            total_len = ICMP_IP_HDR_LEN_BYTE + icmp_len;

            send_ip_hdr.ip_len = htons(total_len);
            send_ip_hdr.ip_sum = cksum(&send_ip_hdr, ICMP_IP_HDR_LEN_BYTE);

            cache_packet = malloc(total_len);
            memcpy(error_packet.data, ip_hdr, ICMP_DATA_SIZE);

            memcpy(cache_packet, &(send_ip_hdr), ICMP_IP_HDR_LEN_BYTE);
            memcpy(cache_packet + ICMP_IP_HDR_LEN_BYTE, &(error_packet), 
              sizeof(struct sr_icmp_t3_hdr));
            
            /*Check if we should send immediately or wait */
            struct sr_arpentry *arp_entry;
            arp_entry = sr_arpcache_lookup(&sr->cache, dst);

            struct sr_icmp_hdr *icmp_hdr_ptr;
            icmp_hdr_ptr = icmp_header((struct sr_ip_hdr *)cache_packet);
            icmp_hdr_ptr->icmp_sum = cksum(icmp_hdr_ptr, icmp_len);

            if (arp_entry != 0){
                /* Entry Exists, we can send it out right now */
                sr_add_ethernet_send(sr, cache_packet, total_len, dst, ethertype_ip);
            } else {
                req = sr_arpcache_queuereq(&(sr->cache), dst, 
                    cache_packet, total_len, interface);
            }  
            return;
        }

        /* Get the corresponding interface of the destination IP. */
        struct sr_if* s_interface = sr_get_interface(sr, lpmatch->interface);
      
        /* Check ARP cache */
        arp_entry = sr_arpcache_lookup(&sr->cache, lpmatch->gw.s_addr);

        if (arp_entry == 0){
            /* IF miss APR cache, add the packet to ARP request queue */
            req = sr_arpcache_queuereq(&sr->cache, lpmatch->gw.s_addr, ip_pkt, 
                  len, s_interface->name);
            sr_handle_arpreq(sr, req);
        } else{

            /* Hit ARP cache, send out the packet right away, next-hop */

            /* Encap the arp request into ethernet frame and then send it */
            sr_ethernet_hdr_t sr_ether_pkt;

            memcpy(sr_ether_pkt.ether_dhost, arp_entry->mac, ETHER_ADDR_LEN); /*address from routing table*/
            memcpy(sr_ether_pkt.ether_shost, s_interface->addr, ETHER_ADDR_LEN); /*hardware address of the outgoing interface*/
            sr_ether_pkt.ether_type = htons(ethertype_ip);

            uint8_t *packet_rqt;
            unsigned int total_len = len + sizeof(struct sr_ethernet_hdr);
            packet_rqt = malloc(total_len);
            memcpy(packet_rqt, &(sr_ether_pkt), sizeof(sr_ether_pkt));
            memcpy(packet_rqt + sizeof(sr_ether_pkt), ip_pkt, len);

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

          printf("** Port Unreachable\n");
          /* Send ICMP host unreachable*/
          struct sr_packet *ip_packet;
          ip_packet = req->packets;

          sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(ip_packet->buf);
          struct sr_if *r_interface = sr_get_interface(sr, ip_packet->iface);

          uint32_t dst;
          /* Send ICMP net unreachable */
          struct sr_ip_hdr send_ip_hdr;
          send_ip_hdr.ip_hl = 5;
          send_ip_hdr.ip_v = ip_hdr->ip_v;
          send_ip_hdr.ip_tos = 0;
          send_ip_hdr.ip_id = ip_hdr->ip_id;
          send_ip_hdr.ip_off = htons(IP_DF);
          send_ip_hdr.ip_ttl = 64;
          send_ip_hdr.ip_p = ip_protocol_icmp;
          send_ip_hdr.ip_sum = 0;
          send_ip_hdr.ip_dst = ip_hdr->ip_src;
          send_ip_hdr.ip_src = r_interface->ip;
          dst = ip_hdr->ip_src;
  	      
          /* Copy the packet over */
          uint8_t *cache_packet;
          uint16_t total_len;
          uint16_t icmp_len;

          icmp_len = sizeof(struct sr_icmp_t3_hdr);
          total_len = ICMP_IP_HDR_LEN_BYTE + icmp_len;
          cache_packet = malloc(total_len);
          struct sr_icmp_t3_hdr icmp_error_packet = icmp_send_error_packet(ip_hdr, 1);

          memcpy(cache_packet, &(send_ip_hdr), ICMP_IP_HDR_LEN_BYTE);
          memcpy(cache_packet + ICMP_IP_HDR_LEN_BYTE, &(icmp_error_packet), 
              sizeof(struct sr_icmp_t3_hdr));

          print_hdr_ip(cache_packet);

          struct sr_arpreq *req;
          struct sr_arpentry *arp_entry;

          /* Check ARP cache  */
          arp_entry = sr_arpcache_lookup(&sr->cache, dst);

          if (arp_entry != 0){
              /* Entry Exists, we can send it out right now */
              sr_add_ethernet_send(sr, cache_packet, total_len, dst, ethertype_ip);
          } else {
              req = sr_arpcache_queuereq(&(sr->cache), dst, 
                    cache_packet, total_len, r_interface->name);
          }  

      } else {
          arp_boardcast(sr, req);
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
    unsigned int hdr_len = ip_hl(ip_hdr);

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
    sr_icmp_hdr_t *icmp_hdr = icmp_header(ip_hdr);
    uint16_t c_cksum;
    uint16_t r_cksum;

    /* Check cksum */
    r_cksum = icmp_hdr->icmp_sum;
    icmp_hdr->icmp_sum = 0;
    c_cksum = cksum(icmp_hdr, ip_len(ip_hdr)-ip_hl(ip_hdr));
    if(c_cksum != r_cksum){
      return 0;
    }

    return 1;
}

int sr_packet_is_for_me(struct sr_instance* sr, uint32_t ip_dst)
{
    /* -- REQUIRES -- */

    struct sr_if* if_walker = sr->if_list;
    while(if_walker) {
      if(ip_dst == if_walker->ip){
        return 1;
      }
      if_walker = if_walker->next;
    }
    return 0;
}

void arp_boardcast(struct sr_instance* sr, struct sr_arpreq *req)
{
      /* Initalize ARP header and Input Interface */
      struct sr_arp_hdr arp_boarcast;
      struct sr_if *interface;

      /* Get outgoing Interface */
      interface = sr_get_interface(sr, req->packets->iface);

      /* set value of arp packet  */
      arp_boarcast.ar_hrd = htons(arp_hrd_ethernet);
      arp_boarcast.ar_pro = htons(arp_pro_ip);
      arp_boarcast.ar_hln = ETHER_ADDR_LEN;
      arp_boarcast.ar_pln = ARP_PLEN;
      arp_boarcast.ar_op = htons(arp_op_request);
      arp_boarcast.ar_sip = interface->ip;
      arp_boarcast.ar_tip = req->ip;
  
      memcpy(arp_boarcast.ar_sha, interface->addr, ETHER_ADDR_LEN); 
      memset(arp_boarcast.ar_tha, 255, ETHER_ADDR_LEN);

      /* Build the Ethernet Packet */
      struct sr_ethernet_hdr sr_ether_pkt;
      memcpy(sr_ether_pkt.ether_shost, interface->addr, ETHER_ADDR_LEN);
      memset(sr_ether_pkt.ether_dhost, 255, ETHER_ADDR_LEN);
      sr_ether_pkt.ether_type = htons(ethertype_arp);

      /* Copy the Packet into the sender buf */
      uint8_t *send_packet;
      unsigned int eth_pkt_len;
      eth_pkt_len = sizeof(arp_boarcast) + sizeof(sr_ether_pkt);
      send_packet = malloc(eth_pkt_len);
      memcpy(send_packet, &sr_ether_pkt, sizeof(sr_ether_pkt));
      memcpy(send_packet + sizeof(sr_ether_pkt), &arp_boarcast, sizeof(arp_boarcast));

      /* send the reply*/
      sr_send_packet(sr, send_packet, eth_pkt_len, interface->name);
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

struct sr_icmp_t3_hdr icmp_send_error_packet(struct sr_ip_hdr *ip_hdr, int code_num)
{

    struct sr_icmp_t3_hdr icmp_error_reply;
    
    icmp_error_reply.icmp_type = 3;
    memcpy(icmp_error_reply.data, ip_hdr, ICMP_DATA_SIZE);

    icmp_error_reply.icmp_code = code_num;
    
    icmp_error_reply.next_mtu = htons(MTU);
    icmp_error_reply.icmp_sum = 0;
    icmp_error_reply.unused = 0;
    icmp_error_reply.icmp_sum = cksum(&(icmp_error_reply), ICMP_TYPE3_LEN);

    return icmp_error_reply;
}

