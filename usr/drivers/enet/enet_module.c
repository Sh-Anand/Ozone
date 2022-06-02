/**
 * \file
 * \brief imx8 NIC driver module
 */
/*
 * Copyright (c) 2019, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <devif/queue_interface_backend.h>
#include <devif/backends/net/enet_devif.h>
#include <aos/aos.h>
#include <aos/deferred.h>
#include <driverkit/driverkit.h>
#include <dev/imx8x/enet_dev.h>

#include <netutil/htons.h>
#include <netutil/etharp.h>
#include <netutil/ip.h>
#include <netutil/checksum.h>
#include <netutil/icmp.h>
#include <netutil/udp.h>

#include "enet.h"

#define PHY_ID 0x2

static errval_t enet_write_mdio(struct enet_driver_state* st, int8_t phyaddr,
                                int8_t regaddr, int16_t data)
{

    // Some protocol ...

    enet_mmfr_t reg = 0;
    reg = enet_mmfr_pa_insert(reg, phyaddr);
    reg = enet_mmfr_ra_insert(reg, regaddr);
    reg = enet_mmfr_data_insert(reg, data);
    reg = enet_mmfr_st_insert(reg, 0x1);
    reg = enet_mmfr_ta_insert(reg, 0x2);

    // 1 is write 2 is read
    reg = enet_mmfr_op_insert(reg, 0x1);

    ENET_DEBUG("Write MDIO: write cmd %lx \n", reg);

    enet_mmfr_wr(st->d, reg);

    uint16_t tries = 1000;
    while (!(enet_eir_mii_rdf(st->d) & 0x1)) {
        tries--;
        //barrelfish_usleep(10);
        if (tries == 0) {
            return ENET_ERR_MDIO_WRITE;
        }
    }

    enet_eir_mii_wrf(st->d, 0x1);
    return SYS_ERR_OK;
}

static errval_t enet_read_mdio(struct enet_driver_state* st, int8_t phyaddr,
                               int8_t regaddr, int16_t *data)
{

    // Some protocol ...
    enet_eir_mii_wrf(st->d, 0x1);

    enet_mmfr_t reg = 0;
    reg = enet_mmfr_pa_insert(reg, phyaddr);
    reg = enet_mmfr_ra_insert(reg, regaddr);
    reg = enet_mmfr_st_insert(reg, 0x1);
    reg = enet_mmfr_ta_insert(reg, 0x2);
    // 1 is write 2 is read
    reg = enet_mmfr_op_insert(reg, 0x2);

    enet_mmfr_wr(st->d, reg);

    ENET_DEBUG("Read MDIO: read cmd %lx \n", reg);

    uint16_t tries = 1000;
    while (!(enet_eir_mii_rdf(st->d) & 0x1)) {
        barrelfish_usleep(10);
        tries--;
        if (tries == 0) {
            return ENET_ERR_MDIO_WRITE;
        }
    }

    enet_eir_mii_wrf(st->d, 0x1);
    *data = enet_mmfr_data_rdf(st->d);

    return SYS_ERR_OK;
}

static errval_t enet_get_phy_id(struct enet_driver_state* st)
{
    errval_t err;
    int16_t data;
    uint32_t phy_id;

    // get phy ID1
    err = enet_read_mdio(st, PHY_ID,  0x2, &data);
    if (err_is_fail(err))  {
        return err;
    }
    phy_id = data << 16;

    // get phy ID2
    err = enet_read_mdio(st, PHY_ID,  0x3, &data);
    if (err_is_fail(err))  {
        return err;
    }

    phy_id |= data;
    st->phy_id = phy_id;
    return err;
}

#define PHY_RESET 0x8000

#define PHY_RESET_CMD 0x0
#define PHY_STATUS_CMD 0x1
#define PHY_AUTONEG_CMD 0x4
#define PHY_LPA_CMD 0x5
#define PHY_CTRL1000_CMD 0x09
#define PHY_STAT1000_CMD 0x0a

static errval_t enet_reset_phy(struct enet_driver_state* st)
{
    errval_t err;
    err = enet_write_mdio(st, PHY_ID, PHY_RESET_CMD, PHY_RESET);
    if (err_is_fail(err))  {
        return err;
    }

    int16_t data;
    err = enet_read_mdio(st, PHY_ID, PHY_RESET_CMD, &data);
    if (err_is_fail(err))  {
        return err;
    }

    int timeout = 500;
    while ((data & PHY_RESET) && timeout > 0) {
        err = enet_read_mdio(st, PHY_ID, PHY_RESET_CMD, &data);
        if (err_is_fail(err))  {
            return err;
        }

        barrelfish_usleep(1000);
        timeout--;
    }

    if (data & PHY_RESET) {
        return ENET_ERR_PHY_RESET;
    }

    return SYS_ERR_OK;
}

static errval_t enet_setup_autoneg(struct enet_driver_state* st)
{
    errval_t err;
    int16_t status;
    int16_t autoneg;

    // Read BASIC MODE status register
    err = enet_read_mdio(st, PHY_ID, 0x1, &status);
    if (err_is_fail(err))  {
        return err;
    }

    // READ autoneg status
    err = enet_read_mdio(st, PHY_ID, PHY_AUTONEG_CMD, &autoneg);
    if (err_is_fail(err))  {
        return err;
    }

    // Read BASIC contorl register
    err = enet_read_mdio(st, PHY_ID, PHY_RESET_CMD, &status);
    if (err_is_fail(err))  {
        return err;
    }

    return SYS_ERR_OK;
}

#define AUTONEG_100FULL 0x0100
#define AUTONEG_100HALF 0x0080
#define AUTONEG_10FULL  0x0040
#define AUTONEG_10HALF  0x0020
#define AUTONEG_PSB_802_3 0x0001

#define AUTONEG_ENABLE 0x1000
#define AUTONEG_RESTART 0x0200
static errval_t enet_restart_autoneg(struct enet_driver_state* st)
{
    errval_t err;
    err = enet_write_mdio(st, PHY_ID, PHY_RESET_CMD, PHY_RESET);
    if (err_is_fail(err)) {
        return err;
    }

    barrelfish_usleep(1000);
    //barrelfish_usleep(1000);

    err = enet_write_mdio(st, PHY_ID, PHY_AUTONEG_CMD,
                          AUTONEG_100FULL | AUTONEG_100HALF | AUTONEG_10FULL |
                          AUTONEG_10HALF | AUTONEG_PSB_802_3);
    if (err_is_fail(err)) {
        return err;
    }

    err = enet_write_mdio(st, PHY_ID, PHY_RESET_CMD,
                          AUTONEG_ENABLE | AUTONEG_RESTART);
    if (err_is_fail(err)) {
        return err;
    }

    return SYS_ERR_OK;
}


static errval_t enet_init_phy(struct enet_driver_state* st)
{
    errval_t err;
    err = enet_get_phy_id(st);
    if (err_is_fail(err))  {
        return err;
    }

    err = enet_reset_phy(st);
    if (err_is_fail(err))  {
        return err;
    }

    // board_phy_config in uboot driver. Don't know what
    // this actually does ...
    err = enet_write_mdio(st, PHY_ID, 0x1d, 0x1f);
    assert(err_is_ok(err));
    err = enet_write_mdio(st, PHY_ID, 0x1e, 0x8);
    assert(err_is_ok(err));
    err = enet_write_mdio(st, PHY_ID, 0x1d, 0x00);
    assert(err_is_ok(err));
    err = enet_write_mdio(st, PHY_ID, 0x1e, 0x82ee);
    assert(err_is_ok(err));
    err = enet_write_mdio(st, PHY_ID, 0x1d, 0x05);
    assert(err_is_ok(err));
    err = enet_write_mdio(st, PHY_ID, 0x1e, 0x100);
    assert(err_is_ok(err));

    err = enet_setup_autoneg(st);
    if (err_is_fail(err))  {
        return err;
    }

    return SYS_ERR_OK;
}



#define PHY_STATUS_LSTATUS 0x0004
#define PHY_STATUS_ANEG_COMP 0x0020
#define PHY_STATUS_ESTAT 0x0100
#define PHY_STATUS_ERCAP 0x0001


#define PHY_LPA_100HALF  0x0080
#define PHY_LPA_100FULL 0x0100
#define PHY_LPA_10FULL  0x0040
// TODO check for rest of link capabilities
static void enet_parse_link(struct enet_driver_state* st)
{
    // just a sanity check if values are ok
    errval_t err;
    int16_t status;
    err = enet_read_mdio(st, PHY_ID, PHY_STAT1000_CMD, &status);
    assert(err_is_ok(err));

    int16_t mii_reg;
    err = enet_read_mdio(st, PHY_ID, PHY_STATUS_CMD, &mii_reg);
    assert(err_is_ok(err));

    if (status < 0) {
        debug_printf("ENET not capable of 1G \n");
        return;
    } else {
        err = enet_read_mdio(st, PHY_ID, PHY_CTRL1000_CMD, &status);
        assert(err_is_ok(err));

        if (status == 0) {
            int16_t lpa, lpa2;
            err = enet_read_mdio(st, PHY_ID, PHY_AUTONEG_CMD, &lpa);
            assert(err_is_ok(err));

            err = enet_read_mdio(st, PHY_ID, PHY_LPA_CMD, &lpa2);
            assert(err_is_ok(err));

            lpa &= lpa2;
            if (lpa & (PHY_LPA_100FULL | PHY_LPA_100HALF)) {
                if (lpa & PHY_LPA_100FULL) {
                    debug_printf("LINK 100 Mbit/s FULL duplex \n");
                } else {
                    debug_printf("LINK 100 Mbit/s half\n");
                }
            }
        }
    }

}

static errval_t enet_phy_startup(struct enet_driver_state* st)
{
    errval_t err;
    // board_phy_config in uboot driver. Don't know what
    // this actually does ...
    int16_t mii_reg;
    err = enet_read_mdio(st, PHY_ID, PHY_STATUS_CMD, &mii_reg);
    assert(err_is_ok(err));

    if (mii_reg & PHY_STATUS_LSTATUS) {
        debug_printf("LINK already UP\n");
        return SYS_ERR_OK;
    }

    if (!(mii_reg & PHY_STATUS_ANEG_COMP)) {

        debug_printf("[enet] Starting autonegotiation \n");
        while(!(mii_reg & PHY_STATUS_ANEG_COMP))  {
            err = enet_read_mdio(st, PHY_ID, PHY_STATUS_CMD, &mii_reg);
            assert(err_is_ok(err));
            barrelfish_usleep(1000);
        }

        ENET_DEBUG("Autonegotation done\n");
    }

    enet_parse_link(st);

    return SYS_ERR_OK;
}

// bool promiscous for promiscous mode.
// This will also set it so that all multicast packets will also be received!
/*
static void enet_init_multicast_filt(struct enet_driver_state* st, bool promisc)
{
    if (promisc) {
        enet_rcr_prom_wrf(st->d, 1);
        return;
    }

    enet_rcr_prom_wrf(st->d, 0);

    // TODO Catching all multicast packets for now
    enet_gaur_wr(st->d, 0xFFFFFFFF);
    enet_galr_wr(st->d, 0xFFFFFFFF);
    // TODO if we do not catch all multicast packet then do this:
    // crc32 value of mac address
    #if 0
    unsigned int crc = 0xffffffff;
    unsigned char hash;
    unsigned int hash_high = 0, hash_low = 0;
    for (int i = 0; i < 6; i++) {
        unsigned char data = ((uint8_t*) &st->mac)[i];

        for (int bit = 0; bit < 8; bit++, data >>= 1) {
            crc = (crc >> 1) ^ (((crc ^ data) & 1) ? ENET_CRC32_POLY : 0);
        }

        hash = (crc >> (32 - ENET_HASH_BITS)) & 0x3f;

        if (hash > 31) {
            hash_high |= 1 << (hash - 32);
        } else {
            hash_low |= 1 << hash;
        }
    }

    enet_gaur_gaddr_wrf(st->d, hash_high);
    enet_galr_gaddr_wrf(st->d, hash_low);
    #endif
    // TODO if this is M5272 then set the hash table entries to 0 ...
}
*/

static void enet_read_mac(struct enet_driver_state* st)
{
    uint32_t lower = enet_palr_paddr1_rdf(st->d);
    uint32_t upper = enet_paur_paddr2_rdf(st->d);

    st->mac.addr[5] = upper;
    upper >>= 8;
    st->mac.addr[4] = upper;
    st->mac.addr[3] = lower;
    lower >>= 8;
    st->mac.addr[2] = lower;
    lower >>= 8;
    st->mac.addr[1] = lower;
    lower >>= 8;
    st->mac.addr[0] = lower;

    ENET_DEBUG("MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", st->mac.addr[0], st->mac.addr[1], st->mac.addr[2], st->mac.addr[3], st->mac.addr[4], st->mac.addr[5]);
}

static void enet_write_mac(struct enet_driver_state* st)
{
    uint32_t upper;
    uint32_t lower;

    lower = st->mac.addr[0];
    lower <<= 8;
    lower |= st->mac.addr[1];
    lower <<= 8;
    lower |= st->mac.addr[2];
    lower <<= 8;
    lower |= st->mac.addr[3];
    upper = st->mac.addr[4];
    upper <<= 8;
    upper |= st->mac.addr[5];

    enet_palr_paddr1_wrf(st->d, lower);
    enet_paur_paddr2_wrf(st->d, upper);
}

static errval_t enet_reset(struct enet_driver_state* st)
{
    // reset device
    ENET_DEBUG("Reset device\n");

    uint64_t ecr = enet_ecr_rd(st->d);
    enet_ecr_wr(st->d, ecr | 0x1);
    int timeout = 500;
    while ((enet_ecr_rd(st->d) & 0x1) && timeout > 0) {
        barrelfish_usleep(10);
        // TODO timeout
    }

    if (timeout <= 0) {
        return ENET_ERR_DEV_RESET;
    }

    return SYS_ERR_OK;
}

static void enet_reg_setup(struct enet_driver_state* st)
{
    // Set interrupt mask register
    ENET_DEBUG("Set interrupt mask register\n");
    enet_eimr_wr(st->d, 0x0);
    // Clear outstanding interrupts
    ENET_DEBUG("Clear outstanding interrupts\n");
    enet_eir_wr(st->d, 0xFFFFFFFF);

    uint64_t reg;
    // TODO see if other fields are required, not in dump
    reg = enet_rcr_rd(st->d);
    reg = enet_rcr_loop_insert(reg, 0x0);
    reg = enet_rcr_rmii_mode_insert(reg, 0x1);
    reg = enet_rcr_mii_mode_insert(reg, 0x1);
    reg = enet_rcr_fce_insert(reg, 0x1);
    reg = enet_rcr_max_fl_insert(reg, 1522);
    //reg = enet_rcr_prom_insert(reg, 1);
    enet_rcr_wr(st->d, reg);
}

static errval_t enet_open(struct enet_driver_state *st)
{
    errval_t err = SYS_ERR_OK;
    // Enable full duplex, disable heartbeet
    enet_tcr_fden_wrf(st->d, 0x1);

    // Enable HW endian swap
    enet_ecr_dbswp_wrf(st->d, 0x1);
    enet_ecr_en1588_wrf(st->d, 0x0);
    // Enable store and forward mode
    enet_tfwr_strfwd_wrf(st->d, 0x1);
    // Enable controler
    enet_ecr_etheren_wrf(st->d, 0x1);

    // TODO don't think this is MX25/MX53 or MX6SL
    // Startup PHY
    err = enet_phy_startup(st);
    if (err_is_fail(err))  {
        return err;
    }

    uint8_t speed = enet_ecr_speed_rdf(st->d);

    if (!speed) {
        enet_rcr_rmii_10t_wrf(st->d, 0x0);
    }

    //enet_activate_rx_ring(st);
    ENET_DEBUG("Init done! \n");
    return err;
}

static errval_t enet_init(struct enet_driver_state* st)
{
    errval_t err = SYS_ERR_OK;
    // set HW addreses
    enet_iaur_wr(st->d, 0);
    enet_ialr_wr(st->d, 0);
    enet_gaur_wr(st->d, 0);
    enet_galr_wr(st->d, 0);
    enet_write_mac(st);

    enet_reg_setup(st);

    uint64_t reg;
    // Set MII speed, do not drop preamble and set hold time to 10ns
    reg = enet_mscr_rd(st->d);
    reg = enet_mscr_mii_speed_insert(reg, 0x18);
    reg = enet_mscr_hold_time_insert(reg, 0x1);
    enet_mscr_wr(st->d, reg);

    // Set Opcode and Pause duration
    enet_opd_wr(st->d, 0x00010020);
    enet_tfwr_tfwr_wrf(st->d, 0x2);

    // Set multicast addr filter
    enet_gaur_wr(st->d, 0);
    enet_galr_wr(st->d, 0);

    // Max pkt size rewrite ...
    enet_mrbr_wr(st->d, 0x600);

    // Tell card beginning of rx/tx rings
    //enet_rdsr_wr(st->d, st->rxq->desc_mem.devaddr);
    //enet_tdsr_wr(st->d, st->txq->desc_mem.devaddr);

    err = enet_restart_autoneg(st);
    if (err_is_fail(err)) {
        return err;
    }

    err = enet_open(st);
    if (err_is_fail(err)) {
        // TODO cleanup
        return err;
    }

    return err;
}

static errval_t enet_probe(struct enet_driver_state* st)
{
    errval_t err;
    err = enet_reset(st);
    if (err_is_fail(err)) {
        return err;
    }

    enet_reg_setup(st);

    uint64_t reg;
    // Set MII speed, do not drop preamble and set hold time to 10ns
    reg = enet_mscr_rd(st->d);
    reg = enet_mscr_mii_speed_insert(reg, 0x18);
    reg = enet_mscr_hold_time_insert(reg, 0x1);
    enet_mscr_wr(st->d, reg);

    err = enet_init_phy(st);
    if (err_is_fail(err))  {
        debug_printf("Failed PHY reset\n");
        return err;
    }

    // Write back mac again
    ENET_DEBUG("Reset MAC\n");
    // TODO do this later? NOT in dump
    enet_write_mac(st);
    enet_read_mac(st);

    // TODO checked dump until here!
    return SYS_ERR_OK;
}

static errval_t enet_enqueue(struct enet_queue *q, struct devq_buf *buf) {
    return devq_enqueue((struct devq*) q, buf->rid, buf->offset, buf->length, buf->valid_data, buf->valid_length, buf->flags);
}

static errval_t enet_dequeue(struct enet_queue *q, struct devq_buf *buf) {
    return devq_dequeue((struct devq*) q, &buf->rid, &buf->offset, &buf->length, &buf->valid_data, &buf->valid_length, &buf->flags);
}

static errval_t add_tx_buf(struct enet_driver_state *st, genoffset_t offset) {
    // Offset must be multiple
    if (offset % ENET_MAX_BUF_SIZE) return ERR_INVALID_ARGS;

    struct buf_node *node = malloc(sizeof(struct buf_node));
    if (node == NULL) return NIC_ERR_UNKNOWN;

    node->buf.offset = offset;
    node->buf.length = ENET_MAX_BUF_SIZE;
    node->buf.valid_data = ENET_MAX_BUF_SIZE - ENET_MAX_PKT_SIZE;
    node->buf.valid_length = 0;
    node->buf.flags = 0;
    node->buf.rid = st->tx_rid;

    // Add to singly linked list
    node->next = st->tx_bufs;
    st->tx_bufs = node;

    return SYS_ERR_OK;
}

static errval_t free_tx_buf(struct enet_driver_state *st, struct devq_buf *buf) {
    if (buf->rid != st->tx_rid || buf->flags != 0 || buf->length != ENET_MAX_BUF_SIZE) return ERR_INVALID_ARGS;

    return add_tx_buf(st, buf->offset);
}

static errval_t alloc_tx_buf(struct enet_driver_state *st, struct buf_node **tx_buf, bool is_arp) {
    // Reserve last buffer for arp
    if (st->tx_bufs->next || (is_arp && st->tx_bufs)) {
        *tx_buf = st->tx_bufs;
        st->tx_bufs = (*tx_buf)->next;
        (*tx_buf)->next = NULL;

        return SYS_ERR_OK;
    }
    else return NIC_ERR_ALLOC_BUF;
}

static errval_t create_cache_entry(struct buf_node *pending, struct cache_entry **entry) {
    // Only cache, arp query is triggered by sending ip packet. Hence, there has to be a pending buffer
    if (pending == NULL || pending->next) return ERR_INVALID_ARGS;

    *entry = malloc(sizeof(struct cache_entry));
    if (*entry == NULL) return NIC_ERR_UNKNOWN;

    (*entry)->mac = query_mac;
    (*entry)->pending = pending;

    return SYS_ERR_OK;
}

static errval_t send_ethernet(struct enet_driver_state *st, struct buf_node *tx_buf, struct eth_addr dst_mac, uint16_t eth_type) {
    if (tx_buf == NULL || tx_buf->next) return ERR_INVALID_ARGS;
    if (tx_buf->buf.valid_data < ETH_HLEN) return NIC_ERR_TX_PKT;
    tx_buf->buf.valid_data -= ETH_HLEN;
    tx_buf->buf.valid_length += ETH_HLEN;

    struct eth_hdr *hdr = (struct eth_hdr*) ((char*)st->tx_mem_addr + tx_buf->buf.offset + tx_buf->buf.valid_data);

    hdr->dst = dst_mac;
    hdr->src = st->mac;
    hdr->type = htons(eth_type);

    errval_t err = enet_enqueue(st->txq, &tx_buf->buf);
    if (err_is_fail(err)) return err;
    free(tx_buf);

    return SYS_ERR_OK;
}

static errval_t send_arp(struct enet_driver_state *st, uint16_t opcode, struct eth_addr dst_mac, ip_addr_t dst_ip) {
    struct buf_node *tx_buf;
    errval_t err = alloc_tx_buf(st, &tx_buf, true);
    if (err_is_fail(err)) return err;

    if (tx_buf->buf.valid_data + tx_buf->buf.valid_length + ARP_HLEN > tx_buf->buf.length) return NIC_ERR_TX_PKT;
    tx_buf->buf.valid_length += ARP_HLEN;

    struct arp_hdr *hdr = (struct arp_hdr*) ((char*)st->tx_mem_addr + tx_buf->buf.offset + tx_buf->buf.valid_data);

    hdr->hwtype = htons(ARP_HW_TYPE_ETH);
    hdr->proto = htons(ARP_PROT_IP);
    hdr->hwlen = ETH_ADDR_LEN;
    hdr->protolen = IP_ADDR_LEN;
    hdr->opcode = htons(opcode);
    hdr->eth_src = st->mac;
    hdr->ip_src = htonl(st->ip_addr);
    hdr->eth_dst = dst_mac;
    hdr->ip_dst = htonl(dst_ip);

    err = send_ethernet(st, tx_buf, broadcast_mac, ETH_TYPE_ARP);
    if (err_is_fail(err)) return err;

    return SYS_ERR_OK;
}

static errval_t query_arp(struct enet_driver_state *st, ip_addr_t ip) {
    return send_arp(st, ARP_OP_REQ, query_mac, ip);
}

static errval_t answer_arp(struct enet_driver_state *st, struct eth_addr mac, ip_addr_t ip) {
    return send_arp(st, ARP_OP_REP, mac, ip);
}

static errval_t send_ip(struct enet_driver_state *st, struct buf_node *tx_buf, ip_addr_t dst_ip, uint8_t proto) {
    if (tx_buf == NULL || tx_buf->next) return ERR_INVALID_ARGS;

    if (tx_buf->buf.valid_data < IP_HLEN) return NIC_ERR_TX_PKT;
    tx_buf->buf.valid_data -= IP_HLEN;
    tx_buf->buf.valid_length += IP_HLEN;

    struct ip_hdr *hdr = (struct ip_hdr*) ((char*)st->tx_mem_addr + tx_buf->buf.offset + tx_buf->buf.valid_data);

    IPH_VHL_SET(hdr, IP_VERSION, IP_HLEN_32);
    hdr->tos = IP_TOS;
    hdr->len = htons(tx_buf->buf.valid_length);
    hdr->id = htons(st->ip_id++);
    hdr->offset = htons(IP_NO_FRAGMENT);
    hdr->ttl = IP_TTL;
    hdr->proto = proto;
    hdr->chksum = htons(IP_NO_CHECKSUM);
    hdr->src = htonl(st->ip_addr);
    hdr->dest = htonl(dst_ip);

    hdr->chksum = inet_checksum(hdr, IP_HLEN);

    struct cache_entry *entry = collections_hash_find(st->arp_cache, dst_ip);

    if (entry == NULL) { // First time packet for MAC is available, send request
        errval_t err = create_cache_entry(tx_buf, &entry);
        if (err_is_fail(err)) return err;
        collections_hash_insert(st->arp_cache, dst_ip, entry);

        return query_arp(st, dst_ip);
    } else if (entry->pending) { // We encountered the MAC before but got no answer, so ask again
        tx_buf->next = entry->pending;
        entry->pending = tx_buf;

        return query_arp(st, dst_ip);
    } else {
        return send_ethernet(st, tx_buf, entry->mac, ETH_TYPE_IP);
    }
}

static errval_t send_icmp_echo(struct enet_driver_state *st, struct buf_node *tx_buf, uint8_t type, uint16_t identifier, uint16_t sequence_number, ip_addr_t dst_ip) {
    if (tx_buf == NULL || tx_buf->next) return ERR_INVALID_ARGS;
    if (tx_buf->buf.valid_data < ICMP_HLEN) return NIC_ERR_TX_PKT;
    tx_buf->buf.valid_data -= ICMP_HLEN;
    tx_buf->buf.valid_length += ICMP_HLEN;

    struct icmp_echo_hdr *hdr = (struct icmp_echo_hdr*) ((char*)st->tx_mem_addr + tx_buf->buf.offset + tx_buf->buf.valid_data);

    ICMPH_TYPE_SET(hdr, type);
    ICMPH_CODE_SET(hdr, ICMP_ECHO_CODE);
    hdr->chksum = htons(ICMP_NO_CHECKSUM);
    hdr->id = htons(identifier);
    hdr->seqno = htons(sequence_number);

    hdr->chksum = inet_checksum(hdr, tx_buf->buf.valid_length);

    errval_t err = send_ip(st, tx_buf, dst_ip, IP_PROTO_ICMP);
    if (err_is_fail(err)) return err;

    return SYS_ERR_OK;
}

static errval_t send_udp(struct enet_driver_state *st, struct buf_node *tx_buf, uint16_t src_port, uint16_t dst_port, ip_addr_t dst_ip) {
    if (tx_buf == NULL || tx_buf->next) return ERR_INVALID_ARGS;
    if (tx_buf->buf.valid_data < UDP_HLEN + UDP_PSEUDO_HLEN) return NIC_ERR_TX_PKT; // There should be space for the pseudo header as other headers will be added later
    tx_buf->buf.valid_data -= UDP_HLEN;
    tx_buf->buf.valid_length += UDP_HLEN;

    struct udp_hdr *hdr = (struct udp_hdr*) ((char*)st->tx_mem_addr + tx_buf->buf.offset + tx_buf->buf.valid_data);
    struct udp_pseudo_hdr *_hdr = (struct udp_pseudo_hdr*) ((char*)st->tx_mem_addr + tx_buf->buf.offset + tx_buf->buf.valid_data - UDP_PSEUDO_HLEN);

    hdr->src = htons(src_port);
    hdr->dest = htons(dst_port);
    hdr->len = htons(tx_buf->buf.valid_length);
    hdr->chksum = htons(UDP_NO_CHECKSUM);

    _hdr->src = htonl(st->ip_addr);
    _hdr->dst = htonl(dst_ip);
    _hdr->zeroes = 0;
    _hdr->protocol = IP_PROTO_UDP;
    _hdr->len = htons(tx_buf->buf.valid_length);

    hdr->chksum = inet_checksum(_hdr, tx_buf->buf.valid_length + UDP_PSEUDO_HLEN);

    errval_t err = send_ip(st, tx_buf, dst_ip, IP_PROTO_UDP);
    if (err_is_fail(err)) return err;

    return SYS_ERR_OK;
}

static errval_t handle_udp(struct enet_driver_state *st, struct devq_buf *rx_buf, ip_addr_t src_ip) {
    errval_t err;
    if (rx_buf == NULL) return ERR_INVALID_ARGS;

    if (rx_buf->valid_length < UDP_HLEN) return NIC_ERR_RX_PKT;
    struct udp_hdr *hdr = (struct udp_hdr*) ((char*)st->rx_mem_addr + rx_buf->offset + rx_buf->valid_data);
    rx_buf->valid_data += UDP_HLEN;
    rx_buf->valid_length -= UDP_HLEN;

    if (hdr->chksum) { // checksum is optional
        struct udp_pseudo_hdr *_hdr = malloc(rx_buf->valid_length + UDP_HLEN + UDP_PSEUDO_HLEN); // hdr is readonly!
        if (_hdr == NULL) return NIC_ERR_UNKNOWN;
        _hdr->src = htonl(src_ip);
        _hdr->dst = htonl(st->ip_addr);
        _hdr->zeroes = 0;
        _hdr->protocol = IP_PROTO_UDP;
        _hdr->len = htons(rx_buf->valid_length + UDP_HLEN);
        memcpy(_hdr + 1, hdr, rx_buf->valid_length + UDP_HLEN);
        ((struct udp_hdr*)(_hdr + 1))->chksum = htons(UDP_NO_CHECKSUM);
        uint16_t checksum = inet_checksum(_hdr, rx_buf->valid_length + UDP_HLEN + UDP_PSEUDO_HLEN);
        free(_hdr);
        if (hdr->chksum != checksum) {
            ENET_DEBUG("UDP packet has invalid checksum \n");
            return NIC_ERR_RX_DISCARD;
        }
    }

    if (ntohs(hdr->len) != rx_buf->valid_length + UDP_HLEN) {
        ENET_DEBUG("UDP packet has wrong length \n");
        return NIC_ERR_RX_DISCARD;
    }

    ENET_DEBUG("UDP packet of length %i received from %08X:%i on port %i \n", rx_buf->valid_length, src_ip, ntohs(hdr->src), ntohs(hdr->dest));

    if (st->udp_ports[ntohs(hdr->dest)] == NULL) {
        ENET_DEBUG("No listener for incoming UDP packet \n");
        return NIC_ERR_RX_DISCARD;
    }

    struct enet_udp_endpoint *enet_hdr = malloc(sizeof(struct enet_udp_endpoint) + rx_buf->valid_length);
    char *enet_data = (char*)(enet_hdr + 1);
    char *data = (char*)(hdr + 1);
    enet_hdr->ip = src_ip;
    enet_hdr->port = ntohs(hdr->src);
    memcpy(enet_data, data, rx_buf->valid_length);

    LISTEN_DURING_RPC_CALL(
        err = nameservice_rpc(st->udp_ports[ntohs(hdr->dest)], enet_hdr, sizeof(struct enet_udp_endpoint) + rx_buf->valid_length, NULL, 0, NULL_CAP, NULL_CAP);
    );

    return err;
}

static errval_t handle_icmp(struct enet_driver_state *st, struct devq_buf *rx_buf, ip_addr_t src_ip) {
    if (rx_buf == NULL) return ERR_INVALID_ARGS;

    if (rx_buf->valid_length < ICMP_HLEN) return NIC_ERR_RX_PKT;
    struct icmp_echo_hdr *hdr = (struct icmp_echo_hdr*) ((char*)st->rx_mem_addr + rx_buf->offset + rx_buf->valid_data);
    rx_buf->valid_data += ICMP_HLEN;
    rx_buf->valid_length -= ICMP_HLEN;

    if ((ICMPH_TYPE(hdr) != ICMP_ER && ICMPH_TYPE(hdr) != ICMP_ECHO) || ICMPH_CODE(hdr) != ICMP_ECHO_CODE) {
        ENET_DEBUG("ICMP packet type/code is not supported \n");
        return NIC_ERR_RX_DISCARD;
    }

    struct icmp_echo_hdr *_hdr = malloc(rx_buf->valid_length + ICMP_HLEN); // hdr is readonly!
    if (_hdr == NULL) return NIC_ERR_UNKNOWN;

    memcpy(_hdr, hdr, rx_buf->valid_length + ICMP_HLEN);
    _hdr->chksum = htons(ICMP_NO_CHECKSUM);
    uint16_t checksum = inet_checksum(_hdr, rx_buf->valid_length + ICMP_HLEN);
    free(_hdr);

    if (hdr->chksum != checksum) {
        ENET_DEBUG("ICMP packet has invalid checksum \n");
        return NIC_ERR_RX_DISCARD;
    }

    struct buf_node *reply_buf;
    errval_t err;
    switch(hdr->type) {
        case ICMP_ECHO:
            err = alloc_tx_buf(st, &reply_buf, false);
            if (err_is_fail(err)) return err;
            memcpy((char*)st->tx_mem_addr + reply_buf->buf.offset + reply_buf->buf.valid_data, (char*)st->rx_mem_addr + rx_buf->offset + rx_buf->valid_data, rx_buf->valid_length);
            reply_buf->buf.valid_length = rx_buf->valid_length;
            return send_icmp_echo(st, reply_buf, ICMP_ER, ntohs(hdr->id), ntohs(hdr->seqno), src_ip);
        case ICMP_ER:
            ENET_DEBUG("ICMP reply received from %08X \n", src_ip);
            // TODO maybe do something with the reply
            break;
        default:
            ENET_DEBUG("ICMP packet has unsupported type \n");
            return NIC_ERR_RX_DISCARD;
    }

    return SYS_ERR_OK;
}

static errval_t handle_ip(struct enet_driver_state *st, struct devq_buf *rx_buf) {
    if (rx_buf == NULL) return ERR_INVALID_ARGS;

    if (rx_buf->valid_length < IP_HLEN) return NIC_ERR_RX_PKT;
    struct ip_hdr *hdr = (struct ip_hdr*) ((char*)st->rx_mem_addr + rx_buf->offset + rx_buf->valid_data);
    rx_buf->valid_data += IP_HLEN;
    rx_buf->valid_length -= IP_HLEN;

    if (IPH_V(hdr) != IP_VERSION || IPH_HL(hdr) != IP_HLEN_32) {
        ENET_DEBUG("IP packet version/options is not supported \n");
        return NIC_ERR_RX_DISCARD;
    }

    struct ip_hdr _hdr = *hdr; // hdr is readonly!
    _hdr.chksum = htons(IP_NO_CHECKSUM);

    if (hdr->chksum != inet_checksum(&_hdr, IP_HLEN)) {
        ENET_DEBUG("IP packet has invalid checksum \n");
        return NIC_ERR_RX_DISCARD;
    } else if ((ntohs(hdr->offset) & ~IP_DF) != 0) {
        ENET_DEBUG("IP packet is fragmented \n");
        return NIC_ERR_RX_DISCARD;
    }

    uint16_t len = ntohs(hdr->len); // Includes ip header length!

    if (len < IP_HLEN) {
        ENET_DEBUG("IP packet has invalid length \n");
        return NIC_ERR_RX_DISCARD;
    }

    len -= IP_HLEN;

    if (len > rx_buf->valid_length) {
        ENET_DEBUG("IP packet is incomplete \n");
        return NIC_ERR_RX_DISCARD;
    }

    rx_buf->valid_length = len; // If the frame was padded this might be larger

    if (ntohl(hdr->dest) != st->ip_addr) {
        ENET_DEBUG("IP packet is for someone else (or broadcast) \n");
        return NIC_ERR_RX_DISCARD;
    }

    switch (hdr->proto) {
        case IP_PROTO_ICMP:
            return handle_icmp(st, rx_buf, ntohl(hdr->src));
        case IP_PROTO_UDP:
            return handle_udp(st, rx_buf, ntohl(hdr->src));
        default:
            ENET_DEBUG("IP packet has unsupported protocol \n");
            return NIC_ERR_RX_DISCARD;
    }

    return SYS_ERR_OK;
}

static errval_t handle_arp(struct enet_driver_state *st, struct devq_buf *rx_buf, struct eth_addr src_mac) {
    if (rx_buf == NULL) return ERR_INVALID_ARGS;

    if (rx_buf->valid_length < ARP_HLEN) return NIC_ERR_RX_PKT;
    struct arp_hdr *hdr = (struct arp_hdr*) ((char*)st->rx_mem_addr + rx_buf->offset + rx_buf->valid_data);
    rx_buf->valid_data += ARP_HLEN;
    rx_buf->valid_length -= ARP_HLEN;

    if (ntohs(hdr->hwtype) != ARP_HW_TYPE_ETH || ntohs(hdr->proto) != ARP_PROT_IP || hdr->hwlen != ETH_ADDR_LEN || hdr->protolen != IP_ADDR_LEN) {
        ENET_DEBUG("ARP packet is for non-supported protocols \n");
        return NIC_ERR_RX_DISCARD;
    }

    ip_addr_t ip_src = ntohl(hdr->ip_src);
    ip_addr_t ip_dst = ntohl(hdr->ip_dst);
    switch(ntohs(hdr->opcode)) {
        case ARP_OP_REQ:
            if (ip_dst != st->ip_addr) {
                ENET_DEBUG("ARP request is for someone else \n");
                return NIC_ERR_RX_DISCARD;
            }

            return answer_arp(st, hdr->eth_src, ip_src);
        case ARP_OP_REP: {
            if (ip_dst != st->ip_addr || !ETH_ADDR_EQUAL(&hdr->eth_dst, &st->mac)) {
                ENET_DEBUG("ARP response is for someone else \n");
                return NIC_ERR_RX_DISCARD;
            }

            struct cache_entry *entry = collections_hash_find(st->arp_cache, ip_src);
            if (entry == NULL) {
                ENET_DEBUG("Unrequested ARP response \n");
                return NIC_ERR_RX_DISCARD;
            } else if (entry->pending) {
                entry->mac = hdr->eth_src;

                struct buf_node *tx_buf, *next;
                tx_buf = entry->pending;

                while (tx_buf) {
                    next = tx_buf->next;
                    tx_buf->next = NULL;

                    errval_t err = send_ethernet(st, tx_buf, entry->mac, ETH_TYPE_IP);
                    if (err_is_fail(err)) ENET_DEBUG("Failed to send pending packet \n");

                    tx_buf = next;
                }

                entry->pending = NULL;

                return SYS_ERR_OK;
            } else { // TODO overwrite instead?
                ENET_DEBUG("Already received an ARP response previously \n");
                return NIC_ERR_RX_DISCARD;
            }
        }
        default:
            ENET_DEBUG("ARP packet contains unknown operation \n");
            return NIC_ERR_RX_DISCARD;
    }

    return SYS_ERR_OK;
}

static errval_t handle_ethernet(struct enet_driver_state *st, struct devq_buf *rx_buf) {
    if (rx_buf == NULL) return ERR_INVALID_ARGS;

    if (rx_buf->valid_length < ETH_HLEN) return NIC_ERR_RX_PKT;
    struct eth_hdr *hdr = (struct eth_hdr*) ((char*)st->rx_mem_addr + rx_buf->offset + rx_buf->valid_data);
    rx_buf->valid_data += ETH_HLEN;
    rx_buf->valid_length -= ETH_HLEN;
    rx_buf->valid_length -= ETH_CRC_LEN; // TODO is assumed to have been checked by hardware => verify

    switch (ntohs(ETH_TYPE(hdr))) {
        case ETH_TYPE_ARP:
            if (!ETH_ADDR_EQUAL(&hdr->dst, &st->mac) && !ETH_ADDR_EQUAL(&hdr->dst, &broadcast_mac)) {
                ENET_DEBUG("ETH packet (ARP) is not for us \n");
                return NIC_ERR_RX_DISCARD;
            }

            return handle_arp(st, rx_buf, hdr->src);
        case ETH_TYPE_IP:
            if (!ETH_ADDR_EQUAL(&hdr->dst, &st->mac)) {
                ENET_DEBUG("ETH packet (IP) is not for us \n");
                return NIC_ERR_RX_DISCARD;
            }

            return handle_ip(st, rx_buf);
        default:
            ENET_DEBUG("Unknown ETH TYPE received \n");
            return NIC_ERR_RX_DISCARD;
    }


    return SYS_ERR_OK;
}

static void enet_recv_handler(void *vst, void *message, size_t bytes, void **response,
                                size_t *response_bytes, struct capref rx_cap,
                                struct capref *tx_cap)
{
    struct enet_driver_state *st = vst;

    st->response.err = NIC_ERR_UNKNOWN;
    st->response.socket = 0;

    if (!capref_is_null(rx_cap) || message == NULL || bytes < sizeof(struct enet_udp_msg) || response == NULL || response_bytes == NULL || tx_cap == NULL) {
        st->response.err = ERR_INVALID_ARGS;
        return;
    }

    *response = &st->response;
    *response_bytes = sizeof(struct enet_udp_res);
    *tx_cap = NULL_CAP;


    struct enet_udp_msg *hdr = message;
    bytes -= sizeof(struct enet_udp_msg);
    switch (hdr->type) {
        case create: {
            char *name = (char*)(hdr + 1);
            if (bytes != strnlen(name, bytes) + 1) {
                st->response.err = ERR_INVALID_ARGS;
                return;
            }

            uint16_t port = hdr->socket;
            if (hdr->socket == 0) {
                for (int i = 0; i < UDP_PORT_CNT; i++) {
                    port = st->next_port++;
                    if (!port) continue;
                    if (st->udp_ports[hdr->socket] == NULL) break;
                }
            }

            if (st->udp_ports[port]) {
                st->response.err = NIC_ERR_PORT_TAKEN;
                return;
            }

            st->response.err = nameservice_lookup(name, &st->udp_ports[port]);
            if (err_is_ok(st->response.err)) st->response.socket = port;
            break;
        }
        case destroy:
            if (st->udp_ports[hdr->socket] == NULL) {
                st->response.err = NIC_ERR_PORT_AVAILABLE;
                return;
            }

            st->response.err = SYS_ERR_OK;
            st->response.socket = hdr->socket;
            st->udp_ports[hdr->socket] = NULL;
            break;
        case send: {
            if (bytes < sizeof(struct enet_udp_endpoint) || bytes > ENET_MAX_PKT_SIZE - UDP_HLEN - IP_HLEN - ETH_HLEN - ETH_CRC_LEN) {
                st->response.err = ERR_INVALID_ARGS;
                return;
            }

            struct enet_udp_endpoint *endpoint = (struct enet_udp_endpoint*)(hdr + 1);
            bytes -= sizeof(struct enet_udp_endpoint);
            char* data = (char*)(endpoint + 1);

            struct buf_node *tx_buf;
            st->response.err = alloc_tx_buf(st, &tx_buf, false);
            if (err_is_fail(st->response.err)) return;

            memcpy((char*)st->tx_mem_addr + tx_buf->buf.offset + tx_buf->buf.valid_data, data, bytes);
            tx_buf->buf.valid_length = bytes;

            st->response.err = send_udp(st, tx_buf, hdr->socket, endpoint->port, endpoint->ip);
            if (err_is_ok(st->response.err)) st->response.socket = hdr->socket;
            break;
        }
    }
}

int main(int argc, char *argv[]) {
    errval_t err;

    debug_printf("Enet driver started \n");
    struct enet_driver_state * st = (struct enet_driver_state*)
                                    calloc(1, sizeof(struct enet_driver_state));
    assert(st != NULL);

    struct capref enet = {
        .cnode = cnode_task,
        .slot = TASKCN_SLOTS_FREE
    };

    struct capability enet_c;
    err = cap_direct_identify(enet, &enet_c);
    assert(enet_c.type == ObjType_DevFrame);
    if (err_is_fail(err))
        return err;

    // map capability to enet
    err = paging_map_frame_attr(get_current_paging_state(), (void**)&st->d_vaddr, enet_c.u.ram.bytes, enet, VREGION_FLAGS_READ_WRITE_NOCACHE);
    if (err_is_fail(err))
        return err;

    if ((void *)st->d_vaddr == NULL) {
        USER_PANIC("ENET: No register region mapped \n");
    }

    /* Initialize Mackerel binding */
    st->d = (enet_t *) malloc(sizeof(enet_t));
    enet_initialize(st->d, (void *) st->d_vaddr);

    st->udp_ports = malloc(UDP_PORT_CNT * sizeof(nameservice_chan_t));
    if (st->udp_ports == NULL) return NIC_ERR_UNKNOWN;
    for (int i = 0; i < UDP_PORT_CNT; i++) st->udp_ports[i] = NULL;

    collections_hash_create(&st->arp_cache, NULL);

    st->ip_id = 0;
    st->next_port = 40000;
    st->ip_addr = 0x0a000201;

    assert(st->d != NULL);
    enet_read_mac(st);

    err = enet_probe(st);
    if (err_is_fail(err)) {
        // TODO cleanup
        return err;
    }

    err = enet_init(st);
    if (err_is_fail(err)) {
        // TODO cleanup
        return err;
    }

    debug_printf("Enet driver init done \n");

    debug_printf("Creating devqs \n");

    err = enet_rx_queue_create(&st->rxq, st->d);
    if (err_is_fail(err)) {
        debug_printf("Failed creating RX devq \n");
        return err;
    }

    err = enet_tx_queue_create(&st->txq, st->d);
    if (err_is_fail(err)) {
        debug_printf("Failed creating TX devq \n");
        return err;
    }

    // Add some memory to receive stuff
    err = frame_alloc(&st->rx_mem, st->rxq->size * ENET_MAX_BUF_SIZE, NULL);
    if (err_is_fail(err)) {
        return err;
    }

    err = paging_map_frame_attr(get_current_paging_state(), &st->rx_mem_addr, st->rxq->size * ENET_MAX_BUF_SIZE, st->rx_mem, VREGION_FLAGS_READ);
    if (err_is_fail(err)) {
        return err;
    }

    err = devq_register((struct devq*) st->rxq, st->rx_mem, &st->rx_rid);
    if (err_is_fail(err)) {
        return err;
    }

    // Enqueue buffers
    // TODO why is the -1 required??? Can we also not use the last element for tx?
    // (when removing -1 receiving does not work anymore)
    for (int i = 0; i < st->rxq->size-1; i++) {
        err = devq_enqueue((struct devq*) st->rxq, st->rx_rid, i * ENET_MAX_BUF_SIZE, ENET_MAX_BUF_SIZE, 0, ENET_MAX_BUF_SIZE, 0);
        if (err_is_fail(err)) {
            return err;
        }
    }

    // Add some memory to send stuff
    err = frame_alloc(&st->tx_mem, st->txq->size * ENET_MAX_BUF_SIZE, NULL);
    if (err_is_fail(err)) {
        return err;
    }

    // READ required for checksum calculation
    err = paging_map_frame_attr(get_current_paging_state(), &st->tx_mem_addr, st->txq->size * ENET_MAX_BUF_SIZE, st->tx_mem, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        return err;
    }

    err = devq_register((struct devq*) st->txq, st->tx_mem, &st->tx_rid);
    if (err_is_fail(err)) {
        return err;
    }

    // Add tx buffers to stack
    for (int i = 0; i < st->txq->size; i++) {
        err = add_tx_buf(st, i * ENET_MAX_BUF_SIZE);
        if (err_is_fail(err)) {
            return err;
        }
    }

    nameservice_register(ENET_DRIVER_NAME, enet_recv_handler, st);

    struct devq_buf buf;
    while(true) {
        err = enet_dequeue(st->rxq, &buf);
        if (err_is_ok(err)) {
            err = handle_ethernet(st, &buf);
            // Uncomment if incoming packets are lost
            // if (err) {
            //     ENET_DEBUG(err, "handle_ethernet");
            // }
            buf.valid_data = 0;
            buf.valid_length = ENET_MAX_BUF_SIZE;
            err = enet_enqueue(st->rxq, &buf);
            assert(err_is_ok(err));
        }

        err = enet_dequeue(st->txq, &buf);
        if (err_is_ok(err)) {
            buf.valid_data = 0;
            buf.valid_length = ENET_MAX_BUF_SIZE;
            err = free_tx_buf(st, &buf);
            assert(err_is_ok(err));
        }

        err = event_dispatch_non_block(get_default_waitset());
        if (err_is_ok(err)) {
            ENET_DEBUG("Dispatched event!\n");
        }
    }
}
