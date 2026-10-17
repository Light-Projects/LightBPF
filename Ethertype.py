# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

ETHERTYPE_KEYWORDS = {
    # --- cBPF / libpcap canonical keywords (ethproto[] in gencode.c) ---
    "ip":              0x0800,   # ETHERTYPE_IP
    "ip4":             0x0800,
    "ipv4":            0x0800,
    "ip6":             0x86DD,   # ETHERTYPE_IPV6
    "arp":             0x0806,   # ETHERTYPE_ARP
    "rarp":            0x8035,   # ETHERTYPE_REVARP
    "atalk":           0x809B,   # ETHERTYPE_ATALK
    "aarp":            0x80F3,   # ETHERTYPE_AARP
    "decnet":          0x6003,   # ETHERTYPE_DECNET
    "sca":             0x8038,   # ETHERTYPE_DEC_LB  (alias lanbridge)
    "lanbridge":       0x8038,   # ETHERTYPE_DEC_LB  (alias sca)
    "lat":             0x6004,   # ETHERTYPE_LAT
    "mopdl":           0x6001,   # ETHERTYPE_MOPDL
    "moprc":           0x6002,   # ETHERTYPE_MOPRC
    "iso":             0xFEFE,   # ETHERTYPE_ISO
    "qnx":             0x8204,   # ETHERTYPE_QNX
    "sna":             0x80D5,   # ETHERTYPE_IBM_SNA
    "netbeui":         0xF0F0,   # ETHERTYPE_NETBEUI
    "ppp":             0x880B,   # ETHERTYPE_PPP
    "mpls":            0x8847,   # ETHERTYPE_MPLS
    "mpls_mc":         0x8848,   # ETHERTYPE_MPLS_MCAST
    "pppoed":          0x8863,   # ETHERTYPE_PPPOED
    "pppoes":          0x8864,   # ETHERTYPE_PPPOES
    "aoe":             0x88A2,   # ETHERTYPE_AOE
    "loopback":        0x9000,   # ETHERTYPE_LOOPBACK

    # --- cBPF keyword (VLAN-aware codegen, not in ethproto[]) ---
    "vlan":            0x8100,   # ETHERTYPE_VLAN (keyword triggers offset shift)

    # --- Common but not cBPF keywords (descriptive) ---
    "qinq":            0x88A8,
    "vlan_double":     0x9100,
    "wol":             0x0842,
    "trill":           0x22F3,
    "srp":             0x22EA,
    "avtp":            0x22F0,
    "xerox_ns_idp":    0x0600,
    "x75_internet":    0x0801,
    "nbs_internet":    0x0802,
    "ecma_internet":   0x0803,
    "chaosnet":        0x0804,
    "x25_level3":      0x0805,
    "xns_compat":      0x0807,
    "frame_relay_arp": 0x0808,
    "trans_eth_bridge":0x6558,
    "raw_frame_relay": 0x6559,
    "dec_encrypt":     0x803D,
    "dec_lan_monitor": 0x803F,
    "planning_research":0x8044,
    "experdata":       0x8049,
    "stanford_v_exp":  0x805B,
    "stanford_v_prod": 0x805C,
    "evans_sutherland":0x805D,
    "little_machines": 0x8060,
    "counterpoint":    0x8062,
    "veeco":           0x8067,
    "general_dynamics":0x8068,
    "autophon":        0x806A,
    "comdesign":       0x806C,
    "computgraphic":   0x806D,
    "matra":           0x807A,
    "dansk_data":      0x807B,
    "merit":           0x807C,
    "vitalink":        0x8080,
    "datability":      0x809C,
    "spider_systems":  0x809F,
    "nixdorf":         0x80A3,
    "banyan":          0x80C4,
    "pacer":           0x80C6,
    "applitek":        0x80C7,
    "varian":          0x80DD,
    "retix":           0x80F2,
    "apollo":          0x80F7,
    "wellfleet":       0x80FF,
    "symbolics":       0x8107,
    "hayes":           0x8130,
    "vg_lab":          0x8131,
    "ipx":             0x8137,   # Novell IPX (also "novell" in some lists)
    "novell":          0x8137,
    "logicraft":       0x8148,
    "ncd":             0x8149,
    "alpha_micro":     0x814A,
    "snmp":            0x814C,
    "biin":            0x814D,
    "technically_elite":0x814F,
    "rational":        0x8150,
    "qualcomm":        0x8151,
    "computer_protocol":0x815C,
    "charles_river":   0x8164,
    "xtp":             0x817D,
    "sgi_time_warner": 0x817E,
    "hippi_fp":        0x8180,
    "stp_hippi":       0x8181,
    "silicon_graphics":0x8184,
    "motorola":        0x818D,
    "arai":            0x81A4,
    "rad_network":     0x81A5,
    "xyplex":          0x81B7,
    "apricot":         0x81CC,
    "artisoft":        0x81D6,
    "polygon":         0x81E6,
    "comsat_labs":     0x81F0,
    "saic":            0x81F3,
    "vg_analytical":   0x81F6,
    "quantum_software":0x8203,
    "ascom":           0x8221,
    "advanced_encryption":0x823E,
    "athena":          0x827F,
    "inst_ind_info":   0x829A,
    "taurus":          0x829C,
    "walker_richer":   0x82AC,
    "idea_courier":    0x8694,
    "computer_network":0x869E,
    "gateway_comms":   0x86A3,
    "sectra":          0x86DB,
    "delta_controls":  0x86DE,
    "atomic":          0x86DF,
    "landis_gyr":      0x86E0,
    "tcp_ip_compression":0x876B,
    "ip_autonomous":   0x876C,
    "secure_data":     0x876D,
    "slow_protocols":  0x8809,
    "flow_control":    0x8808,
    "cobranet":        0x8819,
    "eth_test":        0x8822,
    "mcap":            0x8861,
    "jumbo":           0x8870,
    "homeplug":        0x887B,
    "hyperscsi":       0x889A,
    "powerlink":       0x88AB,
    "eapol":           0x888E,
    "pbb":             0x88E7,
    "homeplug_av":     0x88E1,
    "mrp":             0x88E3,
    "macsec":          0x88E5,
    "ptp":             0x88F7,
    "ethercat":        0x88A4,
    "profinet":        0x8892,
    "sercos":          0x88CD,
    "prp":             0x88FB,
    "hsr":             0x892F,
    "cfm":             0x8902,
    "lldp":            0x88CC,
    "fcoe":            0x8906,
    "fcoe_init":       0x8914,
    "roce":            0x8915,
    "tte":             0x891D,
    "local_exp":       0x88B5,   # 0x88B5/6/7 are all local experimental

    # --- Aliases for user's existing descriptive names ---
    "ipv6":            0x86DD,   # alias for "ip6"
    "pppoe_disc":      0x8863,   # alias for "pppoed"
    "pppoe_sess":      0x8864,   # alias for "pppoes"
    "mpls_mcast":      0x8848,   # alias for "mpls_mc"
}