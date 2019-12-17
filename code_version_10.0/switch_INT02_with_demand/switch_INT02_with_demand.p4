/* -*- P4_16 -*- */


#include <core.p4>
#include <v1model.p4>


// **********  constant variable  ********

const bit<16> ETHERTYPE_IPV4 = 0x800;
const bit<16> ETHERTYPE_ARP = 0x806;
const bit<8> PROTOCOLO_TCP = 0x06;
const bit<8> PROTOCOLO_UDP = 0x11;
const bit<8> DSCP_INT = 0x17;
const bit<16> HW_ID = 2;





/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<16> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;






// **********  Header of networks  **********
const bit<16> ETH_HEADER_LEN = 14;

header ethernet_t {
    macAddr_t destinationAddress;
    macAddr_t sourceAddress;
    bit<16>   etherType;
}


header arp_t {
    bit<16>   hardwareType;
    bit<16>   protocoloType;
    bit<8>    hardwareAddressLength;
    bit<8>    protocolAddressLength;
    bit<16>   opcode;
    bit<48>   senderHardwareAddress;
    bit<32>   senderProtocolAddress;
    bit<48>   targetHardwareAddress;
    bit<32>   targetProtocolAddress;
}

const bit<16> IPV4_MIN_HEAD_LEN = 20;

header ipv4_t {
    bit<4>    version;
    bit<4>    headerLength;
    bit<8>    typeServiceDiffServ;
    bit<16>   totalLength;
    bit<16>   identification;
    bit<16>   fragmentOffset;
    bit<8>    timeToLive;
    bit<8>    protocol;
    bit<16>   headerChecksum;
    ip4Addr_t sourceAddress;
    ip4Addr_t destinationAddress;
}

header tcp_t {
    bit<16>   sourcePort;
    bit<16>   destinationPort;
    bit<32>   sequenceNumber;
    bit<32>   acknowledgementNumber;
    bit<4>    dataOffset;
    bit<4>    reserved;
    bit<8>    flags;
    bit<16>   windowSize;
    bit<16>   checksum;
    bit<16>   urgentPointers;
}

const bit<16> UDP_HEADER_LEN = 8;


header udp_t {
    bit<16>   sourcePort;
    bit<16>   destinationPort;
    bit<16>   lengthUDP;
    bit<16>   checksum;
}



// **********  INT header   **********

const bit<16> INT_SHIM_HEADER_SIZE = 4;



header INTshim_t {

    bit<8>  shim_type;
    bit<8>  shim_reserved1;
    bit<8>  shim_length;
    bit<8>  shim_rsvd2;

}



const bit<16> INT_HEADER_SIZE = 8;



header INThopByhopHeader_t {

    bit<8>  int_version;
    bit<8>  int_replication;
    bit<1>  int_copy;
    bit<1>  int_exceeded;
    bit<8>  int_rsvd_1;
    bit<8>  int_ins_cnt;
    bit<8>  int_max_hops;
    bit<8>  int_total_hops;
    bit<8>  int_instruction_bit;
    bit<6>  int_rsvd_instructions;


}










// **********  header INT data    **********



const bit<16> INT_SWITCH_SIZE = 4;



header int_switch_id_t {
    bit<32>  int_switch_id;

}  //bit 0



const bit<16> INT_INGRESS_EGRESS = 4;

header int_ingress_egress_ports_t {
    bit<16>  int_ingress_id;
    bit<16>  int_egress_id;

}   //bit 1


const bit<16> INT_HOP_SIZE = 8;

header int_hop_latency_t {
    bit<64>  int_hop_latency;

}   //bit 2





const bit<16> INT_IN_TIMESTAMP_SIZE = 8;

header int_ingressTimestamp_t {
    bit<64>  int_ingressTimestamp;

}  //bit 3


const bit<64> INT_OUT_TIMESTAMP_SIZE = 8;


header int_egressTimestamp_t {
    bit<64>  int_egressTimestamp;

}  //bit 4


const bit<64> INT_COUNT_PACKAGE_SIZE = 4;


header int_countpackage_t {
    bit<32>  int_ingresscountpackage;

}  //bit 5 

const bit<64> INT_BYTE_PACKAGE_SIZE = 4;

header int_bytepackage_t {
    bit<32>  int_bytepackageingress;

} //bit 6 
//bit 7 - not definy by noveflow




const bit<16> REPORT_FIXED_HEADER_LEN = 16;



header telemetryreport_t {
    bit<8> f_version;
    bit<8> f_next_proto;
    bit<1> f_drop;
    bit<1> f_queue;
    bit<1> f_flow;
    bit<5> f_rsvd;
    bit<8> f_hw_id;
    bit<32> f_seq_num;
    bit<64> f_ingress_ts;
}





// **********  Struct header Inner   **********





header report_ethernet_t {

    macAddr_t destinationAddress;
    macAddr_t sourceAddress;
    bit<16>   etherType;

}



header report_ipv4_t {

    bit<4>    version;
    bit<4>    headerLength;
    bit<8>    typeServiceDiffServ;
    bit<16>   totalLength;
    bit<16>   identification;
    bit<16>   fragmentOffset;
    bit<8>    timeToLive;
    bit<8>    protocol;
    bit<16>   headerChecksum;
    ip4Addr_t sourceAddress;
    ip4Addr_t destinationAddress;

}







header report_udp_t {

    bit<16>   sourcePort;
    bit<16>   destinationPort;
    bit<16>   lengthUDP;
    bit<16>   checksum;

}




header INTtail_t {
    bit<32> tail_header;
    bit<8> tail_proto;
    bit<8> tail_port;
    bit<8> tail_dscp;
}




// **********  Struct P4   **********

header intrinsic_metadata_t {

    bit<64> ingress_global_tstamp; /* sec[63:32], nsec[31:0] */
    bit<64> current_global_tstamp; /* sec[63:32], nsec[31:0] */

}





header switch_data_t {

    bit<16> switch_id;
    bit<16> port_in;
    bit<16> port_out;
    bit<16> shimINTlength;
    bit<8>  instruction;
    bit<64> ingresststamp;
    bit<64> egresststamp;
    bit<32> ingressbyte;
    bit<32> ingresspackage;



}



struct metadata {

    switch_data_t           switch_local;
    intrinsic_metadata_t    intrinsic_metadata;

    /* empty */

}




struct headers {



    report_ethernet_t     report_ethernet;
    report_ipv4_t         report_ipv4;
    report_udp_t          report_udp;
    telemetryreport_t     report;
    ethernet_t          ethernet;
    arp_t               arp;
    ipv4_t              ipv4;
    tcp_t               tcp;
    udp_t               udp;

    

    INThopByhopHeader_t         hopINT;
    INTshim_t                   shimINT;



    int_switch_id_t             switch_id;
    int_ingress_egress_ports_t  int_ingress_egress_ports;
    int_hop_latency_t           hop_latency;

    int_ingressTimestamp_t      ingressTimestamp;
    int_egressTimestamp_t       egressTimestamp;
    int_countpackage_t          countpackage;
    int_bytepackage_t           bytepackage;




    INTtail_t                   tailINT;
}









/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_ARP: parse_arp;
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }

    }
    state parse_arp {
        packet.extract(hdr.arp);
        transition select(hdr.arp.hardwareType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTOCOLO_TCP: parse_tcp;
            PROTOCOLO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.ipv4.typeServiceDiffServ) {
            DSCP_INT : parse_shimINT;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.ipv4.typeServiceDiffServ) {
            DSCP_INT : parse_shimINT;
            default: accept;
        }
    }





// **********  parse INT  ********
    state parse_shimINT {
        packet.extract(hdr.shimINT);
//        meta.switch_local.shimINTlength = ((75 - 6 - 4));
        transition parse_hopINT;
    }

    state parse_hopINT {
        packet.extract(hdr.hopINT);
        transition accept;
    }

}




/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}







/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    








    action drop() {
        mark_to_drop();
    }

    action port_forward(){
        meta.switch_local.port_out = standard_metadata.egress_spec;
        meta.switch_local.port_in = standard_metadata.ingress_port;
        meta.switch_local.switch_id = HW_ID;
    }







// **********  Table and Action of header ARP ********

    action arp_forward(macAddr_t dstmac, macAddr_t srcmac, egressSpec_t espec) {
        standard_metadata.egress_spec = espec;
        hdr.ethernet.sourceAddress = srcmac;
        hdr.ethernet.destinationAddress = dstmac;

    }

    table arp_lpm {
        key = {
            hdr.arp.targetProtocolAddress: exact;
        }
        actions = {
            arp_forward;
            drop;
            NoAction;
        }
        size = 128;
        default_action = drop();

    }




// **********  Table and Action of header IPV4 ********
    action ipv4_forward(macAddr_t dstmac, macAddr_t srcmac, egressSpec_t espec) {
        standard_metadata.egress_spec = espec;
        hdr.ethernet.sourceAddress = srcmac;
        hdr.ethernet.destinationAddress = dstmac;
        hdr.ipv4.timeToLive = hdr.ipv4.timeToLive - 1;

        
        
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.destinationAddress: exact;

        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 128;
        default_action = drop();
    }






// **********  Table and Action of  INT header souce ********
  action send_telemetry_report(macAddr_t monitor_mac, ip4Addr_t monitor_ip, egressSpec_t monitor_port) {
        port_forward();

        meta.switch_local.instruction = hdr.hopINT.int_instruction_bit;
        hdr.shimINT.setInvalid();
        hdr.hopINT.setInvalid();


        //Report Ethernet Header
        hdr.report_ethernet.setValid();

        hdr.report_ethernet.destinationAddress = monitor_mac;
        hdr.report_ethernet.sourceAddress =  hdr.ethernet.sourceAddress;
        hdr.report_ethernet.etherType = ETHERTYPE_IPV4;

        //Report IPV4 Header
        hdr.report_ipv4.setValid();

        hdr.report_ipv4.version = hdr.ipv4.version ;
        hdr.report_ipv4.headerLength = hdr.ipv4.headerLength;
        hdr.report_ipv4.typeServiceDiffServ = DSCP_INT;
        /* Total Len is report_ipv4_len + report_udp_len + report_fixed_hdr_len + ethernet_len + ipv4_totalLen */
        hdr.report_ipv4.totalLength =  hdr.ipv4.totalLength;
        /* Dont Fragment bit should be set */
        hdr.report_ipv4.identification = hdr.ipv4.identification;

        hdr.report_ipv4.fragmentOffset = hdr.ipv4.fragmentOffset;
        hdr.report_ipv4.timeToLive = hdr.ipv4.timeToLive;
        hdr.report_ipv4.protocol = PROTOCOLO_UDP;
        hdr.report_ipv4.sourceAddress = hdr.ipv4.sourceAddress;
        hdr.report_ipv4.destinationAddress = monitor_ip;


        //Report UDP Header
        hdr.report_udp.setValid();

        hdr.report_udp.sourcePort = hdr.udp.sourcePort;
        hdr.report_udp.destinationPort = monitor_port;
        hdr.report_udp.lengthUDP =  hdr.udp.lengthUDP;
        hdr.report_udp.checksum = hdr.udp.checksum;

        hdr.report.setValid();

        hdr.report.f_version = 4;
        hdr.report.f_next_proto = hdr.ipv4.protocol;
        hdr.report.f_drop = 0;
        hdr.report.f_queue = 0 ;
        hdr.report.f_flow = 0 ;
        hdr.report.f_rsvd = 0 ;
        hdr.report.f_hw_id = (bit<8>)HW_ID ;
        hdr.report.f_seq_num = (bit<32>) meta.switch_local.instruction;
        hdr.report.f_ingress_ts = meta.switch_local.ingresststamp;

    }




    table process_int_report {

        actions = {
            send_telemetry_report;
        }

    }




            register<bit<32>>(8) ingresscount;
            register<bit<32>>(8) bytecountingress;

   apply {

        meta.switch_local.ingresststamp = meta.intrinsic_metadata.ingress_global_tstamp;
               
  


        if(hdr.arp.isValid()) {
            arp_lpm.apply();
        }
        else if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
            if(hdr.ipv4.typeServiceDiffServ == DSCP_INT){
                process_int_report.apply();
            }
        }

       if(hdr.ethernet.isValid()){

            //Count package
            ingresscount.read(meta.switch_local.ingresspackage, (bit<32>)meta.switch_local.port_in);
            meta.switch_local.ingresspackage = meta.switch_local.ingresspackage + 1;
            ingresscount.write((bit<32>)meta.switch_local.port_in, meta.switch_local.ingresspackage);

            
            //Count bytes
            bytecountingress.read(meta.switch_local.ingressbyte, (bit<32>)meta.switch_local.port_in);
            meta.switch_local.ingressbyte = meta.switch_local.ingressbyte + (bit<32>)standard_metadata.packet_length;
            bytecountingress.write((bit<32>)meta.switch_local.port_in, meta.switch_local.ingressbyte);


            

        }     







        if(hdr.ipv4.typeServiceDiffServ == DSCP_INT){
                ingresscount.write((bit<32>)meta.switch_local.port_in, 0);
                bytecountingress.write((bit<32>)meta.switch_local.port_in, 0);


        }




    }
}




/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
   

    






    
// **********  header INT data    **********



    action action_switch_id(){
        hdr.switch_id.setValid();
        hdr.switch_id.int_switch_id = (bit<32>)meta.switch_local.switch_id;
        hdr.shimINT.shim_length = hdr.shimINT.shim_length + (bit<8>)INT_SWITCH_SIZE;
    } //bit 0



    action action_ingress_egress_ports(){
        hdr.int_ingress_egress_ports.setValid();
        hdr.int_ingress_egress_ports.int_ingress_id = meta.switch_local.port_in;
        hdr.int_ingress_egress_ports.int_egress_id = meta.switch_local.port_out;
        hdr.shimINT.shim_length = hdr.shimINT.shim_length + (bit<8>)INT_INGRESS_EGRESS;

    }  //bit 1





    action action_hop_latency(){
        
        meta.switch_local.egresststamp = meta.intrinsic_metadata.current_global_tstamp;


        hdr.hop_latency.setValid();
        hdr.hop_latency.int_hop_latency = ((meta.switch_local.egresststamp) - (meta.switch_local.ingresststamp));
        hdr.shimINT.shim_length = hdr.shimINT.shim_length + (bit<8>)INT_HOP_SIZE;

    }  //bit 2



    action action_ingress_tstamp(){

        hdr.ingressTimestamp.setValid();
        hdr.ingressTimestamp.int_ingressTimestamp = meta.switch_local.ingresststamp;
        hdr.shimINT.shim_length = hdr.shimINT.shim_length + (bit<8>)INT_IN_TIMESTAMP_SIZE;


    }  //bit 3



    action action_egress_tstamp(){
        hdr.egressTimestamp.setValid();
        hdr.egressTimestamp.int_egressTimestamp = meta.switch_local.egresststamp;
        hdr.shimINT.shim_length = hdr.shimINT.shim_length + (bit<8>) INT_OUT_TIMESTAMP_SIZE;


    }  //bit 4


    action action_countpackage(){
        hdr.countpackage.setValid();
        hdr.countpackage.int_ingresscountpackage = meta.switch_local.ingresspackage;
        hdr.shimINT.shim_length = hdr.shimINT.shim_length + (bit<8>) INT_COUNT_PACKAGE_SIZE;


    }  //bit 5


    action action_bytepackage(){
        hdr.bytepackage.setValid();
        hdr.bytepackage.int_bytepackageingress = meta.switch_local.ingressbyte;
        hdr.shimINT.shim_length = hdr.shimINT.shim_length + (bit<8>) INT_BYTE_PACKAGE_SIZE;


    } //bit 6




    action action_eq128(){
        action_switch_id();
        hdr.hopINT.int_total_hops = hdr.hopINT.int_total_hops + 1;
        hdr.ipv4.totalLength = hdr.ipv4.totalLength + (bit<16>)hdr.shimINT.shim_length;
    }


    action action_eq192(){
        action_switch_id();
        action_ingress_egress_ports();
        hdr.hopINT.int_total_hops = hdr.hopINT.int_total_hops + 1;
        hdr.ipv4.totalLength = hdr.ipv4.totalLength + (bit<16>)hdr.shimINT.shim_length;
    }


    action action_eq224(){
        action_switch_id();
        action_ingress_egress_ports();
        action_hop_latency();
        hdr.hopINT.int_total_hops = hdr.hopINT.int_total_hops + 1;
        hdr.ipv4.totalLength = hdr.ipv4.totalLength + (bit<16>)hdr.shimINT.shim_length;
    }


    action action_eq240(){
        action_switch_id();
        action_ingress_egress_ports();
        action_hop_latency();
        action_ingress_tstamp();
        hdr.hopINT.int_total_hops = hdr.hopINT.int_total_hops + 1;
        hdr.ipv4.totalLength = hdr.ipv4.totalLength + (bit<16>)hdr.shimINT.shim_length;
    }



    action action_eq248(){
        action_switch_id();
        action_ingress_egress_ports();
        action_hop_latency();
        action_ingress_tstamp();
        action_egress_tstamp();
        hdr.hopINT.int_total_hops = hdr.hopINT.int_total_hops + 1;
        hdr.ipv4.totalLength = hdr.ipv4.totalLength + (bit<16>)hdr.shimINT.shim_length;

    }



    action action_eq252(){
        action_switch_id();
        action_ingress_egress_ports();
        action_hop_latency();
        action_ingress_tstamp();
        action_egress_tstamp();
        action_countpackage();
        hdr.hopINT.int_total_hops = hdr.hopINT.int_total_hops + 1;
        hdr.ipv4.totalLength = hdr.ipv4.totalLength + (bit<16>)hdr.shimINT.shim_length;

    }


    action action_eq254(){
        action_switch_id();
        action_ingress_egress_ports();
        action_hop_latency();
        action_ingress_tstamp();
        action_egress_tstamp();
        action_countpackage();
        action_bytepackage();
        hdr.hopINT.int_total_hops = hdr.hopINT.int_total_hops + 1;
        hdr.ipv4.totalLength = hdr.ipv4.totalLength + (bit<16>)hdr.shimINT.shim_length;

    }



    action action_eq160(){
        action_switch_id();
        action_hop_latency();
        hdr.hopINT.int_total_hops = hdr.hopINT.int_total_hops + 1;
        hdr.ipv4.totalLength = hdr.ipv4.totalLength + (bit<16>)hdr.shimINT.shim_length;

    }


    action action_eq184(){
        action_switch_id();
        action_hop_latency();
        action_ingress_tstamp();
        action_egress_tstamp();
        hdr.hopINT.int_total_hops = hdr.hopINT.int_total_hops + 1;
        hdr.ipv4.totalLength = hdr.ipv4.totalLength + (bit<16>)hdr.shimINT.shim_length;

    }

    action action_eq88(){
        action_ingress_egress_ports();
        action_ingress_tstamp();
        action_egress_tstamp();
        hdr.hopINT.int_total_hops = hdr.hopINT.int_total_hops + 1;
        hdr.ipv4.totalLength = hdr.ipv4.totalLength + (bit<16>)hdr.shimINT.shim_length;

    }




    table add_metadata {

        key = {
            meta.switch_local.instruction: exact;
        }

        actions = {
            action_eq128;
            action_eq192;
            action_eq224;
            action_eq240;
            action_eq248;
            action_eq254;
            action_eq252;
            action_eq160;
            action_eq184;
            action_eq88;
        }
    }


// create of INT profile to INT data project

//bit 0 = switch id
//bit 1 = ingress port && egress port &&  
//bit 2 = hop lataency
//bit 3 = ingress timestamp
//bit 4 = egress timestamp
//bit 5 = count package
//bit 6 = bytes 
//bit 7 = not suport


// action_eq128   = 10000000
// action_eq192   = 11000000
// action_eq224   = 11100000
// action_eq240   = 11110000
// action_eq248   = 11111000 
// action_eq252   = 11111100
// action_eq254   = 11111110


// action_eq160   = 10100000
// action_eq184   = 10111000
// action_eq88    = 01011000


    apply {
        
        

              

        
        if(hdr.report_ipv4.typeServiceDiffServ == DSCP_INT){
//        if(hdr.ipv4.typeServiceDiffServ == DSCP_INT){

            add_metadata.apply(); 

        }

    }
}




/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.headerLength,
              hdr.ipv4.typeServiceDiffServ,
              hdr.ipv4.totalLength,
              hdr.ipv4.identification,
              hdr.ipv4.fragmentOffset,
              hdr.ipv4.timeToLive,
              hdr.ipv4.protocol,
              hdr.ipv4.sourceAddress,
              hdr.ipv4.destinationAddress },
            hdr.ipv4.headerChecksum,
            HashAlgorithm.csum16);


    update_checksum(
	    hdr.report_ipv4.isValid(),
            { hdr.report_ipv4.version,
	          hdr.report_ipv4.headerLength,
              hdr.report_ipv4.typeServiceDiffServ,
              hdr.report_ipv4.totalLength,
              hdr.report_ipv4.identification,
              hdr.report_ipv4.fragmentOffset,
              hdr.report_ipv4.timeToLive,
              hdr.report_ipv4.protocol,
              hdr.report_ipv4.sourceAddress,
              hdr.report_ipv4.destinationAddress },
            hdr.report_ipv4.headerChecksum,
            HashAlgorithm.csum16);
    }
    
}






/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {

        packet.emit(hdr.report_ethernet);
        packet.emit(hdr.report_ipv4);
        packet.emit(hdr.report_udp);
        packet.emit(hdr.report);

        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.hopINT);
        packet.emit(hdr.shimINT);

        packet.emit(hdr.switch_id);
        packet.emit(hdr.int_ingress_egress_ports);
        packet.emit(hdr.hop_latency);
        packet.emit(hdr.ingressTimestamp);
        packet.emit(hdr.egressTimestamp);
        packet.emit(hdr.countpackage);
        packet.emit(hdr.bytepackage);


        packet.emit(hdr.tailINT);
    }
}









/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
