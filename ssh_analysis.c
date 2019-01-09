#include<stdint.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include"ssh_analysis.h"

#define KEX_INIT  20
#define DH_REQUEST 34
#define DH_GROUP 31
#define DH_INIT 32
#define DH_REPLY 33
#define NEW_KEYS 21

int print_hex(const unsigned char *data, int len){
    int i;
    for(i=0; i<len; i++){
        printf("%02x ", data[i]);
        if(i%8 == 7) printf("  ");
        if(i%16==15) printf("\n");
    }
    printf("\n");
}

struct Algorithms{
    uint32_t kex_algorithms_len;
    char *kex_algorithms;

    uint32_t s_hkey_algorithms_len;
    char *s_hkey_algorithms;

    uint32_t enc_algorithms_ctos_len;
    char *enc_algorithms_ctos;

    uint32_t enc_algorithms_stoc_len;
    char *enc_algorithms_stoc;

    uint32_t mac_algorithms_ctos_len;
    char *mac_algorithms_ctos;

    uint32_t mac_algorithms_stoc_len;
    char *mac_algorithms_stoc;

    uint32_t comp_algorithms_ctos_len;
    char *comp_algorithms_ctos;

    uint32_t comp_algorithms_stoc_len;
    char *comp_algorithms_stoc;
};



struct SSH_info{
    char c_id_string[255];
    char s_id_string[255];
    struct Algorithms  client_algorithms;
    struct Algorithms  server_algorithms;
};



int proto_ssh_init(void **handle, void *userdata){
    *handle = malloc(sizeof(struct SSH_info));
    struct SSH_info *ssh_info = (struct SSH_info*)(*handle);
    memset(ssh_info->c_id_string, 0, 255);
    memset(ssh_info->s_id_string, 0, 255);
    memset(&(ssh_info->client_algorithms), 0, sizeof(struct Algorithms));
    memset(&(ssh_info->client_algorithms), 0, sizeof(struct Algorithms));
    return 0;
}


/*
 * direction: client -> server  0
 *            server -> client  1
 *
 * return:  0 succese, 1 failure
 */

int process_ssh_stream(void *handle, const char *protodata, int32_t len, int32_t direction){
    //puts("In func process_ssh_stream"); 
    //print_hex(protodata, 50);
    char ssh_str[] = "SSH";
    //printf("first byte: %02x, ssh_str: %02x\n", protodata[0], ssh_str[0]);
    if(memcmp(protodata, ssh_str, 3)==0){
        puts("process id string");
        process_id_string(handle, protodata, len, direction);
    }else{
        puts("process kex");
        uint8_t msg_code = protodata[5];
        //ssh_callback(msg_code,NULL,NULL);
        printf("message code : %02x\n", msg_code);
        if(msg_code == KEX_INIT){
            static int cnt = 0;
            cnt ++;
            //ssh_callback(msg_code, NULL, NULL);
            /*4bytes packet length and 1byte padding length, so binary packet starts at fifth byte*/
            process_kex_init(handle, protodata+5, direction);
            if(cnt == 2){
                ssh_callback(msg_code, handle, NULL);
            }
        }
        else if(msg_code == DH_REQUEST){
            ssh_callback(msg_code, NULL, NULL);
            process_dh_request(handle, protodata+5,len, direction);
        }
        else if(msg_code == DH_GROUP){
            ssh_callback(msg_code, NULL, NULL);
            process_dh_group(handle, protodata+5, len, direction);
        }
        else if(msg_code == DH_INIT){
            ssh_callback(msg_code, NULL, NULL);
            process_dh_init(handle, protodata+5, len, direction);
        }
        else if(msg_code == DH_REPLY){
            ssh_callback(msg_code, NULL, NULL);
            process_dh_reply(handle, protodata+5, len, direction);
        }
        else if(msg_code == NEW_KEYS){
            ssh_callback(msg_code, NULL, NULL);
            process_new_keys(handle, protodata+5, len, direction);
        }

        // there may be multiple ssh packets in a sigle tcp payload
        //uint32_t  ssh_packet_len = ntohl(*(uint32_t*)protodata);
        //if( (ssh_packet_len + 4) < len ){
        //    protodata = protodata + 4 + ssh_packet_len;
        //    len = len - 4 - ssh_packet_len;
        //    process_ssh_stream(handle, protodata, len, direction);
        //}
   }
   return 0; 
}


int process_id_string(void *handle, const char *protodata, int32_t len, int32_t direction){
    //client -> server
    struct SSH_info  *s_info = (struct SSH_info *)handle; 
    printf("In func process_id_string.\n");
    printf("len: %d\n", len);
    if( direction == 0 ){
        memcpy(s_info->c_id_string, protodata, len-2);        
        puts(s_info->c_id_string);
    }else if(direction == 1){                          // server -> client
        memcpy(s_info->s_id_string, protodata, len-2);
        puts(s_info->s_id_string);
    }
    return 0;
}

int process_kex_init(void *handle, const char *protodata, int32_t direction){
    //puts("In func process_kex_init");
    struct SSH_info *s_info = (struct SSH_info*)handle;
    const char *ptr_data = protodata;
    if(direction == 0 ) {   // c -> s
        
        //message code 1 byte
        //cookies 16 bytes
        //algorithms namelist starts at 17th byte
        //namelist format is specified in RFC 4251
        ptr_data += 17;
        uint32_t kex_algorithms_len = ntohl(*(uint32_t*)ptr_data);
        //printf("kex_algorithms_len:%u\n", kex_algorithms_len);
        (s_info->client_algorithms).kex_algorithms_len = kex_algorithms_len;
        (s_info->client_algorithms).kex_algorithms = (char *)malloc(kex_algorithms_len+1);
        memcpy( (s_info->client_algorithms).kex_algorithms, ptr_data+4, kex_algorithms_len);
        (s_info->client_algorithms).kex_algorithms[kex_algorithms_len] = 0;

        ptr_data = ptr_data + 4 + kex_algorithms_len;
        uint32_t s_hkey_algorithms_len = ntohl(*(uint32_t*)ptr_data);
        printf("s_hkey_algorithms_len:%u\n", s_hkey_algorithms_len);
        (s_info->client_algorithms).s_hkey_algorithms_len = s_hkey_algorithms_len;
        (s_info->client_algorithms).s_hkey_algorithms = (char *)malloc(s_hkey_algorithms_len+1);
        memcpy( (s_info->client_algorithms).s_hkey_algorithms, ptr_data+4, s_hkey_algorithms_len);
        (s_info->client_algorithms).s_hkey_algorithms[s_hkey_algorithms_len] = 0;


        ptr_data = ptr_data + 4 + s_hkey_algorithms_len;
        uint32_t enc_algorithms_ctos_len = ntohl(*(uint32_t*)ptr_data);
        (s_info->client_algorithms).enc_algorithms_ctos_len = enc_algorithms_ctos_len;
        (s_info->client_algorithms).enc_algorithms_ctos = (char *)malloc(enc_algorithms_ctos_len+1);
        memcpy( (s_info->client_algorithms).enc_algorithms_ctos, ptr_data+4, enc_algorithms_ctos_len);
        (s_info->client_algorithms).enc_algorithms_ctos[enc_algorithms_ctos_len] = 0;

        ptr_data = ptr_data + 4 + enc_algorithms_ctos_len;
        uint32_t enc_algorithms_stoc_len = ntohl(*(uint32_t*)ptr_data);
        (s_info->client_algorithms).enc_algorithms_stoc_len = enc_algorithms_stoc_len;
        (s_info->client_algorithms).enc_algorithms_stoc = (char *)malloc(enc_algorithms_stoc_len+1);
        memcpy( (s_info->client_algorithms).enc_algorithms_stoc, ptr_data+4, enc_algorithms_stoc_len);
        (s_info->client_algorithms).enc_algorithms_stoc[enc_algorithms_stoc_len] = 0;


        ptr_data = ptr_data + 4 + enc_algorithms_stoc_len;
        uint32_t mac_algorithms_ctos_len = ntohl(*(uint32_t*)ptr_data);
        (s_info->client_algorithms).mac_algorithms_ctos_len = mac_algorithms_ctos_len;
        (s_info->client_algorithms).mac_algorithms_ctos = (char *)malloc(mac_algorithms_ctos_len+1);
        memcpy( (s_info->client_algorithms).mac_algorithms_ctos, ptr_data+4, mac_algorithms_ctos_len);
        (s_info->client_algorithms).mac_algorithms_ctos[mac_algorithms_ctos_len] = 0;


        ptr_data = ptr_data + 4 + mac_algorithms_ctos_len;
        uint32_t mac_algorithms_stoc_len = ntohl(*(uint32_t*)ptr_data);
        (s_info->client_algorithms).mac_algorithms_stoc_len = mac_algorithms_stoc_len;
        (s_info->client_algorithms).mac_algorithms_stoc = (char *)malloc(mac_algorithms_stoc_len+1);
        memcpy( (s_info->client_algorithms).mac_algorithms_stoc, ptr_data+4, mac_algorithms_stoc_len);
        (s_info->client_algorithms).mac_algorithms_stoc[mac_algorithms_stoc_len] = 0;

        ptr_data = ptr_data + 4 + mac_algorithms_stoc_len;
        uint32_t comp_algorithms_ctos_len = ntohl(*(uint32_t*)ptr_data);
        (s_info->client_algorithms).comp_algorithms_ctos_len = comp_algorithms_ctos_len;
        (s_info->client_algorithms).comp_algorithms_ctos = (char *)malloc(comp_algorithms_ctos_len+1);
        memcpy( (s_info->client_algorithms).comp_algorithms_ctos, ptr_data+4, comp_algorithms_ctos_len);
        (s_info->client_algorithms).comp_algorithms_ctos[comp_algorithms_ctos_len] = 0;


        ptr_data = ptr_data + 4 + comp_algorithms_ctos_len;
        uint32_t comp_algorithms_stoc_len = ntohl(*(uint32_t*)ptr_data);
        (s_info->client_algorithms).comp_algorithms_stoc_len = comp_algorithms_stoc_len;
        (s_info->client_algorithms).comp_algorithms_stoc = (char *)malloc(comp_algorithms_stoc_len+1);
        memcpy( (s_info->client_algorithms).comp_algorithms_stoc, ptr_data+4, comp_algorithms_stoc_len);
        (s_info->client_algorithms).comp_algorithms_stoc[comp_algorithms_stoc_len] = 0;

    }
    if(direction == 1 ) {   // c -> s
        
        ptr_data += 17;
        uint32_t kex_algorithms_len = ntohl(*(uint32_t*)ptr_data);
        printf("kex_algorithms_len:%u\n", kex_algorithms_len);
        (s_info->server_algorithms).kex_algorithms_len = kex_algorithms_len;
        (s_info->server_algorithms).kex_algorithms = (char *)malloc(kex_algorithms_len+1);
        memcpy( (s_info->server_algorithms).kex_algorithms, ptr_data+4, kex_algorithms_len); 
        (s_info->server_algorithms).kex_algorithms[kex_algorithms_len] = 0;

        ptr_data = ptr_data + 4 + kex_algorithms_len;
        uint32_t s_hkey_algorithms_len = ntohl(*(uint32_t*)ptr_data);
        printf("s_hkey_algorithms_len:%u\n",s_hkey_algorithms_len);
        (s_info->server_algorithms).s_hkey_algorithms_len = s_hkey_algorithms_len;
        (s_info->server_algorithms).s_hkey_algorithms = (char *)malloc(s_hkey_algorithms_len+1);
        memcpy( (s_info->server_algorithms).s_hkey_algorithms, ptr_data+4, s_hkey_algorithms_len);
        (s_info->server_algorithms).s_hkey_algorithms[s_hkey_algorithms_len] = 0;

        ptr_data = ptr_data + 4 + s_hkey_algorithms_len;
        uint32_t enc_algorithms_ctos_len = ntohl(*(uint32_t*)ptr_data);
        (s_info->server_algorithms).enc_algorithms_ctos_len = enc_algorithms_ctos_len;
        (s_info->server_algorithms).enc_algorithms_ctos = (char *)malloc(enc_algorithms_ctos_len+1);
        memcpy( (s_info->server_algorithms).enc_algorithms_ctos, ptr_data+4, enc_algorithms_ctos_len);
        (s_info->server_algorithms).enc_algorithms_ctos[enc_algorithms_ctos_len] = 0;


        ptr_data = ptr_data + 4 + enc_algorithms_ctos_len;
        uint32_t enc_algorithms_stoc_len = ntohl(*(uint32_t*)ptr_data);
        (s_info->server_algorithms).enc_algorithms_stoc_len = enc_algorithms_stoc_len;
        (s_info->server_algorithms).enc_algorithms_stoc = (char *)malloc(enc_algorithms_stoc_len+1);
        memcpy( (s_info->server_algorithms).enc_algorithms_stoc, ptr_data+4, enc_algorithms_stoc_len);
        (s_info->server_algorithms).enc_algorithms_stoc[enc_algorithms_stoc_len] = 0;



        ptr_data = ptr_data + 4 + enc_algorithms_stoc_len;
        uint32_t mac_algorithms_ctos_len = ntohl(*(uint32_t*)ptr_data);
        (s_info->server_algorithms).mac_algorithms_ctos_len = mac_algorithms_ctos_len;
        (s_info->server_algorithms).mac_algorithms_ctos = (char *)malloc(mac_algorithms_ctos_len+1);
        memcpy( (s_info->server_algorithms).mac_algorithms_ctos, ptr_data+4, mac_algorithms_ctos_len);
        (s_info->server_algorithms).mac_algorithms_ctos[mac_algorithms_ctos_len] = 0;



        ptr_data = ptr_data + 4 + mac_algorithms_ctos_len;
        uint32_t mac_algorithms_stoc_len = ntohl(*(uint32_t*)ptr_data);
        (s_info->server_algorithms).mac_algorithms_stoc_len = mac_algorithms_stoc_len;
        (s_info->server_algorithms).mac_algorithms_stoc = (char *)malloc(mac_algorithms_stoc_len+1);
        memcpy( (s_info->server_algorithms).mac_algorithms_stoc, ptr_data+4, mac_algorithms_stoc_len);
        (s_info->server_algorithms).mac_algorithms_stoc[mac_algorithms_stoc_len] = 0;


        ptr_data = ptr_data + 4 + mac_algorithms_stoc_len;
        uint32_t comp_algorithms_ctos_len = ntohl(*(uint32_t*)ptr_data);
        (s_info->server_algorithms).comp_algorithms_ctos_len = comp_algorithms_ctos_len;
        (s_info->server_algorithms).comp_algorithms_ctos = (char *)malloc(comp_algorithms_ctos_len+1);
        memcpy( (s_info->server_algorithms).comp_algorithms_ctos, ptr_data+4, comp_algorithms_ctos_len);
        (s_info->server_algorithms).comp_algorithms_ctos[comp_algorithms_ctos_len] = 0;



        ptr_data = ptr_data + 4 + comp_algorithms_ctos_len;
        uint32_t comp_algorithms_stoc_len = ntohl(*(uint32_t*)ptr_data);
        (s_info->server_algorithms).comp_algorithms_stoc_len = comp_algorithms_stoc_len;
        (s_info->server_algorithms).comp_algorithms_stoc = (char *)malloc(comp_algorithms_stoc_len+1);
        memcpy( (s_info->server_algorithms).comp_algorithms_stoc, ptr_data+4, comp_algorithms_stoc_len);
        (s_info->server_algorithms).comp_algorithms_stoc[comp_algorithms_stoc_len] = 0;
    }
    return 0;
}

int process_dh_request(void *handle, const char *protodata, int32_t len, int32_t direction){
    return 0;
}
int process_dh_group(void *handle, const char *protodata, int32_t len, int32_t direction){
    return 0;
}

int process_dh_init(void *handle, const char *protodata, int32_t len, int32_t direction){
    return 0;
}

int process_dh_reply(void *handle, const char *protodata, int32_t len, int32_t direction){
    return 0;
}
int process_new_keys(void *handle, const char *protodata, int32_t len, int32_t direction){
    return 0;
}





int ssh_callback(int type, void *content, void *userdata){
    //printf("message code : %x\n", type);
    struct SSH_info *s_info = (struct SSH_info *)content;
    if(type == KEX_INIT){
        struct Algorithms alg = s_info->client_algorithms;
        printf("client:\n");
        printf("kex:%s\n",alg.kex_algorithms);
        free((s_info->client_algorithms).kex_algorithms);
        printf("s_hkey:%s\n", alg.s_hkey_algorithms);
        free((s_info->client_algorithms).s_hkey_algorithms);
        printf("enc_ctos:%s\n", alg.enc_algorithms_ctos);
        free((s_info->client_algorithms).enc_algorithms_ctos);
        printf("enc_stoc:%s\n", alg.enc_algorithms_stoc);
        free((s_info->client_algorithms).enc_algorithms_stoc);
        printf("mac_ctos:%s\n", alg.mac_algorithms_ctos);
        free((s_info->client_algorithms).mac_algorithms_ctos);
        printf("mac_stoc:%s\n", alg.mac_algorithms_stoc);
         free((s_info->client_algorithms).mac_algorithms_stoc);
        printf("comp_ctos:%s\n", alg.comp_algorithms_ctos);
        free((s_info->client_algorithms).comp_algorithms_ctos);
        printf("comp_stoc:%s\n", alg.comp_algorithms_stoc);
        free((s_info->client_algorithms).comp_algorithms_stoc);

        alg = s_info->server_algorithms;
        printf("server:\n");
        printf("kex:%s\n",alg.kex_algorithms);
        free((s_info->server_algorithms).kex_algorithms);
        printf("s_hkey:%s\n", alg.s_hkey_algorithms);
        free((s_info->server_algorithms).s_hkey_algorithms);
        printf("enc_ctos:%s\n", alg.enc_algorithms_ctos);
        free((s_info->server_algorithms).enc_algorithms_ctos);
        printf("enc_stoc:%s\n", alg.enc_algorithms_stoc);
        free((s_info->server_algorithms).enc_algorithms_stoc);
        printf("mac_ctos:%s\n", alg.mac_algorithms_ctos);
        free((s_info->server_algorithms).mac_algorithms_ctos);
        printf("mac_stoc:%s\n", alg.mac_algorithms_stoc);
        free((s_info->server_algorithms).mac_algorithms_stoc);
        printf("comp_ctos:%s\n", alg.comp_algorithms_ctos);
        free((s_info->server_algorithms).comp_algorithms_ctos);
        printf("comp_stoc:%s\n", alg.comp_algorithms_stoc);
        free((s_info->server_algorithms).comp_algorithms_stoc);
    }
    return 0;    
}


int proto_ssh_release(void **handle){
    struct SSH_info *s_info = (struct SSH_info*)(*handle);
    free(s_info);
    return 0;
}







