#include<stdio.h>
#include<string.h>
#include"ssh_analysis.h"

#define KEX_INIT  20
#define DH_REQUEST 34
#define DH_GROUP 31
#define DH_INIT 32
#define DH_REPLY 33
#define NEW_KEYS 21


struct SSH_info{
    char c_id_string[255];
    char s_id_string[255];
    struct Algorithms  client_algorithms;
    struct Algorithms  server_algorithms;
};


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

int proto_ssh_init(void **handle, void *userdata){
    *handle = malloc(sizeof(struct SSH_info));
}


/*
 * direction: client -> server  0
 *            server -> client  1
 *
 * return:  0 succese, 1 failure
 */

int process_ssh_stream(void *handle, const char *protodata, int32_t len, int32_t direction){
    
    if(strncmp(protodata, "ssh-", 4)==0){
        process_id_string(handle, protodata, len, direction);
    }else{
        
        int msg_code = protodata[5];
        if(msg_code == KEX_INIT){
            ssh_callback(msg_code, NULL, NULL);
            process_kex_init(handle, protodata, len, direction);
        }
        else if(msg_code == DH_REQUEST){
            ssh_callback(msg_code, NULL, NULL);
            process_dh_request(handle, protodata, len, direction);
        }
        else if(msg_code == DH_GROUP){
            ssh_callback(msg_code, NULL, NULL);
            process_dh_group(handle, protodata, len, direction);
        }
        else if(msg_code == DH_INIT){
            ssh_callback(msg_code, NULL, NULL);
            process_dh_init(handle, protodata, len, direction);
        }
        else if(msg_code == DH_REPLY){
            ssh_callback(msg_code, NULL, NULL);
            process_dh_reply(handle, protodata, len, direction);
        }
        else if(msg_code == NEW_KEYS){
            ssh_callback(msg_code, NULL, NULL);
            process_new_keys(handle, protodata, len, direction);
        }

        // there may be multiple ssh packets in a sigle tcp payload
        uint32_t  ssh_packet_len = protodata;
        if( (ssh_packet_len + 4) < len ){
            protodata = protodata + 4 + ssh_packet_len;
            len = len - 4 - ssh_packet_len;
            process_ssh_stream(handle, protodata, len, direction);
        }
   }
   return 0; 
}


int process_id_string(void *handle, const char *protodata, int32_t len, int32_t direction){
    //client -> server
    struct SSH_info  *s_info = (struct SSH_info *)handle; 
    if( direction == 0 ){
        memcpy(s_info->c_id_string, protodata, len-2);        
    }else if(direction == 1){                          // server -> client
        memcpy(s_info->s_id_string, protodata, len-2);
    }
    return 0;
}

int process_kex_init(void *handle, const char *protodata, int32_t len, int32_t direction){
    struct SSH_info *s_info = (struct SSH_info*)handle;
    if(direction == 0 ) {   // c -> s
        char *ptr_data = protodata;
        
        //message code 1 byte
        //cookies 16 bytes
        //algorithms namelist starts at 17th byte
        //namelist format is specified in RFC 4251
        ptr_data += 17;
        uint32_t kex_algorithms_len = (uint32_t)ptr_data;
        (s_info->client_algorithms).kex_algorithms_len = kex_algorithms_len;
        (s_info->client_algorithms).kex_algorithms = (char *)malloc(kex_algorithms_len);
        memcpy( (s_info->client_algorithms).kex_algorithms, ptr_data+4, kex_algorithms_len); 

        ptr_data = ptr_data + 4 + kex_algorithms_len;
        uint32_t s_hkey_algorithms_len = (uint32_t)ptr_data;
        (s_info->client_algorithms).hkey_algorithms_len = hkey_algorithms_len;
        (s_info->client_algorithms).hkey_algorithms = (char *)malloc(hkey_algorithms_len);
        memcpy( (s_info->client_algorithms).hkey_algorithms, ptr_data+4, hkey_algorithms_len);

        ptr_data = ptr_data + 4 + s_hkey_algorithms_len;
        uint32_t enc_algorithms_ctos_len = (uint32_t)ptr_data;
        (s_info->client_algorithms).enc_algorithms_ctos_len = enc_algorithms_ctos_len;
        (s_info->client_algorithms).enc_algorithms_ctos = (char *)malloc(enc_algorithms_ctos_len);
        memcpy( (s_info->client_algorithms).enc_algorithms_ctos, ptr_data+4, enc_algorithms_ctos_len);

        ptr_data = ptr_data + 4 + enc_algorithms_ctos_len;
        uint32_t enc_algorithms_stoc_len = (uint32_t)ptr_data;
        (s_info->client_algorithms).enc_algorithms_stoc_len = enc_algorithms_stoc_len;
        (s_info->client_algorithms).enc_algorithms_stoc = (char *)malloc(enc_algorithms_stoc_len);
        memcpy( (s_info->client_algorithms).enc_algorithms_stoc, ptr_data+4, enc_algorithms_stoc_len);



        ptr_data = ptr_data + 4 + enc_algorithms_stoc_len;
        uint32_t mac_algorithms_ctos_len = (uint32_t)ptr_data;
        (s_info->client_algorithms).mac_algorithms_ctos_len = mac_algorithms_ctos_len;
        (s_info->client_algorithms).mac_algorithms_ctos = (char *)malloc(mac_algorithms_ctos_len);
        memcpy( (s_info->client_algorithms).mac_algorithms_ctos, ptr_data+4, mac_algorithms_ctos_len);



        ptr_data = ptr_data + 4 + mac_algorithms_ctos_len;
        uint32_t mac_algorithms_stoc_len = (uint32_t)ptr_data;
        (s_info->client_algorithms).mac_algorithms_stoc_len = mac_algorithms_stoc_len;
        (s_info->client_algorithms).mac_algorithms_stoc = (char *)malloc(mac_algorithms_stoc_len);
        memcpy( (s_info->client_algorithms).mac_algorithms_stoc, ptr_data+4, mac_algorithms_stoc_len);


        ptr_data = ptr_data + 4 + mac_algorithms_stoc_len;
        uint32_t comp_algorithms_ctos_len = (uint32_t)ptr_data;
        (s_info->client_algorithms).comp_algorithms_ctos_len = comp_algorithms_ctos_len;
        (s_info->client_algorithms).comp_algorithms_ctos = (char *)malloc(comp_algorithms_ctos_len);
        memcpy( (s_info->client_algorithms).comp_algorithms_ctos, ptr_data+4, comp_algorithms_ctos_len);



        ptr_data = ptr_data + 4 + comp_algorithms_ctos_len;
        uint32_t comp_algorithms_stoc_len = (uint32_t)ptr_data;
        (s_info->client_algorithms).comp_algorithms_stoc_len = comp_algorithms_stoc_len;
        (s_info->client_algorithms).comp_algorithms_stoc = (char *)malloc(comp_algorithms_stoc_len);
        memcpy( (s_info->client_algorithms).comp_algorithms_stoc, ptr_data+4, comp_algorithms_stoc_len);


    }
    if(direction == 1 ) {   // c -> s
        char *ptr_data = protodata;
        
        ptr_data += 17;
        uint32_t kex_algorithms_len = (uint32_t)ptr_data;
        (s_info->server_algorithms).kex_algorithms_len = kex_algorithms_len;
        (s_info->server_algorithms).kex_algorithms = (char *)malloc(kex_algorithms_len);
        memcpy( (s_info->server_algorithms).kex_algorithms, ptr_data+4, kex_algorithms_len); 

        ptr_data = ptr_data + 4 + kex_algorithms_len;
        uint32_t s_hkey_algorithms_len = (uint32_t)ptr_data;
        (s_info->server_algorithms).hkey_algorithms_len = hkey_algorithms_len;
        (s_info->server_algorithms).hkey_algorithms = (char *)malloc(hkey_algorithms_len);
        memcpy( (s_info->server_algorithms).hkey_algorithms, ptr_data+4, hkey_algorithms_len);

        ptr_data = ptr_data + 4 + s_hkey_algorithms_len;
        uint32_t enc_algorithms_ctos_len = (uint32_t)ptr_data;
        (s_info->server_algorithms).enc_algorithms_ctos_len = enc_algorithms_ctos_len;
        (s_info->server_algorithms).enc_algorithms_ctos = (char *)malloc(enc_algorithms_ctos_len);
        memcpy( (s_info->server_algorithms).enc_algorithms_ctos, ptr_data+4, enc_algorithms_ctos_len);

        ptr_data = ptr_data + 4 + enc_algorithms_ctos_len;
        uint32_t enc_algorithms_stoc_len = (uint32_t)ptr_data;
        (s_info->server_algorithms).enc_algorithms_stoc_len = enc_algorithms_stoc_len;
        (s_info->server_algorithms).enc_algorithms_stoc = (char *)malloc(enc_algorithms_stoc_len);
        memcpy( (s_info->server_algorithms).enc_algorithms_stoc, ptr_data+4, enc_algorithms_stoc_len);



        ptr_data = ptr_data + 4 + enc_algorithms_stoc_len;
        uint32_t mac_algorithms_ctos_len = (uint32_t)ptr_data;
        (s_info->server_algorithms).mac_algorithms_ctos_len = mac_algorithms_ctos_len;
        (s_info->server_algorithms).mac_algorithms_ctos = (char *)malloc(mac_algorithms_ctos_len);
        memcpy( (s_info->server_algorithms).mac_algorithms_ctos, ptr_data+4, mac_algorithms_ctos_len);



        ptr_data = ptr_data + 4 + mac_algorithms_ctos_len;
        uint32_t mac_algorithms_stoc_len = (uint32_t)ptr_data;
        (s_info->server_algorithms).mac_algorithms_stoc_len = mac_algorithms_stoc_len;
        (s_info->server_algorithms).mac_algorithms_stoc = (char *)malloc(mac_algorithms_stoc_len);
        memcpy( (s_info->server_algorithms).mac_algorithms_stoc, ptr_data+4, mac_algorithms_stoc_len);


        ptr_data = ptr_data + 4 + mac_algorithms_stoc_len;
        uint32_t comp_algorithms_ctos_len = (uint32_t)ptr_data;
        (s_info->server_algorithms).comp_algorithms_ctos_len = comp_algorithms_ctos_len;
        (s_info->server_algorithms).comp_algorithms_ctos = (char *)malloc(comp_algorithms_ctos_len);
        memcpy( (s_info->server_algorithms).comp_algorithms_ctos, ptr_data+4, comp_algorithms_ctos_len);



        ptr_data = ptr_data + 4 + comp_algorithms_ctos_len;
        uint32_t comp_algorithms_stoc_len = (uint32_t)ptr_data;
        (s_info->server_algorithms).comp_algorithms_stoc_len = comp_algorithms_stoc_len;
        (s_info->server_algorithms).comp_algorithms_stoc = (char *)malloc(comp_algorithms_stoc_len);
        memcpy( (s_info->server_algorithms).comp_algorithms_stoc, ptr_data+4, comp_algorithms_stoc_len);

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
    printf("message code : %d", type);
    
}










