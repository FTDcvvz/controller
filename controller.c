#include <stdio.h>  
#include <stdlib.h>  
#include <errno.h>  
#include <string.h>  
#include <sys/types.h>  
#include <netinet/in.h>  
#include <sys/socket.h>  
#include <sys/wait.h>  
#include <pthread.h>
#include "ruletables.h"
#include <arpa/inet.h>

#define SERVERPORT 3333
#define CONNPORT 6666

#define SET_POLICY 0
#define APPEND 1

#define BUFFER_SIZE 10
#define LENGTH 4

struct handle_c{
    int command;
    ruletable table;
};

void do_init(struct handle_c * handle, int command, struct list_head p,
	const char* saddr,const char* daddr,const char* smsk,const char* dmsk,
	uint16_t spts0,uint16_t spts1,uint16_t dpts0,uint16_t dpts1,
	int priority,const char* actionType,
	const char* actionDesc,const char* tablename)
{
	
	handle->command = command;
	handle->table.list = p;
	handle->table.head.s_addr =  inet_addr(saddr);
	handle->table.head.d_addr =  inet_addr(daddr);
	handle->table.head.smsk =  inet_addr(smsk);
	handle->table.head.dmsk =  inet_addr(dmsk);
	handle->table.head.spts[0] = spts0;
	handle->table.head.spts[1] = spts1;
	handle->table.head.dpts[0] = dpts0;
	handle->table.head.dpts[1] = dpts1;
	handle->table.priority = priority;
	strcpy(handle->table.actionType,actionType);
	strcpy(handle->table.actionDesc,actionDesc);
	strcpy(handle->table.property.tablename,tablename);
}

void init_handle(struct handle_c * handle)
{	
	struct list_head p;
	p.prev = p.next = NULL;
//	do_init(handle,SET_POLICY,p,"0.0.0.0","0.0.0.0","0.0.0.0",
//		"0.0.0.0",0,0,0,0,0,"FORWARD","ACCEPT","filter");

//	do_init(handle,APPEND,p,"192.168.0.1","0.0.0.0","255.255.255.255",
//		"0.0.0.0",0,0,0,0,0,"INPUT","ACCEPT","filter");

//	do_init(handle,APPEND,p,"0.0.0.0","0.0.0.0","0.0.0.0",
//		"0.0.0.0",0,0,137,138,0,"INPUT","ACCEPT","filter");

	do_init(handle,APPEND,p,"192.168.0.1","10.10.10.10","255.255.255.255",
		"255.255.255.255",0,0,0,0,0,"INPUT","ACCEPT","filter");

}

void send_to_my_mod(struct handle_c* handle)
{
	
}

void do_server()
{

}

int main ()
{
	int    sockfd, n;
    struct sockaddr_in    servaddr;
	
	if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
	    printf("create socket error: %s(errno: %d)\n", strerror(errno),errno);
	    exit(0);
	}
	memset(&servaddr, 0, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(CONNPORT);
    if( inet_pton(AF_INET, "127.0.0.1", &servaddr.sin_addr) <= 0){
    printf("inet_pton error\n");
    exit(0);
    }

    if( connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0){
    printf("connect error: %s(errno: %d)\n",strerror(errno),errno);
    exit(0);
    }

    int needSend=sizeof(struct handle_c); 
/** fatal question: why handle must be malloced  after buffer?????
*   struct handle_c *handle =(struct handle_c *) malloc(needSend);
*   init_handle(handle);
**/
    char *buffer=(char*)malloc(needSend);
    //handle malloced after buffer,everthing is ok.
    struct handle_c *handle =(struct handle_c *) malloc(needSend);
    init_handle(handle);
  
    int pos=0;
    int len;
    memcpy(buffer,handle,needSend);
    while(pos < needSend){
	        len = send(sockfd, buffer+pos, BUFFER_SIZE, 0);
	        if (len < 0)
	        {
	            printf("Send Data Failed!\n");
	            break;
	        }
	        pos+=len;
    }
    close(sockfd);
    free(buffer);
    free(handle);
    buffer = NULL;
    handle = NULL;


    do_server();
}
