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

#define SERVERPORT 3333  //server
#define CONNPORT 6666     //client
#define MY_MOD_ADDR "127.0.0.1"

#define BUFFER_SIZE 10

typedef enum _command_list
{	SET_POLICY ,
	APPEND	,
	INSERT ,
	ALTER ,
	DELETE ,
	CLEAN  ,
	ALLIN		
}command_list;
struct handle_c{
    int index;
    command_list command;
    ruletable table;
}; 

static void 
do_init(struct handle_c * handle, command_list command,int index, struct list_head p,
	const char* saddr,const char* daddr,const char* smsk,const char* dmsk,
	uint16_t spts0,uint16_t spts1,uint16_t dpts0,uint16_t dpts1,
	int priority,const char * proto,const char* actionType,
	const char* actionDesc,const char* tablename)
{
	
	handle->command = command;
	handle->index = index;
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
	if(proto == NULL)
		handle->table.head.proto = PROTO_NONE;
	else if(strcmp(proto,"tcp") == 0)
		handle->table.head.proto = TCP;
	else if(strcmp(proto,"udp") == 0)
		handle->table.head.proto = UDP;
	else if(strcmp(proto,"icmp") == 0)
		handle->table.head.proto = ICMP;
	else if(strcmp(proto,"arp") == 0)
		handle->table.head.proto = ARP;
	
	if(actionType == NULL) handle->table.actionType = TYPE_NONE;
	   else  if(strcmp(actionType,"INPUT") == 0)
		handle->table.actionType = INPUT;
	    else if(strcmp(actionType,"OUTPUT") == 0)
		handle->table.actionType = OUTPUT;
	    else if(strcmp(actionType,"FORWARD") == 0)
		handle->table.actionType = FORWARD;
	    else if(strcmp(actionType,"PREROUTING") == 0)
		handle->table.actionType = PREROUTING;
	    else if(strcmp(actionType,"POSTROUTING") == 0)
		handle->table.actionType = POSTROUTING;
	    
 	    if(actionDesc== NULL) handle->table.actionDesc = DESC_NONE;
	    else if(strcmp(actionDesc,"ACCEPT") == 0)
		handle->table.actionDesc = ACCEPT;
	    else if(strcmp(actionDesc,"DROP") == 0)
		handle->table.actionDesc = DROP;
	    else if(strcmp(actionDesc,"QUEUE") == 0)
		handle->table.actionDesc = QUEUE;
	    else if(strcmp(actionDesc,"RETURN") == 0)
		handle->table.actionDesc = RETURN;
	   
	    if(tablename == NULL) handle->table.property.tablename = NAME_NONE;
	    else if(strcmp(tablename,"filter") == 0)
		handle->table.property.tablename = filter;
	    else if(strcmp(tablename,"nat") == 0)
		handle->table.property.tablename = nat;
	    else if(strcmp(tablename,"mangle") == 0)
		handle->table.property.tablename = mangle;
	    
}

static void 
init_handle(struct handle_c * handle)
{	
	struct list_head p;
	p.prev = p.next = NULL;
//	do_init(handle,SET_POLICY,0,p,"0.0.0.0","0.0.0.0","0.0.0.0",
//		"0.0.0.0",0,0,0,0,0,NULL,"FORWARD","DROP","filter");

//	do_init(handle,APPEND,0,p,"192.168.0.1","10.10.10.10","255.255.255.255",
//		"0.0.0.0",0,137,138,80,0,"udp","INPUT","ACCEPT","filter");

//	do_init(handle,APPEND,0,p,"0.0.0.0","0.0.0.0","0.0.0.0",
//		"0.0.0.0",0,0,137,0,0,"tcp","INPUT","ACCEPT","filter");

//	do_init(handle,APPEND,0,p,"192.168.0.1","15.15.15.15","255.255.255.255",
//		"255.255.255.255",123,128,300,301,0,"tcp","INPUT","ACCEPT","filter");

//	do_init(handle,CLEAN,0,p,"0.0.0.0","0.0.0.0","0.0.0.0",
//		"0.0.0.0",0,0,0,0,0,NULL,NULL,NULL,"filter");

	do_init(handle,DELETE,2,p,"0.0.0.0","0.0.0.0","0.0.0.0",
		"0.0.0.0",0,0,0,0,0,NULL,"INPUT",NULL,"filter");

}

static void 
send_message_to_my_mod()
{
	int    sockfd;
    struct sockaddr_in    servaddr;
	
	if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
	    printf("create socket error: %s(errno: %d)\n", strerror(errno),errno);
	    exit(0);
	}
	memset(&servaddr, 0, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(CONNPORT);
    if( inet_pton(AF_INET, MY_MOD_ADDR, &servaddr.sin_addr) <= 0){
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
}

static void 
print_message(struct handle_c * h)
{
	printf("info from my module: %u %u %u %u \n",h->command,h->table.actionType,h->table.property.tablename,
        h->table.actionDesc);
}

static void 
do_server()
{
	int    listenfd,connfd;
    struct sockaddr_in  servaddr;

    if( (listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ){
        printf("create socket error: %s(errno: %d)\n",strerror(errno),errno);
        exit(0);
    }
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(SERVERPORT);
    if( bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) == -1){
        printf("bind socket error: %s(errno: %d)\n",strerror(errno),errno);
        exit(0);
    }
    if( listen(listenfd, 10) == -1){
        printf("listen socket error: %s(errno: %d)\n",strerror(errno),errno);
        exit(0);
    }

    printf("======waiting for my module's request ======\n");
    while(1){
        if((connfd = accept(listenfd, (struct sockaddr*)NULL, NULL)) == -1){
            printf("accept socket error: %s(errno: %d)",strerror(errno),errno);
            continue;
        }
	printf("messages coming from my module.\n");
            int recvSize = sizeof(struct handle_c); 
            char * buffer = (char*)malloc(recvSize); 
	    if(!buffer){ 
	      fprintf(stderr, "malloc error : %s\n",strerror(errno));
            } 
            struct handle_c *handle = (struct handle_c *)malloc(recvSize); 
            int pos=0; 
            int len=0; 
            while(pos<recvSize){ 
                len = recv(connfd,buffer+pos,BUFFER_SIZE,0); 
                if(len<=0){ 
                    perror("recv error! \n"); 
                    break; 
                } 
                pos+=len; 
            } 
            if(!memcpy(handle,buffer,recvSize)){ 
	      fprintf(stderr, "memcpy error : %s\n",strerror(errno));
            } 
            free(buffer); 
            buffer = NULL ;
	print_message(handle);
	free(handle);
    close(connfd);
    }
    close(listenfd);
}

int 
main ()
{
	send_message_to_my_mod();
    do_server();
}

