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
#include <pthread.h>

#define MESSAGEPORT 5555  
#define SERVERPORT 3333  //server
#define CONNPORT 6666     //client
#define MY_MOD_ADDR "127.0.0.1"
#define MAX_PRIORITY 100	//operate_tables.c also defined

#define BUFFER_SIZE 10

typedef enum _command_list
{	SET_POLICY ,
	APPEND	,
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
	char saddr[],char daddr[],char smsk[], char dmsk[],
	uint16_t spts0,uint16_t spts1,uint16_t dpts0,uint16_t dpts1,
	int priority,ProtoType proto,ActionType actionType,
	ActionDesc actionDesc,table_name tablename)
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
	handle->table.head.proto = proto;
	handle->table.actionType = actionType;
 	handle->table.actionDesc = actionDesc;
	handle->table.property.tablename = tablename;
	    
}

static void 
init_handle(struct handle_c * handle)
{	
	command_list command;
	int index;
	char sip[20],dip[20],smask[20],dmask[20];
	uint16_t spts0,spts1,dpts0,dpts1;
	int priority;
	ProtoType proto;
	ActionType actionType;
	ActionDesc actionDesc;
	table_name tablename;
	struct list_head p;
		p.prev = p.next = NULL;
		printf("输入信息构造发送数据:\n");
		printf("command: 0-SET_POLICY,1-APPEND,2-ALTER,3-DELETE,4-CLEAN,5-ALLIN"); 
		scanf("%d",&command);
		printf("index: ");
		scanf("%d",&index);
		printf("s ip: ");
		scanf("%s",sip);
		printf("d ip: ");
		scanf("%s",dip);
		printf("s mask : ");
		scanf("%s",smask);
		printf("d mask : ");
		scanf("%s",dmask);
		printf("s port low :");
		scanf("%d",&spts0);
		printf("s port high :");
		scanf("%d",&spts1);
		printf("d port low :");
		scanf("%d",&dpts0);
		printf("d port high :");
		scanf("%d",&dpts1);
		printf("priority : (MAX 100)");
		scanf("%d",&priority);
		printf("protocol:0-PROTO_NONE,1-TCP,2-UDP,3-ARP,4-ICMP\n");
		scanf("%d",&proto);
		printf("action type:0-TYPE_NONE,1-PREROUTING, 2-INPUT,3-OUTPUT,4-FORWARD,5-POSTROUTING\n");
		scanf("%d",&actionType);
		printf("action description:0-DESC_NONE,1-ACCEPT,2-DROP,3-QUEUE,4-RETURN\n");
		scanf("%d",&actionDesc);
		printf("tablename:0-NAME_NONE,1-filter,2-nat,3-mangle\n");
		scanf("%d",&tablename);

		do_init(handle,command,index,p,sip,dip,smask,dmask,spts0,spts1,dpts0,dpts1,priority,
proto,actionType,actionDesc,tablename);

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

   // while(1){
	    int needSend=sizeof(struct handle_c); 
	/** fatal question: why handle must be malloced  after buffer?????
	*   struct handle_c *handle =(struct handle_c *) malloc(needSend);
	*   init_handle(handle);
	**/
	    char *buffer=(char*)malloc(needSend);
	    //handle malloced after buffer,everything is ok.
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
	    free(buffer);
	    free(handle);
	    buffer = NULL;
	    handle = NULL;
  //  }
    close(sockfd);
}

static void 
print_message(struct handle_c * h)
{
	struct in_addr addr1,addr2,addr3,addr4;
    	memcpy(&addr1, &(h->table.head.s_addr), 4);
   	memcpy(&addr2, &(h->table.head.d_addr), 4);
	memcpy(&addr3, &(h->table.head.smsk), 4);
   	memcpy(&addr4, &(h->table.head.dmsk), 4);
	printf("table name :%u , actionType:%u , actionDesc:%u , priority:%u ,  saddr:%s ,",h->table.property.tablename,h->table.actionType,h->table.actionDesc,h->table.priority,inet_ntoa(addr1));
	printf(" daddr:%s , ",inet_ntoa(addr2) );
	printf("smsk:%s , ",inet_ntoa(addr3));
	printf("dmsk:%s ,",inet_ntoa(addr4));
	printf("spts[0]:%d , spts[1]:%d , dpts[0]:%d , dpts[1]:%d , protocal: %u \n\n",h->table.head.spts[0],h->table.head.spts[1],h->table.head.dpts[0],h->table.head.dpts[1],h->table.head.proto);
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


static void 
listen_alert_info()
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
    servaddr.sin_port = htons(MESSAGEPORT);
    if( bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) == -1){
        printf("bind socket error: %s(errno: %d)\n",strerror(errno),errno);
        exit(0);
    }
    if( listen(listenfd, 10) == -1){
        printf("listen socket error: %s(errno: %d)\n",strerror(errno),errno);
        exit(0);
    }
	
	printf("======waiting for my module's alert ======\n");
    while(1){
        if((connfd = accept(listenfd, (struct sockaddr*)NULL, NULL)) == -1){
            printf("accept socket error: %s(errno: %d)",strerror(errno),errno);
            continue;
        }
            int recvSize = 100; 
            char * buffer = (char*)malloc(recvSize); 
	    if(!buffer){ 
	      fprintf(stderr, "malloc error : %s\n",strerror(errno));
            }  
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
	    printf("%s",buffer);
            free(buffer); 
            buffer = NULL ;
    close(connfd);
    }
    close(listenfd);
}

int 
main ()
{
//do_server();
   pthread_t id1,id2;
   void * ret;
    if(pthread_create(&id1,NULL,(void *)(&do_server),NULL) == -1)
    {
        fprintf(stderr,"pthread_create error!\n");
        exit(0);
    }

/*     if(pthread_create(&id2,NULL,(void *)(&listen_alert_info),NULL) == -1)
    {
        fprintf(stderr,"pthread_create error!\n");
        exit(0);
    }
*/
    pthread_join(id1,&ret);
    send_message_to_my_mod();
}

