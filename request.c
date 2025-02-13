#include "io_helper.h"
#include "request.h"
#include<stdio.h>
#include<unistd.h>
#include<string.h>
#define MAXBUF (8192)
#define BUFSIZE 10000        //(10000, assuming the max size of buffer given by the user would be less than 10000)as queue and heap array required some constant expression for declaration

//
//	TODO: add code to create and manage the buffer
//
struct req_info {
    int is_static;
    int size;
    int fd;
    char buf[MAXBUF], method[MAXBUF], uri[MAXBUF], version[MAXBUF];
    char filename[MAXBUF], cgiargs[MAXBUF];
};

struct heap_node{
    int size;                   //size of the request
    struct req_info req;            //info of the request
};

struct q_node{
  struct req_info req;            //info of the request
};

struct queue_tag{
  struct q_node req_queue[BUFSIZE];
  int head;
  int tail;
};

struct Heap_Tag{
    struct heap_node req_queue[BUFSIZE];
    int count;
};

pthread_mutex_t mutex= PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t task_available= PTHREAD_COND_INITIALIZER; 
pthread_cond_t no_more_tasks= PTHREAD_COND_INITIALIZER; 

typedef struct Heap_Tag Heap;
typedef struct heap_node heapNode;
typedef struct q_node queueNode;
typedef struct queue_tag Queue;

Heap h;             //heap for requests for sff
Heap* heap=&h;
Queue q;        // queue of requests for fifo
Queue*queue=&q;

//----------------------------------minHeap functions-----------------------------------
void heapify_bottom_top(Heap *hptr,int key){
    heapNode temp;
    int parent_node = (key-1)/2;
    if(hptr->req_queue[parent_node].size > hptr->req_queue[key].size){
        //swap and recursive call
        temp = hptr->req_queue[parent_node];
        hptr->req_queue[parent_node] = hptr->req_queue[key];
        hptr->req_queue[key] = temp;
        heapify_bottom_top(hptr,parent_node);
    }
}

void heapify_top_bottom(Heap *h, int parent_node){
    int left = parent_node*2+1;
    int right = parent_node*2+2;
    int min;
    heapNode temp;

    if(left >= h->count || left <0)
        left = -1;
    if(right >= h->count || right <0)
        right = -1;

    if(left != -1 && h->req_queue[left].size < h->req_queue[parent_node].size)
        min=left;
    else
        min=parent_node;
    if(right != -1 && h->req_queue[right].size < h->req_queue[min].size)
        min = right;

    if(min != parent_node){
        temp = h->req_queue[min];
        h->req_queue[min] = h->req_queue[parent_node];
        h->req_queue[parent_node] = temp;

        // recursive  call
        heapify_top_bottom(h, min);
    }
}

void insertRequest(Heap *h, heapNode key){
    if( h->count < buffer_max_size){
        h->req_queue[h->count] = key;
        heapify_bottom_top(h, h->count);
        h->count++;
        buffer_size++;
    }
}

//returns the request with minimum size in the heap
heapNode PopMinReq(Heap *hptr){
    heapNode popped_req;
    if(hptr->count==0){
        printf("\n__Heap is Empty__\n");
        return popped_req;
    }
    // replace first node by last and delete last
    popped_req = hptr->req_queue[0];
    hptr->req_queue[0] = hptr->req_queue[hptr->count-1];
    hptr->count--;
    buffer_size--;
    heapify_top_bottom(hptr, 0);
    return popped_req;
}
//--------------------------------------minHeap functions over-----------------------------

//returns the frequency of substring in string
int substring_count(char* string, char* substring) {
  int i, j, l1, l2;
  int count = 0;
  int found = 0;
 
  l1 = strlen(string);
  l2 = strlen(substring);
 
  for(i = 0; i < l1 - l2; i++) {
    found = 1;
    for(j = 0; j < l2; j++) {
      if(string[i+j] != substring[j]) {
        found = 0;
        break;
      }
    }
 
    if(found) {
      count++;
      i = i + l2 -1;
    }
  }
 
  return count;
}

//checks if the count of '..' is equal to 'root' or not if yes then its a valid access if not then the asked file is prohibited
int checkFileSecurity(char* filename){
    char str[MAXBUF];
    getcwd(str,MAXBUF);                                     //get the path of curr working directory
    char delim[]="/";                 
    char *ptr = strtok(str, delim);                         //slice the path with '/' to get the root name            
    char*root;
    while (ptr != NULL)                                     //store the last string after '/'(i.e. the root name)in root 
    {
      root=ptr;
      ptr = strtok(NULL, delim);
    }
    int count_root=substring_count(filename,root);
    int count_delim=substring_count(filename,"..");                                  //delim=..
    if(count_root!=count_delim)
    {
      return 1;
    }
    return 0;
}
//
// Sends out HTTP response in case of errors
//
void request_error(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg) {
    char buf[MAXBUF], body[MAXBUF];
    
    // Create the body of error message first (have to know its length for header)
    sprintf(body, ""
	    "<!doctype html>\r\n"
	    "<head>\r\n"
	    "  <title>OSTEP WebServer Error</title>\r\n"
	    "</head>\r\n"
	    "<body>\r\n"
	    "  <h2>%s: %s</h2>\r\n" 
	    "  <p>%s: %s</p>\r\n"
	    "</body>\r\n"
	    "</html>\r\n", errnum, shortmsg, longmsg, cause);
    
    // Write out the header information for this response
    sprintf(buf, "HTTP/1.0 %s %s\r\n", errnum, shortmsg);
    write_or_die(fd, buf, strlen(buf));
    
    sprintf(buf, "Content-Type: text/html\r\n");
    write_or_die(fd, buf, strlen(buf));
    
    sprintf(buf, "Content-Length: %lu\r\n\r\n", strlen(body));
    write_or_die(fd, buf, strlen(buf));
    
    // Write out the body last
    write_or_die(fd, body, strlen(body));
    
    // close the socket connection
    close_or_die(fd);
}

//
// Reads and discards everything up to an empty text line
//
void request_read_headers(int fd) {
    char buf[MAXBUF];
    
    readline_or_die(fd, buf, MAXBUF);
    while (strcmp(buf, "\r\n")) {
		readline_or_die(fd, buf, MAXBUF);
    }
    return;
}

//
// Return 1 if static, 0 if dynamic content (executable file)
// Calculates filename (and cgiargs, for dynamic) from uri
//
int request_parse_uri(char *uri, char *filename, char *cgiargs) {
    char *ptr;
    
    if (!strstr(uri, "cgi")) { 
	// static
	strcpy(cgiargs, "");
	sprintf(filename, ".%s", uri);
	if (uri[strlen(uri)-1] == '/') {
	    strcat(filename, "index.html");
	}
	return 1;
    } else { 
	// dynamic
	ptr = index(uri, '?');
	if (ptr) {
	    strcpy(cgiargs, ptr+1);
	    *ptr = '\0';
	} else {
	    strcpy(cgiargs, "");
	}
	sprintf(filename, ".%s", uri);
	return 0;
    }
}

//
// Fills in the filetype given the filename
//
void request_get_filetype(char *filename, char *filetype) {
    if (strstr(filename, ".html")) 
		strcpy(filetype, "text/html");
    else if (strstr(filename, ".gif")) 
		strcpy(filetype, "image/gif");
    else if (strstr(filename, ".jpg")) 
		strcpy(filetype, "image/jpeg");
    else 
		strcpy(filetype, "text/plain");
}

//
// Handles requests for static content
//
void request_serve_static(int fd, char *filename, int filesize) {
    int srcfd;
    char *srcp, filetype[MAXBUF], buf[MAXBUF];
    
    request_get_filetype(filename, filetype);
    srcfd = open_or_die(filename, O_RDONLY, 0);
    
    // Rather than call read() to read the file into memory, 
    // which would require that we allocate a buffer, we memory-map the file
    srcp = mmap_or_die(0, filesize, PROT_READ, MAP_PRIVATE, srcfd, 0);
    close_or_die(srcfd);
    
    // put together response
    sprintf(buf, ""
	    "HTTP/1.0 200 OK\r\n"
	    "Server: OSTEP WebServer\r\n"
	    "Content-Length: %d\r\n"
	    "Content-Type: %s\r\n\r\n", 
	    filesize, filetype);
      //printf("\ncontent till now:\n%s",buf);
    write_or_die(fd, buf, strlen(buf));
    
    //  Writes out to the client socket the memory-mapped file 
    write_or_die(fd, srcp, filesize);
    //printf("\nMore content(final): %s",srcp);
    munmap_or_die(srcp, filesize);
    
}

//
// Fetches the requests from the buffer and handles them (thread locic)
//
void* thread_request_serve_static(void* arg)
{
  printf("\nin thread serve static() sched algo=%d \n",scheduling_algo);
	// TODO: write code to actualy respond to HTTP requests

  //consumer
   while(1){                                      //keep serving requests
     pthread_mutex_lock(&mutex);
     int req_fd,req_filesize;
     char req_filename[MAXBUF];
    
    if(scheduling_algo==1)
    {
      while(buffer_size==0){
        //empty queue
        pthread_cond_wait(&task_available,&mutex);          //as queue is empty wait for producer(server) to insert a request
      }
      printf("\nEXECUTING CONSUMER sched algo=SFF");
      heapNode task_picked=PopMinReq(heap);                    //as task has been inserted,pick the task(request)with minimum req size of all
      printf("\npicked task size=%d details:filename=%s\n",task_picked.size,task_picked.req.filename);

      //storing details of the task picked according to schedule to serve the request
      req_fd=task_picked.req.fd;
      req_filesize=task_picked.req.size;
      strcpy(req_filename,task_picked.req.filename);
    }
    else{
      while(queue->head==queue->tail){
        //empty queue
        pthread_cond_wait(&task_available,&mutex);          //as queue is empty wait for producer to insert a request
      }
      printf("\nEXECUTING CONSUMER sched algo=FIFO");
      queueNode task_picked=queue->req_queue[queue->head%BUFSIZE];  //pick the task(request) which in the front of queue
      queue->head++;
      buffer_size--;
      printf("\npicked task size=%d details:filename=%s\n",task_picked.req.size,task_picked.req.filename);
      
      //storing details of the task picked according to schedule to serve the request
      req_fd=task_picked.req.fd;
      req_filesize=task_picked.req.size;
      strcpy(req_filename,task_picked.req.filename);
    }
    
    pthread_cond_signal(&no_more_tasks);          //if buffer was full signal that one task has been done so its not full
    pthread_mutex_unlock(&mutex);
    
    request_serve_static(req_fd,req_filename,req_filesize);   //serve the request
   }
}

//Print the heap(for sff)
void print_heap(Heap*h) {
    int i;
    struct req_info temp;
    printf("\n____________Print Heap_____________\n");
    for(i=0;i< h->count;i++){
        temp=(h->req_queue[i]).req;
        printf("-> Size:%d FD:%d",(h->req_queue[i]).size,(temp.fd));
    }
    printf("-> END \n");
}

//Print the queue
void print_queue(Queue*queue)
{
  int i;
  struct req_info temp;
  printf("\n______________Print Queue_____________\n");
  for(i=queue->head;i<queue->tail;i++)
  {
    temp=(queue->req_queue[i]).req;
    printf("-> Size:%d FD:%d",(queue->req_queue[i]).req.size,(temp.fd));
  }
  printf("-> END");
}

//
// Initial handling of the request
//
void request_handle(int fd) {
    int is_static;
    struct stat sbuf;
    char buf[MAXBUF], method[MAXBUF], uri[MAXBUF], version[MAXBUF];
    char filename[MAXBUF], cgiargs[MAXBUF];
    
	// get the request type, file path and HTTP version
    readline_or_die(fd, buf, MAXBUF);
    sscanf(buf, "%s %s %s", method, uri, version);
    printf("method:%s uri:%s version:%s\n", method, uri, version);

	// verify if the request type is GET is not
    if (strcasecmp(method, "GET")) {
		request_error(fd, method, "501", "Not Implemented", "server does not implement this method");
		return;
    }
    request_read_headers(fd);
    
	// check requested content type (static/dynamic)
    is_static = request_parse_uri(uri, filename, cgiargs);
    
	// get some data regarding the requested file, also check if requested file is present on server
    if (stat(filename, &sbuf) < 0) {
		request_error(fd, filename, "404", "Not found", "server could not find this file");
		return;
    }
    
	// verify if requested content is static
    if (is_static) {
		if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode)) {
			request_error(fd, filename, "403", "Forbidden", "server could not read this file");
			return;
		}

    //-------------------------check file security-----------------------------------------------
    if(checkFileSecurity(filename)){
        request_error(fd, filename, "403", "Forbidden", "This file is Prohibited");
        return;
    }

// TODO: write code to add HTTP requests in the buffer based on the scheduling policy

    //storing the information of request in a node
		  struct req_info *temp=(struct info*)malloc(sizeof(struct req_info));
      temp->fd=fd;
      temp->is_static= is_static;
      strcpy(temp->buf,buf);
      strcpy(temp->filename,filename);
      strcpy(temp->cgiargs,cgiargs);
      strcpy(temp->method,method);
      strcpy(temp->uri,uri);
      strcpy(temp->version,version);
      temp->size=sbuf.st_size;
      
      //producer
      pthread_mutex_lock(&mutex);   //locking the critical section
      
        while(buffer_size==buffer_max_size){                          //buffer full
            pthread_cond_wait(&no_more_tasks,&mutex);         //wait cant take more tasks
        }
      if(scheduling_algo==1)              //sched algo= sff
      {
        printf("\nEXECUTING PRODUCER sched algo=SFF");
        heapNode task;
        task.size = sbuf.st_size;                   //store the size of request
        task.req = *temp;                           //store the request info
        insertRequest(heap,task);                          //insert the request into the heap for sff
        print_heap(heap);
      }  
      else{                               //sched algo= fifo
        printf("\nEXECUTING PRODUCER sched algo=FIFO");
        queueNode task;
        task.req=*temp;                             //store the request info
        //insertion of the request into the queue of requests 
        queue->req_queue[queue->tail%buffer_max_size]=task;
        queue->tail++;
        buffer_size++;
        print_queue(queue);
      }
      pthread_cond_signal(&task_available);         //signal as a task has been inserted, request can be processed
      pthread_mutex_unlock(&mutex);                 //unlock the code

    } else {
		request_error(fd, filename, "501", "Not Implemented", "server does not serve dynamic content request");
    }
}
