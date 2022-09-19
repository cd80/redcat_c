#include <time.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

typedef struct _MSG {
    unsigned int idx;
    struct _CLIENT *sender;
    char *msg;
    time_t time;

    struct _MSG *prev;
    struct _MSG *next;
} MSG;

typedef struct _CLIENT {
    int sock;
    int thread_idx;
    char *name;
    char *ip;
    unsigned int msg_cursor;
} CLIENT;

pthread_t g_threads[100] = {0, };
CLIENT *g_clients[100] = {0, };
char *recv_buf[100] = {0, };
MSG *g_msg_head = NULL;
MSG *g_msg_tail = NULL;
unsigned int g_msg_count = 0;
pthread_cond_t g_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t g_thread_create_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_create_msg_lock = PTHREAD_MUTEX_INITIALIZER;

void client_exit();
void cleanup_thread(int thread_idx);
void *handle_client(void *v);
void *handle_messages(void *v);
MSG *create_msg(CLIENT *sender, char *msg);
MSG *get_msg_by_idx(unsigned int idx);
void get_time_string(time_t time, char *time_string);

int main (int argc, char *argv[]) {
    int server_sock, client_sock;    
    struct sockaddr_in server_addr, client_addr;

    if (argc < 2) {
        printf("Usage: ./server [PORT]\n");
        exit(1);
    }

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == -1) {
        perror("socket");
        exit(1);
    }

    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
        perror("setsockopt");
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(atoi(argv[1]));

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        exit(1);
    }

    if (listen(server_sock, 10) == -1) {
        perror("listen");
        exit(1);
    }

    pthread_cond_init(&g_cond, NULL);

    create_msg(NULL, "==== Beginning of the chat ====");

    pthread_mutex_init(&g_thread_create_lock, NULL);
    pthread_mutex_init(&g_create_msg_lock, NULL);

    // install signal handler


    while (1) {
        socklen_t len;
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &len);
        if (client_sock == -1) {
            perror("accept");
            exit(1);
        }

        for (int i = 0; i < sizeof(g_threads) / sizeof(pthread_t *); ++i) {
            if (g_threads[i] == 0) {
                CLIENT *client = malloc(sizeof(CLIENT));
                client->sock = client_sock;
                client->thread_idx = i;
                client->ip = (char *)calloc(1, INET_ADDRSTRLEN);
                client->name = (char *)calloc(1, 32);
                client->msg_cursor = 0;
                inet_ntop(AF_INET, &client_addr.sin_addr, client->ip, INET_ADDRSTRLEN);

                g_clients[i] = client;

                pthread_mutex_lock(&g_thread_create_lock);
                pthread_create(&g_threads[i], 0, &(handle_client), (void *)client);
                pthread_mutex_unlock(&g_thread_create_lock);
                break;
            }
        }
    }

    return 0;
}

void client_exit() {
    pthread_mutex_lock(&g_thread_create_lock);
    for (int i = 0; i < 100; ++i) {
        if (g_threads[i] != 0) {
            if (pthread_kill(g_threads[i], 0) != 0) {
                printf("[Client exit] %-15s [%s]\n", g_clients[i]->ip, g_clients[i]->name);
                cleanup_thread(i);
                break;
            }
        }
    }
    pthread_mutex_unlock(&g_thread_create_lock);
}

void cleanup_thread(int thread_idx) {
    int tid = thread_idx;

    char buf[256] = {0, };
    sprintf(buf, "Client exited: %s [%s]", g_clients[tid]->name, g_clients[tid]->ip);
    create_msg(g_clients[tid], buf);

    g_threads[tid] = 0;
    free(g_clients[tid]->name);
    free(g_clients[tid]->ip);
    free(g_clients[tid]);
    g_clients[tid] = 0;
}

void *handle_client(void *v) {
    CLIENT *client = (CLIENT *)v;
    pthread_t recv_thread;

    struct sigaction sa;
    sa.sa_handler = client_exit;
    sigfillset(&sa.sa_mask);
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGKILL, &sa, NULL);

    // get client's name
    send(client->sock, "Name: ", 6, 0);
    if (recv(client->sock, client->name, 31, 0) <= 0) {
        return NULL;
    }
    *strchr(client->name, '\n') = '\0';

    printf("[New Client:%d] %-15s [%s]\n", client->thread_idx, client->ip, client->name);

    pthread_mutex_lock(&g_thread_create_lock);
    pthread_create(&recv_thread, 0, handle_messages, (void *)client);
    pthread_mutex_unlock(&g_thread_create_lock);

    char msg[4096];
    int idx = 0;
    while (1) {
        if (recv(client->sock, &msg[idx], 1, 0) <= 0) {
            goto CLEANUP;
        }
        if (idx >= 4094 || msg[idx] == '\n') {
            if (strlen(msg) == 1) {
                msg[0] = '\0';
                continue;
            }
            create_msg(client, msg);
            memset(msg, 0, 4096);
            pthread_cond_broadcast(&g_cond);
            idx = 0;
            continue;
        }
        idx += 1;
    }

    CLEANUP:
    // cleanup thread
    printf("[Client exit] %-15s [%s]\n", g_clients[client->thread_idx]->ip, 
                                         g_clients[client->thread_idx]->name);
    cleanup_thread(client->thread_idx);
    return NULL;
}

void *handle_messages(void *v) {
    MSG *last_msg = NULL;
    CLIENT *client = (CLIENT *)v;
    pthread_mutex_t local_lock;

    pthread_mutex_init(&local_lock, NULL);

    while(1) {
        assert(client->msg_cursor <= g_msg_tail->prev->idx && "msg_cursor overflowed!");
        if (client->msg_cursor == g_msg_tail->prev->idx) {
            pthread_cond_wait(&g_cond, &local_lock);
            continue;
        }
        else {
            last_msg = get_msg_by_idx(client->msg_cursor + 1);
        }

        do {
            client->msg_cursor++;
            char time_str[256] = "00:00:00";
            strftime(time_str, sizeof(time_str), "%T", localtime(&last_msg->time));

            // msg format
            // SENDER|TIME|MSG
            char *buf = NULL;
            if (last_msg->sender == NULL) {
                buf = malloc(strlen("SYSTEM") + strlen(time_str) + strlen(last_msg->msg) + 3);
                sprintf(buf, "SYSTEM|%s|%s", time_str, last_msg->msg);
            }
            else {
                buf = malloc(strlen(last_msg->sender->name) + strlen(time_str) + strlen(last_msg->msg) + 3);
                sprintf(buf, "%s|%s|%s", last_msg->sender->name, time_str, last_msg->msg);
            }

            send(client->sock, buf, strlen(buf), 0);

            free(buf);
            last_msg = last_msg->next;
        } while (last_msg != g_msg_tail);

        // printf("[handle_messages2, %s] waiting...\n", client->name);
        // pthread_cond_wait(&g_cond, &local_lock);
        // printf("[handle_messages2, %s] continuing...\n", client->name);
    }
    return NULL;
}

MSG *create_msg(CLIENT *sender, char *msg) {
    pthread_mutex_lock(&g_create_msg_lock);
    MSG *last_msg = NULL;
    MSG *new_msg = (MSG *)malloc(sizeof(MSG));
    new_msg->sender = sender;
    new_msg->idx = ++g_msg_count;
    time(&new_msg->time);

    new_msg->msg = malloc(strlen(msg) + 1);
    strcpy(new_msg->msg, msg);

    if (g_msg_head == NULL || g_msg_tail == NULL) {
        g_msg_head = (MSG *)malloc(sizeof(MSG));
        g_msg_tail = (MSG *)malloc(sizeof(MSG));
        g_msg_head->next = new_msg;
        g_msg_head->prev = g_msg_tail;
        g_msg_tail->prev = new_msg;
        g_msg_tail->next = g_msg_head;

        new_msg->next = g_msg_tail;
        new_msg->prev = g_msg_head;
        pthread_mutex_unlock(&g_create_msg_lock);
        return new_msg;
    }

    last_msg = g_msg_tail->prev;

    last_msg->next = new_msg;
    new_msg->next = g_msg_tail;
    new_msg->prev = last_msg;
    g_msg_tail->prev = new_msg;

    pthread_mutex_unlock(&g_create_msg_lock);
    return new_msg;
}

void get_time_string(time_t time, char *time_string) {

}

MSG *get_msg_by_idx(unsigned int idx) {
    MSG *msg = g_msg_head->next;
    while (msg->idx != idx && msg != g_msg_tail) {
        msg = msg->next;
    }
    
    return msg;
}