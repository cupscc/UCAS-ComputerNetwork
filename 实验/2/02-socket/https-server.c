#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <pthread.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

typedef struct Url
{
    char url[50];
    char Protocol[10];
    char IP[15];
    char Path[50];
} Url_t;
typedef struct Request
{
    char Method[10];
    Url_t Url;
    char Version[10];
    char Hearder[512];
    char Content[1024];
} Request_t;
void handle_https_request(SSL *ssl);
void handle_http_request(int csock);
void *monitor80(void *sock);
void *monitor443(void *to_443_para);
struct to_443
{
    int sock;
    SSL_CTX *ctx;
};
int main()
{
    // init SSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0)
    {
        perror("load cert failed");
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0)
    {
        perror("load prikey failed");
        exit(1);
    }
    // init 80
    int sock_80 = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_80 < 0)
    {
        perror("Opening socket_80 failed");
        exit(1);
    }
    int enable = 1;
    if (setsockopt(sock_80, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
    {
        perror("setsockopt(SO_REUSEADDR) failed");
        exit(1);
    }
    struct sockaddr_in addr_80;
    bzero(&addr_80, sizeof(addr_80));
    addr_80.sin_family = AF_INET;
    addr_80.sin_addr.s_addr = INADDR_ANY;
    addr_80.sin_port = htons(80);
    if (bind(sock_80, (struct sockaddr *)&addr_80, sizeof(addr_80)) < 0)
    {
        perror("socker_80 Bind failed");
        exit(1);
    }
    // init 443
    int sock_443 = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_443 < 0)
    {
        perror("Opening socket_443 failed");
        exit(1);
    }
    if (setsockopt(sock_443, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
    {
        perror("setsockopt(SO_REUSEADDR) failed");
        exit(1);
    }
    struct sockaddr_in addr_443;
    bzero(&addr_443, sizeof(addr_443));
    addr_443.sin_family = AF_INET;
    addr_443.sin_addr.s_addr = INADDR_ANY;
    addr_443.sin_port = htons(443);
    if (bind(sock_443, (struct sockaddr *)&addr_443, sizeof(addr_443)) < 0)
    {
        perror("socker_443 Bind failed");
        exit(1);
    }
    // two threads to listen each port
    listen(sock_80, 10);
    listen(sock_443, 10);
    pthread_t thport_80;
    pthread_t thport_443;
    struct to_443 to_443_para = {sock_443, ctx};
    if (pthread_create(&thport_443, NULL, monitor443, &to_443_para) != 0)
    {
        perror("Create th1 failed");
        exit(1);
    }
    if (pthread_create(&thport_80, NULL, monitor80, (void *)sock_80) != 0)
    {
        perror("Create th2 failed");
        exit(1);
    }
    pthread_join(thport_80, NULL);
    pthread_join(thport_443, NULL);
    close(sock_80);
    close(sock_443);
    SSL_CTX_free(ctx);
    return 0;
}
void *monitor80(void *psock)
{
    int sock_80 = (int)psock;
    while (1)
    {
        struct sockaddr_in caddr;
        socklen_t len = sizeof(struct sockaddr_in);
        int csock_80 = accept(sock_80, (struct sockaddr *)&caddr, &len);
        if (csock_80 < 0)
        {
            perror("80 Port Sock Accept Failed");
            exit(1);
        }
        handle_http_request(csock_80);
    }
}
void *monitor443(void *pto_443_para)
{
    struct to_443 *to_443_para = (struct to_443 *)pto_443_para;
    int sock = to_443_para->sock;
    SSL_CTX *ctx = to_443_para->ctx;
    while (1)
    {
        struct sockaddr_in caddr;
        socklen_t len;
        int csock = accept(sock, (struct sockaddr *)&caddr, &len);
        if (csock < 0)
        {
            perror("443 Port Sock Accept Failed");
            exit(1);
        }
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, csock);
        handle_https_request(ssl);
    }
}
void reset_url(Request_t *request)
{
    memset(request->Url.url, 0, 50);
    strcat(request->Url.url, request->Url.Protocol);
    strcat(request->Url.url, "://");
    strcat(request->Url.url, request->Url.IP);
    strcat(request->Url.url, request->Url.Path);
}
void find_url(char *str, Request_t *request)
{
    int start, end, count = 0;
    for (int i = 0; i < strlen(str); i++)
    {
        if (str[i] == ' ' && count == 0)
        {
            start = i + 1;
            count = 1;
            i++;
        }
        if (str[i] == ' ' && count == 1)
        {
            end = i - 1;
            count = 2;
            break;
        }
    }
    memset(request->Method, 0, 10);
    for (int i = 0, j = 0; i < start - 1 && j < 10; i++, j++)
    {
        request->Method[j] = str[i];
    }
    for (int i = start, j = 0; i <= end && j < 25; i++, j++)
    {
        request->Url.Path[j] = str[i];
    }
}
void handle_https_request(SSL *ssl)
{
    char *response_200 = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: Close\r\n\r\n";
    char *response_206 = "HTTP/1.0 206 Partial Content\r\nContent-Type: text/html\r\nConnection: Close\r\n\r\n";
    char *response_404 = "HTTP/1.0 404 Not Found\r\nConnection: Close\r\n\r\n";
    if (SSL_accept(ssl) == -1)
    {
        perror("SSL_accept failed");
        exit(1);
    }
    else
    {

        char buf[1024] = "0";
        int bytes = SSL_read(ssl, buf, sizeof(buf));
        if (bytes < 0)
        {
            perror("SSL_read failed");
            exit(1);
        }
        printf("%s\n",buf);
        fflush(stdout);
        Request_t *request = (Request_t *)malloc(sizeof(Request_t));
        memset(request->Url.Path, 0, 50);
        find_url(buf, request);
        int Method_err = strcmp(request->Method, "GET");
        if (Method_err != 0)
        {
            perror("not Get\n");
            exit(1);
        }

        FILE *fp = fopen(request->Url.Path + 1, "r");
        if (fp == NULL)
        {
            SSL_write(ssl, response_404, strlen(response_404));
        }
        else
        { // get the file content
            int file_size = 0;
            fseek(fp, 0, SEEK_END);
            file_size = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            char *temp = (char *)malloc(file_size * sizeof(char));
            memset(temp, 0, file_size * sizeof(char));
            fread(temp, sizeof(char), file_size, fp);
            char *range = strstr(buf, "Range");
            if (range != NULL)
            {
                range = range + 13;
                char start[10] = "\0";
                char end[10] = "\0";
                int i = 0;
                while (range[0] != '-' && i < 10)
                {
                    if (isdigit(range[0]))
                    {
                        start[i++] = range[0];
                    }
                    range++;
                }
                range++;
                i = 0;
                int intstart = atoi(start);
                while (range[0] != '\r' && i < 10)
                {
                    if (isdigit(range[0]))
                    {
                        end[i++] = range[0];
                    }
                    range++;
                }
                int intend = file_size - 1;
                if (end[0] != '\0')
                {
                    intend = atoi(end);
                }
                int rsp_length = strlen(response_206);
                for (int i = 0; i < rsp_length; i++)
                {
                    SSL_write(ssl, &response_206[i], 1);
                }
                for (int i = intstart; i <= intend; i++)
                {
                    SSL_write(ssl, &temp[i], 1);
                }
                printf("Send Success, rsp_size: %d\n", rsp_length + file_size);
                fflush(stdout);
            }
            else
            {
                int rsp_length = strlen(response_200);
                for (int i = 0; i < rsp_length; i++)
                {
                    SSL_write(ssl, &response_200[i], 1);
                }
                for (int i = 0; i < file_size; i++)
                {
                    SSL_write(ssl, &temp[i], 1);
                }
                printf("Send Success, rsp_size: %d\n", rsp_length + file_size);
                fflush(stdout);
            }
            free(temp);
            fclose(fp);
        }
    }
    int sock = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sock);
}

void handle_http_request(int csock)
{
    char buffer[512] = "0";
    int read_err = read(csock, buffer, 512);
    if (read_err <= 0)
    {
        perror("cant read csock 80");
        exit(1);
    }
    Request_t *request = (Request_t *)malloc(sizeof(Request_t));
    // get the path
    find_url(buffer, request);
    printf("%s\n",buffer);
    fflush(stdout);
    strcpy(request->Url.Protocol, "https");
    strcpy(request->Url.IP, "10.0.0.1");
    // reset url
    reset_url(request);
    char response[100] = "HTTP/1.0 301 Moved Permanently\r\nLocation: ";
    strcat(response, request->Url.url);
    strcat(response, "\r\n\r\n");
    printf("%s\n",response);
    fflush(stdout);
    int write_err = write(csock, response, strlen(response));
    if (write_err <= 0)
    {
        perror("can't write csock 80");
        exit(1);
    }
    close(csock);
}
