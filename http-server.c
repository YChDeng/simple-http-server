#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT_HTTP 80
#define PORT_HTTPS 443

#define MAX_BUFFER_SIZE 8192

void *http_server(void *arg);
void *https_server(void *arg);

void initialize_ssl();
void cleanup_ssl();
SSL_CTX *create_ssl_context();
void configure_ssl_context(SSL_CTX *ctx);

const char* get_mime_type(const char* path);

int main(int argc, char *argv[]) {
    pthread_t thread_http, thread_https;

    // 初始化SSL库
    initialize_ssl();

    // 创建HTTP服务器线程
    if (pthread_create(&thread_http, NULL, http_server, NULL) != 0) {
        perror("Failed to create HTTP server thread");
        exit(EXIT_FAILURE);
    }

    // 创建HTTPS服务器线程
    if (pthread_create(&thread_https, NULL, https_server, NULL) != 0) {
        perror("Failed to create HTTPS server thread");
        exit(EXIT_FAILURE);
    }

    // 等待两个线程结束
    pthread_join(thread_http, NULL);
    pthread_join(thread_https, NULL);

    // 清理SSL库
    cleanup_ssl();

    return 0;
}

void initialize_ssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

void cleanup_ssl() {
    EVP_cleanup();
}

SSL_CTX *create_ssl_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_ssl_context(SSL_CTX *ctx) {
    // 载入证书和私钥
    if (SSL_CTX_use_certificate_file(ctx, "keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

const char* get_mime_type(const char* path) {
    const char* ext = strrchr(path, '.');
    if (!ext) {
        return "application/octet-stream"; // 默认MIME类型
    }
    ext++; // 跳过'.'
    if (strcasecmp(ext, "html") == 0 || strcasecmp(ext, "htm") == 0) {
        return "text/html";
    } else if (strcasecmp(ext, "css") == 0) {
        return "text/css";
    } else if (strcasecmp(ext, "js") == 0) {
        return "application/javascript";
    } else if (strcasecmp(ext, "json") == 0) {
        return "application/json";
    } else if (strcasecmp(ext, "png") == 0) {
        return "image/png";
    } else if (strcasecmp(ext, "jpg") == 0 || strcasecmp(ext, "jpeg") == 0) {
        return "image/jpeg";
    } else if (strcasecmp(ext, "gif") == 0) {
        return "image/gif";
    } else if (strcasecmp(ext, "txt") == 0) {
        return "text/plain";
    } else if (strcasecmp(ext, "mp4") == 0) {
        return "video/mp4";  // 支持MP4视频文件
    } else {
        return "application/octet-stream";
    }
}


void *http_server(void *arg) {
    int sockfd, new_sock;
    struct sockaddr_in addr, client_addr, local_addr;
    socklen_t addr_len = sizeof(addr);
    socklen_t client_addr_len = sizeof(client_addr);
    socklen_t local_addr_len = sizeof(local_addr);

    char buffer[MAX_BUFFER_SIZE];
    char response[MAX_BUFFER_SIZE];

    // 创建套接字
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("HTTP socket creation failed");
        pthread_exit(NULL);
    }

    // 绑定端口80
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT_HTTP);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("HTTP bind failed");
        close(sockfd);
        pthread_exit(NULL);
    }

    // 监听连接
    if (listen(sockfd, 10) < 0) {
        perror("HTTP listen failed");
        close(sockfd);
        pthread_exit(NULL);
    }

    printf("HTTP server listening on port %d\n", PORT_HTTP);

    while (1) {
        new_sock = accept(sockfd, (struct sockaddr*)&client_addr, &client_addr_len);
        if (new_sock < 0) {
            perror("HTTP accept failed");
            continue;
        }

        // 获取本地地址信息
        if (getsockname(new_sock, (struct sockaddr*)&local_addr, &local_addr_len) == -1) {
            perror("getsockname failed");
            close(new_sock);
            continue;
        }

        // 将本地IP地址转换为字符串
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(local_addr.sin_addr), ip_str, INET_ADDRSTRLEN);

        // 输出客户端连接信息
        printf("HTTP connection from %s:%d\n",
            inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        memset(buffer, 0, MAX_BUFFER_SIZE);
        int bytes = read(new_sock, buffer, MAX_BUFFER_SIZE);
        if (bytes < 0) {
            perror("HTTP read failed");
            close(new_sock);
            continue;
        }

        // 解析请求方法和URL
        char method[16], url[256];
        sscanf(buffer, "%s %s", method, url);

        // 输出请求信息
        printf("HTTP request: %s %s\n", method, url);

        // 只支持GET方法
        if (strcmp(method, "GET") == 0) {
            // 构建301重定向响应，使用服务器的IP地址
            snprintf(response, MAX_BUFFER_SIZE,
                "HTTP/1.1 301 Moved Permanently\r\n"
                "Location: https://%s%s\r\n"
                "Content-Length: 0\r\n"
                "\r\n",
                ip_str, url);

            // 输出响应状态
            printf("HTTP response: 301 Moved Permanently, redirecting to https://%s%s\n", ip_str, url);
        } else {
            // 方法不被允许
            snprintf(response, MAX_BUFFER_SIZE,
                "HTTP/1.1 405 Method Not Allowed\r\n"
                "Content-Length: 0\r\n"
                "\r\n");

            // 输出响应状态
            printf("HTTP response: 405 Method Not Allowed\n");
        }

        // 发送响应
        write(new_sock, response, strlen(response));
        close(new_sock);
    }

    close(sockfd);
    pthread_exit(NULL);
}

void *https_server(void *arg) {
    SSL_CTX *ctx;
    int sockfd;
    struct sockaddr_in addr, client_addr;
    socklen_t addr_len = sizeof(addr);
    socklen_t client_addr_len = sizeof(client_addr);

    // 初始化SSL上下文
    ctx = create_ssl_context();
    configure_ssl_context(ctx);

    // 创建套接字
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("HTTPS socket creation failed");
        SSL_CTX_free(ctx);
        pthread_exit(NULL);
    }

    // 绑定端口443
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT_HTTPS);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("HTTPS bind failed");
        close(sockfd);
        SSL_CTX_free(ctx);
        pthread_exit(NULL);
    }

    // 监听连接
    if (listen(sockfd, 10) < 0) {
        perror("HTTPS listen failed");
        close(sockfd);
        SSL_CTX_free(ctx);
        pthread_exit(NULL);
    }

    printf("HTTPS server listening on port %d\n", PORT_HTTPS);

    while (1) {
        int client_sock = accept(sockfd, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_sock < 0) {
            perror("HTTPS accept failed");
            continue;
        }

        // 输出客户端连接信息
        printf("HTTPS connection from %s:%d\n",
            inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock);

        if (SSL_accept(ssl) <= 0) {
            int err = SSL_get_error(ssl, -1);
            fprintf(stderr, "SSL_accept failed with error code %d\n", err);
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_sock);
            continue;
        }

        char buffer[MAX_BUFFER_SIZE];
        char response[MAX_BUFFER_SIZE];
        char method[16], url[256], http_version[16];

        int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes <= 0) {
            int ssl_err = SSL_get_error(ssl, bytes);
            fprintf(stderr, "SSL_read failed with error: %d\n", ssl_err);
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_sock);
            continue;
        }

        buffer[bytes] = '\0';

        // 解析请求行
        sscanf(buffer, "%s %s %s", method, url, http_version);

        // 输出请求信息
        printf("HTTPS request: %s %s %s\n", method, url, http_version);

        // 只支持GET方法
        if (strcmp(method, "GET") == 0) {
            // 去掉URL前的'/'
            char *file_path = url + 1;
            if (strlen(file_path) == 0) {
                file_path = "index.html";  // 默认首页
            }

            // 检查文件是否存在
            FILE *fp = fopen(file_path, "rb");
            if (fp) {
                const char* mime_type = get_mime_type(file_path);
                printf("Serving file: %s, MIME type: %s\n", file_path, mime_type);

                // 打印Range请求头
                char *range_header = strstr(buffer, "Range: bytes=");
                if (range_header) {
                    printf("Range header found: %s\n", range_header);
                    long start = 0, end = -1;
                    sscanf(range_header, "Range: bytes=%ld-%ld", &start, &end);

                    // 获取文件大小
                    fseek(fp, 0, SEEK_END);
                    long file_size = ftell(fp);
                    fseek(fp, 0, SEEK_SET);

                    if (end == -1 || end >= file_size) {
                        end = file_size - 1;
                    }

                    long content_length = end - start + 1;

                    // 打印读取的文件大小信息
                    printf("Reading file from byte %ld to %ld (total size: %ld)\n", start, end, file_size);

                    // 移动到开始位置
                    fseek(fp, start, SEEK_SET);

                    // 读取内容
                    char *file_buffer = (char *)malloc(content_length);
                    fread(file_buffer, 1, content_length, fp);

                    // 构建206响应
                    snprintf(response, MAX_BUFFER_SIZE,
                        "HTTP/1.1 206 Partial Content\r\n"
                        "Content-Type: %s\r\n"
                        "Content-Length: %ld\r\n"
                        "Content-Range: bytes %ld-%ld/%ld\r\n"
                        "\r\n",
                        mime_type, content_length, start, end, file_size);

                    // 输出响应状态
                    printf("HTTPS response: 206 Partial Content, file: %s, range: %ld-%ld\n",
                        file_path, start, end);

                    SSL_write(ssl, response, strlen(response));
                    SSL_write(ssl, file_buffer, content_length);

                    free(file_buffer);
                } else {
                    // 读取整个文件
                    fseek(fp, 0, SEEK_END);
                    long file_size = ftell(fp);
                    fseek(fp, 0, SEEK_SET);

                    char *file_buffer = (char *)malloc(file_size);
                    fread(file_buffer, 1, file_size, fp);

                    // 构建200响应
                    snprintf(response, MAX_BUFFER_SIZE,
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: %s\r\n"
                        "Content-Length: %ld\r\n"
                        "\r\n",
                        mime_type, file_size);

                    // 输出响应状态
                    printf("HTTPS response: 200 OK, file: %s, size: %ld bytes\n",
                        file_path, file_size);

                    SSL_write(ssl, response, strlen(response));
                    SSL_write(ssl, file_buffer, file_size);

                    free(file_buffer);
                }

                fclose(fp);
            } else {
                // 文件未找到，返回404
                snprintf(response, MAX_BUFFER_SIZE,
                    "HTTP/1.1 404 Not Found\r\n"
                    "Content-Length: 0\r\n"
                    "\r\n");

                // 输出响应状态
                printf("HTTPS response: 404 Not Found, file: %s\n", file_path);

                SSL_write(ssl, response, strlen(response));
            }
        } else {
            // 方法不被允许
            snprintf(response, MAX_BUFFER_SIZE,
                "HTTP/1.1 405 Method Not Allowed\r\n"
                "Content-Length: 0\r\n"
                "\r\n");

            // 输出响应状态
            printf("HTTPS response: 405 Method Not Allowed\n");

            SSL_write(ssl, response, strlen(response));
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_sock);
    }

    close(sockfd);
    SSL_CTX_free(ctx);
    pthread_exit(NULL);
}
