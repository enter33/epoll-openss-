使用epoll加上openssl实现客户端与服务端加密通信
服务端使用epoll监听读事件
客户端使用多进程
    一个负责写
    一个负责读,判断客户端是否关闭连接

make之后
    ./main server
    ./main client


server的密钥协商过程
    加载错误输出字符床和支持的加密算法
    1.SSL_load_error_strings();
    2.OpenSSL_add_ssl_algorithms();

    创建表示所使用协议方法的结构体
    3.const SSL_METHOD *method = SSLv23_server_method();

    根据协议方法创建上下文(环境)并加载使用的证书和密钥
    4.SSL_CTX *ctx = SSL_CTX_new(method);
    5.SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM)
    6.SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM)

    开始密钥协商
    7.服务端接受连接,创建套接字
    8.根据环境创建SSL(用以协商密钥)
    9.关联套接字和SSL
    10.SSL_accept(ssl)进行密钥协商
    11.客户端使用SSL_connect进行密钥协商,类似于三次握手
