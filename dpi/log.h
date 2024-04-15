#ifndef __LOG_H__
#define __LOG_H__

#define DeBug 1
//打印日志

#define log_err(...) printf(__VA_ARGS__)//__VA_ARGS__可变参数列表
#define log_info(...) printf(__VA_ARGS__)

#if DeBug
    #define log_dbg(...) do{ \
        printf("%s:%s:%d\t",__FILE__,__func__,__LINE__); \
        printf(__VA_ARGS__);   \
    }while(0)
#else
    #define log_dbg(...)

#endif

#endif