#ifndef __LOG_H__
#define __LOG_H__

#define log_info(...) printf(__VA_ARGS__)
#define log_err(...) printf(__VA_ARGS__)

#define DeBug 1

#if DeBug
#define log_dbg(...) printf(__VA_ARGS__)

#endif /*DeBug*/

#endif /*__LOG_H__*/