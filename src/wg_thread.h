#ifndef WG_THREAD_H
#define WG_THREAD_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

typedef void *(*WgThreadFunc)(void *);

typedef struct {
    pthread_t thread;
} WgThread;

typedef struct {
    pthread_mutex_t mutex;
} WgMutex;

typedef struct {
    pthread_cond_t cond;
} WgCond;

typedef struct {
    WgCond cond;
    WgMutex mutex;
    bool pred;
} WgStopCond;

typedef bool (*WgCheckPred)(void *);

int wg_thread_create(WgThread *thread, WgThreadFunc func, void *arg);
int wg_thread_join(WgThread *thread, void **retval);
int wg_thread_set_name(WgThread *thread, const char *name);

int wg_mutex_init(WgMutex *mutex, bool recursive);
void wg_mutex_fini(WgMutex *mutex);
void wg_mutex_lock(WgMutex *mutex);
int wg_mutex_trylock(WgMutex *mutex);
void wg_mutex_unlock(WgMutex *mutex);

int wg_cond_init(WgCond *cond);
void wg_cond_fini(WgCond *cond);
void wg_cond_wait(WgCond *cond, WgMutex *mutex);
int wg_cond_timedwait(WgCond *cond, WgMutex *mutex, uint64_t timeout_ms);
void wg_cond_signal(WgCond *cond);
void wg_cond_broadcast(WgCond *cond);

int wg_stop_cond_init(WgStopCond *cond);
void wg_stop_cond_fini(WgStopCond *cond);
void wg_stop_cond_lock(WgStopCond *cond);
void wg_stop_cond_unlock(WgStopCond *cond);
int wg_stop_cond_timedwait(WgStopCond *cond, uint64_t timeout_ms);
void wg_stop_cond_signal(WgStopCond *cond);
bool wg_stop_cond_check(WgStopCond *cond);

#endif
