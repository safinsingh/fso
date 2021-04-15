/*
  fso - fast [link] shortener
  Copyright (C) 2021 Safin Singh

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as
  published by the Free Software Foundation, either version 3 of the
  License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 3107
#define INITIAL_VEC_CAPACITY 64

#define THREAD_POOL_QUEUE_LEN 8192
#define THREAD_POOL_THREADS 8

#define EPOLL_MAX_EVENTS 512
#define HTTP_REQUEST_BUFFER 128

#define CONFIG_FILE "config.fso"

#define web(fmt, ...) printf("   \033[0;36m[web]\033[0m " fmt "\n", ##__VA_ARGS__);
#define config(fmt, ...) printf("\033[0;32m[config]\033[0m " fmt "\n", ##__VA_ARGS__);
#define reload(fmt, ...) printf("\033[0;35m[reload]\033[0m " fmt "\n", ##__VA_ARGS__);
#define warn(fmt, ...) printf("  \033[0;33m[warn]\033[0m " fmt "\n", ##__VA_ARGS__);
#define die(fmt, ...)                                                                \
  do {                                                                               \
    fprintf(stderr, " \033[0;31m[fatal]\033[0m :: " fmt "\n            errno: %s\n", \
            ##__VA_ARGS__, strerror(errno));                                         \
    exit(EXIT_FAILURE);                                                              \
  } while (0)

void *xmalloc(size_t size) {
  void *ret = malloc(size);
  if (!ret) die("failed to allocate with malloc");
  return ret;
}

void *xcalloc(size_t els, size_t size) {
  void *ret = calloc(els, size);
  if (!ret) die("failed to allocate with calloc");
  return ret;
}

void *xrealloc(void *ptr, size_t size) {
  void *ret = realloc(ptr, size);
  if (!ret) die("failed to reallocate with recalloc");
  return ret;
}

void *xmemcpy(void *dest, const void *src, size_t len) {
  void *ret = memcpy(dest, src, len);
  if (!ret) die("failed to memcpy");
  return ret;
}

char *xstrtok_r(char *str, char *delim, char **save_ptr) {
  char *tok = strtok_r(str, delim, save_ptr);
  if (!tok) die("failed to strtok");
  return tok;
}

void xpthread_mutex_init(pthread_mutex_t *mux, pthread_mutexattr_t *attr) {
  if (pthread_mutex_init(mux, attr)) die("failed to initialize mutex");
}

void xpthread_cond_init(pthread_cond_t *cond, pthread_condattr_t *attr) {
  if (pthread_cond_init(cond, attr)) die("failed to initialize condvar");
}

void xpthread_create(pthread_t *thread, pthread_attr_t *attr, void *(*init)(void *), void *arg) {
  if (pthread_create(thread, attr, init, arg)) die("failed to create thread");
}

void xpthread_cancel(pthread_t thread) {
  if (pthread_cancel(thread)) die("failed to cancel thread");
}

void xpthread_join(pthread_t thread, void **thread_return) {
  if (pthread_join(thread, thread_return)) die("failed to join thread");
}

void xpthread_cond_signal(pthread_cond_t *cond) {
  if (pthread_cond_signal(cond)) die("failed to wake up threads with condvar");
}

int xinotify_init1(int flags) {
  int ifd = inotify_init1(flags);
  if (ifd < 0) die("failed to initialize inotify instance");
  return ifd;
}

void xinotify_add_watch(int fd, char *name, unsigned int mask) {
  int wd = inotify_add_watch(fd, name, mask);
  if (wd < 0) die("failed to add watch to inotify instance");
}

FILE *xfopen(char *name, char *mode) {
  FILE *fp = fopen(name, mode);
  if (!fp) die("failed to open file: %s", name);
  return fp;
}

FILE *xfdopen(int fd, char *mode) {
  FILE *stream = fdopen(fd, mode);
  if (!stream) die("failed to create stream for fd: %d", fd);
  return stream;
}

int xfcntl(int fd, int flags, ...) {
  va_list argp;
  va_start(argp, flags);
  void *arg = va_arg(argp, void *);
  int s = fcntl(fd, flags, arg);
  va_end(argp);

  if (s < 0) die("fnctl failed to set flags: %d on fd: %d", flags, fd);
  return s;
}

void xsetsockopt(int fd, int level, int optname, void *optval, socklen_t optlen) {
  if (setsockopt(fd, level, optname, optval, optlen))
    die("failed to set opt: %d on socket fd: %d", optname, fd);
}

void xbind(int fd, struct sockaddr *addr, socklen_t len) {
  bind(fd, addr, len);
}

void xlisten(int fd, int maxconns) {
  if (listen(fd, maxconns)) die("failed to begin listening");
}

void xsend(int fd, char *msg) {
  if (send(fd, msg, strlen(msg), 0) < 0) {
    die("failed to write to socket fd %d", fd);
  }
  close(fd);
}

void xfprintf(FILE *stream, const char *fmt, ...) {
  va_list argp;
  va_start(argp, fmt);
  if (vfprintf(stream, fmt, argp) < 0) die("failed to fprintf to stream");
  va_end(argp);
}

void xepoll_ctl(int epfd, int op, int fd, struct epoll_event *ev) {
  if (epoll_ctl(epfd, op, fd, ev)) die("failed to add fd %d to epoll interest list", fd);
}

int xepoll_create1(int flags) {
  int epfd = epoll_create1(flags);
  if (epfd < 0) die("failed to create epoll instance");
  return epfd;
}

int xepoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
  int evs = epoll_wait(epfd, events, maxevents, timeout);
  if (evs < 0) die("failed to epoll_wait");
  return evs;
}

typedef struct {
  void (*fn)(void *);
  void *arg;
} job_t;

typedef struct {
  pthread_t *threads;
  int threads_len;

  // baseed on: https://www.snellman.net/blog/archive/2016-12-13-ring-buffers/
  job_t *jobs;
  int jobs_len;
  int jobs_cap;
  atomic_uint jobs_reader;
  atomic_uint jobs_writer;

  atomic_bool keep_alive;
} thread_pool_t;

const uint32_t LOCK_MASK = 1 << ((sizeof(LOCK_MASK) * 8) - 1);
thread_pool_t pool;

void *thread_init(void *arg);
void thread_pool_init(thread_pool_t *pool) {
  pool->jobs_cap = THREAD_POOL_QUEUE_LEN;

  pool->jobs_reader = ATOMIC_VAR_INIT(0);
  pool->jobs_writer = ATOMIC_VAR_INIT(0);
  pool->keep_alive = ATOMIC_VAR_INIT(true);

  pool->threads_len = THREAD_POOL_THREADS;
  pool->threads = xmalloc(pool->threads_len * sizeof(*pool->threads));
  pool->jobs = xmalloc(pool->jobs_cap * sizeof(*pool->jobs));

  for (int t = 0; t < pool->threads_len; t++) {
    xpthread_create(&pool->threads[t], NULL, thread_init, pool);
  }
}

void thread_pool_dealloc(thread_pool_t *pool) {
  atomic_store(&pool->keep_alive, false);
  for (int t = 0; t < pool->threads_len; t++) {
    xpthread_cancel(pool->threads[t]);
    xpthread_join(pool->threads[t], NULL);
  }
  free(pool->threads);
  free(pool->jobs);
}

void thread_pool_enqueue(thread_pool_t *pool, job_t job) {
  for (;;) {
    // load the writer position
    uint32_t tail = atomic_load(&pool->jobs_writer);

    // NOTE: the following would be uncommented if this was an MPMC queue, in order
    // to ensure enqueue safety. however, for performance reasons, it is ommitted.
    //
    // // if our writer is locked, an enqueue is in progress
    // if (tail & LOCK_MASK) continue;
    // // attempt to lock our writer, starting over if an enqueue has occurred
    // if (!atomic_compare_exchange_weak(&pool->jobs_writer, &tail, tail | LOCK_MASK)) continue;

    // load the reader position
    uint32_t head = atomic_load(&pool->jobs_reader);
    // if writer position + a full rotation modulo 2 full rotations equals
    // our reader position, die. we don't care if the reader is locked lol.
    // we use modulo 2 * cap so we don't have to waste a spot in our ringbuffer!
    if (((tail + pool->jobs_cap) % (pool->jobs_cap * 2)) == (head & ~LOCK_MASK))
      die("job queue is full!");
    // now, to compute our actual write offset, we modulo our writer position
    // with the capacity (NOTE: not *2)
    pool->jobs[tail] = job;
    // shift over and unlock the writer!
    atomic_store(&pool->jobs_writer, (tail + 1) % (pool->jobs_cap * 2));
    break;
  }
}

job_t thread_pool_dequeue(thread_pool_t *pool) {
  for (;;) {
    // load the reader position
    uint32_t head = atomic_load(&pool->jobs_reader);
    // if our reader is locked, a dequeue is in progress
    if (head & LOCK_MASK) continue;
    // attempt to lock our reader, starting over if a dequeue has occurred
    if (!atomic_compare_exchange_weak(&pool->jobs_reader, &head, head | LOCK_MASK)) continue;
    // load the writer position
    uint32_t tail = atomic_load(&pool->jobs_writer);
    // if our reader is equal to our writer position, our queue is empty. here,
    // we spin!
    if (head == (tail & ~LOCK_MASK)) {
      atomic_store(&pool->jobs_reader, head);
      continue;
    }
    // dequeue our job from the buffer
    job_t job = pool->jobs[head];
    // shift over and unlock the reader!
    atomic_store(&pool->jobs_reader, (head + 1) % (pool->jobs_cap * 2));
    // return our job
    return job;
  }
}

void *thread_init(void *arg) {
  thread_pool_t *pool = (thread_pool_t *)arg;

  for (;;) {
    job_t job = thread_pool_dequeue(pool);
    (*job.fn)(job.arg);
  }

  pthread_exit(EXIT_SUCCESS);
  return NULL;
}

static inline void thread_pool_dispatch(thread_pool_t *pool, void (*fn)(void *), void *arg) {
  thread_pool_enqueue(pool, (job_t){ .fn = fn, .arg = arg });
}

typedef struct {
  char *backing;
  int len;
  int cap;
} string_t;

void string_init(string_t *str) {
  str->backing = xmalloc(INITIAL_VEC_CAPACITY * sizeof(*str->backing));
  *str->backing = '\0';
  str->cap = INITIAL_VEC_CAPACITY;
  str->len = 0;
}

void string_push(string_t *str, char c) {
  if (str->cap == str->len + 1) {
    str->backing = xrealloc(str->backing, (str->cap <<= 1) * sizeof(*str->backing));
  }
  str->backing[str->len] = c;
  str->backing[str->len + 1] = '\0';
  str->len++;
}

typedef struct {
  char **backing;
  int len;
  int cap;
} vec_string_t;

void vec_string_init(vec_string_t *vec) {
  vec->backing = xmalloc(INITIAL_VEC_CAPACITY * sizeof(*vec->backing));
  vec->cap = INITIAL_VEC_CAPACITY;
  vec->len = 0;
}

void vec_string_push(vec_string_t *vec, char *str) {
  if (vec->cap == vec->len) {
    vec->backing = xrealloc(vec->backing, (vec->cap <<= 1) * sizeof(*vec->backing));
  }
  vec->backing[vec->len] = str;
  vec->len++;
}

typedef struct {
  vec_string_t keys;
  vec_string_t values;
} config_t;

static pthread_mutex_t config_mux = PTHREAD_MUTEX_INITIALIZER;
config_t cfg;

void config_dealloc() {
  for (int i = 0; i < cfg.keys.len; i++) {
    free(cfg.keys.backing[i]);
  }
  for (int i = 0; i < cfg.values.len; i++) {
    free(cfg.values.backing[i]);
  }
  free(cfg.keys.backing);
  free(cfg.values.backing);
}

void config_print() {
  if (cfg.keys.len != cfg.values.len) {
    config_dealloc();
    die("config key/value array length mismatch: got %d, %d", cfg.keys.len, cfg.values.len);
  }
  for (int n = 0; n < cfg.keys.len; ++n) {
    config("alias '%s' points to '%s'", cfg.keys.backing[n], cfg.values.backing[n]);
  }
}

static inline char *config_get(char *alias) {
  int n_keys = cfg.keys.len;
  for (int n = 0; n < n_keys; ++n) {
    if (!strcmp(alias, cfg.keys.backing[n])) return cfg.values.backing[n];
  }
  return NULL;
}

void config_parse() {
  FILE *fp = xfopen(CONFIG_FILE, "r");

  vec_string_init(&cfg.keys);
  vec_string_init(&cfg.values);

  string_t temp;
  int value = 0;
  string_init(&temp);

  char c;
  while ((c = fgetc(fp)) != EOF) {
    switch (c) {
      case ' ':
      case '\t':
      case '\v':
      case '\r':
      case '\f':
        continue;
      case '-':
        vec_string_push(&cfg.keys, temp.backing);
        string_init(&temp);
        value = 1;
        break;
      case '\n':
        vec_string_push(&cfg.values, temp.backing);
        string_init(&temp);
        value = 0;
        break;
      default:
        string_push(&temp, c);
        break;
    }
  }

  if (temp.len != 0) {
    if (value) vec_string_push(&cfg.values, temp.backing);
    else
      die("expected value for key: %s", temp.backing);
  } else if (temp.backing)
    free(temp.backing);

#ifndef PROD
  config_print();
#endif

  fclose(fp);
}

int config_initialize_inotify(void) {
  int ifd = xinotify_init1(IN_NONBLOCK);
  xinotify_add_watch(ifd, CONFIG_FILE, IN_CLOSE_WRITE);

  return ifd;
}

void sock_set_nonblock(int fd) {
  int flags = xfcntl(fd, F_GETFL);
  xfcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int sock_bind(void) {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);

  static int yes = 1;
  xsetsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  sock_set_nonblock(sockfd);

  struct sockaddr_in addr = { .sin_port = htons(PORT),
                              .sin_addr = { .s_addr = htonl(INADDR_ANY) },
                              .sin_family = AF_INET,
                              .sin_zero = { 0 } };

  xbind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
  xlisten(sockfd, SOMAXCONN);

  web("starting server on port %d", PORT);
  return sockfd;
}

typedef struct {
  char *method;
  char *path;
} http_request_t;

void http_request_parse(http_request_t *req, char *buf) {
  req->method = xstrtok_r(buf, " ", &buf);
  req->path = xstrtok_r(NULL, " ", &buf);
  if (strlen(req->path) != 1) req->path += sizeof(char);
}

typedef struct {
  int fd;
} handler_args_t;

void handle_conn(handler_args_t *args) {
  char buf[HTTP_REQUEST_BUFFER];

  while (recv(args->fd, buf, HTTP_REQUEST_BUFFER, 0) == -1) {
    if (errno != EAGAIN) die("failed to read socket fd %d", args->fd);
  }

  http_request_t req;
  http_request_parse(&req, buf);

  if (strcmp(req.method, "GET")) {
    xsend(args->fd, "HTTP/1.1 404 Not Found\r\n\r\nInvalid method!\r\n");
    return;
  }

  char *redirect = config_get(req.path);
  if (!redirect) {
    xsend(args->fd, "HTTP/1.1 404 Not Found\r\n\r\nInvalid route!\r\n");
    return;
  }

  FILE *stream = xfdopen(args->fd, "w");
  xfprintf(stream, "HTTP/1.1 307 Temporary Redirect\r\nLocation: %s\r\nConnection: close\r\n",
           "http://safin.dev");
  fclose(stream);
}

void sig_handler(int signum) {
  warn("caught signal: %s, exiting peacefully...", strsignal(signum));
  config_dealloc();
  thread_pool_dealloc(&pool);
  exit(EXIT_SUCCESS);
}

int main(void) {
  config_parse();

  int ifd = config_initialize_inotify();
  int sfd = sock_bind();
  int epfd = xepoll_create1(O_CLOEXEC);

  struct epoll_event listen_ev = { .data.fd = sfd, .events = EPOLLIN };
  struct epoll_event inotify_ev = { .data.fd = ifd, .events = EPOLLIN };
  xepoll_ctl(epfd, EPOLL_CTL_ADD, ifd, &inotify_ev);
  xepoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &listen_ev);

  thread_pool_init(&pool);
  signal(SIGINT, sig_handler);

  struct epoll_event events[EPOLL_MAX_EVENTS];
  for (;;) {
    int evs = xepoll_wait(epfd, events, EPOLL_MAX_EVENTS, -1);
    for (int e = 0; e < evs; e++) {
      struct epoll_event event = events[e];
      if (event.events & EPOLLERR) {
        warn("epoll err");
        close(event.data.fd);
      } else if (event.data.fd == sfd) {
        int newfd;
        while ((newfd = accept(sfd, NULL, NULL)) != -1) {
          sock_set_nonblock(newfd);
          struct epoll_event accepted_ev = { .data.fd = newfd, .events = EPOLLIN | EPOLLET };
          xepoll_ctl(epfd, EPOLL_CTL_ADD, newfd, &accepted_ev);
        }
      } else if (event.data.fd == ifd) {
        struct inotify_event iev;
        int len = read(ifd, &iev, sizeof(iev));
        if (len == -1) die("failed to read from inotify fd");

        if (iev.mask & IN_CLOSE_WRITE) {
          reload("detected config file change! reloading...");

          pthread_mutex_lock(&config_mux);
          config_dealloc();
          config_parse();
          pthread_mutex_unlock(&config_mux);

          reload("reloaded successfully!");
        }
      } else {
        handler_args_t args = { .fd = event.data.fd };
        thread_pool_dispatch(&pool, (void *)&handle_conn, &args);
      }
    }
  }
}
