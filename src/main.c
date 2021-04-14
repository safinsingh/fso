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
#define INITIAL_STRING_CAPACITY 32

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

typedef struct String {
  char *ptr;
  int len;
  int cap;
} string_t;

string_t string_new(void) {
  static int cap = INITIAL_STRING_CAPACITY;
  char *ptr = xcalloc(cap, sizeof(*ptr));

  return (string_t){ .ptr = ptr, .len = 0, .cap = cap };
}

void _string_realloc(string_t *string) {
  int cap = string->cap * 2;
  char *ptr = xrealloc(string->ptr, cap * sizeof(*ptr));

  string->cap = cap;
  string->ptr = ptr;
}

void string_push(string_t *string, char ch) {
  if (string->len + 1 == string->cap) _string_realloc(string);
  string->ptr[string->len] = ch;
  string->len++;
}

void string_dealloc(string_t *string) {
  free(string->ptr);
}

string_t string_from(char *ptr) {
  int len = strlen(ptr);

  int pow = 1;
  while ((1 << pow) < len) pow++;
  int cap = 1 << pow;

  char *dup = xcalloc(cap, sizeof(*dup));
  return (string_t){ .ptr = xmemcpy(dup, ptr, len), .len = len, .cap = cap };
}

void string_push_str(string_t *string, char *ptr, int len) {
  for (int i = 0; i < len; i++) string_push(string, ptr[i]);
}

typedef struct Job {
  void (*fn)(void *);
  void *arg;
} job_t;

typedef struct ThreadPool {
  pthread_mutex_t job_notify_lock;
  pthread_cond_t job_notify;
  pthread_t *threads;
  int threads_len;

  pthread_mutex_t job_lock;
  job_t *jobs;
  int jobs_len;
  int jobs_cap;
  int jobs_head;
  int jobs_tail;

  atomic_bool keep_alive;
} thread_pool_t;

thread_pool_t pool;

void *thread_init(void *arg);
void thread_pool_init(thread_pool_t *pool, int threads_len, int jobs_cap) {
  xpthread_mutex_init(&pool->job_lock, NULL);
  xpthread_mutex_init(&pool->job_notify_lock, NULL);
  xpthread_cond_init(&pool->job_notify, NULL);

  pool->jobs_cap = jobs_cap;
  pool->jobs_head = 0;
  pool->jobs_len = 0;
  pool->jobs_tail = jobs_cap - 1;
  pool->threads_len = threads_len;
  pool->keep_alive = ATOMIC_VAR_INIT(true);

  pool->threads = xmalloc(threads_len * sizeof(*pool->threads));
  pool->jobs = xmalloc(jobs_cap * sizeof(*pool->jobs));

  for (int t = 0; t < threads_len; t++) {
    xpthread_create(&pool->threads[t], NULL, thread_init, pool);
  }
}

void thread_pool_dealloc(thread_pool_t *pool) {
  atomic_store_explicit(&pool->keep_alive, false, memory_order_release);
  for (int t = 0; t < pool->threads_len; t++) {
    xpthread_cancel(pool->threads[t]);
    xpthread_join(pool->threads[t], NULL);
  }
  free(pool->threads);
  free(pool->jobs);
}

job_t thread_pool_dequeue(thread_pool_t *pool) {
  job_t job = pool->jobs[pool->jobs_head];
  pool->jobs_head = (pool->jobs_head + 1) % pool->jobs_cap;
  pool->jobs_len -= 1;
  return job;
}

void thread_pool_enqueue(thread_pool_t *pool, job_t job) {
  if (pool->jobs_cap == pool->jobs_len) die("thread pool job queue full");
  pool->jobs_tail = (pool->jobs_tail + 1) % pool->jobs_cap;
  pool->jobs[pool->jobs_tail] = job;
  pool->jobs_len += 1;
}

void thread_cleanup(void *arg) {
  thread_pool_t *pool = (thread_pool_t *)arg;
  pthread_mutex_unlock(&pool->job_notify_lock);
}

void *thread_init(void *arg) {
  thread_pool_t *pool = (thread_pool_t *)arg;
  pthread_cleanup_push(&thread_cleanup, arg);

  while (atomic_load_explicit(&pool->keep_alive, memory_order_acquire)) {
    pthread_mutex_lock(&pool->job_notify_lock);
    pthread_cond_wait(&pool->job_notify, &pool->job_notify_lock);
    pthread_mutex_unlock(&pool->job_notify_lock);

    pthread_mutex_lock(&pool->job_lock);
    job_t job = thread_pool_dequeue(pool);
    pthread_mutex_unlock(&pool->job_lock);

    (*job.fn)(job.arg);
  }

  pthread_cleanup_pop(0);
  pthread_exit(EXIT_SUCCESS);
  return NULL;
}

void thread_pool_dispatch(thread_pool_t *pool, void (*fn)(void *), void *arg) {
  pthread_mutex_lock(&pool->job_lock);
  thread_pool_enqueue(pool, (job_t){ .fn = fn, .arg = arg });
  pthread_mutex_unlock(&pool->job_lock);

  pthread_mutex_lock(&pool->job_notify_lock);
  xpthread_cond_signal(&pool->job_notify);
  pthread_mutex_unlock(&pool->job_notify_lock);
}

typedef struct Link {
  string_t alias;
  string_t to;
  struct Link *next;
} link_t;

link_t *new_link_entry(void) {
  link_t *link = xmalloc(sizeof(*link));
  link->alias = string_new();
  link->to = string_new();
  link->next = NULL;
  return link;
}

link_t *last_link_entry(link_t *head) {
  link_t *link = head;
  while (link->next) link = link->next;
  return link;
}

typedef struct Config {
  link_t *head;
} config_t;

pthread_mutex_t config_mux = PTHREAD_MUTEX_INITIALIZER;
config_t *config;

void config_print(config_t *config) {
  link_t *link = config->head;
  while (link->next) {
    config("alias '%s' points to '%s'", link->alias.ptr, link->to.ptr);
    link = link->next;
  }
}

string_t *config_get(config_t *config, char *alias) {
  link_t *link = config->head;
  while (link->next) {
    if (strcmp(link->alias.ptr, alias)) {
      link = link->next;
    } else {
      return &link->to;
    }
  }
  return NULL;
}

void config_dealloc(config_t *config) {
  link_t *link = config->head;
  while (link) {
    link_t *tmp = link;

    string_dealloc(&tmp->alias);
    string_dealloc(&tmp->to);

    link = link->next;
    free(tmp);
  }
  free(config);
}

typedef enum ParserState { KEY, VALUE } parser_state_t;
config_t *config_parse(void) {
  FILE *fp = xfopen(CONFIG_FILE, "r");

  parser_state_t state = KEY;
  config_t *config = xmalloc(sizeof(*config));
  config->head = new_link_entry();

  char c;
  while ((c = fgetc(fp)) != EOF) {
    if (c == ' ' || c == '\t' || c == '\v' || c == '\r' || c == '\f') continue;
    if (state == KEY) {
      if (c == ':') state = VALUE;
      else
        string_push(&last_link_entry(config->head)->alias, c);
    } else {
      if (c == '\n') {
        state = KEY;
        last_link_entry(config->head)->next = new_link_entry();
      } else {
        string_push(&last_link_entry(config->head)->to, c);
      }
    }
  }

#ifndef PROD
  config_print(config);
#endif

  fclose(fp);
  return config;
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

typedef struct Request {
  char *method;
  char *path;
} http_request_t;

http_request_t http_request_parse(char *buf) {
  http_request_t req;

  req.method = xstrtok_r(buf, " ", &buf);
  req.path = xstrtok_r(NULL, " ", &buf);
  if (strlen(req.path) != 1) req.path += sizeof(char);

  return req;
}

typedef struct HandlerArgs {
  int fd;
} handler_args_t;

void handle_conn(handler_args_t *args) {
  char buf[HTTP_REQUEST_BUFFER];

  while (recv(args->fd, buf, HTTP_REQUEST_BUFFER, 0) == -1) {
    if (errno != EAGAIN) die("failed to read socket fd %d", args->fd);
  }

  http_request_t req = http_request_parse(buf);

  if (strcmp(req.method, "GET")) {
    xsend(args->fd, "HTTP/1.1 404 Not Found\r\n\r\nInvalid method!\r\n");
    return;
  }

  string_t *redirect = config_get(config, req.path);
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
  config_dealloc(config);
  thread_pool_dealloc(&pool);
  exit(EXIT_SUCCESS);
}

int main(void) {
  config = config_parse();

  signal(SIGINT, sig_handler);

  int ifd = config_initialize_inotify();
  int sfd = sock_bind();
  int epfd = xepoll_create1(O_CLOEXEC);

  struct epoll_event listen_ev = { .data.fd = sfd, .events = EPOLLIN };
  struct epoll_event inotify_ev = { .data.fd = ifd, .events = EPOLLIN };

  xepoll_ctl(epfd, EPOLL_CTL_ADD, ifd, &inotify_ev);
  xepoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &listen_ev);

  thread_pool_init(&pool, THREAD_POOL_THREADS, THREAD_POOL_QUEUE_LEN);

  struct epoll_event events[EPOLL_MAX_EVENTS];
  for (;;) {
    int evs = xepoll_wait(epfd, events, EPOLL_MAX_EVENTS, -1);
    for (int e = 0; e < evs; e++) {
      struct epoll_event event = events[e];
      if (event.events & EPOLLERR || !(event.events & EPOLLIN)) {
        warn("epoll err");
        close(event.data.fd);
        continue;
      }
      if (event.data.fd == sfd) {
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
          config_dealloc(config);
          config = config_parse();
          pthread_mutex_unlock(&config_mux);

          reload("reloaded successfully!");
        }
      } else {
        handler_args_t *args = xmalloc(sizeof(*args));
        args->fd = event.data.fd;

        thread_pool_dispatch(&pool, (void *)&handle_conn, args);
      }
    }
  }
}
