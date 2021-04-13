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

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
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

#define THREAD_POOL_QUEUE_LEN 128
#define THREAD_POOL_THREADS 8

#define EPOLL_MAX_EVENTS 512
#define HTTP_REQUEST_BUFFER 128

#define CONFIG_FILE "config.fso"

#define web(fmt, ...) printf("   \033[0;36m[web]\033[0m :: " fmt "\n", ##__VA_ARGS__);
#define config(fmt, ...) printf("\033[0;32m[config]\033[0m :: " fmt "\n", ##__VA_ARGS__);
#define reload(fmt, ...) printf("\033[0;35m[reload]\033[0m :: " fmt "\n", ##__VA_ARGS__);
#define die(fmt, ...)                                                                \
  do {                                                                               \
    fprintf(stderr, " \033[0;31m[fatal]\033[0m :: " fmt "\n            errno: %s\n", \
            ##__VA_ARGS__, strerror(errno));                                         \
    exit(EXIT_FAILURE);                                                              \
  } while (0)
#define fat_ptr_impl(T) \
  typedef struct {      \
    T *data;            \
    int len;            \
  } fat_##T;

fat_ptr_impl(char);

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

typedef struct String {
  fat_char slice;
  int cap;
} string_t;

string_t string_new(void) {
  static int cap = INITIAL_STRING_CAPACITY;
  char *ptr = xcalloc(cap, sizeof(*ptr));

  return (string_t){ .slice = { .data = ptr, .len = 0 }, .cap = cap };
}

void _string_realloc(string_t *string) {
  int cap = string->cap * 2;
  char *ptr = xrealloc(string->slice.data, cap * sizeof(*ptr));

  string->cap = cap;
  string->slice.data = ptr;
}

void string_push(string_t *string, char ch) {
  if (string->slice.len + 1 == string->cap) _string_realloc(string);
  string->slice.data[string->slice.len] = ch;
  string->slice.len++;
}

void string_dealloc(string_t *string) {
  free(string->slice.data);
}

string_t string_from(char *ptr) {
  int len = strlen(ptr);

  int pow = 1;
  while ((1 << pow) < len) pow++;
  int cap = 1 << pow;

  char *dup = xcalloc(cap, sizeof(*dup));
  return (string_t){ .slice = { .data = xmemcpy(dup, ptr, len), .len = len }, .cap = cap };
}

void string_push_str(string_t *string, char *ptr, int len) {
  for (int i = 0; i < len; i++) string_push(string, ptr[i]);
}

typedef struct Job {
  void (*fn)(void *);
  void *arg;
} job_t;

typedef struct ThreadPool {
  pthread_mutex_t job_lock;
  pthread_cond_t job_notify;
  pthread_t *threads;
  int threads_len;

  job_t *jobs;
  int jobs_cap;
  int jobs_len;
  int jobs_head;
  int jobs_tail;
} thread_pool_t;

static void *thread_init(void *arg);
void thread_pool_init(thread_pool_t *pool, int threads_len, int jobs_cap) {
  if (pthread_mutex_init(&pool->job_lock, NULL)) die("failed to initialize thread pool job mutex");
  if (pthread_cond_init(&pool->job_notify, NULL))
    die("failed to initialize thread pool job condvar");

  pool->jobs_cap = jobs_cap;
  pool->jobs_head = 0;
  pool->jobs_len = 0;
  pool->jobs_tail = jobs_cap - 1;

  pool->threads = xmalloc(threads_len * sizeof(*pool->threads));
  pool->jobs = xmalloc(jobs_cap * sizeof(*pool->jobs));

  for (int t = 0; t < threads_len; t++) {
    if (pthread_create(&pool->threads[t], NULL, thread_init, pool)) die("failed to create thread");
    pool->threads_len++;
  }
}

job_t thread_pool_dequeue(thread_pool_t *pool) {
  job_t job = pool->jobs[pool->jobs_head];
  pool->jobs_head = (pool->jobs_head + 1) % pool->jobs_cap;
  pool->jobs_len -= 1;
  return job;
}

void thread_pool_enqueue(thread_pool_t *pool, job_t job) {
  pool->jobs_tail = (pool->jobs_tail + 1) % pool->jobs_cap;
  pool->jobs[pool->jobs_tail] = job;
  pool->jobs_len += 1;
}

void *thread_init(void *arg) {
  thread_pool_t *pool = (thread_pool_t *)arg;

  for (;;) {
    pthread_mutex_lock(&pool->job_lock);
    while (pool->jobs_len == 0) pthread_cond_wait(&pool->job_notify, &pool->job_lock);

    job_t job = thread_pool_dequeue(pool);
    pthread_mutex_unlock(&pool->job_lock);

    (*job.fn)(job.arg);
  }

  pthread_exit(EXIT_SUCCESS);
  return NULL;
}

void thread_pool_dispatch(thread_pool_t *pool, void (*fn)(void *), void *arg) {
  pthread_mutex_lock(&pool->job_lock);
  if (pool->jobs_cap == pool->jobs_len) die("thread pool job queue full");

  thread_pool_enqueue(pool, (job_t){ .fn = fn, .arg = arg });

  if (pthread_cond_signal(&pool->job_notify)) die("failed to wake up threads with condvar");
  pthread_mutex_unlock(&pool->job_lock);
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
    config("alias '%s' points to '%s'", link->alias.slice.data, link->to.slice.data);
    link = link->next;
  }
}

string_t *config_get(config_t *config, char *alias) {
  link_t *link = config->head;
  while (link->next) {
    if (strcmp(link->alias.slice.data, alias)) {
      link = link->next;
    } else {
      return &link->to;
    }
  }
  return NULL;
}

void config_dealloc(config_t *config) {
  link_t *link = config->head;
  while (link->next) {
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
  FILE *fp = fopen(CONFIG_FILE, "r");
  if (!fp) die("failed to open configuration file");

  parser_state_t state = KEY;
  config_t *config = xmalloc(sizeof(*config));
  config->head = new_link_entry();

  int c;
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

  config_print(config);

  fclose(fp);
  return config;
}

int config_initialize_inotify(void) {
  int ifd = inotify_init1(IN_NONBLOCK);
  if (ifd < 0) die("failed to initialize an inotify instance, does `config.fso` exist?");

  int wd = inotify_add_watch(ifd, CONFIG_FILE, IN_CLOSE_WRITE);
  if (wd < 0) die("failed to add watch on config file to inotify instance");

  return ifd;
}

void sock_set_nonblock(int fd) {
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0) die("failed to retrieve flags on socket with fd %d", fd);
  if ((fcntl(fd, F_SETFL, flags | O_NONBLOCK)) < 0)
    die("failed to set socket pointed to by fd %d as nonblocking", fd);
}

int sock_bind(void) {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);

  static int yes = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)))
    die("failed to set SO_REUSEADDR on socket");
  sock_set_nonblock(sockfd);

  struct sockaddr_in addr = { .sin_port = htons(PORT),
                              .sin_addr = { .s_addr = htonl(INADDR_ANY) },
                              .sin_family = AF_INET,
                              .sin_zero = { 0 } };

  if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)))
    die("failed to bind socket to port %d", PORT);
  if (listen(sockfd, SOMAXCONN)) die("failed to begin listening on port %d", PORT);

  web("starting server on port %d", PORT);
  return sockfd;
}

void xsock_write(int fd, char *msg) {
  if (write(fd, msg, strlen(msg)) < 0) {
    die("failed to write to socket fd %d", fd);
  }
}

typedef struct Request {
  char *method;
  char *path;
} http_request_t;

http_request_t http_request_parse(char *buf) {
  http_request_t req;

  req.method = xstrtok_r(buf, " ", &buf);
  req.path = xstrtok_r(NULL, " ", &buf);

  return req;
}

typedef struct HandlerArgs {
  int fd;
} handler_args_t;

void handle_conn(handler_args_t *args) {
  char buf[HTTP_REQUEST_BUFFER] = { 0 };

  int len = read(args->fd, buf, HTTP_REQUEST_BUFFER);
  if (len == -1) {
    if (errno == EAGAIN) {
      return;
    }
    die("failed to read socket fd %d", args->fd);
  }

  http_request_t req = http_request_parse(buf);

  if (strcmp(req.method, "GET")) {
    xsock_write(args->fd, "HTTP/1.1 404 Not Found\r\n\r\nInvalid route!");
    return;
  }

  string_t *redirect = config_get(config, req.path);
  if (!redirect) {
    xsock_write(args->fd, "HTTP/1.1 404 Not Found\r\n\r\nInvalid route!");
    return;
  }

  string_t res = string_from("HTTP/1.1 307 Temporary Redirect\r\nLocation: ");

  string_push_str(&res, redirect->slice.data, redirect->slice.len);
  string_push_str(&res, "\r\n", 2);

  xsock_write(args->fd, res.slice.data);
  string_dealloc(&res);
  close(args->fd);
}

int main(void) {
  int sfd = sock_bind();
  int ifd = config_initialize_inotify();
  int epfd = epoll_create1(O_CLOEXEC);
  if (epfd < 0) die("failed to create epoll instance");

  struct epoll_event listen_ev = { .data.fd = sfd, .events = EPOLLIN | EPOLLET };
  struct epoll_event inotify_ev = { .data.fd = ifd, .events = EPOLLIN | EPOLLET };

  if (epoll_ctl(epfd, EPOLL_CTL_ADD, ifd, &inotify_ev))
    die("failed to add inotify fd to epoll interest list");
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &listen_ev))
    die("failed to add socket fd to epoll interest list");

  struct inotify_event last_inotif_ev;
  struct epoll_event events[EPOLL_MAX_EVENTS];

  thread_pool_t pool;
  thread_pool_init(&pool, THREAD_POOL_THREADS, THREAD_POOL_QUEUE_LEN);

  config = config_parse();

  for (;;) {
    int evs = epoll_wait(epfd, events, EPOLL_MAX_EVENTS, -1);
    if (evs < 0) die("epoll wait failed");

    for (int e = 0; e < evs; e++) {
      struct epoll_event event = events[e];
      if ((event.events & EPOLLERR) || (event.events & EPOLLHUP)) die("epoll err/hup");
      if (event.data.fd == sfd) {
        int newfd;
        while ((newfd = accept4(sfd, NULL, NULL, SOCK_NONBLOCK)) != -1) {
          struct epoll_event accepted_ev = { .data.fd = newfd, .events = EPOLLIN | EPOLLET };
          if (epoll_ctl(epfd, EPOLL_CTL_ADD, newfd, &accepted_ev)) {
            die("failed to add fd %d to epoll interest list", newfd);
          }
        }
      } else if (event.data.fd == ifd) {
        int len = read(ifd, &last_inotif_ev, sizeof(last_inotif_ev));
        if (len == -1) {
          if (errno == EAGAIN) continue;
          die("failed to read from inotify fd");
        };

        if (last_inotif_ev.mask & IN_CLOSE_WRITE) {
          reload("detected config file change! reloading...");

          pthread_mutex_lock(&config_mux);
          config_dealloc(config);
          config = config_parse();
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
