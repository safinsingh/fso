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
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 5012
#define JOBS 128
#define THREADS 8
#define REQUEST_BUFFER 64
#define INOTIFY_BUF_LEN 512
#define MAX_QUEUED_REQUESTS 64
#define CONFIG_FILE "config.fso"
#define INITIAL_STRING_CAPACITY 32
#define MAX_EVENTS MAX_QUEUED_REQUESTS + 2

void die(char *msg) {
  fprintf(stderr, " \033[0;31m[fatal]\033[0m :: %s", msg);
  fprintf(stderr, "            Error: %s\n", strerror(errno));
  exit(EXIT_FAILURE);
}

typedef struct String {
  char *ptr;
  int len;
  int cap;
} string_t;

string_t string_new() {
  static int cap = INITIAL_STRING_CAPACITY;
  char *ptr = (char *)calloc(cap, sizeof(char));
  if (!ptr) die("failed to allocate string");

  return (string_t){.ptr = ptr, .len = 0, .cap = cap};
}

void _string_realloc(string_t *string) {
  int cap = string->cap * 2;
  char *ptr = realloc(string->ptr, cap * sizeof(char));

  string->cap = cap;
  string->ptr = ptr;
}

void string_push(string_t *string, char ch) {
  if (string->len + 1 == string->cap) _string_realloc(string);
  string->ptr[string->len] = ch;
  string->len++;
}

void string_dealloc(string_t *string) {
  string->cap = 0;
  string->len = 0;
  free(string->ptr);
}

string_t string_from(char *ptr) {
  string_t str = string_new();
  for (char *s = ptr; *s != '\0'; s++)
    string_push(&str, *s);
  return str;
}

void string_push_str(string_t *string, const char *ptr, int len) {
  for (int i = 0; i < len; i++)
    string_push(string, ptr[i]);
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
thread_pool_t *thread_pool_new(int threads_len, int jobs_cap) {
  thread_pool_t *pool = (thread_pool_t *)malloc(sizeof(thread_pool_t));
  if (!pool) die("Failed to allocate thread pool");

  if (pthread_mutex_init(&pool->job_lock, NULL))
    die("failed to initialize thread pool job mutex");
  if (pthread_cond_init(&pool->job_notify, NULL))
    die("failed to initialize thread pool job condvar");

  pool->jobs_cap = jobs_cap;
  pool->jobs_head = 0;
  pool->jobs_len = 0;
  pool->jobs_tail = jobs_cap - 1;

  if (!(pool->threads = (pthread_t *)malloc(threads_len * sizeof(pthread_t))))
    die("failed to allocate pool thread pointers");
  if (!(pool->jobs = (job_t *)malloc(jobs_cap * sizeof(job_t))))
    die("failed to allocate pool jobs");

  for (int t = 0; t < threads_len; t++) {
    if (pthread_create(&pool->threads[t], NULL, (void *)thread_init, pool))
      die("failed to create thread");
    pool->threads_len++;
  }

  return pool;
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
    if (pthread_mutex_lock(&pool->job_lock)) die("failed to lock mutex");
    while (pool->jobs_len == 0)
      pthread_cond_wait(&pool->job_notify, &pool->job_lock);

    job_t job = thread_pool_dequeue(pool);

    if (pthread_mutex_unlock(&pool->job_lock)) die("failed to unlock mutex");
    job.fn(job.arg);
  }

  pthread_exit(0);
  return NULL;
}

typedef struct Config config_t;
typedef struct HandleArgs {
  int fd;
  config_t *config;
} handle_args_t;

void thread_pool_dispatch(thread_pool_t *pool, void (*fn)(void *), void *arg) {
  if (pthread_mutex_lock(&pool->job_lock)) die("failed to lock mutex");
  if (pool->jobs_cap == pool->jobs_len) die("thread pool job queue full");

  thread_pool_enqueue(pool, (job_t){.fn = fn, .arg = arg});

  if (pthread_cond_signal(&pool->job_notify))
    die("failed to wake up threads with condvar");
  if (pthread_mutex_unlock(&pool->job_lock)) die("failed to unlock mutex");
}

typedef struct Link {
  string_t alias;
  string_t to;
  struct Link *next;
} link_t;

link_t *new_link_entry() {
  link_t *link = (link_t *)malloc(sizeof(link_t));
  link->alias = string_new();
  link->to = string_new();
  link->next = NULL;
  return link;
}

link_t *last_link_entry(link_t *head) {
  link_t *link = head;
  while (link->next)
    link = link->next;
  return link;
}

typedef struct Config {
  link_t *head;
} config_t;

void config_print(config_t config) {
  link_t *link = config.head;
  while (link->next) {
    printf("\033[0;32m[config]\033[0m :: alias '%s' points to '%s'\n",
           link->alias.ptr, link->to.ptr);
    link = link->next;
  }
}

string_t *config_get(config_t *config, string_t alias) {
  link_t *link = config->head;
  while (link->next) {
    if (memcmp(link->alias.ptr, alias.ptr, alias.len)) {
      link = link->next;
    } else {
      return &link->to;
    }
  }
  return NULL;
}

typedef enum ParserState { KEY, VALUE } parser_state_t;
config_t config_parse() {
  FILE *fp = fopen(CONFIG_FILE, "r");
  if (!fp) die("failed to open configuration file\n");

  parser_state_t state = KEY;
  config_t config = {.head = new_link_entry()};

  int c;
  while ((c = fgetc(fp)) != EOF) {
    if (c == ' ' || c == '\t' || c == '\v' || c == '\r' || c == '\f') continue;
    if (state == KEY) {
      if (c == ':') state = VALUE;
      else
        string_push(&last_link_entry(config.head)->alias, c);
    } else {
      if (c == '\n') {
        state = KEY;
        last_link_entry(config.head)->next = new_link_entry();
      } else
        string_push(&last_link_entry(config.head)->to, c);
    }
  }

#ifndef QUIET
  config_print(config);
#endif

  fclose(fp);
  return config;
}

int config_initialize_inotify() {
  int ifd = inotify_init1(IN_NONBLOCK);
  if (ifd < 0) die("failed to initialize an inotify instance");

  int wd = inotify_add_watch(ifd, CONFIG_FILE, IN_CLOSE_WRITE);
  if (wd < 0) die("failed to add watch to inotify instance");

  return ifd;
}

void sock_set_nonblock(int fd) {
  if (fd < 0) die("failed to create new socket");
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0) die("failed to retrieve flags on socket fd");
  if ((fcntl(fd, F_SETFL, flags | O_NONBLOCK)) < 0)
    die("failed to set tcp socket as nonblocking");
}

int sock_bind() {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  sock_set_nonblock(sockfd);

  struct sockaddr_in addr = {.sin_port = htons(PORT),
                             .sin_addr = {.s_addr = htonl(INADDR_ANY)},
                             .sin_family = AF_INET,
                             .sin_zero = {0}};
  if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)))
    die("failed to bind socket to port\n");
  if (listen(sockfd, MAX_QUEUED_REQUESTS))
    die("failed to begin listening on port\n");

#ifndef QUIET
  printf("   \033[0;36m[web]\033[0m :: starting server on port %d\n", PORT);
#endif

  return sockfd;
}

void *handle_conn(handle_args_t *args) {
  int fd = args->fd;
  config_t *config = args->config;

  if (!fd) die("failed to open socket for new connection");

#ifndef QUIET
  printf("   \033[0;36m[web]\033[0m :: got new connection, opening socket %d\n",
         fd);
#endif

  const char *prefix = "GET /";
  char buf[REQUEST_BUFFER] = {0};
  if (read(fd, buf, REQUEST_BUFFER) < 0) die("failed to read from socket");

  if (memcmp(&buf, prefix, strlen(prefix))) return NULL;

  string_t alias = string_new();
  for (int i = strlen(prefix); i < REQUEST_BUFFER; i++) {
    char a = buf[i];
    if (a != ' ') string_push(&alias, a);
    else {
      if (alias.len == 0) string_push(&alias, '@');
      break;
    }
  }

  string_t res = string_from("HTTP/1.1 307 Temporary Redirect\r\nLocation: ");
  string_t *redirect = config_get(config, alias);
  if (!redirect) {
#ifndef QUIET
    printf(
        "  \033[0;31m[fail]\033[0m :: encountered invalid redirect for: %s\n",
        alias.ptr);
#endif

    char *err = "HTTP/1.1 404 Not Found\r\n\r\nInvalid route!";
    if (write(fd, err, strlen(err)) < 0) die("failed to write to socket");

    goto END_SOCK;
  }

  string_push_str(&res, redirect->ptr, redirect->len);
  string_push_str(&res, "\r\n", 2);

  if (write(fd, res.ptr, res.len) < 0) die("failed to write to socket");

END_SOCK:
  string_dealloc(&res);
  string_dealloc(&alias);
  close(fd);

  return NULL;
}

int main() {
  int sfd = sock_bind();
  int ifd = config_initialize_inotify();
  int epfd = epoll_create(1);

  struct epoll_event listen_ev = {.data.fd = sfd, .events = EPOLLIN | EPOLLET};
  struct epoll_event inotify_ev = {.data.fd = ifd, .events = EPOLLIN | EPOLLET};

  if (epoll_ctl(epfd, EPOLL_CTL_ADD, ifd, &inotify_ev))
    die("failed to add inotify fd to epoll interest list");
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &listen_ev))
    die("failed to add socket fd to epoll interest list");

  struct inotify_event *last_inotif_ev =
      (struct inotify_event *)malloc(sizeof(struct inotify_event));
  struct epoll_event *events = calloc(MAX_EVENTS, sizeof(struct epoll_event));
  thread_pool_t *pool = thread_pool_new(THREADS, JOBS);
  config_t config = config_parse();

  for (;;) {
    int evs = epoll_wait(epfd, events, MAX_EVENTS, -1);
    if (evs < 0) die("epoll wait failed");

    for (int e = 0; e < evs; e++) {
      struct epoll_event event = events[e];
      if ((event.events & EPOLLERR) || (event.events & EPOLLHUP)) {
        die("epoll wait failed");
        close(event.data.fd);
        continue;
      }

      if (event.data.fd == sfd) {
        int newfd = accept(sfd, NULL, NULL);
        if (newfd < 0) die("failed to accept connection");
        sock_set_nonblock(newfd);

        struct epoll_event accepted_ev = {.data.fd = newfd,
                                          .events = EPOLLIN | EPOLLET};
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, newfd, &accepted_ev))
          die("failed to add connection fd to epoll interest list");
      } else if (event.data.fd == ifd) {
        int len = read(ifd, last_inotif_ev, INOTIFY_BUF_LEN);
        if (len == -1 && errno != EAGAIN) die("failed to read from inotify fd");
        if (len <= 0) continue;

        if (last_inotif_ev->mask & IN_CLOSE_WRITE) {
          printf("\033[0;35m[config]\033[0m :: detected config file change! "
                 "reloading...\n");
          // lol this is a race condition
          sleep(1);
          config = config_parse();
          printf("\033[0;35m[config]\033[0m :: reloaded successfully!\n");
        }
      } else {
        handle_args_t arg = {.fd = event.data.fd, .config = &config};
        thread_pool_dispatch(pool, (void *)handle_conn, &arg);
      }
    }
  }
}
