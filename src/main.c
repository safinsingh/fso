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

#define PORT 5012
#define JOBS 128
#define THREADS 8
#define MAX_EVENTS 512
#define REQUEST_BUFFER 32
#define INOTIFY_BUF_LEN 512
#define CONFIG_FILE "config.fso"
#define INITIAL_STRING_CAPACITY 32

void die(char *msg) {
  fprintf(stderr, " \033[0;31m[fatal]\033[0m :: %s\n            error: %s\n", msg, strerror(errno));
  exit(EXIT_FAILURE);
}

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

typedef struct String {
  char *ptr;
  int len;
  int cap;
} string_t;

string_t string_new() {
  static int cap = INITIAL_STRING_CAPACITY;
  char *ptr = xcalloc(cap, sizeof(*ptr));
  if (!ptr) die("failed to allocate string");

  return (string_t){ .ptr = ptr, .len = 0, .cap = cap };
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

static string_t string_from(char *ptr) {
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
  void (*fn)(void *, void *);
  void *arg1;
  void *arg2;
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
  thread_pool_t *pool = xmalloc(sizeof(*pool));

  if (pthread_mutex_init(&pool->job_lock, NULL)) die("failed to initialize thread pool job mutex");
  if (pthread_cond_init(&pool->job_notify, NULL))
    die("failed to initialize thread pool job condvar");

  pool->jobs_cap = jobs_cap;
  pool->jobs_head = 0;
  pool->jobs_len = 0;
  pool->jobs_tail = jobs_cap - 1;

  pool->threads = (pthread_t *)xmalloc(threads_len * sizeof(pthread_t));
  pool->jobs = (job_t *)xmalloc(jobs_cap * sizeof(job_t));

  for (int t = 0; t < threads_len; t++) {
    if (pthread_create(&pool->threads[t], NULL, thread_init, pool)) die("failed to create thread");
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
    pthread_mutex_lock(&pool->job_lock);
    while (pool->jobs_len == 0)
      pthread_cond_wait(&pool->job_notify, &pool->job_lock);

    job_t job = thread_pool_dequeue(pool);
    pthread_mutex_unlock(&pool->job_lock);

    job.fn(job.arg1, job.arg2);
  }

  pthread_exit(0);
  return NULL;
}

typedef struct Config config_t;

void thread_pool_dispatch(thread_pool_t *pool, void (*fn)(void *, void *), void *arg1, void *arg2) {
  pthread_mutex_lock(&pool->job_lock);
  if (pool->jobs_cap == pool->jobs_len) die("thread pool job queue full");

  thread_pool_enqueue(pool, (job_t){ .fn = fn, .arg1 = arg1, .arg2 = arg2 });

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
  while (link->next)
    link = link->next;
  return link;
}

typedef struct Config {
  link_t *head;
} config_t;

void config_print(config_t *config) {
  link_t *link = config->head;
  while (link->next) {
    printf("\033[0;32m[config]\033[0m :: alias '%s' points to '%s'\n", link->alias.ptr,
           link->to.ptr);
    link = link->next;
  }
}

string_t *config_get(config_t *config, string_t alias) {
  link_t *link = config->head;
  while (link->next) {
    if (strncmp(link->alias.ptr, alias.ptr, alias.len)) {
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
      } else
        string_push(&last_link_entry(config->head)->to, c);
    }
  }

  config_print(config);

  fclose(fp);
  return config;
}

int config_initialize_inotify(void) {
  int ifd = inotify_init1(IN_NONBLOCK);
  if (ifd < 0) die("failed to initialize an inotify instance");

  int wd = inotify_add_watch(ifd, CONFIG_FILE, IN_CLOSE_WRITE);
  if (wd < 0) die("failed to add watch to inotify instance");

  return ifd;
}

void sock_set_nonblock(int fd) {
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0) die("failed to retrieve flags on socket fd");
  if ((fcntl(fd, F_SETFL, flags | O_NONBLOCK)) < 0) die("failed to set tcp socket as nonblocking");
}

int sock_bind(void) {
  static int yes = 1;

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)))
    die("failed to set SO_REUSEADDR on socket");
  sock_set_nonblock(sockfd);

  struct sockaddr_in addr = { .sin_port = htons(PORT),
                              .sin_addr = { .s_addr = htonl(INADDR_ANY) },
                              .sin_family = AF_INET,
                              .sin_zero = { 0 } };

  if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr))) die("failed to bind socket to port");
  if (listen(sockfd, SOMAXCONN)) die("failed to begin listening on port");

  printf("   \033[0;36m[web]\033[0m :: starting server on port %d\n", PORT);
  return sockfd;
}

void *handle_conn(int const *fd, config_t *config) {
  char buf[REQUEST_BUFFER] = { 0 };
  int bytes = 0;

  for (;;) {
    int len = read(*fd, &buf[bytes], REQUEST_BUFFER - bytes);
    if (len == -1) {
      if (errno == EAGAIN) break;
      die("failed to read socket");
    } else if (len == 0) {
      break;
    } else {
      bytes += len;
      if (bytes == REQUEST_BUFFER) break;
    }
  }

  char prefix[] = "GET /";
  if (memcmp(buf, prefix, strlen(prefix))) {
    char err[] = "HTTP/1.1 404 Not Found\r\n\r\nInvalid route!";
    if (write(*fd, err, strlen(err)) < 0) die("failed to write to socket");
    goto END;
  }

  string_t alias = string_new();
  for (int i = strlen(prefix); i < REQUEST_BUFFER; i++) {
    char a = buf[i];
    if (a != ' ') string_push(&alias, a);
    else {
      if (alias.len == 0) string_push(&alias, '@');
      break;
    }
  }

  string_t *redirect = config_get(config, alias);
  string_dealloc(&alias);

  if (!redirect) {
    char err[] = "HTTP/1.1 404 Not Found\r\n\r\nInvalid route!";
    if (write(*fd, err, strlen(err)) < 0) die("failed to write to socket");

    goto END;
  }

  string_t res = string_from("HTTP/1.1 307 Temporary Redirect\r\nLocation: ");
  string_push_str(&res, redirect->ptr, redirect->len);
  string_push_str(&res, "\r\n", 2);

  if (write(*fd, res.ptr, res.len) < 0) die("failed to write to socket");
  string_dealloc(&res);

END:
  printf("   \033[0;36m[web]\033[0m :: handled conn on sockfd %d\n", *fd);
  close(*fd);
  return NULL;
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

  struct inotify_event last_inotif_ev[1];
  struct epoll_event events[MAX_EVENTS];
  thread_pool_t *pool = thread_pool_new(THREADS, JOBS);

  config_t *config = config_parse();
  pthread_mutex_t config_mux;
  pthread_mutex_init(&config_mux, NULL);

  for (;;) {
    int evs = epoll_wait(epfd, events, MAX_EVENTS, -1);
    if (evs < 0) die("epoll wait failedtt");

    for (int e = 0; e < evs; e++) {
      struct epoll_event event = events[e];
      if ((event.events & EPOLLERR) || (event.events & EPOLLHUP) || (!(event.events & EPOLLIN))) {
        close(event.data.fd);
        continue;
      }
      if (event.data.fd == sfd) {
        for (;;) {
          int newfd = accept(sfd, NULL, NULL);
          if (newfd == -1) {
            if (errno == EAGAIN) break;
            die("failed to accept connection");
          }

          sock_set_nonblock(newfd);
          struct epoll_event accepted_ev = { .data.fd = newfd, .events = EPOLLIN | EPOLLET };
          if (epoll_ctl(epfd, EPOLL_CTL_ADD, newfd, &accepted_ev)) {
            die("failed to add connection fd to epoll interest list");
          } else {
            printf(
                "   \033[0;36m[web]\033[0m :: got ev, awaiting conn on sockfd "
                "%d\n",
                newfd);
          }
        }
      } else if (event.data.fd == ifd) {
        int len = read(ifd, last_inotif_ev, sizeof(last_inotif_ev));
        if (len == -1 && errno != EAGAIN) die("failed to read from inotify fd");
        if (len <= 0) continue;

        if (last_inotif_ev->mask & IN_CLOSE_WRITE) {
          printf(
              "\033[0;35m[config]\033[0m :: detected config file change! "
              "reloading...\n");

          pthread_mutex_lock(&config_mux);
          config_dealloc(config);
          config = config_parse();
          pthread_mutex_unlock(&config_mux);

          printf("\033[0;35m[config]\033[0m :: reloaded successfully!\n");
        }
      } else {
        // attempt lock to wait for config reloading to finish
        pthread_mutex_lock(&config_mux);
        // unlock immediately
        pthread_mutex_unlock(&config_mux);

        thread_pool_dispatch(pool, (void *)handle_conn, &event.data.fd, config);
      }
    }
  }
}
