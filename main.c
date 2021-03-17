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

#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 5012

void die(char *msg) {
  fprintf(stderr, " \033[0;31m[fatal]\033[0m :: %s", msg);
  fprintf(stderr, "           Error: %s\n", strerror(errno));
  exit(EXIT_FAILURE);
}

typedef struct String {
  char *ptr;
  int len;
  int cap;
} string_t;

string_t string_new() {
  static int cap = 32;
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

string_t *config_get(config_t config, string_t alias) {
  link_t *link = config.head;
  while (link->next) {
    if (memcmp(link->alias.ptr, alias.ptr, alias.len)) {
      link = link->next;
    } else {
      return &link->to;
    }
  }
  return NULL;
}

void config_dealloc(config_t config) {
  link_t *link = config.head;
  while (link->next) {
    link_t *tmp = link;

    string_dealloc(&tmp->alias);
    string_dealloc(&tmp->to);
    free(tmp);

    link = link->next;
  }
}

typedef enum ParserState { KEY, VALUE } parser_state_t;

int main() {
  FILE *fp = fopen("config.fso", "r");
  if (!fp) die("failed to open configuration file\n");

  parser_state_t state = KEY;
  config_t config = {.head = new_link_entry()};

  char c;
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

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (!sockfd) die("failed to create new socket\n");

  struct sockaddr_in addr = {.sin_port = htons(PORT),
                             .sin_addr = {.s_addr = htonl(INADDR_ANY)},
                             .sin_family = AF_INET,
                             .sin_zero = {0}};
  int addr_sz = sizeof(addr);
  if (bind(sockfd, (struct sockaddr *)&addr, addr_sz))
    die("failed to bind socket to port\n");
  if (listen(sockfd, 5)) die("failed to begin listening on port\n");

#ifndef QUIET
  printf("   \033[0;36m[web]\033[0m :: starting server on port %d\n", PORT);
#endif

  for (;;) {
    int newfd = accept(sockfd, (struct sockaddr *)&addr, (socklen_t *)&addr_sz);
    if (!newfd) die("Failed to open socket for new connection\n");

#ifndef QUIET
    printf(
        "   \033[0;36m[web]\033[0m :: got new connection, opening socket %d\n",
        newfd);
#endif

    const char *prefix = "GET /";
    char buf[64] = {0};
    if (read(newfd, buf, 64) == -1) die("failed to read from socket");

    if (memcmp(&buf, prefix, 5)) continue;

    string_t alias = string_new();
    for (int i = 5; i < 128; i++) {
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
      printf("encountered invalid redirect for: %s\n", alias.ptr);
#endif

      char *err = "HTTP/1.1 404 Not Found\r\n\r\nInvalid route!";
      if (write(newfd, err, strlen(err)) == -1)
        die("failed to write to socket");
      continue;
    }

    string_push_str(&res, redirect->ptr, redirect->len);
    string_push_str(&res, "\r\n", 2);

    if (write(newfd, res.ptr, res.len) == -1) die("failed to write to socket");

    string_dealloc(&res);
    string_dealloc(&alias);
    close(newfd);
  }

  fclose(fp);
  config_dealloc(config);
}
