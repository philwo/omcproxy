#include "list.h"

void INIT_LIST_HEAD(struct ListHead* list) {
  list->next = list->prev = list;
}

bool list_empty(const struct ListHead* head) {
  return (head->next == head);
}

bool list_is_first(const struct ListHead* list, const struct ListHead* head) {
  return list->prev == head;
}

bool list_is_last(const struct ListHead* list, const struct ListHead* head) {
  return list->next == head;
}

void _list_del(struct ListHead* entry) {
  entry->next->prev = entry->prev;
  entry->prev->next = entry->next;
}

void list_del(struct ListHead* entry) {
  _list_del(entry);
  entry->next = entry->prev = nullptr;
}

void _list_add(struct ListHead* _new,
               struct ListHead* prev,
               struct ListHead* next) {
  next->prev = _new;
  _new->next = next;
  _new->prev = prev;
  prev->next = _new;
}

void list_add(struct ListHead* _new, struct ListHead* head) {
  _list_add(_new, head, head->next);
}

void list_add_tail(struct ListHead* _new, struct ListHead* head) {
  _list_add(_new, head->prev, head);
}

void list_move_tail(struct ListHead* entry, struct ListHead* head) {
  _list_del(entry);
  list_add_tail(entry, head);
}

void _list_splice(const struct ListHead* list,
                  struct ListHead* prev,
                  struct ListHead* next) {
  struct ListHead* first;
  struct ListHead* last;

  if (list_empty(list)) {
    return;
  }

  first = list->next;
  last = list->prev;
  first->prev = prev;
  prev->next = first;
  last->next = next;
  next->prev = last;
}

void list_splice(const struct ListHead* list, struct ListHead* head) {
  _list_splice(list, head, head->next);
}

void list_splice_init(struct ListHead* list, struct ListHead* head) {
  _list_splice(list, head, head->next);
  INIT_LIST_HEAD(list);
}
