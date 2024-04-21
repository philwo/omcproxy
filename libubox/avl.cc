/*
 * PacketBB handler library (see RFC 5444)
 * Copyright (c) 2010 Henning Rogge <hrogge@googlemail.com>
 * Original OLSRd implementation by Hannes Gredler <hannes@gredler.at>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of olsr.org, olsrd nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Visit http://www.olsr.org/git for more information.
 *
 * If you find this software useful feel free to make a donation
 * to the project. For more information see the website or contact
 * the copyright holders.
 */

#include "avl.h"
#include "list.h"

/**
 * Internal function to support returning the element from a avl tree query
 * @param tree pointer to avl tree
 * @param key pointer to key
 * @param offset offset of node inside the embedded struct
 * @param mode mode of lookup operation (less equal, equal or greater equal)
 * @param pointer to elemen, nullptr if no fitting one was found
 */
void* __avl_find_element(const struct AvlTree* tree,
                         const void* key,
                         size_t offset,
                         enum AvlFindMode mode) {
  void* node = nullptr;

  switch (mode) {
    case AVL_FIND_EQUAL:
      node = avl_find(tree, key);
      break;
    case AVL_FIND_LESSEQUAL:
      node = avl_find_lessequal(tree, key);
      break;
    case AVL_FIND_GREATEREQUAL:
      node = avl_find_greaterequal(tree, key);
      break;
  }
  return node == nullptr ? nullptr : (((char*)node) - offset);
}

static struct AvlNode* avl_find_rec(struct AvlNode* node,
                                    const void* key,
                                    avl_tree_comp comp,
                                    void* ptr,
                                    int* cmp_result);
static void avl_insert_before(struct AvlTree* tree,
                              struct AvlNode* pos_node,
                              struct AvlNode* node);
static void avl_insert_after(struct AvlTree* tree,
                             struct AvlNode* pos_node,
                             struct AvlNode* node);
static void post_insert(struct AvlTree* tree, struct AvlNode* node);
static void avl_delete_worker(struct AvlTree* tree, struct AvlNode* node);
static void avl_remove(struct AvlTree* tree, struct AvlNode* node);

/**
 * Initialize a new AvlTree struct
 * @param tree pointer to avl-tree
 * @param comp pointer to comparator for the tree
 * @param allow_dups true if the tree allows multiple
 *   elements with the same
 * @param ptr custom parameter for comparator
 */
void avl_init(struct AvlTree* tree,
              avl_tree_comp comp,
              bool allow_dups,
              void* ptr) {
  INIT_LIST_HEAD(&tree->list_head);
  tree->root = nullptr;
  tree->count = 0;
  tree->comp = comp;
  tree->allow_dups = allow_dups;
  tree->cmp_ptr = ptr;
}

static struct AvlNode* avl_next(struct AvlNode* node) {
  return list_entry(node->list.next, struct AvlNode, list);
}

/**
 * Finds a node in an avl-tree with a certain key
 * @param tree pointer to avl-tree
 * @param key pointer to key
 * @return pointer to avl-node with key, nullptr if no node with
 *    this key exists.
 */
struct AvlNode* avl_find(const struct AvlTree* tree, const void* key) {
  struct AvlNode* node;
  int diff;

  if (tree->root == nullptr) {
    return nullptr;
  }

  node = avl_find_rec(tree->root, key, tree->comp, tree->cmp_ptr, &diff);

  return diff == 0 ? node : nullptr;
}

/**
 * Finds the last node in an avl-tree with a key less or equal
 * than the specified key
 * @param tree pointer to avl-tree
 * @param key pointer to specified key
 * @return pointer to avl-node, nullptr if no node with
 *    key less or equal specified key exists.
 */
struct AvlNode* avl_find_lessequal(const struct AvlTree* tree,
                                   const void* key) {
  struct AvlNode *node, *next;
  int diff;

  if (tree->root == nullptr) {
    return nullptr;
  }

  node = avl_find_rec(tree->root, key, tree->comp, tree->cmp_ptr, &diff);

  /* go left as long as key<node.key */
  while (diff < 0) {
    if (list_is_first(&node->list, &tree->list_head)) {
      return nullptr;
    }

    node = (struct AvlNode*)node->list.prev;
    diff = (*tree->comp)(key, node->key, tree->cmp_ptr);
  }

  /* go right as long as key>=next_node.key */
  next = node;
  while (diff >= 0) {
    node = next;
    if (list_is_last(&node->list, &tree->list_head)) {
      break;
    }

    next = (struct AvlNode*)node->list.next;
    diff = (*tree->comp)(key, next->key, tree->cmp_ptr);
  }
  return node;
}

/**
 * Finds the first node in an avl-tree with a key greater or equal
 * than the specified key
 * @param tree pointer to avl-tree
 * @param key pointer to specified key
 * @return pointer to avl-node, nullptr if no node with
 *    key greater or equal specified key exists.
 */
struct AvlNode* avl_find_greaterequal(const struct AvlTree* tree,
                                      const void* key) {
  struct AvlNode *node, *next;
  int diff;

  if (tree->root == nullptr) {
    return nullptr;
  }

  node = avl_find_rec(tree->root, key, tree->comp, tree->cmp_ptr, &diff);

  /* go right as long as key>node.key */
  while (diff > 0) {
    if (list_is_last(&node->list, &tree->list_head)) {
      return nullptr;
    }

    node = (struct AvlNode*)node->list.next;
    diff = (*tree->comp)(key, node->key, tree->cmp_ptr);
  }

  /* go left as long as key<=next_node.key */
  next = node;
  while (diff <= 0) {
    node = next;
    if (list_is_first(&node->list, &tree->list_head)) {
      break;
    }

    next = (struct AvlNode*)node->list.prev;
    diff = (*tree->comp)(key, next->key, tree->cmp_ptr);
  }
  return node;
}

/**
 * Inserts an AvlNode into a tree
 * @param tree pointer to tree
 * @param new pointer to node
 * @return 0 if node was inserted successfully, -1 if it was not inserted
 *   because of a key collision
 */
int avl_insert(struct AvlTree* tree, struct AvlNode* new_node) {
  struct AvlNode *node, *next, *last;
  int diff;

  new_node->parent = nullptr;

  new_node->left = nullptr;
  new_node->right = nullptr;

  new_node->balance = 0;
  new_node->leader = true;

  if (tree->root == nullptr) {
    list_add(&new_node->list, &tree->list_head);
    tree->root = new_node;
    tree->count = 1;
    return 0;
  }

  node =
      avl_find_rec(tree->root, new_node->key, tree->comp, tree->cmp_ptr, &diff);

  last = node;

  while (!list_is_last(&last->list, &tree->list_head)) {
    next = avl_next(last);
    if (next->leader) {
      break;
    }
    last = next;
  }

  diff = (*tree->comp)(new_node->key, node->key, tree->cmp_ptr);

  if (diff == 0) {
    if (!tree->allow_dups) {
      return -1;
    }

    new_node->leader = false;

    avl_insert_after(tree, last, new_node);
    return 0;
  }

  if (node->balance == 1) {
    avl_insert_before(tree, node, new_node);

    node->balance = 0;
    new_node->parent = node;
    node->left = new_node;
    return 0;
  }

  if (node->balance == -1) {
    avl_insert_after(tree, last, new_node);

    node->balance = 0;
    new_node->parent = node;
    node->right = new_node;
    return 0;
  }

  if (diff < 0) {
    avl_insert_before(tree, node, new_node);

    node->balance = -1;
    new_node->parent = node;
    node->left = new_node;
    post_insert(tree, node);
    return 0;
  }

  avl_insert_after(tree, last, new_node);

  node->balance = 1;
  new_node->parent = node;
  node->right = new_node;
  post_insert(tree, node);
  return 0;
}

/**
 * Remove a node from an avl tree
 * @param tree pointer to tree
 * @param node pointer to node
 */
void avl_delete(struct AvlTree* tree, struct AvlNode* node) {
  struct AvlNode* next;
  struct AvlNode* parent;
  struct AvlNode* left;
  struct AvlNode* right;
  if (node->leader) {
    if (tree->allow_dups && !list_is_last(&node->list, &tree->list_head) &&
        !(next = avl_next(node))->leader) {
      next->leader = true;
      next->balance = node->balance;

      parent = node->parent;
      left = node->left;
      right = node->right;

      next->parent = parent;
      next->left = left;
      next->right = right;

      if (parent == nullptr) {
        tree->root = next;
      }

      else {
        if (node == parent->left) {
          parent->left = next;
        }

        else {
          parent->right = next;
        }
      }

      if (left != nullptr) {
        left->parent = next;
      }

      if (right != nullptr) {
        right->parent = next;
      }
    }

    else {
      avl_delete_worker(tree, node);
    }
  }

  avl_remove(tree, node);
}

static struct AvlNode* avl_find_rec(struct AvlNode* node,
                                    const void* key,
                                    avl_tree_comp comp,
                                    void* cmp_ptr,
                                    int* cmp_result) {
  int diff;

  diff = (*comp)(key, node->key, cmp_ptr);
  *cmp_result = diff;

  if (diff < 0) {
    if (node->left != nullptr) {
      return avl_find_rec(node->left, key, comp, cmp_ptr, cmp_result);
    }

    return node;
  }

  if (diff > 0) {
    if (node->right != nullptr) {
      return avl_find_rec(node->right, key, comp, cmp_ptr, cmp_result);
    }

    return node;
  }

  return node;
}

static void avl_rotate_right(struct AvlTree* tree, struct AvlNode* node) {
  struct AvlNode *left, *parent;

  left = node->left;
  parent = node->parent;

  left->parent = parent;
  node->parent = left;

  if (parent == nullptr) {
    tree->root = left;
  }

  else {
    if (parent->left == node) {
      parent->left = left;
    }

    else {
      parent->right = left;
    }
  }

  node->left = left->right;
  left->right = node;

  if (node->left != nullptr) {
    node->left->parent = node;
  }

  node->balance += 1 - (left->balance < 0 ? left->balance : 0);
  left->balance += 1 + (node->balance > 0 ? node->balance : 0);
}

static void avl_rotate_left(struct AvlTree* tree, struct AvlNode* node) {
  struct AvlNode *right, *parent;

  right = node->right;
  parent = node->parent;

  right->parent = parent;
  node->parent = right;

  if (parent == nullptr) {
    tree->root = right;
  }

  else {
    if (parent->left == node) {
      parent->left = right;
    }

    else {
      parent->right = right;
    }
  }

  node->right = right->left;
  right->left = node;

  if (node->right != nullptr) {
    node->right->parent = node;
  }

  node->balance -= 1 + (right->balance > 0 ? right->balance : 0);
  right->balance -= 1 - (node->balance < 0 ? node->balance : 0);
}

static void post_insert(struct AvlTree* tree, struct AvlNode* node) {
  struct AvlNode* parent = node->parent;

  if (parent == nullptr) {
    return;
  }

  if (node == parent->left) {
    parent->balance--;

    if (parent->balance == 0) {
      return;
    }

    if (parent->balance == -1) {
      post_insert(tree, parent);
      return;
    }

    if (node->balance == -1) {
      avl_rotate_right(tree, parent);
      return;
    }

    avl_rotate_left(tree, node);
    avl_rotate_right(tree, node->parent->parent);
    return;
  }

  parent->balance++;

  if (parent->balance == 0) {
    return;
  }

  if (parent->balance == 1) {
    post_insert(tree, parent);
    return;
  }

  if (node->balance == 1) {
    avl_rotate_left(tree, parent);
    return;
  }

  avl_rotate_right(tree, node);
  avl_rotate_left(tree, node->parent->parent);
}

static void avl_insert_before(struct AvlTree* tree,
                              struct AvlNode* pos_node,
                              struct AvlNode* node) {
  list_add_tail(&node->list, &pos_node->list);
  tree->count++;
}

static void avl_insert_after(struct AvlTree* tree,
                             struct AvlNode* pos_node,
                             struct AvlNode* node) {
  list_add(&node->list, &pos_node->list);
  tree->count++;
}

static void avl_remove(struct AvlTree* tree, struct AvlNode* node) {
  list_del(&node->list);
  tree->count--;
}

static void avl_post_delete(struct AvlTree* tree, struct AvlNode* node) {
  struct AvlNode* parent;

  if ((parent = node->parent) == nullptr) {
    return;
  }

  if (node == parent->left) {
    parent->balance++;

    if (parent->balance == 0) {
      avl_post_delete(tree, parent);
      return;
    }

    if (parent->balance == 1) {
      return;
    }

    if (parent->right->balance == 0) {
      avl_rotate_left(tree, parent);
      return;
    }

    if (parent->right->balance == 1) {
      avl_rotate_left(tree, parent);
      avl_post_delete(tree, parent->parent);
      return;
    }

    avl_rotate_right(tree, parent->right);
    avl_rotate_left(tree, parent);
    avl_post_delete(tree, parent->parent);
    return;
  }

  parent->balance--;

  if (parent->balance == 0) {
    avl_post_delete(tree, parent);
    return;
  }

  if (parent->balance == -1) {
    return;
  }

  if (parent->left->balance == 0) {
    avl_rotate_right(tree, parent);
    return;
  }

  if (parent->left->balance == -1) {
    avl_rotate_right(tree, parent);
    avl_post_delete(tree, parent->parent);
    return;
  }

  avl_rotate_left(tree, parent->left);
  avl_rotate_right(tree, parent);
  avl_post_delete(tree, parent->parent);
}

static struct AvlNode* avl_local_min(struct AvlNode* node) {
  while (node->left != nullptr) {
    node = node->left;
  }

  return node;
}

static void avl_delete_worker(struct AvlTree* tree, struct AvlNode* node) {
  struct AvlNode *parent, *min;

  parent = node->parent;

  if (node->left == nullptr && node->right == nullptr) {
    if (parent == nullptr) {
      tree->root = nullptr;
      return;
    }

    if (parent->left == node) {
      parent->left = nullptr;
      parent->balance++;

      if (parent->balance == 1) {
        return;
      }

      if (parent->balance == 0) {
        avl_post_delete(tree, parent);
        return;
      }

      if (parent->right->balance == 0) {
        avl_rotate_left(tree, parent);
        return;
      }

      if (parent->right->balance == 1) {
        avl_rotate_left(tree, parent);
        avl_post_delete(tree, parent->parent);
        return;
      }

      avl_rotate_right(tree, parent->right);
      avl_rotate_left(tree, parent);
      avl_post_delete(tree, parent->parent);
      return;
    }

    if (parent->right == node) {
      parent->right = nullptr;
      parent->balance--;

      if (parent->balance == -1) {
        return;
      }

      if (parent->balance == 0) {
        avl_post_delete(tree, parent);
        return;
      }

      if (parent->left->balance == 0) {
        avl_rotate_right(tree, parent);
        return;
      }

      if (parent->left->balance == -1) {
        avl_rotate_right(tree, parent);
        avl_post_delete(tree, parent->parent);
        return;
      }

      avl_rotate_left(tree, parent->left);
      avl_rotate_right(tree, parent);
      avl_post_delete(tree, parent->parent);
      return;
    }
  }

  if (node->left == nullptr) {
    if (parent == nullptr) {
      tree->root = node->right;
      node->right->parent = nullptr;
      return;
    }

    node->right->parent = parent;

    if (parent->left == node) {
      parent->left = node->right;
    }

    else {
      parent->right = node->right;
    }

    avl_post_delete(tree, node->right);
    return;
  }

  if (node->right == nullptr) {
    if (parent == nullptr) {
      tree->root = node->left;
      node->left->parent = nullptr;
      return;
    }

    node->left->parent = parent;

    if (parent->left == node) {
      parent->left = node->left;
    }

    else {
      parent->right = node->left;
    }

    avl_post_delete(tree, node->left);
    return;
  }

  min = avl_local_min(node->right);
  avl_delete_worker(tree, min);
  parent = node->parent;

  min->balance = node->balance;
  min->parent = parent;
  min->left = node->left;
  min->right = node->right;

  if (min->left != nullptr) {
    min->left->parent = min;
  }

  if (min->right != nullptr) {
    min->right->parent = min;
  }

  if (parent == nullptr) {
    tree->root = min;
    return;
  }

  if (parent->left == node) {
    parent->left = min;
    return;
  }

  parent->right = min;
}

/*
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
