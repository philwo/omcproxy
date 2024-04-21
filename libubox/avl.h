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

#pragma once

#include <cstddef>

#include "list.h"

#define EXPORT(sym) sym

/**
 * This element is a member of a avl-tree. It must be contained in all
 * larger structs that should be put into a tree.
 */
struct AvlNode {
  /**
   * Linked list node for supporting easy iteration and multiple
   * elments with the same key.
   *
   * this must be the first element of an AvlNode to
   * make casting for lists easier
   */
  struct ListHead list;

  /**
   * Pointer to parent node in tree, nullptr if root node
   */
  struct AvlNode* parent;

  /**
   * Pointer to left child
   */
  struct AvlNode* left;

  /**
   * Pointer to right child
   */
  struct AvlNode* right;

  /**
   * pointer to key of node
   */
  const void* key;

  /**
   * balance state of AVL tree (0,-1,+1)
   */
  signed char balance;

  /**
   * true if first of a series of nodes with same key
   */
  bool leader;
};

/**
 * Prototype for avl comparators
 * @param k1 first key
 * @param k2 second key
 * @param ptr custom data for tree comparator
 * @return +1 if k1>k2, -1 if k1<k2, 0 if k1==k2
 */
typedef int (*avl_tree_comp)(const void* k1, const void* k2, void* ptr);

/**
 * This struct is the central management part of an avl tree.
 * One of them is necessary for each AvlTree.
 */
struct AvlTree {
  /**
   * Head of linked list node for supporting easy iteration
   * and multiple elments with the same key.
   */
  struct ListHead list_head;

  /**
   * pointer to the root node of the avl tree, nullptr if tree is empty
   */
  struct AvlNode* root;

  /**
   * number of nodes in the avl tree
   */
  unsigned int count;

  /**
   * true if multiple nodes with the same key are
   * allowed in the tree, false otherwise
   */
  bool allow_dups;

  /**
   * pointer to the tree comparator
   *
   * First two parameters are keys to compare,
   * third parameter is a copy of cmp_ptr
   */
  avl_tree_comp comp;

  /**
   * custom pointer delivered to the tree comparator
   */
  void* cmp_ptr;
};

/**
 * internal enum for avl_find_... macros
 */
enum AvlFindMode { AVL_FIND_EQUAL, AVL_FIND_LESSEQUAL, AVL_FIND_GREATEREQUAL };

void EXPORT(avl_init)(struct AvlTree*, avl_tree_comp, bool, void*);
struct AvlNode* EXPORT(avl_find)(const struct AvlTree*, const void*);
struct AvlNode* EXPORT(avl_find_greaterequal)(const struct AvlTree* tree,
                                              const void* key);
struct AvlNode* EXPORT(avl_find_lessequal)(const struct AvlTree* tree,
                                           const void* key);
int EXPORT(avl_insert)(struct AvlTree*, struct AvlNode*);
void EXPORT(avl_delete)(struct AvlTree*, struct AvlNode*);

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
                         enum AvlFindMode mode);

/**
 * @param tree pointer to avl-tree
 * @param key pointer to key
 * @param element pointer to a node element
 *    (don't need to be initialized)
 * @param node_element name of the AvlNode element inside the
 *    larger struct
 * @return pointer to tree element with the specified key,
 *    nullptr if no element was found
 */
#define avl_find_element(tree, key, element, node_element) \
  ((__typeof__(*(element))*)__avl_find_element(            \
      tree, key, offsetof(typeof(*(element)), node_element), AVL_FIND_EQUAL))

/**
 * This function must not be called for an empty tree
 *
 * @param tree pointer to avl-tree
 * @param element pointer to a node element
 *    (don't need to be initialized)
 * @param node_member name of the AvlNode element inside the
 *    larger struct
 * @return pointer to the first element of the AvlTree
 *    (automatically converted to type 'element')
 */
#define avl_first_element(tree, element, node_member) \
  container_of((tree)->list_head.next, __typeof__(*(element)), node_member.list)

/**
 * @param tree pointer to tree
 * @param element pointer to a node struct that contains the AvlNode
 *    (don't need to be initialized)
 * @param node_member name of the AvlNode element inside the
 *    larger struct
 * @return pointer to the last element of the AvlTree
 *    (automatically converted to type 'element')
 */
#define avl_last_element(tree, element, node_member) \
  container_of((tree)->list_head.prev, __typeof__(*(element)), node_member.list)

/**
 * This function must not be called for the last element of
 * an avl tree
 *
 * @param element pointer to a node of the tree
 * @param node_member name of the AvlNode element inside the
 *    larger struct
 * @return pointer to the node after 'element'
 *    (automatically converted to type 'element')
 */
#define avl_next_element(element, node_member)                               \
  container_of((&(element)->node_member.list)->next, __typeof__(*(element)), \
               node_member.list)

/**
 * Loop over a block of elements of a tree, used similar to a for() command.
 * This loop should not be used if elements are removed from the tree during
 * the loop.
 *
 * @param first pointer to first element of loop
 * @param last pointer to last element of loop
 * @param element pointer to a node of the tree, this element will
 *    contain the current node of the list during the loop
 * @param node_member name of the AvlNode element inside the
 *    larger struct
 */
#define avl_for_element_range(first, last, element, node_member)    \
  for (element = (first);                                           \
       element->node_member.list.prev != &(last)->node_member.list; \
       element = avl_next_element(element, node_member))

/**
 * Loop over all elements of an AvlTree, used similar to a for() command.
 * This loop should not be used if elements are removed from the tree during
 * the loop.
 *
 * @param tree pointer to avl-tree
 * @param element pointer to a node of the tree, this element will
 *    contain the current node of the tree during the loop
 * @param node_member name of the AvlNode element inside the
 *    larger struct
 */
#define avl_for_each_element(tree, element, node_member)                       \
  avl_for_element_range(avl_first_element(tree, element, node_member),         \
                        avl_last_element(tree, element, node_member), element, \
                        node_member)

/**
 * Loop over a block of nodes of a tree, used similar to a for() command.
 * This loop can be used if the current element might be removed from
 * the tree during the loop. Other elements should not be removed during
 * the loop.
 *
 * @param first_element first element of loop
 * @param last_element last element of loop
 * @param element iterator pointer to tree element struct
 * @param node_member name of AvlNode within tree element struct
 * @param ptr pointer to tree element struct which is used to store
 *    the next node during the loop
 */
#define avl_for_element_range_safe(first_element, last_element, element,    \
                                   node_member, ptr)                        \
  for (element = (first_element),                                           \
      ptr = avl_next_element(first_element, node_member);                   \
       element->node_member.list.prev != &(last_element)->node_member.list; \
       element = ptr, ptr = avl_next_element(ptr, node_member))

/**
 * Loop over all elements of an AvlTree, used similar to a for() command.
 * This loop can be used if the current element might be removed from
 * the tree during the loop. Other elements should not be removed during
 * the loop.
 *
 * @param tree pointer to avl-tree
 * @param element pointer to a node of the tree, this element will
 *    contain the current node of the tree during the loop
 * @param node_member name of the AvlNode element inside the
 *    larger struct
 * @param ptr pointer to a tree element which is used to store
 *    the next node during the loop
 */
#define avl_for_each_element_safe(tree, element, node_member, ptr)          \
  avl_for_element_range_safe(avl_first_element(tree, element, node_member), \
                             avl_last_element(tree, element, node_member),  \
                             element, node_member, ptr)
