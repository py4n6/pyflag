/*****************************************
   This file implements a trie.

  A Trie is a special data structure with multiple elements under each
  node.
***********************************/
#ifndef __TRIE_H
#define __TRIE_H
#include "config.h"
#include <Python.h>
#include "class.h"
#include "list.h"
#include <stdint.h>

/** This is the maximum match that will be made with wildcards (must
    be less than unsigned char
*/
#define MAX_MATCH_LENGTH 100

// Each word can be defined as non-unique if its ID has bit 30
// set. This is the mask for that:
#define UNIQUE_BIT_MASK 0x40000000

// Some prototypes to shut up warnings
typedef struct trie_iter;

/** These are the possible types that words may be supplied as **/
enum word_types {
  // This is a literal
  WORD_LITERAL,

  // This is an extended format (regex like) 
  WORD_EXTENDED,

  // This is an english word (case insensitive matching)
  WORD_ENGLISH
};

/** This is an abstract class with no constructors, it must be
    extended.
*/
CLASS(TrieNode, Object)
     struct list_head peers;

     /** This is a hashtable of our children */
     TrieNode hash_table[16];

     unsigned int lower_limit;
     unsigned int upper_limit;

     /** This points to a dummy TrieNode object which serves as a
	 list_head for the peers list of all this nodes children 
     */
     TrieNode child;

     /** Checks if there is a match at the current position in buffer. 
	 May alter result with the value stored in the node.

	 start is a pointer to the start of the match (such that
	 *buffer-start = length of match).
     */
     int METHOD(TrieNode, Match, char *start, char **buffer, int *len, 
		struct trie_iter *result);

     /** This method must return True or False when comparing at
	 buffer. It must consume the number of chars that are equal
     */
     int METHOD(TrieNode, compare, char **buffer, int *len);

     /** Adds the word into the trie with the value in data */
     void METHOD(TrieNode, AddWord, char **word, int *len, long int data,
		 enum word_types type);

/** This is a simple constructor. It is mostly used for creating list
    heads for children */
     TrieNode METHOD(TrieNode, Con);
END_CLASS

CLASS(DataNode, TrieNode)
     int data;

     DataNode METHOD(DataNode, Con, int data);
END_CLASS

CLASS(LiteralNode, TrieNode)
     char value;

     LiteralNode METHOD(LiteralNode, Con, char **value, int *len);
END_CLASS

CLASS(RootNode, TrieNode)
  
     RootNode METHOD(RootNode, Con);
END_CLASS

CLASS(CharacterClassNode, TrieNode)
     char *map;
     CharacterClassNode METHOD(CharacterClassNode, Con, char **word, int *len);
     CharacterClassNode METHOD(CharacterClassNode, Con_with_map, 
			       char **word, int *len, char *map);
END_CLASS

// Some useful prototypes:
int LiteralNode_casecompare(TrieNode self, char **buffer, int *len);
int CharacterClass_wildcard_compare(TrieNode self, char **buffer, int *len);

// The python objects which control it all:
typedef struct {
  PyObject_HEAD
  RootNode root;
  // A bool to signify if we should get all matches or just the first
  // one.
  int all_matches;
  // This is the set where we maintain previous matches and skip any
  // future hits which were already found. The set may be cleared with
  // clear_set() and specific matches can be rejected with
  // reject(). This parameter is set via a keyword arg. By default we
  // return all matches (and this is NULL).
  PyObject *set;
} trie_index;

// The indexer returns an iterator of all the matches:
typedef struct {
  PyObject_HEAD
  trie_index *trie;
  PyObject *pydata;
  char *data;
  int len;
  int i;
  PyObject *match_list;
} trie_iter;


#endif
