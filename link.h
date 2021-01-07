#ifndef LINK_H
#define LINK_H 1
#include <time.h>

/* 2 Dimensional Link List */

typedef struct list
{
   char *name;   /* Name of File/Directory */
   int type;     /* Descriptor type: File = 0, Directory = 1 */
   int root;     /* Root Dir Flag: rootdir = 1; non rootdir = 0 */
   int empty;    /* If an empty dir: emtpy = 1; not empty = 1 */
   int name_len;
   unsigned short st_mode;
   uid_t st_uid;
   gid_t st_gid;
   struct list *up;
   struct list *down;
   struct list *left;
   struct list *right;
   
} dir_item;


extern dir_item *init_2D_list();
extern dir_item *add_right(dir_item *listptr);
extern dir_item *add_down(dir_item *listptr);
extern dir_item *free_right(dir_item *listptr);
extern dir_item *free_dirinfo(dir_item *listptr);

#endif /* !LINK_H */
