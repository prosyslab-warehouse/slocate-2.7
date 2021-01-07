/********************************************************************************
 *  Secure Locate                                                               *
 *  Programmed by: Kevin Lindsay                                                *
 *  Copyright (c) 1999, 2000, 2001 NetNation Communications Inc & Kevin Lindsay *
 * ******************************************************************************/ 

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>  /* for FreeBSD -matt */

#include "link.h"

/* Initialize 2D List */

dir_item *
init_2D_list()
{
   dir_item *listptr;
     
   if ((listptr = (dir_item *)malloc(sizeof(dir_item))) == NULL) {
      fprintf(stderr,"Could not allocate memory for init_2D_list!\n");
   }
   
   listptr->name = NULL;
   listptr->up = NULL;
   listptr->down = NULL;
   listptr->left = NULL;
   listptr->right = NULL;
   listptr->empty = 0;
   listptr->st_mode=0;
   listptr->st_uid=1;
   listptr->st_gid=1;
       
   return(listptr);
}

/* Initialize Dest Item List */

/* Add Right to 2D List */

dir_item *
add_right(dir_item *listptr)
{
   
   if ((listptr->right = (dir_item *)malloc(sizeof(dir_item))) == NULL) {
      fprintf(stderr,"Could not allocate memory for add_right!\n");
   }

   listptr->right->left = listptr;   
   listptr->right->up = NULL;
   listptr->right->down = NULL;
   listptr->right->right = NULL;
   listptr->right->name = NULL;
   listptr->right->name_len = 0;
   listptr->right->type = 0;
   listptr->right->empty = 0;
   listptr->right->st_mode=0;
   listptr->right->st_uid=1;
   listptr->right->st_gid=1;
   
   return(listptr);
}

/* Add Down to 2D List */

dir_item *
add_down(dir_item *listptr)
{
   if ((listptr->down = (dir_item *)malloc(sizeof(dir_item))) == NULL) {
      fprintf(stderr,"Could not allocate memory for add_down!\n");      
   }
   
   listptr->down->up = listptr;
   listptr->down->left = listptr->left;
   listptr->down->down = NULL;
   listptr->down->right = NULL;
   listptr->down->name = NULL;   
   listptr->down->name_len = 0;
   listptr->down->type = 0;
   listptr->down->empty = 0;   
   listptr->down->st_mode=0;
   listptr->down->st_uid=1;
   listptr->down->st_gid=1;
   
   return(listptr);   
}

/* Free 2D List Right */

dir_item *
free_right(dir_item *listptr)
{
   if (listptr->right != NULL) {
      listptr = listptr->right;
      
      while (listptr->down != NULL)
          listptr = listptr->down;
      
      while (listptr->up != NULL) {
         listptr = listptr->up;
         free(listptr->down->name);         
         free(listptr->down);
      }
      listptr = listptr->left;
      free(listptr->right->name);
      free(listptr->right);
      listptr->right = NULL;
   }
   return(listptr);
}

