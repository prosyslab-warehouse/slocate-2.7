/*****************************************************************************
 * Secure Locate v2.7                                                        *
 * January 24, 2003                                                          *
 * Programmed by: Kevin Lindsay                                              *
 * Copyright (c) 1999, 2000, 2001 Kevin Lindsay & Netnation Communications   *
 *                          Inc. & James A. Woods <jwoods@adobe.com>         *
 *                                                                           *
 * NetNation Communications   http://www.netnation.com/                      *
 * Secure Locate: ftp://ftp.geekreview.org/slocate/                          *
 *                ftp://ftp.mkintraweb.com/pub/linux/slocate/                *
 *                                                                           *
 *           Web: http://www.geekreview.org/slocate/                         *
 *                                                                           *
 * Patches:  Sean Mcnulty <lazy@ccf.rutgers.edu>                             *
 *                * Fixed a bug which caused the decode function to fail.    *
 *           Ulf Betlehem <flu@iki.fi>                                       *
 *                * multiple databases                                       *
 *                * LOCATE_PATH environment variable support                 *
 *                * -o, --output options                                     *
 *           Jim Dougharty  <james.dougharty@sabre.com>                      *
 *                * Recursive directory walk will not exit if a directory    *
 *                * cannot be read.  May happen on some NFS directories.     *
 *           Glen Maynard <glennm@mediaone.net>                              *
 *                * Multiple search strings are now possible                 *
 *                * Uses access() instead of opendir() to see if a directory *
 *                  is readable.                                             *
 *           R.G. Wood <rgwood@debian.org>                                   *
 *                * Made a Debian Package for Secure Locate                  *
 *           Alexander V. Lukyanov" <lav@long.yar.ru>                        *
 *                * Fixed some performance issues that I over looked.  Thanx *
 *                  To Alex, slocate -u is much faster!                      *
 *           Matt Heckaman <matt@MLINK.NET>                                  *
 *                * Created a patch to make Secure Locate work with FreeBSD. *
 *           Luca Berra <bluca@vodka.it>                                     *
 *                * Added case insensitive option and optimized code to make *
 *                  searching faster.                                        *
 *           Hans-Juergen Godau <godau@wi-inf.uni-essen.de>                  *
 *                * Fixed a segfault when searching through more than one    *
 *                  database.                                                *
 *           Francis Liu <fxl@enstor.com.au>                                 *
 *                * Solaris Patch                                            *
 *           Wanderlei Antonio Cavassin <cavassin@conectiva.com.br>          *
 *                * Fixed a segfault with invalid regex                      *
 *									     *
 *                                                                           *
 * Report any Bugs to: klindsay@mkintraweb.com                               *
 *                                                                           *
 * This product includes software developed by the University of             *
 * California, Berkeley and its contributors.                                *
 *                                                                           *
 *****************************************************************************/

/*****************************************************************************
 *                                                                            
 * Secure Locate -- search database for filenames that match patterns without 
 *                  showing files that the user using slocate does not have   
 *                  access to.                                                
 *                                                                            
 *    This program is free software; you can redistribute it and/or modify    
 *    it under the terms of the GNU General Public License as published by    
 *    the Free Software Foundation; either version 2, or (at your option)     
 *    any later version.                                                      
 *                                                                            
 *    This program is distributed in the hope that it will be useful,         
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of          
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           
 *    GNU General Public License for more details.                            
 *                                                                            
 *    You should have received a copy of the GNU General Public License       
 *    along with this program; if not, write to the Free Software             
 *    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.               
 *                                                                            
 *****************************************************************************/

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <grp.h>
#include <ctype.h>
#include <fnmatch.h>
#include <regex.h>
#include "config.h"

#ifdef HAVE_FTS_H
#include <fts.h>
#else
#include "sl_fts.h"
#endif

#include "link.h"
#include "misc.h"

#ifdef __FreeBSD__
# include <sys/param.h>
# include <sys/ucred.h>
# include <sys/mount.h>
# undef FNM_CASEFOLD
#endif


/* GLOBALS */

#define SL_RELEASE "January 24, 2003"
#define SL_VERSION "Secure Locate " VERSION " - Released " SL_RELEASE "\n"
#define GRPFILE "/etc/group"
#define SLOC_ESC -0x80
#define SLOC_GRP "slocate"
#define SLOC_UID 0
#define MIN_BLK 4096
#define MTAB_FILE "/etc/mtab"

/* Warn if a database is older than this.  8 days allows for a weekly
 *    update that takes up to a day to perform.  */
#define WARN_SECONDS (60 * 60 * 24 * 8)

/* Printable version of WARN_SECONDS.  */
#define WARN_MESSAGE "8 days"

char **SLOCATE_PATH = NULL;

/* More fitting paths for FreeBSD -matt */
#if defined(__FreeBSD__)
char *SLOCATEDB = "/var/db/slocate/slocate.db";
char *TMPSLOCATEDB = "/var/db/slocate/slocate.db.tmp";
char *SLOCATEDB_DIR = "/var/db/slocate/";
#elif defined(__SunOS__)
char *SLOCATEDB = "/var/db/slocate/slocate.db";
char *TMPSLOCATEDB = "/var/db/slocate/slocate.db.tmp";
char *SLOCATEDB_DIR = "/var/db/slocate/";
#undef MTAB_FILE
#define MTAB_FILE "/etc/mnttab"
#else
char *SLOCATEDB = "/var/lib/slocate/slocate.db";
char *TMPSLOCATEDB = "/var/lib/slocate/slocate.db.tmp";
char *SLOCATEDB_DIR = "/var/lib/slocate/";
#endif

# define UPDATEDB_CONF "/etc/updatedb.conf"
char *EXCLUDE_DIR=NULL;
int EXCLUDE=0;
int VERBOSE=0;
int QUIET=0;
int NOCASE=0;
int REGEXP=0;
int NEWOUTPUT=0;
char *regexp;
char *progname;
char *tmp_path=NULL;
char *cur_dir=NULL;
char prog_CWD[4096];
short fr_num=0;
int t_num=0;
uid_t UID;
gid_t GID;
int first=1;
char slevel='1';
#ifdef __SunOS__
unsigned short SLOC_GID=60001; /* Seems to be the default nobody gid */
#else
unsigned short SLOC_GID=65534; /* Seems to be the default nobody gid */
#endif
int max_queries=0;
int ADD_SLOCATEDB = 1;

#define WARNING 0
#define FATAL 1

int decode_db(char *database, char *str);

/* Usage */

void
    usage() 
{
	int i;
	printf("%s\n"
	       "Copyright (c) 1999, 2000, 2001 Kevin Lindsay & Netnation Communications Inc. &\n"
	       "James A. Woods <jwoods@adobe.com>\n\n"
	       "search usage:   %s [-qi] [-d <path>] [--database=<path>] <search string>...\n"
	       "                %s [-r <regexp>] [--regexp=<regexp>]\n"
	       "database usage: %s [-qv] [-o <file>] [--output=<file>]\n"
	       "                %s [-e <dir1,dir2,...>] [-f <fs_type1,...> ] [-l <level>]\n"
	       ,SL_VERSION,progname,progname,progname,progname);

	for (i = 0; i < strlen(progname)-1; i+=1)
	    printf(" ");
	
	fprintf(stdout,
#ifndef __FreeBSD__
	       "                  [-c] <[-U <path>] [-u]>\n"
#else
	       "                  <[-U <path>] [-u]>\n"
#endif
	       "general usage:  %s [-Vh] [--version] [--help]\n\n"
	       "   Options:\n"
	       "   -u                 - Create slocate database starting at path /.\n"
	       "   -U <dir>           - Create slocate database starting at path <dir>.\n",progname);
#ifndef __FreeBSD__
	printf("   -c                 - Parse original GNU Locate's '/etc/updatedb.conf'\n"
	       "                        when using the -u or -U options.  If 'updatedb' is\n"
	       "                        symbolically linked to the '%s' binary, the\n"
	       "                        original configuration file will automatically be\n"
	       "                        used.\n",progname);
#endif
	printf("   -e <dir1,dir2,...> - Exclude directories from the slocate database when\n"
	       "                        using the -u or -U options.\n"
	       "   -f <fs_type1,...>  - Exclude file system types from the slocate database\n"
	       "                        when using the -u or -U options. (ie. NFS, etc).\n"                                  
	       "   -l <level>         - Security level. \n"
	       "                           0 turns security checks off. This will make\n"
	       "                             searchs faster.\n"
	       "                           1 turns security checks on. This is the default.\n"
	       "   -q                 - Quiet mode.  Error messages are suppressed.\n"
	       "   -n <num>           - Limit the amount of results shown to <num>.\n"
	       "   -i                 - Does a case insensitive search.\n"
	       "   -r <regexp>\n"
	       "   --regexp=<regexp>  - Search the database using a basic POSIX regular\n"
	       "                        expression.\n"
	       "   -o <file>\n"
	       "   --output=<file>    - Specifies the database to create.\n"
	       "   -d <path>\n"
	       "   --database=<path>  - Specfies the path of databases to search in.\n"
	       "   -h\n"
	       "   --help             - Display this help.\n"
	       "   -v\n"
	       "   --verbose          - Verbose mode. Display files when creating database.\n"
	       "   -V\n"
	       "   --version          - Display version.\n"
	       "\n"
	       "Author: Kevin Lindsay\n"
	       "Bugs:   klindsay@mkintraweb.com\n"	       
	       "FTP:    ftp://ftp.geekreview.org/slocate/\n"
	       "        ftp://ftp.mkintraweb.com/pub/linux/slocate/\n"
	       "HTTP:   http://www.geekreview.org/slocate/\n"
	       "\n");

	exit(0);
}

static void
    put_short (int c, FILE *fp)
{
	putc (c >> 8, fp);
	putc (c, fp);
}

/*static int
    get_short (FILE *fp)
{
	register short x;
	
	x = fgetc (fp);
	return (x << 8) | (fgetc (fp) & 0xff);
} */

static int
    get_short (char **fp)
{
	register short x;

	x = **fp;
	
	/* move pointer one byte ahead */
	(*fp)++;
	
	return (x << 8) | (*((*fp)++) & 0xff);
}

/* Validate database file */
int
    validate_db(char *database)
{
	int fd;
	int myerrno;
	char buf[2];
	
	fd = open(database,O_RDONLY);

	if (fd == -1)
	    return errno;
	
	if (read(fd,buf,2) < 2) {
		myerrno = errno;
		close(fd);
		return myerrno;
	}
	
	if ((buf[0] != '1' && buf[0] != '0') ||
	    buf[1] != 0) {
		close(fd);
		return -1;
	}
	
	close(fd);

	return 0;
}

/* Parse Output Path */

void
    parse_create_path(char *path)
{
	int ret_val;
	
	if (!path || strlen(path) == 0) return;
	
	ret_val = creat(path, S_IRWXU|S_IRGRP);
	if(ret_val==-1)	
	    report_error(FATAL,QUIET,"%s: parse_create_path: could not create database: %s: %s\n", progname,path,strerror(errno));
	
	SLOCATEDB = malloc(strlen(path)+1);
	if (!SLOCATEDB)
	    report_error(FATAL,QUIET,"%s: parse_create_path: 'SLOCATEDB': malloc: %s\n",progname,strerror(errno));
	SLOCATEDB[0] = '\0';
	strcat(SLOCATEDB, path);
	
	TMPSLOCATEDB = malloc(strlen(path)+5);
	if (!TMPSLOCATEDB)
	    report_error(FATAL,QUIET,"%s: parse_create_path: 'TMPSLOCATEDB': malloc: %s\n",progname,strerror(errno));
	
	TMPSLOCATEDB[0] = '\0';
	strcat(TMPSLOCATEDB, path);
	strcat(TMPSLOCATEDB, ".tmp");
}

/* Parse Database Paths.
 * 
 * Concatenate all database paths into one string and validate each database.
 */

void
    parse_decode_path(char *path)
{
	char *pathcopy;
	char *part;
	int i;
	int res_errno;

	/* Make sure path is not empty */
	if (!path || strlen(path) == 0) return;
	
	/* Check how many paths are currently in the string. */
	i = 1;
	part = path;
	while ((part = strchr(part+1, ':'))) i++;
	
	/* Allocate enough space to fit existing paths plus new one */
	SLOCATE_PATH = malloc(i * sizeof(char *));
	if (!SLOCATE_PATH)
	    report_error(FATAL,QUIET,"%s: parse_decode_path: 'SLOCATE_PATH': malloc: %s\n",progname,strerror(errno));
	
	pathcopy = malloc(strlen(path)+1);
	if (!pathcopy)
	    report_error(FATAL,QUIET,"%s: parse_decode_path: 'pathcopy': malloc: %s\n",progname,strerror(errno));

	strcpy(pathcopy,path);
	
	/* Get first path just incase a path with ':'s were specified*/
	part = strtok(pathcopy, ":");

	i = 0;
	/* Loop through all paths and validate them.
	 * use SLOCATE_PATH as an array of pointers to each
	 * path */
	while (part) {
		/* Make sure the path is valid */
		if (!(res_errno = validate_db(part)))
		  SLOCATE_PATH[i++] = part;
		else {
			if (res_errno == -1)
			    report_error(WARNING,QUIET,"%s: this is not a valid slocate database: %s\n",progname,part);
			else
			    report_error(WARNING,QUIET,"%s: could not open database: %s: %s\n",progname,part,strerror(res_errno));
		}
		/* Get next path */
		part = strtok(NULL, ":");
	}

	/* Null terminate array */
	SLOCATE_PATH[i] = NULL;
}

/* Parse Dash */

char *
    parse_dash(char *option)
{
	char *ptr;
	char *regexp_opt;
	
	for (ptr = option;*ptr != 0 && *ptr != '=' ; ptr++)
	    *ptr = toupper(*ptr);
	
	if (!strcmp(option,"HELP"))
	    usage();
	
	if (!strcmp(option,"VERSION")) {
		printf("%s",SL_VERSION);
		exit(0);
	}
	
	if (!strcmp(option,"VERBOSE"))
	    VERBOSE=1;
	
	*ptr = '\0';
	ptr++;
	
	if (!strcmp(option,"OUTPUT")) {
		parse_create_path(ptr);
		NEWOUTPUT=1;
	}
	
	if (!strcmp(option,"DATABASE")) {
		parse_decode_path(ptr);
		ADD_SLOCATEDB = 0;
	}
	
	if (!strcmp(option,"REGEXP")) {
		REGEXP = 1;
		regexp_opt = malloc(strlen(ptr)+1);
		if (!regexp_opt)
		    report_error(FATAL,QUIET,"%s: parse_dash: 'regexp_opt': malloc: %s\n",progname,strerror(errno));
		*regexp_opt = 0;
		strcat(regexp_opt,ptr);
		regexp = strdup(regexp_opt);
		// Return regular expression argument here so that the main function can parse
		// run decode_db properly.
		return regexp_opt;
	}
	
	return NULL;
}


/* Make sure that the DB Directory exists */

void
    check_dir(char *dir_str)
{
	struct stat tmpstat;
		
	if (!dir_str || lstat(dir_str,&tmpstat) == -1)
	    report_error(FATAL,QUIET,"%s: error accessing DB Directory: %s : %s\n",progname,SLOCATEDB_DIR,strerror(errno));
}

/* Get the GID for group slocate */

unsigned short
    get_gid()
{
	unsigned short GGID=SLOC_GID;
	struct group *grpres;
	
	if ((grpres = getgrnam(SLOC_GRP)) == NULL) {
		report_error(WARNING,QUIET,"%s: Could not find the group: %s in the /etc/group file.\n",progname,SLOC_GRP);
		report_error(FATAL,QUIET,"This is a result of the group missing or a corrupted group file.\n");
	}
	
	GGID = grpres->gr_gid;
	
	return GGID;
}

/* Parse Exclude Command */

int
    parse_exclude(char *estr)
{
	char *excludestr=NULL;
	char *ptr1;
	char *ptr2=NULL;
	int grow=1;
	int elen;   
	
	EXCLUDE=1;   
	
	excludestr = (char *)malloc(1);
	if (!excludestr)
	    report_error(FATAL,QUIET,"%s: parse_exclude: 'excludestr': malloc: %s\n",progname,strerror(errno));
	
	excludestr[0] = '\0';
	
	elen = strlen(estr);
	
	ptr1 = estr;
	ptr2 = ptr1;
	
	while (ptr2[0] != '\0')  {
		
		if ((ptr2 = strchr(ptr1,',')) == NULL) {
			ptr2 = strchr(ptr1,'\0');
		}
		
		grow += (ptr2-ptr1)+2;
		if (*(ptr2-1) == '/' && (ptr2-1) != estr && *(ptr2-2) != ',' ) {
			grow--;
			ptr2--;
		}
		
		excludestr = realloc(excludestr,grow);
		if (!excludestr)
		    report_error(FATAL,QUIET,"%s: parse_exclude: 'excludestr': realloc: %s\n",progname,strerror(errno));
		strcat(excludestr,"*");
		strncat(excludestr,ptr1,ptr2-ptr1);
		strcat(excludestr,"*");
		
		if (*ptr2 == '/')
		    ptr2++;
		
		if (ptr2[0] == ',')
		    ptr1 = ptr2+1;
	}
	
	if (!EXCLUDE_DIR) {
		EXCLUDE_DIR = malloc(strlen(excludestr)+1);
		if (!EXCLUDE_DIR)
		    report_error(FATAL,QUIET,"%s: parse_exclude: 'EXCLUDE_DIR': malloc: %s\n",progname,strerror(errno));
		*EXCLUDE_DIR = 0;      
	} else {
		EXCLUDE_DIR = realloc(EXCLUDE_DIR,strlen(EXCLUDE_DIR)+strlen(excludestr)+1);
		if (!EXCLUDE_DIR)
		    report_error(FATAL,QUIET,"%s: parse_exclude: 'EXCLUDE_DIR': realloc: %s\n",progname,strerror(errno));
	}
	
	strcat(EXCLUDE_DIR,excludestr);
	free(excludestr);
	
#ifdef DEBUG
	printf("E: %s\n",EXCLUDE_DIR);
#endif
	
	return 1;
}


#ifdef __FreeBSD__
/* Get File System type in the form of a string. "*fstype*" */

char *
    get_fs_type(int fs_type)
{
	if (fs_type == MOUNT_UFS)
	    return("*UFS*");
	else if (fs_type == MOUNT_NFS)
	    return("*NFS*");
	else if (fs_type == MOUNT_MFS)
	    return("*MFS*");
	else if (fs_type == MOUNT_MSDOS)
	    return("*MSDOS*");
	else if (fs_type == MOUNT_LFS)
	    return("*LFS*");
	else if (fs_type == MOUNT_LOFS)
	    return("*LOFS*");   
	else if (fs_type == MOUNT_FDESC)
	    return("*FDESC*");
	else if (fs_type == MOUNT_PORTAL)
	    return("*PORTAL*");
	else if (fs_type == MOUNT_NULL)
	    return("*NULL*");
	else if (fs_type == MOUNT_UMAP)
	    return("*UMAP*");
	else if (fs_type == MOUNT_KERNFS)
	    return("*KERNFS*");
	else if (fs_type == MOUNT_PROCFS)
	    return("*PROCFS*");
	else if (fs_type == MOUNT_AFS)
	    return("*AFS*");
	else if (fs_type == MOUNT_CD9660)
	    return("*CD9660*");
	else if (fs_type == MOUNT_UNION)
	    return("*UNION*");
	else if (fs_type == MOUNT_DEVFS)
	    return("*DEVFS*");
	else if (fs_type == MOUNT_EXT2FS)
	    return("*EXT2FS*");
	else if (fs_type == MOUNT_TFS)
	    return("*TFS*");
	else
	    return("*NONE*");
}
#endif

/* Parse File System Type Exclusion */
int
    parse_fs_exclude(char *estr)
{
	char *ptr;
	char *newestr=NULL;
	int estr_size=0;
	
	/* Uppercase all characters in estr to make parsing easier.
	 * Also add '*'s around each fs type */
	if (estr) {
		estr_size = strlen(estr)+2;
		newestr = malloc(estr_size+1);
		if (!newestr)
		    report_error(FATAL,QUIET,"%s: parse_fs_exclude: 'newestr': malloc: %s\n",progname,strerror(errno));
		*newestr = 0;
		strcat(newestr,"*");
		for (ptr = estr; *ptr != 0; ptr += 1) {
			*ptr = toupper(*ptr);
			if (*ptr == ',') {
				estr_size += 1;
				newestr = realloc(newestr,estr_size+1);
				if (!newestr)
				    report_error(FATAL,QUIET,"%s: parse_fs_exclude: 'newestr': realloc: %s\n",progname,strerror(errno));				
				strcat(newestr,"*");
			} else {
				strncat(newestr,ptr,1);
			}
		}
		strcat(newestr,"*");
		estr = newestr;
	}
	
	/* FreeBSD File System Status */
	
#ifdef __FreeBSD__
	{
		struct statfs *fs_stat;
		long bufsize=4096;
		int num_mounts=0;
		int i;
		char *exclude_str=NULL;

		fs_stat = malloc(sizeof(struct statfs));
		if (!fs_stat)
		    report_error(FATAL,QUIET,"%s: parse_fs_exclude: 'fs_stat': malloc: %s\n",progname,strerror(errno));

		num_mounts = getfsstat(fs_stat,bufsize,MNT_WAIT);
		
		for (i = 0; i < num_mounts; i+=1) {
			if (strstr(estr,get_fs_type(fs_stat[i].f_type))) {
				if (!exclude_str) {
					exclude_str = malloc(strlen(fs_stat[i].f_mntonname)+1);
					if (!exclude_str)
					    report_error(FATAL,QUIET,"%s: parse_fs_exclude: 'exclude_str': malloc: %s\n",progname,strerror(errno));
					*exclude_str = 0;
				} else {
					exclude_str = realloc(exclude_str,strlen(exclude_str)+strlen(fs_stat[i].f_mntonname)+2);
					if (!exclude_str)
					    report_error(FATAL,QUIET,"%s: parse_fs_exclude: 'exclude_str': realloc: %s\n",progname,strerror(errno));
					strcat(exclude_str,",");
				}
				
				strcat(exclude_str,fs_stat[i].f_mntonname);
				
			}
		}
		
		if (exclude_str)
		    parse_exclude(exclude_str);
	}
#else
	/* Linux File System Status */
	{
		char *fbuf=NULL;
		char *head_ptr;
		char *tail_ptr;
		char *exclude_str=NULL;
		char *match_str=NULL;
		
		fbuf = load_file(MTAB_FILE);
		
		if (*fbuf == 0) {
			fbuf += 1;
			report_error(FATAL,QUIET,"%s: File System Exclude: Could not open file %s: %s\n",progname,MTAB_FILE,fbuf);
		}
		
		head_ptr = fbuf;
		
		while (head_ptr) {
			/* find filesystem type */
			if ((head_ptr = strchr(head_ptr,' '))) {
				head_ptr += 1;
				head_ptr = strchr(head_ptr,' ');
			}
			
			if (!head_ptr)
			    continue;
			
			head_ptr += 1;
			
			tail_ptr = strchr(head_ptr,' ');
			if (!tail_ptr) {
				head_ptr = NULL;
				continue;
			}
			
			*tail_ptr = 0;
			
			/* Check if file sytem type exists in exclude string */
			
			match_str = realloc(match_str,strlen(head_ptr)+3);
			if (!match_str)
			    report_error(FATAL,QUIET,"%s: parse_fs_exclude: 'match_str': realloc: %s\n",progname,strerror(errno));			
			match_str[0] = '*';
			match_str[1] = 0;
			strcat(match_str,head_ptr);
			strcat(match_str,"*");
			
			for (ptr = match_str; *ptr != 0; ptr += 1)
			    *ptr = toupper(*ptr);
			*tail_ptr = ' ';
			
			/* If a match is found, move back a few bytes to locate the path */
			if (strstr(estr,match_str)) {
				
				head_ptr -= 2;
				
				while (*head_ptr != ' ' && head_ptr != fbuf)
				    head_ptr -= 1;
				
				if (head_ptr == fbuf)
				    report_error(FATAL,QUIET,"%s: File System Exclude: (1) corrupt mtab file: %s\n",progname,MTAB_FILE);

				head_ptr += 1;
				
				if (!(tail_ptr = strchr(head_ptr,' ')))
				    report_error(FATAL,QUIET,"%s: File System Exclude: (2) corrupt mtab file: %s\n",progname,MTAB_FILE);
				
				*tail_ptr = 0;
				
				/* Add the path to the exclude string */
				if (!exclude_str) {
					exclude_str = malloc(strlen(head_ptr)+1);
					if (!exclude_str)
					    report_error(FATAL,QUIET,"%s: parse_fs_exclude: 'exclude_str': malloc: %s\n",progname,strerror(errno));
					*exclude_str = 0;
					strcat(exclude_str,head_ptr);
				} else {
					exclude_str = realloc(exclude_str,strlen(exclude_str)+strlen(head_ptr)+2);
					if (!exclude_str)
					    report_error(FATAL,QUIET,"%s: parse_fs_exclude: 'exclude_str': realloc: %s\n",progname,strerror(errno));
					strcat(exclude_str,",");
					strcat(exclude_str,head_ptr);
				}
				
				*tail_ptr = ' ';
			}
			
			head_ptr = strchr(head_ptr,'\n');
			
		}
		
# ifdef DEBUG
		printf("=-%s-=\n",exclude_str);
# endif
		
		if (exclude_str)
		    parse_exclude(exclude_str);
		
	}
#endif   
	
	return 1;
}

#ifndef __FreeBSD__

/* Parse updatedb.conf file */

void
    parse_updatedb_conf()
{
	char *fbuf;
	char *head_ptr;
	char *tail_ptr;
	char *ptr;
	char tmp_ch;
	char *parse_str=NULL;
	int times=0;
	char var_type[11];
	
	fbuf = load_file(UPDATEDB_CONF);
	
	if (*fbuf == 0) {
		report_error(WARNING,QUIET,"%s: could not access %s: %s\n",progname,UPDATEDB_CONF,fbuf+1);
		free(fbuf);
		return;
	}

	for (times = 0; times < 2; times += 1) {
		
		head_ptr = fbuf;
		
		var_type[0] = 0;
		
		if (times == 0)
		    strcat(var_type,"PRUNEFS");
		else
		    strcat(var_type,"PRUNEPATHS");        
		
		if ((head_ptr = strstr(fbuf,var_type))) {
			ptr = head_ptr;
			while (ptr != fbuf && *ptr != '\n' && *ptr != '#')
			    ptr -= 1;
			
			if (*ptr != '#') {
				while (*head_ptr != '"' && *head_ptr != '\n' && *head_ptr != '\0')
				    head_ptr += 1;
				
				if (*head_ptr == '"') {
					head_ptr += 1;
					
					/* Get each file system from PRUNEFS variable */
					
					while (*head_ptr != '"' && *head_ptr != 0) {
						
						while (*head_ptr != 0 && isspace(*head_ptr))
						    head_ptr += 1;            
						
						if (*head_ptr == 0 || *head_ptr == '"')
						    break;
						
						tail_ptr = head_ptr;
						while (*tail_ptr != 0 && !isspace(*tail_ptr) && *tail_ptr != '"')
						    tail_ptr += 1;
						
						if (*tail_ptr == 0)
						    break;
						
						tmp_ch = *tail_ptr;
						
						*tail_ptr = 0;
						
						if (!parse_str) {
							parse_str = malloc(strlen(head_ptr)+1);
							if (!parse_str)
							    report_error(FATAL,QUIET,"%s: parse_updatedb_conf: 'parse_str': malloc: %s\n",progname,strerror(errno));
							*parse_str = 0;
						} else {
							parse_str = realloc(parse_str,strlen(parse_str)+strlen(head_ptr)+2);
							if (!parse_str)
							    report_error(FATAL,QUIET,"%s: parse_updatedb_conf: 'parse_str': realloc: %s\n",progname,strerror(errno));							
							strcat(parse_str,",");
						}
						
						strcat(parse_str,head_ptr);
						
						*tail_ptr = tmp_ch;
						head_ptr = tail_ptr;
						
					}
					
				}
			}
		}
		
		if (parse_str) {
			if (times == 0)     
			    parse_fs_exclude(parse_str);
			else
			    parse_exclude(parse_str);
		}      
		
		if (parse_str)
		    free(parse_str);
		
		parse_str = NULL;
	}
	
# ifdef DEBUG
	printf("Final Exclude: %s\n",EXCLUDE_DIR);
	exit(0);   
# endif
}

#endif


/* Check to see if a path matches an excluded one. */

int
    match_exclude(char *path,char *filedir) {
	    int res=0;
	    char *newstr;
	    
	    newstr = malloc(strlen(path)+strlen(filedir)+3);
	    if (!newstr)
		report_error(FATAL,QUIET,"%s: match_exclude: 'newstr': malloc: %s\n",progname,strerror(errno));
	    newstr[0] = '\0';
	    strcat(newstr,"*");
	    strcat(newstr,path);
	    strcat(newstr,filedir);   
	    strcat(newstr,"*");
	    
	    if (strstr(EXCLUDE_DIR,newstr) != NULL)       
		res=1;
	    
	    free(newstr);
	    
	    return res;
    }

/* FRCODE - Incremental Encoding algorithm */

int
    frcode(FILE *fd, char *dir_path, char *filename)
{
	int res=0;
	char *cur_path;
	char *new_path;
	char *ptr1;
	char *ptr2;
	
	int i;

	cur_path = malloc(strlen(dir_path)+strlen(filename)+1);
	if (!cur_path)
		report_error(FATAL,QUIET,"%s: frcode: 'cur_path': malloc: %s\n",progname,strerror(errno));
	strcpy(cur_path,dir_path);
	strcat(cur_path,filename);
	
	if (VERBOSE)
	    fprintf(stdout,"%s\n",cur_path);
	
	if (tmp_path != NULL) {
		ptr1=cur_path;
		ptr2=tmp_path;
		
		for (i=0; ptr1[0] == ptr2[0] && (ptr1[0] != '\0' && ptr2[0] != '\0') ; i++) {
			ptr1++;
			ptr2++;
		}
		
		fr_num = i - t_num;
		
		t_num = t_num + fr_num;            
		
		ptr2 = strchr(ptr1,'\0');
		new_path=malloc((ptr2-ptr1)+1);
		if (!new_path)
		    report_error(FATAL,QUIET,"%s: frcode: 'new_path': malloc: %s\n",progname,strerror(errno));
		new_path[0] = '\0';
		strncat(new_path,ptr1,ptr2-ptr1);         
		
	} else {
		new_path = malloc(strlen(cur_path)+1);
		if (!new_path)
		    report_error(FATAL,QUIET,"%s: frcode: 'new_path': malloc: %s\n",progname,strerror(errno));
		strcpy(new_path,cur_path);
		t_num = strlen(new_path);
	}
	
	if (tmp_path)
	    free(tmp_path);
	
	tmp_path = malloc(strlen(cur_path)+1);
	if (!tmp_path)
	    report_error(FATAL,QUIET,"%s: frcode: 'tmp_path': malloc: %s\n",progname,strerror(errno));	
	strcpy(tmp_path,cur_path);
	
	if (fr_num > 127 || fr_num < -127) {
		putc (SLOC_ESC, fd);
		put_short (fr_num, fd);
	} else
	    putc(fr_num,fd);
	
	fputs(new_path,fd);
	putc('\0',fd);
	
	if (first) {
		chmod(TMPSLOCATEDB,00640);
		if (UID == 0)
		    chown(TMPSLOCATEDB,UID,SLOC_GID);
		first=0;
	}
	
	free(new_path);
	free(cur_path);
	
	return res;
}

/* Create Database */

int
    create_db(char *dirstr)
{
	int res=0;
	struct stat statres;
	FILE *fd;
	FTS *dir;
	FTSENT *file;
	int i;
	char **dirchk;

	if (!NEWOUTPUT && UID != SLOC_UID) {
		report_error(FATAL,QUIET,"%s: You are not authorized to create a default slocate database!\n",progname);
	}

	fd = fopen(TMPSLOCATEDB,"w");

	if (!fd)
	    report_error(FATAL,QUIET,"%s: create_db: fopen: '%s': %s\n",progname,TMPSLOCATEDB,strerror(errno));

	putc(slevel,fd);
	
	if (dirstr) {
		/* Make sure there are no problems accessing the source directory */
		if (lstat(dirstr,&statres) == -1) {			
			report_error(FATAL,QUIET,"%s: lstat: d%s/: %s\n",progname,dirstr,strerror(errno));
//			fclose(fd);
//			return(1);
		}
		
		if (strlen(dirstr) > 1) {
			if (dirstr[strlen(dirstr)-1] == '/')
			    dirstr[strlen(dirstr)-1] = 0;        
		}
	}
	else {
		dirstr = malloc(2);
		if (!dirstr)
		    report_error(FATAL,QUIET,"%s: create_db: 'dirstr': malloc: %s\n",progname,strerror(errno));
		*dirstr = 0;
		strcat(dirstr,"/");
	}
	
	dirchk = malloc(sizeof(char **)*2);
	if (!dirchk)
	    report_error(FATAL,QUIET,"%s: create_db: 'dirchk': malloc: %s\n",progname,strerror(errno));	
	*dirchk = dirstr;
	dirchk[1] = NULL;
	
	dir = fts_open(dirchk,FTS_PHYSICAL,NULL);
	
	/* If fts_open failes, report and exit */
	if (!dir)
	    report_error(FATAL,QUIET,"%s: fts_open: %s\n",progname,strerror(errno));

	/* The new FTS() funtionality */
	
	for (i = 0; i > -1; i+=1) {
		file = fts_read(dir);
		
		if (!file)
		    break;
		
		if (file->fts_info != FTS_DP && file->fts_info != FTS_NS) {
			
			if ((EXCLUDE && !match_exclude(file->fts_path,"")) || !EXCLUDE)
			    frcode(fd,file->fts_path,"");
			else {
				fts_set(dir,file,FTS_SKIP);
			}
		}
		
	}
	
	fts_close(dir);
	
	fclose(fd);
	if (chdir(prog_CWD) == -1)
	    report_error(FATAL,QUIET,"%s: create_db(): chdir: %s\n",progname,strerror(errno));
	
	if (rename(TMPSLOCATEDB,SLOCATEDB) == -1)
	    report_error(FATAL,QUIET,"%s: create_db(): rename: %s\n",progname,strerror(errno));
	if (chmod(SLOCATEDB,00640) == -1)
	    report_error(FATAL,QUIET,"%s: create_db(): chmod: %s\n",progname,strerror(errno));
	/* Only change group to SLOC_GID if UID == 0 so that regular users can make their
	   own databases */
	if (UID == 0 && chown(SLOCATEDB,UID,SLOC_GID) == -1)
	    report_error(FATAL,QUIET,"%s: create_db(): chown: %s\n",progname,strerror(errno));
	
	return res;
}

/* Check to make sure the entire path is readable */
int
    check_path_access(char *codedpath)
{
	char *dir = NULL;
	char *path = NULL;
	int res;
	char *str_ptr;

	if (access(codedpath, R_OK) != 0) {
		free(codedpath);
		return 0;
	}
	
	path = malloc(strlen(codedpath)+1);
	*path = 0;
	
	res = 1;
	str_ptr = codedpath;
	
	while ((dir = strtok(str_ptr, "/"))) {
		strcat(path,"/");
		strcat(path,dir);
		if (access(path, R_OK) != 0) {
			res = 0;
			break;
		}
		str_ptr = NULL;
	}

	free(codedpath);

        free(path);
	
        return res;
}

/* Decode Database */

int
    decode_db(char *database, char *str)
{
	int res = 1;
	int fd;
	short code_num;
	int pathlen=0;
	register char ch;
	int jump=0;
	int first=1;
	char *codedpath=NULL;
//	char *tmpcodedpath; 
	char *code_ptr;
	int printit=0;
	int globflag=0;
	char *globptr1;
	struct stat statres;
	time_t now;
//	char *chk1;
//	char tmpch;
	regex_t *preg=NULL;
	char errbuf[1024];
	int nmatch=32;
	regmatch_t pmatch[32];
	int cur_queries = 0;
	int reg_res;
	int foundit = 0;
	int bytes = -1;
	int ptr_offset;
	char one_char[1];
	char *begin_ptr;
        int begin_offset=0;
	int tot_size = MIN_BLK;
	int cur_size;
	int code_tot_size = MIN_BLK;
#ifndef FNM_CASEFOLD
	char *casestr=NULL;
	char *casecodedpath=NULL;
	char *cp=NULL;
#endif
	char *bucket_of_holding=NULL;

	if ((fd = open(database,O_RDONLY)) == -1) {
		report_error(WARNING,QUIET,"%s: decode_db(): %s: %s\n",progname,database,strerror(errno));
		return(0);
	}
	
	lstat(database,&statres);
	
	if (S_ISDIR(statres.st_mode)) {
		report_error(WARNING,QUIET,"%s: decode_db(): %s is a directory\n",progname,database);
		return(0);
	}
	
	time(&now);
	if (now - statres.st_mtime > WARN_SECONDS)
	    report_error(WARNING,QUIET,"%s: warning: database %s' is more than %s old\n",progname,database,WARN_MESSAGE);

//	slevel = getc(fd);
	read(fd,one_char,1);
	slevel = *one_char;

	codedpath = malloc(MIN_BLK);
	if (!codedpath)
	    report_error(FATAL,QUIET,"%s: decode_db: 'codedpath': malloc: %s\n",progname,strerror(errno));
	*codedpath = 0;
	code_ptr = codedpath;

	
	if ((globptr1 = strchr(str,'*')) != NULL ||
	    (globptr1 = strchr(str,'?')) != NULL ||
	    ((globptr1 = strchr(str,'[')) != NULL && strchr(str,']') != NULL))
	    globflag = 1;
	
	if (REGEXP) {

		preg = malloc(sizeof(regex_t));
		if (!preg)
		    report_error(FATAL,QUIET,"%s: decode_db: 'preg': malloc: %s\n",progname,strerror(errno));
		if ((reg_res = regcomp(preg,regexp,NOCASE?REG_ICASE:0)) != 0) {
			regerror(reg_res, preg, errbuf,1024);
			report_error(FATAL,QUIET,"error: %s: regular expression: %s\n",progname,errbuf);
		}
#ifndef FNM_CASEFOLD
		
	} else if (NOCASE) {
		casestr=strdup(str);
		for (cp = casestr; *cp; cp++)
		    *cp = tolower(*cp);
#endif /* FNM_CASEFOLD */
		
	}
	
	bucket_of_holding = malloc(MIN_BLK);
	if (!bucket_of_holding)
	    report_error(FATAL,QUIET,"%s: decode_db: 'bucket_of_holding': malloc: %s\n",progname,strerror(errno));	
	*bucket_of_holding = 0;
	begin_ptr = bucket_of_holding;
	tot_size = MIN_BLK;
	cur_size = 0;
	while (first || begin_ptr < bucket_of_holding+cur_size) {

		/* No 1 byte reads! */

		if (cur_size + MIN_BLK > tot_size) {
			while (cur_size + MIN_BLK > tot_size)
			    tot_size <<= 1;
			begin_offset = begin_ptr - bucket_of_holding;
			bucket_of_holding = realloc(bucket_of_holding,tot_size);
			if (!bucket_of_holding)
			    report_error(FATAL,QUIET,"%s: decode_db: 'bucket_of_holding': realloc: %s\n",progname,strerror(errno));
			begin_ptr = bucket_of_holding + begin_offset;
		}
		
		
		if (bytes != 0)
		    bytes = read(fd,bucket_of_holding+cur_size,MIN_BLK-1);
		
		if (bytes == -1) {
			fprintf(stderr,"%s: decode_db(): read: %s\n",progname,strerror(errno));
			exit(1);
		}

		cur_size += bytes;

		code_num = (short)*begin_ptr;
		begin_ptr += 1;

		if (code_num == SLOC_ESC) {
			code_num = get_short(&begin_ptr);
		} else if (code_num > 127)
		    code_num = code_num - 256;

		/* FIXME sometimes pathlen is < 0 but it shouldn't be.
		 * corrupt database file? 
		 * This could be from a bug in frcode() or decode_db(). I
		 * am leaning toward frcode() at the moment */

		code_ptr += code_num;
		pathlen = code_ptr - codedpath;
		
		if (pathlen < 0) {
			fprintf(stderr,"%s: decode_db() aborted. Corrupt database?\n",progname);
			exit(1);
		}
		
		jump = 0;
		while (!jump) {
			ch = *begin_ptr;
			begin_ptr++;
			pathlen++;
		
			if (pathlen < 0)
				report_error(FATAL,QUIET,"%s: decode_db: 'pathlen == %d'! Corrupt Database!\n",progname,pathlen);

			if (pathlen > code_tot_size) {
				code_tot_size = pathlen * 2;
				ptr_offset = code_ptr - codedpath;
				codedpath = realloc(codedpath,code_tot_size);
				if (!codedpath)
				    report_error(FATAL,QUIET,"%s: decode_db: 'codedpath': realloc: %s\n",progname,strerror(errno));					
				code_ptr = codedpath+ptr_offset;
			}

			*(codedpath+(pathlen-1)) = ch;
			
			if (!ch)
			    jump = 1;
			/* FIXME: Handle if begin_ptr runs past buffer */
			
			if (begin_ptr > bucket_of_holding+cur_size-1 && bytes) {
				fprintf(stderr,"slocate fluky bug found.\n");
				fprintf(stderr,"Ack! This shouldn't happen unless you have a path over 4096.\n");
				fprintf(stderr,"This could also be a bogus or corrupt database.\n");
				fprintf(stderr,"Report this as a bug to klindsay@mkintraweb.com\n");
				exit(1);
			}
			
		}

//		printf("%s\n",codedpath);

		if (first) {
			code_ptr = code_ptr+strlen(codedpath);
			first=0;
		}

		pathlen--;

		printit=0;

		if (REGEXP) {
		    foundit = !regexec(preg,codedpath,nmatch,pmatch,0);
		} else if (NOCASE) {
#ifdef FNM_CASEFOLD /* i suppose i also have strcasestr */
			if (globflag)
			    foundit =! fnmatch(str,codedpath,FNM_CASEFOLD);
			else
			    foundit = (strcasestr(codedpath,str) != NULL);			
#else /* FNM_CASEFOLD */
			casecodedpath=strdup(codedpath);
			
			for (cp = casecodedpath; *cp; cp++)
			    *cp = tolower(*cp);
			
			if (globflag)
			    foundit =! fnmatch(casestr,casecodedpath,0);
			else
			    foundit = (strstr(casecodedpath,casestr) != NULL);

			free(casecodedpath);
#endif /* FNM_CASEFOLD */
			
		} else {
			if (globflag)
			    foundit =! fnmatch(str,codedpath,0);
			else
			    foundit=(strstr(codedpath,str) != NULL);			
		}
		
		if (foundit) {
			if (slevel == '1') {
				if (UID == 0 || check_path_access(strdup(codedpath))) {
					printit = 1;
				}
			} else
			    printit=1;
		}
		
		if (printit) {
			res = 0;
			cur_queries += 1;
			printf("%s\n",codedpath);
			if (max_queries > 0 && cur_queries == max_queries)
			    exit(0);
		}
	}
	
	if (REGEXP)
	    regfree(preg);

#ifndef FNM_CASEFOLD
	else if (NOCASE)
	    free(casestr);
#endif /* FNM_CASEFOLD */

	close(fd);
	
	return(res);
}

/* Main Function */

int
    main(int args, char **argv)
{
        int res=0;
	int ch;
	extern char *optarg;
	extern int optind, opterr, optopt;
	char *p;
	int SPECDIR=0;
	int ROOTDIR=0;   
	char *spec_dir=NULL;
	char *database = NULL;
	int i=0;
	int o_OPT_READY = 0;
	char *regexp_opt = NULL;

	/* Get the name of the program as it was executed */
	progname = ((p = strrchr(argv[0],'/')) ? p+1 : *argv);
	
	/* If slocate has been run with the name 'updatedb' then we want to initial
	 * the variables necessary to update the database instead of search it */
	if (!strcmp(progname,"updatedb")) {
		ROOTDIR=1;

#ifndef __FreeBSD__
		parse_updatedb_conf();
#endif
		/* Check to make sure default database directory exists */
		check_dir(SLOCATEDB_DIR);
	}

	/* Get Current Working Directory */	
	getcwd(prog_CWD, 4095);
	
	/* If the working directory is too long, then report a fatal error */
	if (strlen(prog_CWD) == 4095)
	    report_error(FATAL,QUIET,"%s: Current Working Directory is too large!",progname);
	
	/* Print usage if not enough arguments were specified */
	if (args < 2 && !ROOTDIR)
	    usage();
	
	/* Get user IDs */
	UID = getuid();        
	GID = getgid();

	/* Add the LOCATE_PATH environment variable to the list of databases to search in */
	parse_decode_path(getenv("LOCATE_PATH"));
	
	/* Loop through specified command line arguments */
	while ((ch = getopt(args,argv,"VvuhqU:r:o:e:l:d:-:n:f:ci")) != EOF) {
		switch(ch) {
		 /* Help */
		 case 'h':
			usage();
			break;
		 /* Quiet Mode. Don't print warnings or errors. */
		 case 'q':
			QUIET=1;
			break;
		 /* Print version */
		 case 'V':
			printf("%s",SL_VERSION);
			exit(0);
			break;
		 /* Turn VERBOSE mode ON */
		 case 'v':
			VERBOSE=1;
			break;
		 /* Exclude specified directories from database */
		 case 'e':
			parse_exclude(optarg);
			break;
		 /* Exclude specified filesystems from database */
		 case 'f':
			parse_fs_exclude(optarg);
			break;
		 /* Parse the updatedb.conf file */
		 case 'c':
#ifndef __FreeBSD__
			parse_updatedb_conf();
#endif
			break;
		 /* Set the security level of the database when creating or updating the
		  * database. If set to 0, security checks will not be preformed */
		 case 'l':
			slevel = optarg[0];
			if (slevel != '0' && slevel != '1')
			    report_error(FATAL,QUIET,"%s: ERROR: Security level must be 0 or 1.\n",progname);
			break;
		 /* Update the default database */
		 case 'u':
			/* Check to make sure default database directory exists */
			check_dir(SLOCATEDB_DIR);
			ROOTDIR=1;
			o_OPT_READY = 1;
			ADD_SLOCATEDB = 0;
			break;
		 /* Update a specified database */
		 case 'U':
			ADD_SLOCATEDB = 0;
			ROOTDIR=0;
			SPECDIR=1;
			o_OPT_READY = 1;
			spec_dir = malloc(strlen(optarg)+1);
			if (!spec_dir)
			    report_error(FATAL,QUIET,"%s: main: 'spec_dir': malloc: %s\n",progname,strerror(errno));
			*spec_dir = 0;
			strcat(spec_dir,optarg);
			break;
		 /* Search database with specified regular expression */
		 case 'r':
			REGEXP = 1;
			regexp = malloc(strlen(optarg)+1);
			if (!regexp)
			    report_error(FATAL,QUIET,"%s: main: 'regexp': malloc: %s\n",progname,strerror(errno));
			*regexp = 0;
			strcat(regexp,optarg);
			regexp_opt = malloc(strlen(optarg)+1);
			strcpy(regexp_opt,optarg);
/*			while (SLOCATE_PATH && (database = SLOCATE_PATH[i++]))
				res |= decode_db(database, optarg);
			return(res); */
			break;
		 /* Specify the database to search in */
		 case 'd':
			if (args > 3) {
				parse_decode_path(optarg);
				ADD_SLOCATEDB = 0;
			}

			break;
		 /* Specify the database path to write to when creating or updating a database */
		 case 'o':
			if (!o_OPT_READY)
			  report_error(FATAL,QUIET,"%s: Must specify an 'Update' database option first.\n",progname);
			parse_create_path(optarg);
			NEWOUTPUT=1;
			break;
		 /* Parse --<argument> type arguments */
		 case '-':
			regexp_opt = parse_dash(optarg);
			break;
		 /* Limit the amount of search results */
		 case 'n':
			for (i=0; i < strlen(optarg); i+=1) {
				if (!isdigit(optarg[i])) {
					fprintf(stderr,"%s: ERROR: Invalid argument for option -n\n",progname);
					exit(1);
				}
			}
			max_queries = atoi(optarg);
			break;
		 /* Make search case insensitive */
		 case 'i':
			NOCASE=1;         
			break;
		 default:
			return(1);
			break;
			
		}
	}

	/* Only add the default database path if necessary.  We don't want todo this
	 * when creating/updating a database or when a database has been specified
	 * with the -d option, etc */

	if (ADD_SLOCATEDB)
	    parse_decode_path(SLOCATEDB);

	/* Get the 'slocate' group GID */
	SLOC_GID = get_gid(GRPFILE);
	
	
	/* if the -U option has been used, start to create the database at specified path */
	if (SPECDIR)
	    res = create_db(spec_dir);
	/* Create databse from default '/' path */
	else if (ROOTDIR)
	    res = create_db((char *)NULL);
	/* search the database(s) */
	else if (REGEXP) {
		/* We do REGEXP stuff separate even if argv[optind] exists.
		 * Fixes an exploitable segfault. */
		int i = 0;
		while (SLOCATE_PATH && (database = SLOCATE_PATH[i++]))
		    res |= decode_db(database, regexp_opt);
	} else if (argv[optind]) {
		int j = optind;
		int i = 0;
		
		while (j < args) {
			/* while ((database = SLOCATE_PATH[i++])) res |= decode_db(database, argv[j++]);
			 i = 0;
			 * A Bug fix by Hans-Juergen Godau <godau@wi-inf.uni-essen.de>
			 * Prevents segfault when using multiple databases */
			while (SLOCATE_PATH && (database = SLOCATE_PATH[i++]))
			    res |= decode_db(database, argv[j]);
			i = 0; j += 1;
			
		}
	}
	/* Print usage */
	else
	    usage();
	
	return(res);
}
