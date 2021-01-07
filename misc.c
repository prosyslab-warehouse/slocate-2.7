#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#define ALLOC_SIZE 4096

/* Make an error for load_file
 * Error will be put into a (char *) in the following format:
 *   "\0error message\0"
 * 
 * So when looking at the message you have to look one character
 * a head. ie.
 * 
 *    printf("Error: %s",error_buf+1);
 * 
 * This is so that we can do the check:
 * 
 * fbuf = load_file("myfile");
 * if (*fbuf == 0)
 *    printf("Error: %s\n",fbuf+1);
 * else
 *    printf("It worked!");
 */
char *
    load_file_error(const char *message, int myerrno)
{
	char *error_buf;       
	
	/* Allocate memory for error */
	if (message == NULL)
	    error_buf = malloc(strlen(strerror(myerrno))+2);	
	else
	    error_buf = malloc(strlen(message)+strlen(strerror(myerrno))+2);

	/* Set first two characters to \0 for strcat */
	bzero(error_buf,2);
	/* Put message in error_buf */
	if (message)
	    strcat((error_buf+1),message);
	
	if (myerrno)
	    strcat((error_buf+1),strerror(myerrno));
	
	return error_buf;
}

/* Load File into memory */

char *
load_file(const char *filename) {
	int res = 1;
	int fptr;
	char *fbuf;
	int myerrno;
	char buffer[ALLOC_SIZE];
	unsigned int tot_size;

	if (!filename) {
		fbuf = load_file_error("filename is NULL!",0);
		return fbuf;
	}
	
	/* Open the filename read only */
	if ((fptr = open(filename,O_RDONLY)) != -1) {
		
		/* initialize fbuf */
		fbuf = malloc(ALLOC_SIZE+1);
		
		/* If malloc failes, report and exit */
		if (!fbuf) {
			fprintf(stderr,"load_file: malloc: %s",strerror(errno));
			exit(1);
		}
		
		*fbuf = 0;
		tot_size = ALLOC_SIZE;

		/* Read file in 4096 chunks */
		while ((res = read(fptr,buffer,ALLOC_SIZE)) > 0) {
			strncat(fbuf,buffer,res);
			if (res < ALLOC_SIZE)
			    break;

			/* realloc more memory if more of the file is expected. */
			fbuf = realloc(fbuf,tot_size+ALLOC_SIZE);

			/* If realloc failes report and exit. */
			if (!fbuf) {
				fprintf(stderr,"load_file: realloc: %s",strerror(errno));
				exit(1);
			}
		}
		
		myerrno = errno;

		close(fptr);

		/* If read fails, put error message into fbuf */
		if (res == -1) {
			free(fbuf);
			fbuf = load_file_error("read: ",myerrno);
		}
	}
	/* If open fails, put error message into fbuf */
	else
	    fbuf = load_file_error("open: ",errno);

	return(fbuf);
}

/* report an error
 * 
 * int STATUS can equal WARNING == 0
 *                      FATAL   == 1
 * 
 * WARNING status will just return while FATAL status will exit the 
 * program with error code 1
 */
void
report_error(int STATUS, int QUIET, const char *format, ...) {
	
	/* Guess we need no more than 100 bytes. */
	int n;
	unsigned int size = ALLOC_SIZE;
	char *str;
	va_list ap;
	
	/* If QUIET is on and STATUS == 1 (fatal) then exit 
	 * else just return */
	if (QUIET && STATUS == 1)
	    exit(1);
	else if (QUIET)
	    return;
	
	if ((str = malloc (size)) == NULL) {
		fprintf(stderr,"report_fatal_error: malloc: %s\n",strerror(errno));
		exit(1);
	}
	
	while (1) {
		/* Try to print in the allocated space. */
		va_start(ap, format);
		n = vsnprintf(str, size, format, ap);
		va_end(ap);

		/* If that worked, print message. */
		if (n > -1 && n < size) {
			if (STATUS == 1)
			    fprintf(stderr,"fatal error: %s",str);
			else if (STATUS == 0)
			    fprintf(stderr,"warning: %s",str);
			else
			    fprintf(stderr,"%s",str);
			fflush(stderr);
			break;
		}

		/* Else try again with more space. */
		if (n > -1)    /* glibc 2.1 */
		    size = n+1; /* precisely what is needed */
		else           /* glibc 2.0 */
		    size *= 2;  /* twice the old size */

		if ((str = realloc (str, size)) == NULL) {
			fprintf(stderr,"report_fatal_error: realloc: %s\n",strerror(errno));
			exit(1);
		}
	}

	if (STATUS == 1)
	    exit(1);
}
