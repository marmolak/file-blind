#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/vfs.h>

int main (int argc, char **argv)
{
	int fd = open ("first.parent.open", O_RDONLY);
	close (fd);

	const pid_t pid = fork ();
	if ( pid == 0 ) {
		int fd = open ("child.open", O_RDONLY);
		close (fd);

		const pid_t c_pid = fork ();
		if ( c_pid == 0 ) {
			access ("child.child.access", F_OK);
			exit (EXIT_SUCCESS);
		} else if ( c_pid > 0 ) {
			stat ("child.stat", NULL);
			wait (NULL);
		}

		lstat ("child.lstat", NULL);
		exit (EXIT_SUCCESS);
	} else if ( pid > 0 ) {
		int fd = open ("parent.open", O_RDONLY);
		close (fd);
		fd = creat ("parent .creat", O_RDWR);
		close (fd);
	}

	statfs ("parent.statfs", NULL);
	wait (NULL);
	sleep (15);

	return EXIT_SUCCESS;
}
