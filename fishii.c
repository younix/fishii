#include <stdbool.h>
#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blowfish.h"

void
handle_input(char *buf, const char *key, int fd)
{
	char *line;

	while ((line = strsep(&buf, "\n")) != NULL) {
		char *prompt = line;

		line = strchr(line, '>');
		if (line == NULL) {
			dprintf(fd, "%s\n", prompt);
			continue;
		}

		/* XXX: do length check */
		if (*line == '>') {
			++line;
			*line = '\0';
			++line;
		}

		if (strncmp(line, "+OK ", 4) == 0) { /* is encrypted */
			char plain[BUFSIZ];
			line += 4;

			if (decrypt_string(key, line, plain, strlen(line)) == 0)
				errx(EXIT_FAILURE, "decrypt_string");

			dprintf(fd, "%s %s\n", prompt, plain);
		} else {
			dprintf(fd, "%s +p %s\n", prompt, line);
		}
	}
}

void
read_key(char *key, size_t size)
{
	FILE *fh;

	if ((fh = fopen(".key", "r")) == NULL)
		err(EXIT_FAILURE, "fopen");

	if (fgets(key, size, fh) == NULL)
		err(EXIT_FAILURE, "fgets");

	if (fclose(fh) == EOF)
		err(EXIT_FAILURE, "fclose");
}

void
send_msg(const char *msg, const char *key)
{
	int fd;
	char cipher[BUFSIZ] = "+OK ";
	char *nl;

	if ((nl = strrchr(msg, '\n')) != NULL)	/* rm newline */
		*nl = '\0';

	if (encrypt_string(key, msg, cipher + 4, strlen(msg)) == 0)
		errx(EXIT_FAILURE, "encrypt_string");

	strlcat(cipher, "\n", sizeof cipher);

	if ((fd = open("in", O_WRONLY)) == -1)
		err(EXIT_FAILURE, "open");

	if (write(fd, cipher, strlen(cipher)) == -1)
		err(EXIT_FAILURE, "write");

	if (close(fd) == -1)
		err(EXIT_FAILURE, "close");
}

size_t
print_content(const char *key)
{
	size_t size = 0;
	FILE *fh;
	char buf[BUFSIZ];

	if ((fh = fopen("out", "r")) == NULL)
		err(EXIT_FAILURE, "fopen");

	while (fgets(buf, sizeof buf, fh) == NULL) {
		send_msg(buf, key);
	}

	if (fclose(fh) == EOF)
		err(EXIT_FAILURE, "fclose");

	return size;
}

int
open_out(size_t histlen)
{
	char cmd[BUFSIZ];
	FILE *fh;

	snprintf(cmd, sizeof cmd, "tail -fc %zu out", histlen);

	if ((fh = popen(cmd, "r")) == NULL)
		err(EXIT_FAILURE, "popen");

	return fileno(fh);
}

void
usage(void)
{
	fputs("fishii [-h] [-d dir] prog [args]\n", stderr);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	int ch, out;
	char *dir = ".";
	size_t size = 0;
	char key[BUFSIZ];
	bool all_flag = false;

#	define READ_FD 6
#	define WRITE_FD 7

	while ((ch = getopt(argc, argv, "ad:h")) != -1) {
		switch (ch) {
		case 'a':
			all_flag = true;
			break;
		case 'd':
			if ((dir = strdup(optarg)) == NULL)
				err(EXIT_FAILURE, "strdup");
			break;
		case 'h':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage();

	if (chdir(dir) == -1)
		err(EXIT_FAILURE, "chdir");

	read_key(key, sizeof key);
	if (all_flag) {
		size = print_content(key);
	}
	out = open_out(size);

	/* fork frontend program */
	char *prog = argv[0];
#	define PIPE_READ 0
#	define PIPE_WRITE 1
	int pi[2];	/* input pipe */
	int po[2];	/* output pipe */
	if (pipe(pi) == -1) err(EXIT_FAILURE, "pipe");
	if (pipe(po) == -1) err(EXIT_FAILURE, "pipe");

	switch (fork()) {
	case -1:
		err(EXIT_FAILURE, "fork");
	case 0: /* client program */

		/* close non-using ends of pipes */
		if (close(pi[PIPE_READ]) == -1) err(EXIT_FAILURE, "close");
		if (close(po[PIPE_WRITE]) == -1) err(EXIT_FAILURE, "close");

		/*
		 * We have to move one descriptor cause po[] may
		 * overlaps with descriptor 6 and 7.
		 */
		int po_read = 0;
		if ((po_read = dup(po[PIPE_READ])) == -1)
			err(EXIT_FAILURE, "dup");
		if (close(po[PIPE_READ]) < 0) err(EXIT_FAILURE, "close");

		if (dup2(pi[PIPE_WRITE], WRITE_FD) < 0)
			err(EXIT_FAILURE, "dup2");
		if (dup2(po_read, READ_FD) < 0) err(EXIT_FAILURE, "dup2");

		if (close(pi[PIPE_WRITE]) < 0) err(EXIT_FAILURE, "close");
		if (close(po_read) < 0) err(EXIT_FAILURE, "close");
		execvp(prog, argv);
		err(EXIT_FAILURE, "execvpe");
	default: break; /* parent */
	}

	/* close non-using ends of pipes */
	if (close(pi[PIPE_WRITE]) == -1) err(EXIT_FAILURE, "close");
	if (close(po[PIPE_READ]) == -1) err(EXIT_FAILURE, "close");

	struct pollfd pfd[2];
	pfd[0].fd = pi[PIPE_READ];
	pfd[0].events = POLLIN;
	pfd[1].fd = out;
	pfd[1].events = POLLIN;

	for (;;) {
		char buf[BUFSIZ];
		ssize_t n;
		int nready = poll(pfd, 2, INFTIM);

		if (nready == -1)
			err(EXIT_FAILURE, "poll");

		if (pfd[0].revents & (POLLERR | POLLNVAL) ||
		    pfd[1].revents & (POLLERR | POLLNVAL))
			errx(EXIT_FAILURE, "bad fd");

		if (pfd[0].revents & POLLIN) {	/* frontend input */
			if ((n = read(pi[PIPE_READ], buf, sizeof buf)) == -1)
				err(EXIT_FAILURE, "read");
			if (n == 0)
				break;
			buf[n] = '\0';
			send_msg(buf, key);
		}

		if (pfd[1].revents & POLLIN) {	/* backend input */
			if ((n = read(out, buf, sizeof buf)) == -1)
				err(EXIT_FAILURE, "read");
			if (n == 0)
				break;
			buf[n] = '\0';
			handle_input(buf, key, po[PIPE_WRITE]);
		}
	}

	return EXIT_SUCCESS;
}
