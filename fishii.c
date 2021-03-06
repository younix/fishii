#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blowfish.h"

static size_t
handle_crypto(char *buf, const char *key, int fd)
{
	char *line, *sp;
	char *next = buf;

	while ((line = strsep(&next, "\n")) != NULL) {
		char *prompt = line;

		/* ignore empty lines */
		if (line[0] == '\n' || line[0] == '\0')
			continue;

		/* handle incomplete lines in the next read-turn */
		if (next == NULL) {
			memmove(buf, line, strlen(line));
			return strlen(line);
		}

		/* 1504360730 -!- ... */
		if ((sp = strchr(line, ' ')) != NULL)
			if (strncmp(sp, " -!-", 4) == 0)
				goto plain;

		/* 1504360730 <...> +OK ... */
		if ((line = strchr(line, '>')) == NULL)
			goto plain;

		if ((line = strstr(line, " +OK ")) != NULL) { /* is encrypted */
			char plain[BUFSIZ];

			*line = '\0';	/* split string */
			line += 5;

			if (decrypt_string(key, line, plain, strlen(line)) == 0)
				errx(EXIT_FAILURE, "decrypt_string");

			dprintf(fd, "%s %s\n", prompt, plain);
			continue;
		}
 plain:
		dprintf(fd, "%s\n", prompt);
	}

	return 0;
}

static void
handle_plain(const char *msg, const char *key)
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
		err(EXIT_FAILURE, "open in");

	if (write(fd, cipher, strlen(cipher)) == -1)
		err(EXIT_FAILURE, "write in");

	if (close(fd) == -1)
		err(EXIT_FAILURE, "close in");
}

static void
read_key(char *key, size_t size)
{
	FILE *fh;

	/* TODO: check permissions of the key file */

	if ((fh = fopen(".key", "r")) == NULL)
		err(EXIT_FAILURE, "fopen .key");

	if (fgets(key, size, fh) == NULL)
		err(EXIT_FAILURE, "fgets .key");

	if (fclose(fh) == EOF)
		err(EXIT_FAILURE, "fclose .key");
}

static void
usage(void)
{
	fputs("fishii [-h] [folder]\n", stderr);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	int ch;
	int crypt_out, plain_in, plain_out;
	char *dir = ".";
	char key[BUFSIZ];
	FILE *fh;

	while ((ch = getopt(argc, argv, "h")) != -1) {
		switch (ch) {
		case 'h':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 0)
		dir = argv[0];

	if (chdir(dir) == -1)
		err(EXIT_FAILURE, "chdir");

	/* prepare and open plain/{in,out} */
	if (mkdir("plain", S_IRWXU) == -1 && errno != EEXIST)
		err(EXIT_FAILURE, "mkfifo plain");
	if (mkfifo("plain/in", S_IRUSR|S_IWUSR) == -1 && errno != EEXIST)
		err(EXIT_FAILURE, "mkfifo plain/in");
	if ((plain_in = open("plain/in", O_RDONLY|O_NONBLOCK)) == -1)
		err(EXIT_FAILURE, "open plain/in");
	if ((plain_out = open("plain/out", O_WRONLY|O_CREAT|O_TRUNC,
	    S_IRUSR|S_IWUSR)) == -1)
		err(EXIT_FAILURE, "open plain/out");
	if ((fh = popen("exec tail -f -c +0 out", "r")) == NULL)
		err(EXIT_FAILURE, "popen");
	crypt_out = fileno(fh);
	read_key(key, sizeof key);

	struct pollfd pfd[2];
	pfd[0].fd = plain_in;
	pfd[0].events = POLLIN;
	pfd[1].fd = crypt_out;
	pfd[1].events = POLLIN;

	for (;;) {
		ssize_t n;
		int nready = poll(pfd, 2, INFTIM);

		if (nready == -1)
			err(EXIT_FAILURE, "poll");

		if (pfd[0].revents & (POLLERR | POLLNVAL) ||
		    pfd[1].revents & (POLLERR | POLLNVAL))
			errx(EXIT_FAILURE, "bad fd");

		if (pfd[0].revents & POLLIN) {	/* in <- here <- plain/in */
			char buf[PIPE_BUF + 1];

			if ((n = read(plain_in, buf, PIPE_BUF)) == -1) {
				if (errno == EAGAIN)
					continue;
				err(EXIT_FAILURE, "read plain/in");
			}

			if (n == 0) {	/* pipe was closed */
				if (close(plain_in) == -1)
					err(EXIT_FAILURE, "close");
				if ((plain_in = open("plain/in", O_RDONLY|O_NONBLOCK)) == -1)
					err(EXIT_FAILURE, "open");
				pfd[0].fd = plain_in;
			} else {
				buf[n] = '\0';
				handle_plain(buf, key);
			}
		}

		/* handle backend error and its broken pipe */
		if (pfd[1].revents & POLLHUP)
			break;

		if (pfd[1].revents & POLLIN) {	/* out -> here -> plain/out */
			static char buf[BUFSIZ];
			static size_t off = 0;

			n = read(crypt_out, buf + off, sizeof(buf) - off - 1);
			if (n == -1)
				err(EXIT_FAILURE, "read");
			if (n == 0)
				break;
			buf[n + off] = '\0';

			off = handle_crypto(buf, key, plain_out);
		}
	}

	return EXIT_SUCCESS;
}
