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

static void
handle_crypto(char *buf, const char *key, int fd)
{
	char *line;

	while ((line = strsep(&buf, "\n")) != NULL) {
		char *prompt = line;

		/* YYYY-MM-DD HH:MM -!- ... */
		if (line[17] == '-')
			goto plain;

		/* YYYY-MM-DD HH:MM <...> +OK ... */
		line = strchr(line, '>');
		if (line == NULL)
			goto plain;

		if ((line = strstr(line, " +OK ")) != NULL) { /* is encrypted */
			char plain[BUFSIZ];

			*line = '\0';	/* split string */
			line += 5;

			if (decrypt_string(key, line, plain, strlen(line)) == 0)
				errx(EXIT_FAILURE, "decrypt_string");

			dprintf(fd, "%s %s", prompt, plain);
			continue;
		}
 plain:
		dprintf(fd, "%s%s", prompt,
		    prompt[strlen(prompt) - 1] != '\n' ? "\n": "");
	}
}

static void
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
		err(EXIT_FAILURE, "open");

	if (write(fd, cipher, strlen(cipher)) == -1)
		err(EXIT_FAILURE, "write");

	if (close(fd) == -1)
		err(EXIT_FAILURE, "close");
}

static size_t
print_content(const char *key, int crypt_out)
{
	size_t size = 0;
	FILE *fh;
	char buf[BUFSIZ];

	if ((fh = fopen("out", "r")) == NULL)
		err(EXIT_FAILURE, "fopen");

	while (fgets(buf, sizeof buf, fh) != NULL)
		handle_crypto(buf, key, crypt_out);

	if (fclose(fh) == EOF)
		err(EXIT_FAILURE, "fclose");

	return size;
}

static int
open_out(size_t histlen)
{
	char cmd[BUFSIZ];
	FILE *fh;

	snprintf(cmd, sizeof cmd, "tail -fc %zu out", histlen);

	if ((fh = popen(cmd, "r")) == NULL)
		err(EXIT_FAILURE, "popen");

	return fileno(fh);
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
	size_t size = 0;
	char key[BUFSIZ];

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

	read_key(key, sizeof key);
	size = print_content(key, plain_out);
	crypt_out = open_out(size);

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

			if ((n = read(plain_in, buf, PIPE_BUF)) == -1)
				err(EXIT_FAILURE, "read");
			if (n == 0)
				break;

			buf[n] = '\0';
			handle_plain(buf, key);

			/* reopen */
			if (close(plain_in) == -1)
				err(EXIT_FAILURE, "close");
			if ((plain_in = open("plain/in", O_RDONLY)) == -1)
				err(EXIT_FAILURE, "open");
			pfd[0].fd = plain_in;
		}

		if (pfd[1].revents & POLLIN) {	/* out -> here -> plain/out */
			char buf[BUFSIZ];
			if ((n = read(crypt_out, buf, sizeof buf)) == -1)
				err(EXIT_FAILURE, "read");
			if (n == 0)
				break;
			buf[n] = '\0';
			handle_crypto(buf, key, crypt_out);
		}
	}

	return EXIT_SUCCESS;
}
