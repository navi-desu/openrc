#include <einfo.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>
#include <signal.h>

#ifdef HAVE_PAM
#include <security/pam_appl.h>
static struct pam_conv conv = { NULL, NULL };
static pam_handle_t *pamh = NULL;
#endif

#include "helpers.h"
#include "rc.h"

static const struct passwd *user;
static char *fifopath;
static size_t logins;

static void cleanup(void) {
#ifdef HAVE_PAM
	if (pamh) {
		int rc;
		if ((rc = pam_close_session(pamh, PAM_SILENT)) != PAM_SUCCESS)
			elog(LOG_ERR, "Failed to close session: %s", pam_strerror(pamh, rc));
		pam_end(pamh, rc);
	}
#endif

	if (exists(fifopath))
		unlink(fifopath);
	free(fifopath);
}

static bool do_setup(const char *username) {
	char *logname;
	int nullfd;

	xasprintf(&logname, "openrc-user[%s]", username);
	setenv("EINFO_LOG", logname, true);
	free(logname);

	if (!(user = getpwnam(username))) {
		elog(LOG_ERR, "getpwnam failed: %s", strerror(errno));
		return false;
	}

	nullfd = open("/dev/null", O_RDWR);
	dup2(nullfd, STDIN_FILENO);
	close(nullfd);

	xasprintf(&fifopath, "%s/users/%s", rc_svcdir(), user->pw_name);
	if (mkfifo(fifopath, 0600) == -1) {
		elog(LOG_ERR, "mkfifo failed: %s", strerror(errno));
		return false;
	}

	return true;
}

static void do_openrc(bool start) {
	pid_t child;
	char *cmd;

	switch ((child = fork())) {
	case 0:
		if (setgid(user->pw_gid) == -1 || setuid(user->pw_uid) == -1) {
			elog(LOG_ERR, "Failed to drop permissions to user.");
			exit(1);
		}

		setenv("HOME", user->pw_dir, true);
		setenv("SHELL", user->pw_shell, true);

		xasprintf(&cmd, "%s %s", RC_LIBEXECDIR "/sh/openrc-user.sh", start ? "start" : "stop");
		execl(user->pw_shell, "-", "-c", cmd, NULL);

		elog(LOG_ERR, "Failed to execl '%s - -c %s': %s.", user->pw_shell, cmd, strerror(errno));
		exit(1);
	case -1:
		exit(1);
	default:
		break;
	}

	waitpid(child, NULL, 0);
}

static void open_session(void) {
#ifdef HAVE_PAM
	bool pam_session = false;
	int rc;

	if ((rc = pam_start("openrc-user", user->pw_name, &conv, &pamh)) != PAM_SUCCESS)
		elog(LOG_ERR, "Failed to start pam: %s", pam_strerror(pamh, rc));
	else if ((rc = pam_open_session(pamh, PAM_SILENT)) != PAM_SUCCESS)
		elog(LOG_ERR, "Failed to open session: %s", pam_strerror(pamh, rc));
	else
		pam_session = true;

	for (char **env = pam_getenvlist(pamh); env && *env; env++) {
		if (strchr(*env, '='))
			putenv(xstrdup(*env));
		else
			unsetenv(*env);
	}

	if (!pam_session && pamh)
		pam_end(pamh, rc);
#endif

	return;
}

int main(int argc, char **argv) {
	bool start;

	if (argc < 2) {
		fprintf(stderr, "%s: Not enough arguments.\n", argv[0]);
		return 1;
	}

	if (!do_setup(argv[1]))
		return 1;

	atexit(cleanup);

	/* we need to initgroups before pam is setup. */
	if (initgroups(user->pw_name, user->pw_gid) == -1)
		return 1;

	open_session();

	do_openrc(true);

	for (;;) {
		char buf[BUFSIZ];
		size_t count;
		FILE *fifo;

		if (!(fifo = fopen(fifopath, "r"))) {
			if (errno != EINTR)
				elog(LOG_ERR, "fopen failed: %s", strerror(errno));
			continue;
		}

		count = fread(buf, BUFSIZ - 1, fifo);
		buf[count] = '\0';

		fclose(fifo);

		if (strcmp(buf, "start") == 0)
			logins++;
		else if (strcmp(buf, "stop") == 0)
			logins--;
		else if (strcmp(buf, "shutdown") == 0)
			break;

		if (logins == 0)
			break;
	}

	do_openrc(false);

	return 0;
}
