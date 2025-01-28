#include <fcntl.h>
#include <pwd.h>
#ifndef LINUX_PAM
#include <security/pam_appl.h>
#endif
#include <security/pam_modules.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include <einfo.h>
#include <rc.h>
#include "helpers.h"

static int exec_openrc(pam_handle_t *pamh, bool start) {
	const char *username, *session;
	struct passwd *user;
	char *elog_name;
	pid_t child;

	if (pam_get_item(pamh, PAM_SERVICE, (const void **)&session) != PAM_SUCCESS)
		return PAM_SESSION_ERR;
	/* noop if the current stack was started by openrc-user, to avoid looping */
	if (strcmp(session, "openrc-user") == 0)
		return PAM_SUCCESS;

	if (pam_get_user(pamh, &username, "") != PAM_SUCCESS || !(user = getpwnam(username)))
		return PAM_SESSION_ERR;

	if (user->pw_uid == 0)
		return PAM_SUCCESS;

	xasprintf(&elog_name, "pam_openrc[%s]", user->pw_name);
	setenv("EINFO_LOG", elog_name, true);
	free(elog_name);

	child = fork();

	if (child == 0) {
		setsid();
		if (fork() == 0) {
			execl(RC_LIBEXECDIR "/bin/openrc-user", "openrc-user", user->pw_name, start ? "start" : "stop", NULL);
			elog(LOG_ERR, "Failed to exec openrc-user");
			exit(1);
		}
		exit(0);
	}

	waitpid(child, NULL, 0);

	unsetenv("EINFO_LOG");
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	(void) flags; (void) argc; (void) argv;
	return exec_openrc(pamh, true);
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	(void) flags; (void) argc; (void) argv;
	return exec_openrc(pamh, false);
}
