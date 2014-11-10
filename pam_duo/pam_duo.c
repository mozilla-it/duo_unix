/*
 * pam_duo.c
 *
 * Copyright (c) 2010 Duo Security
 * All rights reserved, all wrongs reversed.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#define LDAP_DEPRECATED 1
#include <ldap.h>

/* These #defines must be present according to PAM documentation. */
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

/* NetBSD PAM b0rkage (gnat 39313) */
#ifdef __NetBSD__
#define NO_STATIC_MODULES
#endif

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif
#ifdef HAVE_SECURITY_PAM_EXT_H
#include <security/pam_ext.h>	/* Linux-PAM */
#endif

/* OpenGroup RFC86.0 and XSSO specify no "const" on arguments */
#if defined(__LINUX_PAM__) || defined(OPENPAM)
# define duopam_const   const   /* LinuxPAM, OpenPAM */
#else
# define duopam_const           /* Solaris, HP-UX, AIX */
#endif

#include "util.h"
#include "duo.h"
#include "groupaccess.h"
#include "pam_extra.h"

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#ifndef DUO_PRIVSEP_USER
# define DUO_PRIVSEP_USER	"duo"
#endif
#define DUO_CONF		DUO_CONF_DIR "/pam_duo.conf"
#define MAX_USER_LEN 255

static int
__ini_handler(void *u, const char *section, const char *name, const char *val)
{
	struct duo_config *cfg = (struct duo_config *)u;

	if (strcmp(name, "ldap_resolve_hack") == 0) {
		cfg->ldap_resolve_hack = duo_set_boolean_option(val);
	} else if (strcmp(name, "ldap_failmode") == 0) {
		cfg->ldap_failmode = duo_set_boolean_option(val);
	} else if (strcmp(name, "ldap_server") == 0) {
		cfg->ldap_server = strdup(val);
	} else if (strcmp(name, "ldap_binddn") == 0) {
		cfg->ldap_binddn = strdup(val);
	} else if (strcmp(name, "ldap_basedn") == 0) {
		cfg->ldap_basedn = strdup(val);
	} else if (strcmp(name, "ldap_password") == 0) {
		cfg->ldap_password = strdup(val);
	} else if (strcmp(name, "ldap_smartfail_domain") == 0) {
		cfg->ldap_smartfail_domain = strdup(val);
	} else if (strcmp(name, "ldap_get_attribute") == 0) {
		cfg->ldap_get_attribute = strdup(val);
	} else if (strcmp(name, "ldap_search_user_filter") == 0) {
		cfg->ldap_search_user_filter = strdup(val);
	} else if (!duo_common_ini_handler(cfg, section, name, val)) {
		duo_syslog(LOG_ERR, "Invalid pam_duo option: '%s'", name);
		return (0);
	}
	return (1);
}

static void
__duo_status(void *arg, const char *msg)
{
	pam_info((pam_handle_t *)arg, "%s", msg);
}

static char *
__duo_prompt(void *arg, const char *prompt, char *buf, size_t bufsz)
{
	char *p;
	
	if (pam_prompt((pam_handle_t *)arg, PAM_PROMPT_ECHO_ON, &p,
		"%s", prompt) != PAM_SUCCESS) {
		return (NULL);
	}
	strlcpy(buf, p, bufsz);
	free(p);
	return (buf);
}

const char *
get_email_login_from_ldap(struct duo_config cfg, const char *user, const char *host)
{
	LDAP        *ld;
	char		*ldap_filter;
	char		*attrs[] = { NULL, NULL };
	char		*myattr;
	BerElement	*ber;
	LDAPMessage	*msg = NULL;
	LDAPMessage *res;
	char		**vals = NULL;
	char		*val;
	int		len, userlen;
	char		*def = NULL;

	userlen = strlen(user);
	if (userlen > MAX_USER_LEN) {
		duo_log(LOG_ERR, "user name too long", user, host, NULL);
		return def;
	}

	if ((strstr(user, "@") == NULL) && cfg.ldap_failmode == 0) {
		len = userlen+strlen(cfg.ldap_smartfail_domain)+2;
		def = malloc(len);
		snprintf(def, len, "%s@%s", user, cfg.ldap_smartfail_domain);
	} else {
		duo_log(LOG_ERR, "no lookup needed", user, host, NULL);
		return user;
	}

	attrs[0] = alloca(strlen(cfg.ldap_get_attribute)+1);
	snprintf(attrs[0], strlen(cfg.ldap_get_attribute)+1, cfg.ldap_get_attribute);
	ldap_filter = alloca(strlen(cfg.ldap_search_user_filter)+userlen+1);
	snprintf(ldap_filter, strlen(cfg.ldap_search_user_filter)+userlen+1, cfg.ldap_search_user_filter, user);

	if (ldap_initialize(&ld, cfg.ldap_server)) {
		duo_log(LOG_ERR, "ldap_initialize failed", user, host, NULL);
		return def;
	}

	if (ldap_simple_bind_s(ld, cfg.ldap_binddn, cfg.ldap_password) != LDAP_SUCCESS) {
		duo_log(LOG_ERR, "ldap_simple_bind_s faileds", user, host, NULL);
		return def;
	}

	if (ldap_search_s(ld, cfg.ldap_basedn, LDAP_SCOPE_SUBTREE, ldap_filter, attrs, 0,  &res) != LDAP_SUCCESS) {
		duo_log(LOG_ERR, "ldap_search_s failed", user, host, NULL);
		return def;
	}

	if (ldap_count_entries(ld, res) == 0) {
		duo_log(LOG_ERR, "ldap_count_entries failed", user, host, NULL);
		return def;
	}

	msg = ldap_first_entry(ld, res);
	if (msg == NULL)
		duo_log(LOG_ERR, "ldap_first_entry failed", user, host, NULL);

	myattr = ldap_first_attribute(ld, msg, &ber);
	if (myattr == NULL)
		duo_log(LOG_ERR, "ldap_first_attribute failed", user, host, NULL);

	if ((vals = ldap_get_values(ld, msg, myattr)) == NULL) {
		duo_log(LOG_ERR, "ldap_get_values failed", user, host, NULL);
		return def;
	}

	val = malloc(256);
	val = strndup(vals[0], 256);
	free(def);
	ldap_value_free(vals);
#if 0
	/* For some reason you can't free those properly. Have to look up what's really happening. */
	ber_free(ber, 1);
	ldap_memfree(msg);
#endif
	ldap_msgfree(res);
	ldap_unbind(ld);
	duo_syslog(LOG_INFO, "translated Duo username (will appear as the new user in subsequent log entries) %s=>%s", user, val);
	return val;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int pam_flags,
    int argc, const char *argv[])
{
	struct duo_config cfg;
	struct passwd *pw;
	struct in_addr addr;
	duo_t *duo;
	duo_code_t code;
	duopam_const char *config, *cmd, *p, *service, *user;
	const char *ip, *host;
	int i, flags, pam_err, matched;

	duo_config_default(&cfg);

	/* Parse configuration */
	config = DUO_CONF;
	for (i = 0; i < argc; i++) {
		if (strncmp("conf=", argv[i], 5) == 0) {
			config = argv[i] + 5;
		} else if (strcmp("debug", argv[i]) == 0) {
			duo_debug = 1;
		} else {
			duo_syslog(LOG_ERR, "Invalid pam_duo option: '%s'",
			    argv[i]);
			return (PAM_SERVICE_ERR);
		}
	}
	i = duo_parse_config(config, __ini_handler, &cfg);
	if (i == -2) {
		duo_syslog(LOG_ERR, "%s must be readable only by user 'root'",
		    config);
		return (cfg.failmode == DUO_FAIL_SAFE ? PAM_SUCCESS : PAM_SERVICE_ERR);
	} else if (i == -1) {
		duo_syslog(LOG_ERR, "Couldn't open %s: %s",
		    config, strerror(errno));
		return (cfg.failmode == DUO_FAIL_SAFE ? PAM_SUCCESS : PAM_SERVICE_ERR);
	} else if (i > 0) {
		duo_syslog(LOG_ERR, "Parse error in %s, line %d", config, i);
		return (cfg.failmode == DUO_FAIL_SAFE ? PAM_SUCCESS : PAM_SERVICE_ERR);
	} else if (!cfg.apihost || !cfg.apihost[0] ||
            !cfg.skey || !cfg.skey[0] || !cfg.ikey || !cfg.ikey[0]) {
		duo_syslog(LOG_ERR, "Missing host, ikey, or skey in %s", config);
		return (cfg.failmode == DUO_FAIL_SAFE ? PAM_SUCCESS : PAM_SERVICE_ERR);
	}
        
    /* Check user */
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS ||
        (pw = getpwnam(user)) == NULL) {
            return (PAM_USER_UNKNOWN);
    }
    /* XXX - Service-specific behavior */
	flags = 0;
    cmd = NULL;
	if (pam_get_item(pamh, PAM_SERVICE, (duopam_const void **)
		(duopam_const void *)&service) != PAM_SUCCESS) {
                return (PAM_SERVICE_ERR);
        }
    if (strcmp(service, "sshd") == 0) {
            /*
             * Disable incremental status reporting for sshd :-(
             * OpenSSH accumulates PAM_TEXT_INFO from modules to send in
             * an SSH_MSG_USERAUTH_BANNER post-auth, not real-time!
             */
            flags |= DUO_FLAG_SYNC;
    } else if (strcmp(service, "sudo") == 0) {
            cmd = getenv("SUDO_COMMAND");
    } else if (strcmp(service, "su") == 0) {
            /* Check calling user for Duo auth, just like sudo */
            if ((pw = getpwuid(getuid())) == NULL) {
                    return (PAM_USER_UNKNOWN);
            }
            user = pw->pw_name;
    }
	/* Check group membership */
    matched = duo_check_groups(pw, cfg.groups, cfg.groups_cnt);
    if (matched == -1) {
        return (PAM_SERVICE_ERR);
    } else if (matched == 0) {
        return (PAM_SUCCESS);
    }

    /* Grab the remote host */
	ip = NULL;
	pam_get_item(pamh, PAM_RHOST,
	    (duopam_const void **)(duopam_const void *)&ip);
	host = ip;
	/* PAM is weird, check to see if PAM_RHOST is IP or hostname */
	if (ip == NULL) {
		ip = ""; /* XXX inet_addr needs a non-null IP */
	}
	if (!inet_aton(ip, &addr)) {
		/* We have a hostname, don't try to resolve, check fallback */
		ip = (cfg.local_ip_fallback ? duo_local_ip() : NULL);
	}

	/* Honor configured http_proxy */
	if (cfg.http_proxy != NULL) {
		setenv("http_proxy", cfg.http_proxy, 1);
	}

	/* Try Duo auth */
	if ((duo = duo_open(cfg.apihost, cfg.ikey, cfg.skey,
                    "pam_duo/" PACKAGE_VERSION,
                    cfg.noverify ? "" : cfg.cafile)) == NULL) {
		duo_log(LOG_ERR, "Couldn't open Duo API handle", user, host, NULL);
		return (PAM_SERVICE_ERR);
	}
	duo_set_conv_funcs(duo, __duo_prompt, __duo_status, pamh);

	if (cfg.autopush) {
		flags |= DUO_FLAG_AUTO;
	}

	pam_err = PAM_SERVICE_ERR;
	for (i = 0; i < cfg.prompts; i++) {
		/* hack for unix users which aren't emails */
		if (cfg.ldap_resolve_hack) {
			duo_log(LOG_INFO, "Attempting LDAP lookup", user, host, NULL);
			user = get_email_login_from_ldap(cfg, user, host);
			if (user == NULL) { /* Failmode is fail open*/
				duo_log(LOG_WARNING, "LDAP failed, bypassing DuoSecurity (fail-open)", user, host, NULL);
				return PAM_SUCCESS;
			}
		}

		code = duo_login(duo, user, host, flags,
                    cfg.pushinfo ? cmd : NULL);
		if (code == DUO_FAIL) {
			duo_log(LOG_WARNING, "Failed Duo login",
			    user, host, duo_geterr(duo));
			if ((flags & DUO_FLAG_SYNC) == 0) {
				pam_info(pamh, "%s", "");
                        }
			/* Keep going */
			continue;
		}
		/* Terminal conditions */
		if (code == DUO_OK) {
			if ((p = duo_geterr(duo)) != NULL) {
				duo_log(LOG_WARNING, "Skipped Duo login",
				    user, host, p);
			} else {
				duo_log(LOG_INFO, "Successful Duo login",
				    user, host, NULL);
			}
			pam_err = PAM_SUCCESS;
		} else if (code == DUO_ABORT) {
			duo_log(LOG_WARNING, "Aborted Duo login",
			    user, host, duo_geterr(duo));
			pam_err = PAM_ABORT;
		} else if (cfg.failmode == DUO_FAIL_SAFE &&
                    (code == DUO_CONN_ERROR ||
                     code == DUO_CLIENT_ERROR || code == DUO_SERVER_ERROR)) {
			duo_log(LOG_WARNING, "Failsafe Duo login",
			    user, host, duo_geterr(duo));
			pam_err = PAM_SUCCESS;
		} else {
			duo_log(LOG_ERR, "Error in Duo login",
			    user, host, duo_geterr(duo));
			pam_err = PAM_SERVICE_ERR;
		}
		break;
	}
	if (i == MAX_PROMPTS) {
		pam_err = PAM_MAXTRIES;
	}
	duo_close(duo);
	
	return (pam_err);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
	return (PAM_SERVICE_ERR);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_duo");
#endif
