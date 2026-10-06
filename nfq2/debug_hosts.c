#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <time.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <limits.h>

#include "debug_hosts.h"
#include "helpers.h"

#define DBG_HOSTS_MAX 64
#define DBG_HOST_CAP 256

static char dbg_file[PATH_MAX];		// watched host file
static time_t dbg_mtime;		// last loaded mtime, 0 = never loaded
static bool dbg_armed;
static char dbg_hosts[DBG_HOSTS_MAX][DBG_HOST_CAP];
static int dbg_host_count;
static char dbg_out_path[PATH_MAX];	// output path from the first comment
static char dbg_ctx[DBG_HOST_CAP];	// hostname of the flow being processed
static bool dbg_ctx_valid;
static bool dbg_open_failed;		// output open failure reported once

static void dbg_lower(char *s)
{
	for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

void dbg_hosts_set_default_file(const char *path)
{
	if (path) snprintf(dbg_file, sizeof(dbg_file), "%s", path);
}

// suffix/parent-domain match : "ya.ru" matches "ya.ru" and "www.ya.ru"
static bool dbg_host_match(const char *host)
{
	size_t i, n = strlen(host);
	for (i = 0; i < (size_t)dbg_host_count; i++)
	{
		size_t l = strlen(dbg_hosts[i]);
		if (n < l) continue;
		if (!strcasecmp(host + n - l, dbg_hosts[i]) && (n == l || host[n - l - 1] == '.'))
			return true;
	}
	return false;
}

static void dbg_disarm(void)
{
	dbg_armed = false;
	dbg_host_count = 0;
	dbg_out_path[0] = 0;
}

// parse the host file. comments '#' : the first one that contains a '/'
// (a path-like token) selects the debug output file
static void dbg_load(void)
{
	FILE *F;
	char buf[512];

	dbg_disarm();
	F = fopen(dbg_file, "rt");
	if (!F) return;

	while (fgets(buf, sizeof(buf), F))
	{
		char *p = buf, *e;
		while (*p == ' ' || *p == '\t') p++;
		e = p + strlen(p);
		while (e > p && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t')) e--;
		*e = 0;
		if (!*p) continue;
		if (*p == '#')
		{
			// first path-carrying comment wins : strip '#' and leading spaces
			if (!dbg_out_path[0])
			{
				char *q = p + 1;
				while (*q == ' ' || *q == '\t') q++;
				if (*q == '/' && strlen(q) < sizeof(dbg_out_path))
					snprintf(dbg_out_path, sizeof(dbg_out_path), "%s", q);
			}
			continue;
		}
		if (dbg_host_count >= DBG_HOSTS_MAX) break;
		if (strlen(p) >= DBG_HOST_CAP) continue;
		dbg_lower(p);
		snprintf(dbg_hosts[dbg_host_count], DBG_HOST_CAP, "%s", p);
		dbg_host_count++;
	}
	fclose(F);

	dbg_armed = dbg_host_count > 0 && dbg_out_path[0] == '/';
}

// one-shot load at daemon startup : no periodic re-checks by design. the file
// appearing or changing later requires a restart
void dbg_hosts_load(void)
{
	struct stat st;
	if (!dbg_file[0]) return;
	if (stat(dbg_file, &st) != 0) return;
	dbg_mtime = st.st_mtime;
	dbg_load();
	if (dbg_armed)
		fprintf(stderr, "debug-hosts : %d host(s), output %s (loaded at startup, restart to reload)\n",
			dbg_host_count, dbg_out_path);
}

void dbg_hosts_set_context(const char *host)
{
	if (host && *host)
	{
		snprintf(dbg_ctx, sizeof(dbg_ctx), "%s", host);
		dbg_lower(dbg_ctx);
		dbg_ctx_valid = true;
	}
	else
		dbg_ctx_valid = false;
}

void dbg_hosts_clear_context(void)
{
	dbg_ctx_valid = false;
}

bool dbg_hosts_armed(void)
{
	return dbg_armed;
}

bool dbg_hosts_context_match(void)
{
	return dbg_armed && dbg_ctx_valid && dbg_host_match(dbg_ctx);
}

void dbg_hosts_log_va(const char *format, va_list args)
{
	FILE *F;
	if (!dbg_out_path[0]) return;
	F = fopen(dbg_out_path, "at");
	if (!F)
	{
		if (!dbg_open_failed)
		{
			fprintf(stderr, "debug-hosts : cannot open %s\n", dbg_out_path);
			dbg_open_failed = true;
		}
		return;
	}
	dbg_open_failed = false;
	fprint_localtime(F);
	fprintf(F, " : ");
	vfprintf(F, format, args);
	fprintf(F, "\n");
	fclose(F);
}
