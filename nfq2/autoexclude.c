#include "autoexclude.h"
#include "params.h"
#include "helpers.h"
#include "conntrack.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#if !defined(__CYGWIN__) && !defined(__ANDROID__)
#include <sys/wait.h>
#define AE_CAN_FORK 1
#endif

//#define HASH_BLOOM 20
#define HASH_NONFATAL_OOM 1
#undef HASH_FUNCTION
#define HASH_FUNCTION HASH_BER
#include "uthash.h"

#define AE_FAIL_RING_MAX	20	// hard cap of stored fail timestamps per host
#define AE_HOST_LEN_MAX		255
#define AE_CLEAN_RETENTION	86400	// keep idle history entries this long
#define AE_CURL_UA		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"

typedef struct ae_host {
	char *host;			// key, lowercased
	uint8_t state;
	uint8_t phase;
	uint32_t n_exclusions;		// ttl ladder position
	time_t fail_times[AE_FAIL_RING_MAX]; // ring of recent failed flow timestamps
	uint8_t fail_head;		// next write position in the ring
	uint8_t fail_count;		// valid entries in the ring
	time_t t_state;			// when current state/phase was entered
	time_t deadline;		// phase or cooldown deadline
	time_t exclude_until;		// AE_ST_EXCLUDED ttl end
	time_t t_last_activity;
	uint32_t next_ttl;		// ttl to use on the next exclusion, seconds
	uint8_t probe_attempts;	// active probe retry counter within current phase
	uint8_t po_attempts;	// pass-only client attempts observed in this probe
	uint8_t po_rst;		// early RSTs seen on pass-only attempts (provider block)
	bool l7_seen_tls, l7_seen_http; // protocols seen on attributed flows. picks the probe scheme
	time_t ok_times[3][4];	// recent attack-success timestamps per l7 (0=tls,1=http,2=other)
	uint8_t ok_head[3];
	uint8_t ok_count[3];
	uint8_t last_fail_l7;	// l7 of the most recent failed flow
	uint32_t n_strong;		// exclusions proven with strong B1 evidence (real client/curl success).
					// only strong proofs advance toward chronic : weak-B1 verdicts (stalls
					// without an RST, provider drop-blocks look the same) must not lock a
					// host out of its bypass forever
	bool probe_weak;		// current probe cycle entered reattack via weak B1
	uint32_t last_fail_profile, last_fail_strategy; // strategy attribution of the most recent failed flow (0 = none)
	uint32_t strategy_fail_count; // fails attributed to last_fail_strategy since it was set
	bool adopted;		// external controller owns this host : engine ignores it
	bool force_attack;	// owner override : this exact host must stay attacked even
				// when a parent domain is pass-only. persisted in the state file
	UT_hash_handle hh;
} ae_host;

#define AE_L7_TLS	0
#define AE_L7_HTTP	1
#define AE_L7_OTHER	2

static int ae_l7_idx(t_l7proto p)
{
	return p == L7_TLS ? AE_L7_TLS : p == L7_HTTP ? AE_L7_HTTP : AE_L7_OTHER;
}

static const char * ae_l7_str(int idx)
{
	return idx == AE_L7_TLS ? "tls" : idx == AE_L7_HTTP ? "http" : "other";
}

// how many attack successes within the veto window qualify a host as
// "zapret is helping it" (provider-blocked and bypassed). such hosts must
// never be auto-excluded : removing the bypass would break them for real
#define AE_VETO_OK		3
#define AE_VETO_WINDOW		1800

// manual override list (netrogat.txt). hosts here are never auto-managed
typedef struct ae_manual {
	char *str;
	UT_hash_handle hh;
} ae_manual;

// ip of a pass-only host. lets the reassemble/delay machinery be skipped for
// excluded hosts before the hostname is discovered from a multisegment ClientHello
typedef struct ae_ip {
	uint8_t addr[16];		// key : 4 or 16 bytes of the address
	size_t addrlen;
	char *host;			// hostname binding, checked live
	time_t t_last;
	UT_hash_handle hh;
} ae_ip;

#define AE_IP_MAX	1024

static ae_host *ae_hosts = NULL;
static ae_manual *ae_manual_hosts = NULL;
static ae_ip *ae_ip_hosts = NULL;
static file_mod_sig ae_manual_mod;
static time_t ae_manual_last_check;
static bool ae_dirty_list;		// pass-only set changed, list file rewrite is pending
static bool ae_dirty_state;	// durable state changed, state file rewrite is pending
static time_t ae_last_save_list, ae_last_save_state;
static file_mod_sig ae_list_modsig;	// our own list file signature (hot edit detection)
static time_t ae_list_last_check;
static file_mod_sig ae_mirror_sig_list, ae_mirror_sig_state;
static time_t ae_last_mirror;

static void ae_flow_failed(const char *hostname, const char *reason, int l7idx, const t_ctrack *ctrack);
static void ae_flow_succeeded(const char *hostname);
static void ae_probe_success(const char *hostname);
static ae_host * ae_find(const char *hostname);
static bool ae_adopted_match(const char *hostname);

#ifdef AE_CAN_FORK
static struct {
	bool active;
	pid_t pid;
	int fd;				// read end of the result pipe
	uint8_t phase;			// AE_PH_CURL_B1 or AE_PH_CURL_B2
	char host[AE_HOST_LEN_MAX + 1];
	time_t deadline;
} ae_child;
#endif

static void ae_logev(const char *fmt, ...)
{
	char buf[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	DLOG("autoexclude : %s\n", buf);
	if (*params.autoexclude_log)
	{
		// rotate the event log when it grows too big (tmpfs friendly)
		const char *mode = "a";
		struct stat st;
		if (!stat(params.autoexclude_log, &st) && st.st_size > 262144)
			mode = "w";
		FILE *F = fopen(params.autoexclude_log, mode);
		if (F)
		{
			char s[32];
			time_t t = time(NULL);
			struct tm tm;
			localtime_r(&t, &tm);
			strftime(s, sizeof(s), "%Y-%m-%d %H:%M:%S", &tm);
			fprintf(F, "%s %s\n", s, buf);
			fclose(F);
		}
	}
}

// host-scoped AE_* event on the adaptive telemetry bus. no-op when the bus is
// off : the human log above stays the only channel (current behaviour).
// strategy attribution comes from the tracked host when it exists
static void ae_bus_emit(const char *host, const char *event, const char *fmt, ...)
{
	char payload[256];
	va_list ap;
	ae_host *h;

	if (!host || !*params.adaptive_events_file) return;
	va_start(ap, fmt);
	vsnprintf(payload, sizeof(payload), fmt, ap);
	va_end(ap);
	h = ae_find(host);
	adaptive_emit_host(event, host, payload,
		h ? h->last_fail_profile : 0, h ? h->last_fail_strategy : 0);
}

static void ae_lowercase(char *s)
{
	for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

// suffix walk like hostlist search : full host, then parents while a dot remains.
// bare TLD is not checked.
static ae_host * ae_find(const char *hostname)
{
	char buf[AE_HOST_LEN_MAX + 1];
	const char *p = hostname;
	size_t l;

	for (;;)
	{
		l = strlen(p);
		if (!l || l > AE_HOST_LEN_MAX) return NULL;
		memcpy(buf, p, l + 1);
		ae_lowercase(buf);
		ae_host *h;
		HASH_FIND(hh, ae_hosts, buf, l, h);
		if (h) return h;
		p = strchr(p, '.');
		if (!p) return NULL;
		p++;
		if (!strchr(p, '.')) return NULL; // do not match bare TLD
	}
}

// exact-hostname lookup, no parent-domain walk. used by the control channel
// where the operator addresses one specific host (attack/adopt) and must not
// land on the parent entry
static ae_host * ae_find_exact(const char *hostname)
{
	char buf[AE_HOST_LEN_MAX + 1];
	ae_host *h;
	size_t l = strlen(hostname);

	if (!l || l > AE_HOST_LEN_MAX) return NULL;
	memcpy(buf, hostname, l + 1);
	ae_lowercase(buf);
	HASH_FIND(hh, ae_hosts, buf, l, h);
	return h;
}

static bool ae_manual_match(const char *hostname)
{
	char buf[AE_HOST_LEN_MAX + 1];
	const char *p = hostname;
	size_t l;

	for (;;)
	{
		l = strlen(p);
		if (!l || l > AE_HOST_LEN_MAX) return false;
		memcpy(buf, p, l + 1);
		ae_lowercase(buf);
		ae_manual *m;
		HASH_FIND(hh, ae_manual_hosts, buf, l, m);
		if (m) return true;
		p = strchr(p, '.');
		if (!p) return false;
		p++;
		if (!strchr(p, '.')) return false;
	}
	return false;
}

bool ae_is_pass_only(const char *hostname)
{
	ae_host *h;

	if (!params.ae_inited || !hostname) return false;
	h = ae_find(hostname);
	if (!h) return false;
	if (h->state == AE_ST_EXCLUDED) return true;
	if (h->state == AE_ST_PROBE && (h->phase == AE_PH_PASSIVE_WAIT || h->phase == AE_PH_CURL_B1)) return true;
	return false;
}

bool ae_wants_ticks(void)
{
	return params.ae_inited && (ae_hosts != NULL || ae_ip_hosts != NULL);
}

// remember that this address belongs to a pass-only host. the binding is checked
// live against the host state on lookup, so it is safe to keep it stale
void ae_ip_remember(const struct in_addr *ip4, const struct in6_addr *ip6, const char *hostname)
{
	ae_ip *e;
	size_t l;
	uint8_t buf[16];

	if (!params.ae_inited) return;
	if (ip4) { memcpy(buf, ip4, 4); l = 4; }
	else if (ip6) { memcpy(buf, ip6, 16); l = 16; }
	else return;

	HASH_FIND(hh, ae_ip_hosts, buf, l, e);
	if (!e)
	{
		if (HASH_COUNT(ae_ip_hosts) >= AE_IP_MAX)
		{
			// evict the oldest
			ae_ip *ec, *tmp, *oldest = NULL;
			HASH_ITER(hh, ae_ip_hosts, ec, tmp)
				if (!oldest || ec->t_last < oldest->t_last) oldest = ec;
			if (oldest)
			{
				HASH_DEL(ae_ip_hosts, oldest);
				free(oldest->host);
				free(oldest);
			}
		}
		if (!(e = (ae_ip*)malloc(sizeof(ae_ip)))) return;
		memset(e, 0, sizeof(*e));
		memcpy(e->addr, buf, l);
		e->addrlen = l;
		if (!(e->host = strdup(hostname)))
		{
			free(e);
			return;
		}
		HASH_ADD_KEYPTR(hh, ae_ip_hosts, e->addr, l, e);
	}
	e->t_last = time(NULL);
}

bool ae_ip_pass_only(const struct in_addr *ip4, const struct in6_addr *ip6)
{
	ae_ip *e;
	uint8_t buf[16];
	size_t l;

	if (!params.ae_inited) return false;
	if (ip4) { memcpy(buf, ip4, 4); l = 4; }
	else if (ip6) { memcpy(buf, ip6, 16); l = 16; }
	else return false;

	HASH_FIND(hh, ae_ip_hosts, buf, l, e);
	if (!e) return false;
	// live check : the host may have left the pass-only state (ttl expiry, re-attack)
	return ae_is_pass_only(e->host);
}

// copy the hostname bound to this address. used to backfill ctrack->hostname
// on flows that skip the reassemble machinery (which would discover it)
bool ae_ip_get_hostname(const struct in_addr *ip4, const struct in6_addr *ip6, char *buf, size_t buflen)
{
	ae_ip *e;
	uint8_t abuf[16];
	size_t l;

	if (!params.ae_inited) return false;
	if (ip4) { memcpy(abuf, ip4, 4); l = 4; }
	else if (ip6) { memcpy(abuf, ip6, 16); l = 16; }
	else return false;

	HASH_FIND(hh, ae_ip_hosts, abuf, l, e);
	if (!e) return false;
	snprintf(buf, buflen, "%s", e->host);
	return true;
}

static ae_host * ae_add(const char *hostname)
{
	bool oom = false;
	size_t l = strlen(hostname);
	ae_host *h;

	if (!l || l > AE_HOST_LEN_MAX) return NULL;
	if (!(h = (ae_host*)malloc(sizeof(ae_host)))) return NULL;
	memset(h, 0, sizeof(*h));
	if (!(h->host = malloc(l + 1)))
	{
		free(h);
		return NULL;
	}
	memcpy(h->host, hostname, l + 1);
	ae_lowercase(h->host);
	HASH_ADD_KEYPTR(hh, ae_hosts, h->host, l, h);
	if (oom)
	{
		free(h->host);
		free(h);
		return NULL;
	}
	return h;
}

static bool ae_host_pass_only(const ae_host *h);

static void ae_del(ae_host *h)
{
	// persistence : only durable changes rewrite files. deleting an entry
	// changes the pass-only set if it was pass-only, and the durable state
	// if it carried an exclusion history
	if (ae_host_pass_only(h)) ae_dirty_list = true;
	if (h->n_exclusions || h->state == AE_ST_EXCLUDED || h->state == AE_ST_NOTCAND)
		ae_dirty_state = true;
	HASH_DEL(ae_hosts, h);
	free(h->host);
	free(h);
}

// ttl ladder : first exclusion is short, then the base ttl, then doubling, capped
static uint32_t ae_ttl_for(const ae_host *h)
{
	uint32_t t;

	if (!h->n_exclusions) t = (uint32_t)params.autoexclude_ttl_first;
	else t = h->next_ttl ? h->next_ttl : (uint32_t)params.autoexclude_ttl;
	if (t > (uint32_t)params.autoexclude_ttl_max) t = (uint32_t)params.autoexclude_ttl_max;
	return t;
}

static void ae_set_state(ae_host *h, uint8_t state, uint8_t phase)
{
	bool bPassBefore = ae_host_pass_only(h);

	h->state = state;
	h->phase = phase;
	h->t_state = time(NULL);
	// probe phase transitions are not persisted (the loader maps them back
	// to CLEAN anyway), so they do not touch any file
	if (ae_host_pass_only(h) != bPassBefore) ae_dirty_list = true;
	if (state == AE_ST_EXCLUDED || state == AE_ST_NOTCAND ||
		bPassBefore || h->n_exclusions)
		ae_dirty_state = true;
}

// record an attack success for the veto : this host demonstrably works with
// tampering, zapret is helping it (typical for provider-blocked sites)
static void ae_ok_note(const char *hostname, int l7idx)
{
	ae_host *h = ae_find(hostname);
	time_t now = time(NULL);

	if (!h || l7idx < 0 || l7idx > AE_L7_OTHER) return;
	h->ok_times[l7idx][h->ok_head[l7idx]] = now;
	h->ok_head[l7idx] = (h->ok_head[l7idx] + 1) % 4;
	if (h->ok_count[l7idx] < 4) h->ok_count[l7idx]++;
	h->t_last_activity = now;
}

// true when the host worked under tampering recently in the same l7 that is
// now failing. such hosts are served by zapret : exclusion would remove the
// bypass and break them for real (youtube-class false positive)
static bool ae_veto(const ae_host *h)
{
	time_t now = time(NULL);
	int i, n = 0;

	if (h->last_fail_l7 > AE_L7_OTHER) return false;
	for (i = 0; i < 4; i++)
		if (h->ok_times[h->last_fail_l7][i] >= now - AE_VETO_WINDOW)
			n++;
	return n >= AE_VETO_OK;
}

static uint8_t ae_fail_threshold(const ae_host *h)
{
	// recurrence : re-suspend faster than the first suspicion
	if (h->n_exclusions)
	{
		int t = params.autoexclude_fail_flows - 1;
		return t < 2 ? 2 : (uint8_t)t;
	}
	return (uint8_t)params.autoexclude_fail_flows;
}

// drop timestamps older than the fail window. ring order is monotonic
// because timestamps are appended in chronological order.
static void ae_fail_prune(ae_host *h, time_t now)
{
	while (h->fail_count)
	{
		time_t t = h->fail_times[(h->fail_head + AE_FAIL_RING_MAX - h->fail_count) % AE_FAIL_RING_MAX];
		if (t < now - params.autoexclude_fail_window)
			h->fail_count--;
		else
			break;
	}
}

#ifdef AE_CAN_FORK

static void ae_child_close(void)
{
	if (ae_child.fd >= 0) close(ae_child.fd);
	memset(&ae_child, 0, sizeof(ae_child));
	ae_child.fd = -1;
}

static bool ae_probe_spawn(ae_host *h, uint8_t phase)
{
	int pipefd[2];
	pid_t pid;
	char url[AE_HOST_LEN_MAX + 16];
	char maxtime[8];

	if (ae_child.active) return false;

	if (pipe(pipefd))
	{
		DLOG_PERROR("autoexclude : pipe");
		return false;
	}
	pid = fork();
	if (pid < 0)
	{
		close(pipefd[0]);
		close(pipefd[1]);
		DLOG_PERROR("autoexclude : fork");
		return false;
	}
	if (pid == 0)
	{
		// child. result goes to the pipe, everything else to /dev/null
		close(pipefd[0]);
		if (dup2(pipefd[1], 1) < 0) _exit(127);
		close(pipefd[1]);
		int dn = open("/dev/null", O_RDWR);
		if (dn >= 0)
		{
			if (dup2(dn, 0) < 0) _exit(127);
			if (dup2(dn, 2) < 0) _exit(127);
			if (dn > 2) close(dn);
		}
		bool bhttp = h->l7_seen_http && !h->l7_seen_tls;
		char *argv[20];
		int argc = 0;

		snprintf(url, sizeof(url), "%s://%s/", bhttp ? "http" : "https", h->host);
		snprintf(maxtime, sizeof(maxtime), "%d", params.autoexclude_probe_maxtime);
		argv[argc++] = (char*)"curl";
		argv[argc++] = (char*)"-sS";
		argv[argc++] = (char*)"-o";
		argv[argc++] = (char*)"/dev/null";
		argv[argc++] = (char*)"--max-time";
		argv[argc++] = maxtime;
		argv[argc++] = (char*)"-A";
		argv[argc++] = (char*)AE_CURL_UA;
		if (!bhttp)
		{
			// tls1.2 with a small single-segment ClientHello : multi-segment CHs
			// trigger the platform reasm/offload stall lottery and poison the verdict
			argv[argc++] = (char*)"--tlsv1.2";
			argv[argc++] = (char*)"--tls-max";
			argv[argc++] = (char*)"1.2";
		}
		argv[argc++] = (char*)"-w";
		argv[argc++] = (char*)"%{http_code}";
		argv[argc++] = url;
		argv[argc] = NULL;
		execv(params.autoexclude_curl, argv);
		_exit(127);
	}
	close(pipefd[1]);
	fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
	ae_child_close();
	ae_child.active = true;
	ae_child.pid = pid;
	ae_child.fd = pipefd[0];
	ae_child.phase = phase;
	snprintf(ae_child.host, sizeof(ae_child.host), "%s", h->host);
	ae_child.deadline = time(NULL) + params.autoexclude_probe_maxtime + 5;
	return true;
}

#endif

// verdict after a positive differential check : our tampering breaks the host
static void ae_verdict_excluded(ae_host *h)
{
	uint32_t ttl = ae_ttl_for(h);

	// veto : the host works under tampering in the failing l7. zapret is
	// serving it (provider-blocked and bypassed) - exclusion would remove
	// the bypass and break it for real
	if (ae_veto(h))
	{
		ae_logev("%s : veto : works under tampering, zapret is helping this host. not excluding", h->host);
		ae_bus_emit(h->host, "AE_VETO", "at=verdict l7=%s", ae_l7_str(h->last_fail_l7));
		h->fail_count = 0;
		h->fail_head = 0;
		ae_set_state(h, AE_ST_CLEAN, AE_PH_NONE);
		return;
	}

	h->n_exclusions++;
	h->next_ttl = h->n_exclusions == 1 ?
		(uint32_t)params.autoexclude_ttl :
		(ttl * 2 > (uint32_t)params.autoexclude_ttl_max ? (uint32_t)params.autoexclude_ttl_max : ttl * 2);

	// chronic host : repeatedly proven broken by tampering. a user visiting
	// it every few hours must not re-win the exclusion (3+ page reloads)
	// after every ttl expiry. permanent until the line is removed manually
	if (params.autoexclude_sticky_after && h->n_exclusions >= (uint32_t)params.autoexclude_sticky_after)
	{
		h->exclude_until = 0; // forever
		ae_set_state(h, AE_ST_EXCLUDED, AE_PH_NONE);
		ae_logev("%s : verdict WE_BROKE_IT : chronic (exclusion #%u) : permanent, remove the line manually to re-enable", h->host, h->n_exclusions);
		ae_bus_emit(h->host, "AE_VERDICT", "verdict=WE_BROKE_IT ttl=permanent exclusion=%u", h->n_exclusions);
		ae_bus_emit(h->host, "AE_CHRONIC", "exclusion=%u", h->n_exclusions);
		return;
	}

	h->exclude_until = time(NULL) + ttl;
	ae_set_state(h, AE_ST_EXCLUDED, AE_PH_NONE);
	ae_logev("%s : verdict WE_BROKE_IT : excluded for %u s (exclusion #%u)", h->host, ttl, h->n_exclusions);
	ae_bus_emit(h->host, "AE_VERDICT", "verdict=WE_BROKE_IT ttl=%u exclusion=%u", ttl, h->n_exclusions);
}

static void ae_verdict_notcand(ae_host *h, const char *reason)
{
	h->deadline = time(NULL) + params.autoexclude_cooldown;
	ae_set_state(h, AE_ST_NOTCAND, AE_PH_NONE);
	ae_logev("%s : verdict NOT_CANDIDATE (%s) : not excluded, cooldown %d s", h->host, reason, params.autoexclude_cooldown);
	ae_bus_emit(h->host, "AE_VERDICT", "verdict=NOT_CANDIDATE reason=%s cooldown=%d", reason, params.autoexclude_cooldown);
}

static void ae_verdict_transient(ae_host *h, const char *reason)
{
	// site works with tampering. false alarm or transient outage
	h->fail_count = 0;
	h->fail_head = 0;
	ae_set_state(h, AE_ST_CLEAN, AE_PH_NONE);
	ae_logev("%s : verdict OK_TRANSIENT (%s) : returned to processing", h->host, reason);
	ae_bus_emit(h->host, "AE_VERDICT", "verdict=OK_TRANSIENT reason=%s", reason);
}

#ifdef AE_CAN_FORK

static void ae_child_dispatch(bool bok, bool binconclusive)
{
	ae_host *h = ae_find(ae_child.host);
	uint8_t phase = ae_child.phase;

	ae_child_close();
	if (!h || h->state != AE_ST_PROBE) return;

	if (binconclusive)
	{
		ae_logev("%s : probe inconclusive (curl could not run) : returned to processing", h->host);
		ae_bus_emit(h->host, "AE_VERDICT", "verdict=INCONCLUSIVE reason=curl_unavailable");
		h->fail_count = 0;
		h->fail_head = 0;
		h->probe_attempts = 0;
		ae_set_state(h, AE_ST_CLEAN, AE_PH_NONE);
		return;
	}

	if (phase == AE_PH_CURL_B1)
	{
		// connections to some cdns lose a per-connection lottery (platform
		// stall), a single failed probe is not conclusive. retry a few times
		if (!bok && ++h->probe_attempts < 3)
		{
			if (ae_probe_spawn(h, AE_PH_CURL_B1))
			{
				ae_logev("%s : probe B1 attempt %u failed, retrying", h->host, h->probe_attempts);
				return;
			}
		}
		h->probe_attempts = 0;
		if (bok)
		{
			h->deadline = time(NULL) + params.autoexclude_reattack_window;
			ae_set_state(h, AE_ST_PROBE, AE_PH_REATTACK);
			ae_logev("%s : probe B1 ok (works without tampering), re-attacking for %d s", h->host, params.autoexclude_reattack_window);
			ae_bus_emit(h->host, "AE_PROBE_B1", "source=curl result=ok");
			h->probe_weak = false; // the probe itself opened the site : strong proof
		}
		else if (h->po_attempts && !h->po_rst)
		{
			// all active probes stalled, but client pass-only attempts were
			// observed and none got an RST : weak B1, let the re-attack decide
			h->deadline = time(NULL) + params.autoexclude_reattack_window;
			ae_set_state(h, AE_ST_PROBE, AE_PH_REATTACK);
			ae_logev("%s : weak B1 : probes stalled, %u pass-only attempt(s) without an RST, re-attacking for %d s",
				h->host, h->po_attempts, params.autoexclude_reattack_window);
			ae_bus_emit(h->host, "AE_PROBE_B1", "source=curl result=weak po_attempts=%u", h->po_attempts);
			h->probe_weak = true; // stalls without an RST : a provider drop-block looks the same
		}
		else
		{
			ae_bus_emit(h->host, "AE_PROBE_B1", "source=curl result=fail");
			ae_verdict_notcand(h, "probe failed without tampering");
		}
	}
	else if (phase == AE_PH_CURL_B2)
	{
		// a failed B2 is the expected direction for a broken-by-us host, but
		// retry once to filter out the per-connection stall lottery
		if (bok)
		{
			h->probe_attempts = 0;
			ae_bus_emit(h->host, "AE_PROBE_B2", "source=curl result=ok");
			ae_verdict_transient(h, "probe B2 ok");
		}
		else if (++h->probe_attempts < 2)
		{
			if (ae_probe_spawn(h, AE_PH_CURL_B2))
			{
				ae_logev("%s : probe B2 attempt %u failed, retrying", h->host, h->probe_attempts);
				return;
			}
			h->probe_attempts = 0;
			ae_bus_emit(h->host, "AE_PROBE_B2", "source=curl result=fail");
			ae_verdict_excluded(h);
		}
		else
		{
			h->probe_attempts = 0;
			ae_bus_emit(h->host, "AE_PROBE_B2", "source=curl result=fail");
			ae_verdict_excluded(h);
		}
	}
}

static void ae_child_reap(time_t now)
{
	int status;
	pid_t r;
	char buf[64], code[8];
	ssize_t rd;
	bool bok = false, binconclusive = false;
	int exitcode;

	if (!ae_child.active) return;

	r = waitpid(ae_child.pid, &status, WNOHANG);
	if (!r)
	{
		if (now > ae_child.deadline)
		{
			DLOG("autoexclude : probe child timeout, killing\n");
			kill(ae_child.pid, SIGKILL);
		}
		return;
	}
	if (r < 0)
	{
		if (errno == EINTR) return;
		// child is gone without a status. treat as inconclusive
		ae_child_dispatch(false, true);
		return;
	}

	// curl writes only %{http_code} to stdout. keep the last printable token
	code[0] = 0;
	for (;;)
	{
		rd = read(ae_child.fd, buf, sizeof(buf));
		if (rd <= 0) break;
		size_t len = (size_t)rd, start = len;
		while (start > 0 && isprint((unsigned char)buf[start-1])) start--;
		if (len - start)
		{
			size_t cl = len - start;
			if (cl > sizeof(code)-1) cl = sizeof(code)-1;
			memcpy(code, buf + start, cl);
			code[cl] = 0;
		}
	}

	exitcode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
	if (exitcode == 127)
		binconclusive = true;
	else
		// success = curl completed and got any http status (1xx..5xx)
		bok = exitcode == 0 && code[0] >= '1' && code[0] <= '5';
	ae_child_dispatch(bok, binconclusive);
}

#endif

// ---------------- hooks from the packet path ----------------

void ae_hook_attacked(t_ctrack *ctrack)
{
	if (!params.ae_inited || !ctrack) return;
	ctrack->ae_attacked = true;
}

void ae_hook_retrans(t_ctrack *ctrack, const struct dissect *dis)
{
	if (!params.ae_inited || !ctrack || !ctrack->hostname || ctrack->hostname_is_ip) return;
	if (!ctrack->ae_attacked || ctrack->ae_finalized) return;
	if (dis->proto != IPPROTO_TCP || ctrack->pos.state == SYN) return;
	// same retransmission test as autohostlist : seq did not advance
	if ((ctrack->pos.client.uppos_prev - ctrack->pos.client.pos) & 0x80000000) return;

	ae_l7_note(ctrack->hostname, ctrack->l7proto);

	if (++ctrack->ae_retrans >= params.autoexclude_retrans_threshold)
	{
		ctrack->ae_finalized = true;
		ae_flow_failed(ctrack->hostname, "retrans", ae_l7_idx(ctrack->l7proto), ctrack);
	}
}

void ae_hook_udp(t_ctrack *ctrack, const t_ctrack_positions *tpos)
{
	if (!params.ae_inited || !ctrack || !ctrack->hostname || ctrack->hostname_is_ip) return;
	if (!ctrack->ae_attacked || ctrack->ae_finalized) return;

	if (!tpos) tpos = &ctrack->pos;
	if (tpos->server.pcounter > params.autoexclude_udp_in)
	{
		ctrack->ae_finalized = true;
		ae_flow_succeeded(ctrack->hostname);
	}
	else if (tpos->client.pcounter >= params.autoexclude_udp_out)
	{
		ctrack->ae_finalized = true;
		ae_flow_failed(ctrack->hostname, "udp", ae_l7_idx(ctrack->l7proto), ctrack);
	}
}

// first inbound bytes of a TLS flow must look like a server TLS record.
// wordpress-style breakage returns non-TLS garbage ("packet length too long").
// an early alert record also means the handshake failed.
static bool ae_tls_first_record_ok(const uint8_t *data, size_t len)
{
	uint16_t reclen;

	if (len < 5) return true; // too small to decide, more data may follow
	if (data[0] == 21) return false; // alert
	if (data[0] < 20 || data[0] > 23) return false;
	if (data[1] != 3) return false; // major version
	reclen = (uint16_t)((data[3] << 8) | data[4]);
	if (reclen > 18432 + 256) return false;
	return true;
}

// inbound bytes of an HTTP flow must look like an HTTP reply
static bool ae_http_reply_ok(const uint8_t *data, size_t len)
{
	if (len < 5) return true; // too small to decide, more data may follow
	if (memcmp(data, "HTTP/", 5)) return false;
	return true;
}

// remember which l7 protocols were seen on attributed flows of this host.
// a pure-http site must be probed with http : the https probe would always
// fail and produce a wrong NOT_CANDIDATE
void ae_l7_note(const char *hostname, t_l7proto l7proto)
{
	ae_host *h;

	if (!params.ae_inited || !hostname) return;
	if (l7proto != L7_TLS && l7proto != L7_HTTP) return;
	h = ae_find(hostname);
	if (!h) return;
	if (l7proto == L7_TLS) h->l7_seen_tls = true;
	else h->l7_seen_http = true;
}

void ae_hook_incoming(t_ctrack *ctrack, const struct dissect *dis, const struct in_addr *sdip4, const struct in6_addr *sdip6)
{
	if (!params.ae_inited || !ctrack || !ctrack->hostname || ctrack->hostname_is_ip) return;

	// bind the target ip to the host while the hostname is known and it is pass-only.
	// lets further connections skip the reassemble/delay machinery from the first fragment
	if (ae_is_pass_only(ctrack->hostname))
		ae_ip_remember(sdip4, sdip6, ctrack->hostname);

	if (dis->proto == IPPROTO_TCP && dis->tcp)
	{
		uint32_t rseq = ctrack->pos.server.seq_last - ctrack->pos.server.seq0;
		bool bRST = !!(dis->tcp->th_flags & TH_RST);

		ae_l7_note(ctrack->hostname, ctrack->l7proto);

		if (ctrack->ae_attacked && !ctrack->ae_finalized && rseq <= params.autoexclude_fail_maxseq)
		{
			if (bRST)
			{
				ctrack->ae_finalized = true;
				ae_flow_failed(ctrack->hostname, "rst", ae_l7_idx(ctrack->l7proto), ctrack);
				return;
			}
			if (dis->tcp->th_flags & TH_FIN)
			{
				// server closed the connection without any data. http sites
				// broken by tampering show exactly this : request acked, then
				// a bare FIN (no reply, no RST). a normal small exchange has
				// already finalized this flow on its data packets
				ctrack->ae_finalized = true;
				ae_flow_failed(ctrack->hostname, "fin", ae_l7_idx(ctrack->l7proto), ctrack);
				return;
			}
			if (dis->len_payload && ctrack->l7proto == L7_TLS &&
			    !ae_tls_first_record_ok(dis->data_payload, dis->len_payload))
			{
				ctrack->ae_finalized = true;
				ae_flow_failed(ctrack->hostname, "garbage", ae_l7_idx(ctrack->l7proto), ctrack);
				return;
			}
			if (dis->len_payload && ctrack->l7proto == L7_HTTP &&
			    !ae_http_reply_ok(dis->data_payload, dis->len_payload))
			{
				ctrack->ae_finalized = true;
				ae_flow_failed(ctrack->hostname, "garbage", ae_l7_idx(ctrack->l7proto), ctrack);
				return;
			}
		}
		if (!ctrack->ae_attacked)
		{
			// clean (pass-only) traffic got an early RST : the provider or the
			// server rejects it even without tampering. strong NOT_CANDIDATE
			if (bRST && rseq <= params.autoexclude_fail_maxseq)
			{
				ctrack->ae_finalized = true;
				ae_passonly_rst(ctrack->hostname);
				return;
			}
		}
		// any real server data (not RST, not garbage) means the flow works
		if (dis->len_payload && !bRST)
		{
			if (ctrack->ae_attacked && !ctrack->ae_finalized)
			{
				ctrack->ae_finalized = true;
				ae_ok_note(ctrack->hostname, ae_l7_idx(ctrack->l7proto));
				ae_flow_succeeded(ctrack->hostname);
			}
			else
				ae_probe_success(ctrack->hostname);
		}
	}
	else if (dis->proto == IPPROTO_UDP && dis->len_payload)
	{
		if (ctrack->ae_attacked && !ctrack->ae_finalized)
		{
			ctrack->ae_finalized = true;
			ae_ok_note(ctrack->hostname, ae_l7_idx(ctrack->l7proto));
			ae_flow_succeeded(ctrack->hostname);
		}
		else
			ae_probe_success(ctrack->hostname);
	}
}

// ---------------- state machine events ----------------

// outgoing data of a pass-only flow. counted once per flow. stalled clean
// connections (cdn lottery : data on the wire, nothing userspace-visible)
// still prove the absence of an early RST, which is the weak B1 signal
void ae_passonly_attempt(t_ctrack *ctrack)
{
	ae_host *h;

	if (!params.ae_inited || !ctrack || !ctrack->hostname || ctrack->hostname_is_ip) return;
	if (ctrack->ae_attacked || ctrack->ae_finalized) return;

	h = ae_find(ctrack->hostname);
	if (!h) return;
	if (h->state != AE_ST_PROBE) return;
	ctrack->ae_finalized = true; // count the flow once
	h->po_attempts++;
	h->t_last_activity = time(NULL);
	DLOG("autoexclude : pass-only attempt #%u for %s\n", h->po_attempts, h->host);
}

// clean traffic got an early RST : the site rejects it without tampering
void ae_passonly_rst(const char *hostname)
{
	ae_host *h;

	if (!params.ae_inited) return;
	h = ae_find(hostname);
	if (!h) return;
	h->t_last_activity = time(NULL);
	if (h->state == AE_ST_PROBE && (h->phase == AE_PH_PASSIVE_WAIT || h->phase == AE_PH_CURL_B1))
	{
		h->po_rst++;
		ae_logev("%s : clean traffic got an early RST (attempt %u) : looks provider-blocked", h->host, h->po_rst);
#ifdef AE_CAN_FORK
		if (ae_child.active && ae_child.phase == AE_PH_CURL_B1 && !strcmp(ae_child.host, h->host))
		{
			kill(ae_child.pid, SIGKILL);
			waitpid(ae_child.pid, NULL, 0);
			ae_child_close();
			h->probe_attempts = 0;
		}
#endif
		ae_verdict_notcand(h, "clean traffic got RST without tampering");
	}
}

static void ae_flow_failed(const char *hostname, const char *reason, int l7idx, const t_ctrack *ctrack)
{
	ae_host *h;
	time_t now = time(NULL);

	if (!params.ae_inited) return;
	if (ae_manual_match(hostname)) return; // manual list always wins
	if (ae_adopted_match(hostname)) return; // external controller owns this host

	h = ae_find(hostname);
	if (!h)
	{
		if (HASH_COUNT(ae_hosts) >= (unsigned)params.autoexclude_max_hosts)
		{
			// evict the oldest idle CLEAN entry if any, otherwise refuse
			ae_host *hc, *tmp, *oldest = NULL;
			HASH_ITER(hh, ae_hosts, hc, tmp)
			{
				if (hc->state == AE_ST_CLEAN && (!oldest || hc->t_last_activity < oldest->t_last_activity))
					oldest = hc;
			}
			if (!oldest)
			{
				static time_t t_last_refuse;
				if (now - t_last_refuse >= 60)
				{
					t_last_refuse = now;
					ae_logev("%s : failed flow (%s) ignored, max_hosts=%d reached", hostname, reason, params.autoexclude_max_hosts);
				}
				return;
			}
			ae_del(oldest);
		}
		if (!(h = ae_add(hostname)))
		{
			DLOG_ERR("autoexclude : out of memory\n");
			return;
		}
	}
	h->t_last_activity = now;
	if (l7idx >= AE_L7_TLS && l7idx <= AE_L7_OTHER) h->last_fail_l7 = (uint8_t)l7idx;
	// remember which strategy was attacking the failing flow : the controller
	// uses this attribution to rotate strategies instead of excluding hosts
	if (ctrack && ctrack->strategy_assigned)
	{
		if (h->last_fail_profile != ctrack->profile_id || h->last_fail_strategy != ctrack->strategy_id)
		{
			h->last_fail_profile = ctrack->profile_id;
			h->last_fail_strategy = ctrack->strategy_id;
			h->strategy_fail_count = 0;
		}
		h->strategy_fail_count++;
	}

	switch (h->state)
	{
	case AE_ST_COLLECT:
		ae_fail_prune(h, now);
		h->fail_times[h->fail_head] = now;
		h->fail_head = (h->fail_head + 1) % AE_FAIL_RING_MAX;
		if (h->fail_count < AE_FAIL_RING_MAX) h->fail_count++;
		ae_logev("%s : failed flow (%s) : %u/%u in %d s", h->host, reason, h->fail_count, ae_fail_threshold(h), params.autoexclude_fail_window);
		ae_bus_emit(h->host, "AE_FAIL", "signal=%s l7=%s count=%u threshold=%u",
			reason, ae_l7_str(l7idx), h->fail_count, ae_fail_threshold(h));
		if (h->fail_count >= ae_fail_threshold(h))
		{
			// veto : this host works under tampering, zapret serves it.
			// failing flows are a strategy problem (rotation territory),
			// not a reason to remove the bypass
			if (ae_veto(h))
			{
				ae_logev("%s : threshold reached but host works under tampering, zapret is helping it. not probing", h->host);
				ae_bus_emit(h->host, "AE_VETO", "at=threshold l7=%s", ae_l7_str(l7idx));
				h->fail_count = 0;
				h->fail_head = 0;
				break;
			}
			h->deadline = now + params.autoexclude_probe_wait;
			ae_set_state(h, AE_ST_PROBE, AE_PH_PASSIVE_WAIT);
			ae_logev("%s : fail threshold reached, entering probe (pass-only window)", h->host);
			ae_bus_emit(h->host, "AE_SUSPECT", "signal=%s l7=%s window=%d", reason, ae_l7_str(l7idx), params.autoexclude_fail_window);
			h->po_attempts = 0;
			h->po_rst = 0;
			h->probe_weak = false;
		}
		break;
	case AE_ST_PROBE:
		if (h->phase == AE_PH_REATTACK || h->phase == AE_PH_CURL_B2)
		{
			// differential proof : fails with tampering right after working without it
#ifdef AE_CAN_FORK
			if (ae_child.active && ae_child.phase == AE_PH_CURL_B2 && !strcmp(ae_child.host, h->host))
			{
				// the client verdict is faster than the running probe
				kill(ae_child.pid, SIGKILL);
				waitpid(ae_child.pid, NULL, 0);
				ae_child_close();
			}
#endif
			ae_bus_emit(h->host, "AE_PROBE_B2", "source=client result=fail signal=%s", reason);
			ae_verdict_excluded(h);
		}
		// PASSIVE_WAIT/CURL_B1 : host is pass-only, failures are not expected. ignore
		break;
	case AE_ST_CLEAN:
		// fresh fails after ttl expiry or idle : collect again
		h->fail_times[0] = now;
		h->fail_head = 1;
		h->fail_count = 1;
		ae_set_state(h, AE_ST_COLLECT, AE_PH_NONE);
		ae_logev("%s : failed flow (%s) after clean period, collecting again 1/%u", h->host, reason, ae_fail_threshold(h));
		ae_bus_emit(h->host, "AE_FAIL", "signal=%s l7=%s count=1 threshold=%u fresh=1",
			reason, ae_l7_str(l7idx), ae_fail_threshold(h));
		break;
	default:
		// AE_ST_EXCLUDED / AE_ST_NOTCAND : pass-only or cooldown, ignore
		break;
	}
}

static void ae_flow_succeeded(const char *hostname)
{
	ae_host *h;

	if (!params.ae_inited) return;
	h = ae_find(hostname);
	if (!h) return;
	h->t_last_activity = time(NULL);

	if (h->state == AE_ST_COLLECT)
	{
		if (h->fail_count)
		{
			ae_bus_emit(h->host, "AE_SUCCESS", "context=fail_counter_reset l7=%s", ae_l7_str(h->last_fail_l7));
			h->fail_count = 0;
			h->fail_head = 0;
			ae_logev("%s : flow succeeded with tampering : fail counter reset", h->host);
		}
	}
	else if (h->state == AE_ST_PROBE && h->phase == AE_PH_REATTACK)
	{
		ae_bus_emit(h->host, "AE_SUCCESS", "context=reattack l7=%s", ae_l7_str(h->last_fail_l7));
		ae_verdict_transient(h, "client success under re-attack");
	}
}

static void ae_probe_success(const char *hostname)
{
	ae_host *h;

	if (!params.ae_inited) return;
	h = ae_find(hostname);
	if (!h) return;
	h->t_last_activity = time(NULL);

	if (h->state == AE_ST_PROBE && (h->phase == AE_PH_PASSIVE_WAIT || h->phase == AE_PH_CURL_B1))
	{
		// passive B1 : client traffic works without tampering. accepted during
		// the active B1 too : browsers retry and beat the per-connection
		// cdn lottery faster than sequential probe attempts
#ifdef AE_CAN_FORK
		if (ae_child.active && ae_child.phase == AE_PH_CURL_B1 && !strcmp(ae_child.host, h->host))
		{
			kill(ae_child.pid, SIGKILL);
			waitpid(ae_child.pid, NULL, 0);
			ae_child_close();
			h->probe_attempts = 0;
		}
#endif
		h->deadline = time(NULL) + params.autoexclude_reattack_window;
		ae_set_state(h, AE_ST_PROBE, AE_PH_REATTACK);
		ae_logev("%s : client success in pass-only window (B1), re-attacking for %d s", h->host, params.autoexclude_reattack_window);
		ae_bus_emit(h->host, "AE_PROBE_B1", "source=client result=ok");
		h->probe_weak = false; // real data reached the client : strong proof
	}
	// other states : no event
}

// ---------------- persistence ----------------

static bool ae_write_file(const char *path, const char *content, size_t len)
{
	char tmp[PATH_MAX + 8];
	FILE *F;
	size_t w;
	bool b = false;

	// atomic path first
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	F = fopen(tmp, "w");
	if (F)
	{
		w = fwrite(content, 1, len, F);
		if (w == len)
		{
			if (!fclose(F))
			{
				if (!rename(tmp, path))
					b = true;
				else
					DLOG_PERROR("autoexclude : rename");
			}
		}
		else
		{
			DLOG_ERR("autoexclude : short write\n");
			fclose(F);
		}
	}
	if (!b)
	{
		unlink(tmp);
		// fallback : write in place. works when the directory is not writable
		// but the file itself is (root-owned dir, daemon-owned file)
		F = fopen(path, "w");
		if (F)
		{
			w = fwrite(content, 1, len, F);
			b = (w == len) && !fclose(F);
		}
	}
	return b;
}

static bool ae_host_pass_only(const ae_host *h)
{
	return h->state == AE_ST_EXCLUDED ||
		(h->state == AE_ST_PROBE && (h->phase == AE_PH_PASSIVE_WAIT || h->phase == AE_PH_CURL_B1));
}

static void ae_save_list(void)
{
	char *buf;
	size_t size = 16 * 1024, used = 0;
	ae_host *h, *tmp;
	int w;

	if (!(buf = malloc(size)))
	{
		DLOG_ERR("autoexclude : out of memory\n");
		return;
	}

	// pass-only hosts file. same format as hostlist exclude lists
	used = (size_t)snprintf(buf, size,
		"# autoexclude : hosts currently excluded from processing by nfqws2\n"
		"# managed automatically, hot-reloaded by the daemon. manual removal of a\n"
		"# line takes effect on reload (the daemon re-adds it only on a new verdict)\n");
	HASH_ITER(hh, ae_hosts, h, tmp)
	{
		if (!ae_host_pass_only(h)) continue;
		w = snprintf(buf + used, size - used, "%s\n", h->host);
		if (w < 0 || (size_t)w >= size - used) break;
		used += (size_t)w;
	}
	if (!ae_write_file(params.autoexclude_file, buf, used))
		DLOG_ERR("autoexclude : cannot write %s\n", params.autoexclude_file);

	free(buf);
	ae_dirty_list = false;
	ae_last_save_list = time(NULL);
	file_mod_signature(params.autoexclude_file, &ae_list_modsig);
}

static void ae_save_state(void)
{
	char *buf;
	size_t size = 16 * 1024, used = 0;
	ae_host *h, *tmp;
	int w;

	if (!(buf = malloc(size)))
	{
		DLOG_ERR("autoexclude : out of memory\n");
		return;
	}

	// durable state sidecar : host \t state \t n_exclusions \t exclude_until \t next_ttl \t l7
	used = (size_t)snprintf(buf, size,
		"# autoexclude state (managed by nfqws2). host\\tstate\\tn_exclusions\\texclude_until\\tnext_ttl\n");
	HASH_ITER(hh, ae_hosts, h, tmp)
	{
		if (h->state == AE_ST_CLEAN && !h->n_exclusions) continue;
		w = snprintf(buf + used, size - used, "%s\t%u\t%u\t%lld\t%u\t%u\t%u\n",
			h->host, h->state, h->n_exclusions, (long long)h->exclude_until, h->next_ttl,
			h->l7_seen_tls ? 1 : 0, h->l7_seen_http ? 1 : 0);
		if (w < 0 || (size_t)w >= size - used) break;
		used += (size_t)w;
	}
	if (!ae_write_file(params.autoexclude_state_file, buf, used))
		DLOG_ERR("autoexclude : cannot write %s\n", params.autoexclude_state_file);

	free(buf);
	ae_dirty_state = false;
	ae_last_save_state = time(NULL);
}

static void ae_save(void)
{
	if (ae_dirty_list) ae_save_list();
	if (ae_dirty_state) ae_save_state();
}

static bool ae_file_read_lines(const char *path, void (*cb)(const char *line, void *ctx), void *ctx)
{
	FILE *F;
	char buf[AE_HOST_LEN_MAX + 64];

	if (!path || !*path) return false;
	F = fopen(path, "r");
	if (!F) return false;
	while (fgets(buf, sizeof(buf), F))
	{
		char *p = buf, *e;
		while (*p && isspace((unsigned char)*p)) p++;
		if (*p == '#' || *p == ';' || *p == '/' || !*p) continue;
		e = p + strlen(p);
		while (e > p && isspace((unsigned char)e[-1])) e--;
		*e = 0;
		if (*p) cb(p, ctx);
	}
	fclose(F);
	return true;
}

static void ae_manual_line_cb(const char *line, void *ctx)
{
	ae_manual *m;
	size_t l = strlen(line);

	(void)ctx;
	HASH_FIND(hh, ae_manual_hosts, line, l, m);
	if (m) return;
	m = (ae_manual*)malloc(sizeof(ae_manual));
	if (!m) return;
	if (!(m->str = malloc(l + 1))) { free(m); return; }
	memcpy(m->str, line, l + 1);
	HASH_ADD_KEYPTR(hh, ae_manual_hosts, m->str, l, m);
}

static void ae_manual_reload(bool bForce)
{
	file_mod_sig ms;
	time_t now = time(NULL);

	if (!bForce && now - ae_manual_last_check < 5) return;
	ae_manual_last_check = now;
	if (!*params.autoexclude_manual_file) return;
	if (file_mod_signature(params.autoexclude_manual_file, &ms) &&
	    (bForce || memcmp(&ms, &ae_manual_mod, sizeof(ms))))
	{
		ae_manual *m, *tmp;
		HASH_ITER(hh, ae_manual_hosts, m, tmp)
		{
			HASH_DEL(ae_manual_hosts, m);
			free(m->str);
			free(m);
		}
		ae_manual_hosts = NULL;
		if (ae_file_read_lines(params.autoexclude_manual_file, ae_manual_line_cb, NULL))
		{
			ae_manual_mod = ms;
			DLOG("autoexclude : manual list %s loaded (%u hosts)\n", params.autoexclude_manual_file, HASH_COUNT(ae_manual_hosts));
		}
	}
}

struct ae_load_ctx {
	time_t now;
	bool bHaveState;
};

static void ae_state_line_cb(const char *line, void *ctx)
{
	struct ae_load_ctx *c = (struct ae_load_ctx*)ctx;
	char host[AE_HOST_LEN_MAX + 1];
	unsigned state, nexcl, next_ttl, tls, http;
	long long until;
	ae_host *h;

	if (sscanf(line, "%255s %u %u %lld %u %u %u", host, &state, &nexcl, &until, &next_ttl, &tls, &http) < 5) return;
	if (state > AE_ST_NOTCAND) return;
	h = ae_find(host);
	if (!h && !(h = ae_add(host))) return;
	h->n_exclusions = nexcl;
	h->next_ttl = next_ttl;
	h->l7_seen_tls = !!tls;
	h->l7_seen_http = !!http;
	h->t_last_activity = c->now;
	c->bHaveState = true;

	if (state == AE_ST_EXCLUDED)
	{
		if (until == 0 || until > c->now) // 0 = permanent chronic exclusion
		{
			h->exclude_until = until;
			ae_set_state(h, AE_ST_EXCLUDED, AE_PH_NONE);
		}
		else
			ae_set_state(h, AE_ST_CLEAN, AE_PH_NONE);
	}
	else if (state == AE_ST_NOTCAND)
	{
		if (until > c->now)
		{
			h->deadline = until;
			ae_set_state(h, AE_ST_NOTCAND, AE_PH_NONE);
		}
		else
			ae_set_state(h, AE_ST_CLEAN, AE_PH_NONE);
	}
	else
		ae_set_state(h, AE_ST_CLEAN, AE_PH_NONE);
}

static void ae_passonly_line_cb(const char *line, void *ctx)
{
	struct ae_load_ctx *c = (struct ae_load_ctx*)ctx;
	ae_host *h;

	if (c->bHaveState) return; // state file is the source of truth
	h = ae_find(line);
	if (!h && !(h = ae_add(line))) return;
	if (h->state == AE_ST_CLEAN)
	{
		h->exclude_until = c->now + ae_ttl_for(h);
		ae_set_state(h, AE_ST_EXCLUDED, AE_PH_NONE);
		DLOG("autoexclude : %s restored from list file (no state), ttl %u s\n", h->host, ae_ttl_for(h));
	}
}

// ---------------- hot list editing + flash mirror ----------------

// our own list file is a two-way interface : the daemon tracks its mtime and
// honours manual edits. a removed line demotes the host (chronic history is
// kept for the fast re-suspend path), an added line excludes the host
// permanently

typedef struct ae_strset {
	char *str;
	UT_hash_handle hh;
} ae_strset;

// hosts adopted by the external controller :
// the engine suspends tracking and verdicts for them, but keeps the entry and
// the ttl-ladder history durable (the custody flag itself is re-asserted by
// the controller through the control file after a daemon restart)
static bool ae_adopted_match(const char *hostname)
{
	ae_host *h;

	if (!params.ae_inited || !hostname) return false;
	h = ae_find(hostname);
	return h && h->adopted;
}

static void ae_list_presence_cb(const char *line, void *ctx)
{
	ae_strset **pp = (ae_strset**)ctx;
	ae_strset *e;
	size_t l = strlen(line);

	HASH_FIND(hh, *pp, line, l, e);
	if (e) return;
	if (!(e = malloc(sizeof(ae_strset)))) return;
	if (!(e->str = malloc(l + 1))) { free(e); return; }
	memcpy(e->str, line, l + 1);
	HASH_ADD_KEYPTR(hh, *pp, e->str, l, e);
}

static void ae_list_reload(void)
{
	ae_strset *present = NULL, *s, *stmp;
	ae_host *h, *tmp;

	ae_file_read_lines(params.autoexclude_file, ae_list_presence_cb, &present);

	// lines added manually : exclude permanently
	HASH_ITER(hh, present, s, stmp)
	{
		if (ae_adopted_match(s->str)) continue; // controller custody wins
		h = ae_find(s->str);
		if (!h)
		{
			char buf[AE_HOST_LEN_MAX + 1];
			char *p;
			snprintf(buf, sizeof(buf), "%s", s->str);
			for (p = buf; *p; p++) *p = (char)tolower((unsigned char)*p);
			if (!(h = ae_add(buf))) continue;
		}
		if (!ae_host_pass_only(h))
		{
			h->exclude_until = 0; // manual add means business
			ae_set_state(h, AE_ST_EXCLUDED, AE_PH_NONE);
			ae_logev("%s : added to the list manually : excluded permanently", h->host);
		}
	}

	// pass-only hosts missing from the file : demoted manually
	HASH_ITER(hh, ae_hosts, h, tmp)
	{
		if (!ae_host_pass_only(h)) continue;
		HASH_FIND(hh, present, h->host, strlen(h->host), s);
		if (s) continue;
#ifdef AE_CAN_FORK
		if (ae_child.active && !strcmp(ae_child.host, h->host))
		{
			kill(ae_child.pid, SIGKILL);
			waitpid(ae_child.pid, NULL, 0);
			ae_child_close();
			h->probe_attempts = 0;
		}
#endif
		ae_logev("%s : removed from the list manually : returning to processing", h->host);
		h->fail_count = 0;
		h->fail_head = 0;
		ae_set_state(h, AE_ST_CLEAN, AE_PH_NONE);
	}

	HASH_ITER(hh, present, s, stmp)
	{
		HASH_DEL(present, s);
		free(s->str);
		free(s);
	}
}

static void ae_list_check(void)
{
	file_mod_sig ms;

	if (!file_mod_signature(params.autoexclude_file, &ms)) return;
	if (!memcmp(&ms, &ae_list_modsig, sizeof(ms))) return;
	ae_list_modsig = ms;
	ae_list_reload();
}

// ---------------- external control channel ----------------

// hot command file for the external controller, one command per line :
//   exclude <host> [ttl|perm]   force pass-only for ttl seconds (default :
//                               base ttl), perm = until released. resolves
//                               to the parent domain entry when the exact
//                               host is unknown (exclusion inherits down)
//   release <host>              return the host to processing
//   adopt <host>                controller takes custody : the engine
//                               forgets the host, traffic processing stays
//   release-adopt <host>        engine tracking resumes
// exact hostname only. the file is DESIRED STATE : the whole file is
// re-executed on every mtime change (and after a daemon restart), commands
// are idempotent, the last command per host wins. keep the file
// authoritative, rewrite atomically

static char ae_control_file[PATH_MAX];
// nanosecond mtime + size : a controller may rewrite the file twice within
// one second, seconds-granularity mtime would miss it
static struct {
	time_t sec;
	long nsec;
	off_t size;
} ae_control_sig;

static void ae_control_exclude(const char *host, const char *arg)
{
	ae_host *h;
	uint32_t ttl = (uint32_t)params.autoexclude_ttl;

	if (ae_manual_match(host))
	{
		ae_logev("%s : control exclude ignored : manual list host", host);
		ae_bus_emit(host, "AE_CONTROL", "cmd=exclude host=%s result=manual_list", host);
		return;
	}
	if (arg)
	{
		if (!strcmp(arg, "perm") || !strcmp(arg, "permanent")) ttl = 0;
		else
		{
			ttl = (uint32_t)strtoul(arg, NULL, 10);
			if (!ttl) ttl = (uint32_t)params.autoexclude_ttl;
		}
	}
	h = ae_find(host);
	if (!h && !(h = ae_add(host))) return;
#ifdef AE_CAN_FORK
	if (ae_child.active && !strcmp(ae_child.host, h->host))
	{
		kill(ae_child.pid, SIGKILL);
		waitpid(ae_child.pid, NULL, 0);
		ae_child_close();
		h->probe_attempts = 0;
	}
#endif
	h->fail_count = 0;
	h->fail_head = 0;
	h->exclude_until = ttl ? time(NULL) + ttl : 0;
	ae_set_state(h, AE_ST_EXCLUDED, AE_PH_NONE);
	ae_dirty_state = true;
	if (ttl)
	{
		ae_logev("%s : control exclude : pass-only for %u s", h->host, ttl);
		ae_bus_emit(h->host, "AE_CONTROL", "cmd=exclude host=%s ttl=%u", h->host, ttl);
	}
	else
	{
		ae_logev("%s : control exclude : pass-only permanent", h->host);
		ae_bus_emit(h->host, "AE_CONTROL", "cmd=exclude host=%s ttl=permanent", h->host);
	}
}

static void ae_control_release(const char *host)
{
	ae_host *h = ae_find(host);

	if (!h)
	{
		ae_logev("%s : control release : unknown host", host);
		ae_bus_emit(host, "AE_CONTROL", "cmd=release host=%s result=unknown_host", host);
		return;
	}
	// same transition as a manual line removal : history is kept
#ifdef AE_CAN_FORK
	if (ae_child.active && !strcmp(ae_child.host, h->host))
	{
		kill(ae_child.pid, SIGKILL);
		waitpid(ae_child.pid, NULL, 0);
		ae_child_close();
		h->probe_attempts = 0;
	}
#endif
	h->fail_count = 0;
	h->fail_head = 0;
	ae_set_state(h, AE_ST_CLEAN, AE_PH_NONE);
	ae_logev("%s : control release : returning to processing", h->host);
	ae_bus_emit(h->host, "AE_CONTROL", "cmd=release host=%s result=ok", h->host);
}

static void ae_control_adopt(const char *host)
{
	ae_host *h;

	if (ae_manual_match(host))
	{
		ae_logev("%s : control adopt ignored : manual list host", host);
		ae_bus_emit(host, "AE_CONTROL", "cmd=adopt host=%s result=manual_list", host);
		return;
	}
	// exact-host semantics : adopting must never land on the parent entry
	h = ae_find_exact(host);
	if (!h && !(h = ae_add(host))) return;
#ifdef AE_CAN_FORK
	if (ae_child.active && !strcmp(ae_child.host, h->host))
	{
		kill(ae_child.pid, SIGKILL);
		waitpid(ae_child.pid, NULL, 0);
		ae_child_close();
	}
#endif
	// handover : drop pass-only (the controller decides for itself), keep the
	// exclusion-ladder history for when the custody is released
	if (ae_host_pass_only(h))
	{
		h->fail_count = 0;
		h->fail_head = 0;
		ae_set_state(h, AE_ST_CLEAN, AE_PH_NONE);
	}
	h->adopted = true;
	ae_dirty_state = true;
	ae_logev("%s : control adopt : external controller owns this host, engine suspends tracking", h->host);
	ae_bus_emit(h->host, "AE_CONTROL", "cmd=adopt host=%s result=ok", h->host);
}

static void ae_control_release_adopt(const char *host)
{
	ae_host *h = ae_find_exact(host);

	if (h && h->adopted)
	{
		h->adopted = false;
		h->t_last_activity = time(NULL);
		ae_dirty_state = true;
		ae_logev("%s : control release-adopt : engine tracking resumed", h->host);
		ae_bus_emit(h->host, "AE_CONTROL", "cmd=release-adopt host=%s result=ok", h->host);
	}
	else
	{
		ae_logev("%s : control release-adopt : host was not adopted", host);
		ae_bus_emit(host, "AE_CONTROL", "cmd=release-adopt host=%s result=not_adopted", host);
	}
}

static void ae_control_line_cb(const char *line, void *ctx)
{
	char cmd[32], host[AE_HOST_LEN_MAX + 1], arg[64];
	int n;

	(void)ctx;
	arg[0] = 0;
	n = sscanf(line, "%31s %255s %63s", cmd, host, arg);
	if (n < 2) return;
	ae_lowercase(cmd);
	ae_lowercase(host);
	if (n >= 3) ae_lowercase(arg);
	if (!strcmp(cmd, "exclude")) ae_control_exclude(host, n >= 3 ? arg : NULL);
	else if (!strcmp(cmd, "release-adopt")) ae_control_release_adopt(host);
	else if (!strcmp(cmd, "release")) ae_control_release(host);
	else if (!strcmp(cmd, "adopt")) ae_control_adopt(host);
	else ae_logev("control : unknown command '%s'", cmd);
}

static void ae_control_check(void)
{
	struct stat st;

	if (!*ae_control_file) return;
	if (stat(ae_control_file, &st)) return;
	if (st.st_mtim.tv_sec == ae_control_sig.sec && st.st_mtim.tv_nsec == ae_control_sig.nsec &&
		st.st_size == ae_control_sig.size) return;
	ae_control_sig.sec = st.st_mtim.tv_sec;
	ae_control_sig.nsec = st.st_mtim.tv_nsec;
	ae_control_sig.size = st.st_size;
	ae_file_read_lines(ae_control_file, ae_control_line_cb, NULL);
}

static bool ae_copy_file(const char *src, const char *dst)
{
	FILE *F;
	char *buf;
	long sz;
	size_t rd;
	bool b = false;

	F = fopen(src, "rb");
	if (!F) return false;
	if (fseek(F, 0, SEEK_END) || (sz = ftell(F)) < 0 || fseek(F, 0, SEEK_SET))
	{
		fclose(F);
		return false;
	}
	if (!(buf = malloc(sz ? (size_t)sz : 1)))
	{
		fclose(F);
		return false;
	}
	rd = fread(buf, 1, (size_t)sz, F);
	fclose(F);
	if (rd != (size_t)sz)
	{
		free(buf);
		return false;
	}
	b = ae_write_file(dst, buf, (size_t)sz);
	free(buf);
	return b;
}

// flash mirror : the working state lives in tmpfs and dies on reboot. chronic
// exclusions are worth surviving it, so both files are copied to flash at a
// low fixed cadence and only when they actually changed
static void ae_mirror_paths(char *lbuf, size_t lsize, char *sbuf, size_t ssize)
{
	snprintf(lbuf, lsize, "%s", params.autoexclude_mirror_file);
	snprintf(sbuf, ssize, "%s.state", params.autoexclude_mirror_file);
}

static void ae_mirror_update(bool bForce)
{
	time_t now = time(NULL);
	file_mod_sig sl, ss;
	bool bl, bs, bchanged = false;
	static time_t t_last_err;
	char mlbuf[PATH_MAX + 8], msbuf[PATH_MAX + 8];

	if (!*params.autoexclude_mirror_file) return;
	if (!bForce && now - ae_last_mirror < params.autoexclude_mirror_interval) return;
	ae_last_mirror = now;

	bl = file_mod_signature(params.autoexclude_file, &sl);
	bs = file_mod_signature(params.autoexclude_state_file, &ss);
	if (!bl && !bs) return;
	if (!bForce &&
	    (!bl || !memcmp(&sl, &ae_mirror_sig_list, sizeof(sl))) &&
	    (!bs || !memcmp(&ss, &ae_mirror_sig_state, sizeof(ss))))
		return;

	ae_mirror_paths(mlbuf, sizeof(mlbuf), msbuf, sizeof(msbuf));
	if (bl && memcmp(&sl, &ae_mirror_sig_list, sizeof(sl)))
		if (ae_copy_file(params.autoexclude_file, mlbuf)) { ae_mirror_sig_list = sl; bchanged = true; }
	if (bs && memcmp(&ss, &ae_mirror_sig_state, sizeof(ss)))
		if (ae_copy_file(params.autoexclude_state_file, msbuf)) { ae_mirror_sig_state = ss; bchanged = true; }

	if (!bchanged && now - t_last_err >= 3600)
	{
		t_last_err = now;
		DLOG_ERR("autoexclude : cannot write the flash mirror %s\n", mlbuf);
	}
	else if (bchanged)
		DLOG("autoexclude : flash mirror updated\n");
}

// after a reboot the tmpfs files are empty : restore them from the mirror
// before loading, so chronic exclusions survive
static void ae_mirror_restore(void)
{
	struct stat st, mst;
	char mlbuf[PATH_MAX + 8], msbuf[PATH_MAX + 8];

	if (!*params.autoexclude_mirror_file) return;
	if (!stat(params.autoexclude_file, &st) && st.st_size)
		return; // list file exists and is not empty
	ae_mirror_paths(mlbuf, sizeof(mlbuf), msbuf, sizeof(msbuf));
	if (stat(mlbuf, &mst) || !mst.st_size) return;
	if (ae_copy_file(mlbuf, params.autoexclude_file))
		DLOG("autoexclude : list restored from the flash mirror\n");
	if (!stat(msbuf, &mst) && mst.st_size)
		ae_copy_file(msbuf, params.autoexclude_state_file);
}

// ---------------- init / shutdown / timer ----------------

// resolve the state file location. by default it lives in tmpfs (/tmp),
// next to the daemon logs : it is a restart optimization only and must not
// wear flash-backed storage. override with --autoexclude-state-file
static void ae_state_path(void)
{
	const char *base, *p;

	// control channel : fixed path in tmpfs, hot-polled by mtime. inert
	// while the file does not exist
	snprintf(ae_control_file, sizeof(ae_control_file), "/tmp/nfqws2_ae_control");

	if (*params.autoexclude_state_file) return;
	if (!strncmp(params.autoexclude_file, "/tmp/", 5))
	{
		snprintf(params.autoexclude_state_file, sizeof(params.autoexclude_state_file), "%s.state", params.autoexclude_file);
		return;
	}
	base = params.autoexclude_file;
	p = strrchr(base, '/');
	base = p ? p + 1 : base;
	snprintf(params.autoexclude_state_file, sizeof(params.autoexclude_state_file), "/tmp/nfqws2_%s.state", base);
}

bool ae_prepare(void)
{
	FILE *F;

	if (!params.autoexclude) return true;

	ae_state_path();

	// both files must exist and be writable by the daemon user. ae_prepare runs
	// as root before the privilege drop, so it can create them in a root-owned
	// directory and hand ownership over
	F = fopen(params.autoexclude_file, "a+b");
	if (!F)
	{
		if (params.b_autoexclude_set)
		{
			DLOG_ERR("autoexclude : cannot create %s : %s\n", params.autoexclude_file, strerror(errno));
			return false;
		}
		DLOG_ERR("autoexclude : cannot create %s, feature self-disabled\n", params.autoexclude_file);
		params.autoexclude = false;
		return true;
	}
	fclose(F);

	if ((F = fopen(params.autoexclude_state_file, "a+b")))
		fclose(F);

#ifndef __CYGWIN__
	if (params.droproot)
	{
		if (!ensure_file_access(params.autoexclude_file))
		{
			DLOG_ERR("autoexclude : could not make '%s' accessible. it may not be writable after privilege drop\n", params.autoexclude_file);
			if (params.b_autoexclude_set) return false;
			params.autoexclude = false;
		}
		else
			ensure_file_access(params.autoexclude_state_file); // best effort
		// flash mirror files : create and hand over while still root, best
		// effort (a missing directory simply disables the mirror)
		if (*params.autoexclude_mirror_file)
		{
			char mlbuf[PATH_MAX + 8], msbuf[PATH_MAX + 8];
			ae_mirror_paths(mlbuf, sizeof(mlbuf), msbuf, sizeof(msbuf));
			if ((F = fopen(mlbuf, "a+b"))) fclose(F);
			if ((F = fopen(msbuf, "a+b"))) fclose(F);
			ensure_file_access(mlbuf);
			ensure_file_access(msbuf);
		}
	}
#endif
	return true;
}

void ae_init(void)
{
	struct ae_load_ctx ctx;

	if (!params.autoexclude || params.server)
	{
		if (params.autoexclude && params.server)
			DLOG("autoexclude disabled in server mode\n");
		return;
	}

	ae_state_path();
	ae_mirror_restore();
	ae_manual_reload(true);

	ctx.now = time(NULL);
	ctx.bHaveState = false;
	ae_file_read_lines(params.autoexclude_state_file, ae_state_line_cb, &ctx);
	ae_file_read_lines(params.autoexclude_file, ae_passonly_line_cb, &ctx);

	// current signatures : our own writes and external edits are told apart
	// by comparing against these
	file_mod_signature(params.autoexclude_file, &ae_list_modsig);
	file_mod_signature(params.autoexclude_file, &ae_mirror_sig_list);
	file_mod_signature(params.autoexclude_state_file, &ae_mirror_sig_state);
	ae_last_mirror = 0; // mirror as soon as anything changes

	// control channel starts with a clean signature : a pre-existing file
	// (controller was here before us) is executed on the first tick
	memset(&ae_control_sig, -1, sizeof(ae_control_sig));

#ifdef AE_CAN_FORK
	ae_child.fd = -1;
#endif
	params.ae_inited = true;
	DLOG_CONDUP("autoexclude active : file=%s state=%s manual=%s hosts=%u\n",
		params.autoexclude_file, params.autoexclude_state_file, params.autoexclude_manual_file, HASH_COUNT(ae_hosts));
}

void ae_shutdown(void)
{
	if (!params.ae_inited) return;
#ifdef AE_CAN_FORK
	if (ae_child.active)
	{
		kill(ae_child.pid, SIGKILL);
		waitpid(ae_child.pid, NULL, 0);
		ae_child_close();
	}
#endif
	ae_save();
	ae_mirror_update(true); // survive the restart on flash
}

// attacked flows that never got a single server packet are a fail signature of
// their own : the hw fastpath offload hides retransmissions from nfqueue, so
// the retransmission hook never fires for this class of silently dropped flows
static void ae_scan_conntrack(time_t nowboot)
{
	t_conntrack_pool *cp, *tmp;

	if (!params.conntrack.pool) return;
	HASH_ITER(hh, params.conntrack.pool, cp, tmp)
	{
		t_ctrack *t = &cp->track;
		if (!t->ae_attacked || t->ae_finalized || !t->hostname || t->hostname_is_ip) continue;
		if (cp->conn.l4proto != IPPROTO_TCP) continue;
		// only the SYNACK counts as a "server packet" here : compare sequence
		// positions, not packet counters. no advance means no data, no FIN,
		// no RST was ever seen from the server
		if (params.debug && t->hostname)
			DLOG("autoexclude scan : %s : attacked=%u finalized=%u seq0=%u seq_last=%u idle=%d\n",
				t->hostname, t->ae_attacked, t->ae_finalized,
				t->pos.server.seq0, t->pos.server.seq_last,
				(int)(nowboot - t->pos.t_last.tv_sec));
		// seq0 sits one past the SYNACK sequence, so a flow that got nothing
		// but the SYNACK shows seq_last == seq0+1. data, FIN or RST push it
		// further. no advance means the server never really answered
		if ((uint32_t)(t->pos.server.seq_last - t->pos.server.seq0) > 1) continue;
		if (nowboot - t->pos.t_last.tv_sec >= params.autoexclude_fail_silence)
		{
			t->ae_finalized = true;
			ae_flow_failed(t->hostname, "silence", ae_l7_idx(t->l7proto), t);
		}
	}
}

void ae_timer(void)
{
	ae_host *h, *tmp;
	time_t now = time(NULL);
	static time_t t_sm;

	if (!params.ae_inited) return;

#ifdef AE_CAN_FORK
	ae_child_reap(now);
#endif

	if (now == t_sm) return; // state machine runs once per second
	t_sm = now;

	ae_scan_conntrack(boottime());
	ae_manual_reload(false);
	ae_list_check();
	ae_control_check();
	ae_mirror_update(false);

	// drop stale ip bindings
	{
		ae_ip *e, *tmp;
		HASH_ITER(hh, ae_ip_hosts, e, tmp)
		{
			if (now - e->t_last > AE_CLEAN_RETENTION)
			{
				HASH_DEL(ae_ip_hosts, e);
				free(e->host);
				free(e);
			}
		}
	}

	HASH_ITER(hh, ae_hosts, h, tmp)
	{
		switch (h->state)
		{
		case AE_ST_COLLECT:
			ae_fail_prune(h, now);
			if (!h->fail_count && !h->n_exclusions)
				ae_del(h); // idle, no history
			break;
		case AE_ST_PROBE:
			switch (h->phase)
			{
			case AE_PH_PASSIVE_WAIT:
				if (now >= h->deadline)
				{
					// weak B1 : pass-only client attempts were observed and none
					// of them got an early RST. the site does not reject clean
					// traffic (stalled attempts are the cdn lottery), so proceed
					// to the re-attack and let B2 decide
					if (h->po_attempts && !h->po_rst)
					{
						h->deadline = now + params.autoexclude_reattack_window;
						ae_set_state(h, AE_ST_PROBE, AE_PH_REATTACK);
						ae_logev("%s : weak B1 : %u pass-only attempt(s) without an RST, re-attacking for %d s",
							h->host, h->po_attempts, params.autoexclude_reattack_window);
						ae_bus_emit(h->host, "AE_PROBE_B1", "source=client result=weak po_attempts=%u", h->po_attempts);
						h->probe_weak = true;
						break;
					}
#ifdef AE_CAN_FORK
					if (!params.autoexclude_passive && ae_probe_spawn(h, AE_PH_CURL_B1))
						ae_set_state(h, AE_ST_PROBE, AE_PH_CURL_B1);
					else
#endif
					{
						// passive mode or fork unavailable : wait out the full probe window
						time_t t_end = h->t_state + params.autoexclude_probe_window;
						if (now >= t_end)
						{
							ae_logev("%s : probe window expired without a verdict : returned to processing", h->host);
							ae_bus_emit(h->host, "AE_VERDICT", "verdict=INCONCLUSIVE reason=probe_window_expired");
							h->fail_count = 0;
							h->fail_head = 0;
							ae_set_state(h, AE_ST_CLEAN, AE_PH_NONE);
						}
						else if (h->deadline < t_end)
							h->deadline = t_end;
					}
				}
				break;
			case AE_PH_CURL_B1:
			case AE_PH_CURL_B2:
#ifdef AE_CAN_FORK
				if (!ae_child.active || strcmp(ae_child.host, h->host))
				{
					// child finished without a dispatch (should not happen)
					ae_logev("%s : probe child lost : returned to processing", h->host);
					ae_bus_emit(h->host, "AE_VERDICT", "verdict=INCONCLUSIVE reason=probe_child_lost");
					h->fail_count = 0;
					h->fail_head = 0;
					ae_set_state(h, AE_ST_CLEAN, AE_PH_NONE);
				}
#else
				h->fail_count = 0;
				h->fail_head = 0;
				ae_set_state(h, AE_ST_CLEAN, AE_PH_NONE);
#endif
				break;
			case AE_PH_REATTACK:
				if (now >= h->deadline)
				{
#ifdef AE_CAN_FORK
					if (!params.autoexclude_passive && ae_probe_spawn(h, AE_PH_CURL_B2))
						ae_set_state(h, AE_ST_PROBE, AE_PH_CURL_B2);
					else
#endif
					{
						time_t t_end = h->t_state + params.autoexclude_probe_window;
						if (now >= t_end)
						{
							ae_logev("%s : re-attack window expired without a verdict : returned to processing", h->host);
							ae_bus_emit(h->host, "AE_VERDICT", "verdict=INCONCLUSIVE reason=reattack_window_expired");
							h->fail_count = 0;
							h->fail_head = 0;
							ae_set_state(h, AE_ST_CLEAN, AE_PH_NONE);
						}
						else if (h->deadline < t_end)
							h->deadline = t_end;
					}
				}
				break;
			}
			break;
		case AE_ST_EXCLUDED:
			// exclude_until == 0 means permanent (chronic host)
			if (h->exclude_until && now >= h->exclude_until)
			{
				// ttl expiry is the reprobe : the host returns to processing and
				// a still-broken site re-suspends fast through the reduced threshold
				ae_logev("%s : ttl expired, returning to processing (reprobe)", h->host);
				ae_set_state(h, AE_ST_CLEAN, AE_PH_NONE);
			}
			break;
		case AE_ST_NOTCAND:
			if (now >= h->deadline)
				ae_set_state(h, AE_ST_CLEAN, AE_PH_NONE);
			break;
		case AE_ST_CLEAN:
			// adopted entries keep their history indefinitely
			if (!h->adopted && now - h->t_last_activity > AE_CLEAN_RETENTION)
				ae_del(h);
			break;
		}
	}

	if (ae_dirty_list && now - ae_last_save_list >= 1)
		ae_save_list();
	if (ae_dirty_state && now - ae_last_save_state >= 5)
		ae_save_state();
}

void ae_dump(void)
{
	static const char *statename[] = {"CLEAN","COLLECT","PROBE","EXCLUDED","NOTCAND"};
	static const char *phasename[] = {"NONE","PASSIVE_WAIT","CURL_B1","REATTACK","CURL_B2"};
	ae_host *h, *tmp;
	time_t now;

	printf("\nAUTOEXCLUDE DUMP\n");
	if (!params.ae_inited)
	{
		printf("disabled\n\n");
		return;
	}
	now = time(NULL);
	HASH_ITER(hh, ae_hosts, h, tmp)
	{
		printf("%s : %s/%s : fails %u/%u : excl #%u : next_ttl %u : ",
			h->host, statename[h->state], phasename[h->phase], h->fail_count, ae_fail_threshold(h),
			h->n_exclusions, h->next_ttl);
		if (h->state == AE_ST_EXCLUDED) printf(h->exclude_until ? "expires in %lld s" : "permanent", (long long)(h->exclude_until ? h->exclude_until - now : 0));
		else if (h->state == AE_ST_PROBE || h->state == AE_ST_NOTCAND) printf("deadline in %lld s", (long long)(h->deadline - now));
		printf("\n");
	}
	printf("manual hosts : %u\n", HASH_COUNT(ae_manual_hosts));
	printf("\n");
}
