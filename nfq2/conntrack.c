#define _GNU_SOURCE
#include "conntrack.h"
#include "darkmagic.h"
#include <arpa/inet.h>
#include <stdio.h>

#include "params.h"
#include "lua.h"

#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#ifdef __linux__
#include <sys/socket.h>
#include <sys/un.h>
#endif

static void taddr2str(uint8_t l3proto, const t_addr *a, char *buf, size_t bufsize);
static uint64_t adaptive_flow_seq = 1;
static uint64_t adaptive_strategy_seq = 1;
#define ADAPTIVE_EVENTS_MAX_BYTES (4U * 1024U * 1024U)
static bool adaptive_trace_limited;
static const char adaptive_trace_limit_marker[] = "# TRACE_LIMIT\tmax_bytes=4194304\n";
#ifdef __linux__
static int adaptive_event_socket = -1;
static uint64_t adaptive_event_drops;

static void adaptive_note_drop(void)
{
	if (adaptive_event_drops != UINT64_MAX) adaptive_event_drops++;
}

static bool adaptive_send_unix(const char *path, const char *line, size_t len)
{
	struct sockaddr_un addr;
	int flags;
	ssize_t sent;
	if (adaptive_event_socket < 0) {
		adaptive_event_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
		if (adaptive_event_socket < 0) { adaptive_note_drop(); return false; }
		flags = fcntl(adaptive_event_socket, F_GETFL, 0);
		if (flags < 0 || fcntl(adaptive_event_socket, F_SETFL, flags | O_NONBLOCK) < 0) {
			close(adaptive_event_socket);
			adaptive_event_socket = -1;
			adaptive_note_drop();
			return false;
		}
	}
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path) >= (int)sizeof(addr.sun_path)) {
		adaptive_note_drop();
		return false;
	}
	if (adaptive_event_drops) {
		char gap[64];
		int n = snprintf(gap, sizeof(gap), "# EVENT_GAP\t%" PRIu64 "\n", adaptive_event_drops);
		if (n <= 0 || (size_t)n >= sizeof(gap)) { adaptive_note_drop(); return false; }
		sent = sendto(adaptive_event_socket, gap, (size_t)n, MSG_DONTWAIT,
			(const struct sockaddr *)&addr, sizeof(addr));
		if (sent != n) { adaptive_note_drop(); return false; }
		adaptive_event_drops = 0;
	}
	sent = sendto(adaptive_event_socket, line, len, MSG_DONTWAIT,
		(const struct sockaddr *)&addr, sizeof(addr));
	if (sent != (ssize_t)len) { adaptive_note_drop(); return false; }
	return true;
}
#endif

static void adaptive_emit(t_ctrack *t, const char *event, const char *reason)
{
	int fd;
	struct stat st;
	char scope[64], host[256], dst[INET6_ADDRSTRLEN], line[1200];
	char *h;
	int n;
	struct timespec wall;
	if (!params.adaptive_events_file[0] || !t || !t->flow_id) return;
	snprintf(scope, sizeof(scope), "%s", t->adaptive_scope[0] ? t->adaptive_scope : "default");
	for (h=scope; *h; h++) if (*h=='\t' || *h=='\r' || *h=='\n') *h='_';
	h = t->hostname ? t->hostname : "";
	snprintf(host, sizeof(host), "%s", h);
	for (h=host; *h; h++) if (*h=='\t' || *h=='\r' || *h=='\n') *h='_';
	taddr2str(t->tuple.l3proto, &t->tuple.dst, dst, sizeof(dst));
	clock_gettime(CLOCK_REALTIME, &wall);
	n = snprintf(line, sizeof(line),
		"v2\t%llu\t%s\t%" PRIu64 "\t%u\t%u\t%" PRIu64 "\t%s\t%s\t%s\t%s\t%s\t%u\t%llu\t%llu\t%llu\t%llu\t%d\t%d\t%d\t%d\t%d\t%d\t%llu\t%llu\t%u\t%u\t%s\n",
		(unsigned long long)wall.tv_sec*1000 + wall.tv_nsec/1000000, event, t->flow_id, t->profile_id, t->strategy_id,
		t->strategy_generation, scope, host, t->tuple.l4proto==IPPROTO_TCP ? "tcp" : (t->l7proto==L7_QUIC ? "quic" : "udp"),
		t->tuple.l3proto==IPPROTO_IPV6 ? "ipv6" : "ipv4", dst, ntohs(t->tuple.dport),
		(unsigned long long)t->pos.client.pcounter, (unsigned long long)t->pos.server.pcounter,
		(unsigned long long)t->pos.client.pbcounter, (unsigned long long)t->pos.server.pbcounter,
		t->pos.server.pcounter>0, t->pos.server.pbcounter>0, t->client_rst, t->server_rst,
		t->client_fin, t->server_fin, (unsigned long long)t->t_start.tv_sec*1000 + t->t_start.tv_nsec/1000000,
		(unsigned long long)t->pos.t_last.tv_sec*1000 + t->pos.t_last.tv_nsec/1000000,
		(unsigned)t->clienthello_count, (unsigned)t->clienthello_retransmissions,
		reason ? reason : "");
	if (n<=0 || (size_t)n>=sizeof(line)) return;
	if (!strncmp(params.adaptive_events_file, "unix:", 5)) {
#ifdef __linux__
		(void)adaptive_send_unix(params.adaptive_events_file + 5, line, (size_t)n);
#endif
		return;
	}
	fd=open(params.adaptive_events_file, O_WRONLY|O_CREAT|O_APPEND, 0600);
	if (fd<0) return;
	(void)fchmod(fd, 0600);
	if (adaptive_trace_limited || fstat(fd, &st)<0 || st.st_size<0) {
		close(fd);
		return;
	}
	/* Reserve room for an explicit truncation marker; never grow /tmp without bound. */
	if ((uint64_t)st.st_size + (uint64_t)n >
		ADAPTIVE_EVENTS_MAX_BYTES - (sizeof(adaptive_trace_limit_marker)-1)) {
		if ((uint64_t)st.st_size + sizeof(adaptive_trace_limit_marker)-1 <= ADAPTIVE_EVENTS_MAX_BYTES) {
			ssize_t written = write(fd, adaptive_trace_limit_marker, sizeof(adaptive_trace_limit_marker)-1);
			if (written != (ssize_t)(sizeof(adaptive_trace_limit_marker)-1)) adaptive_trace_limited = true;
		}
		adaptive_trace_limited = true;
		close(fd);
		return;
	}
	{
		ssize_t written = write(fd, line, (size_t)n);
		if (written != n) adaptive_trace_limited = true;
	}
	close(fd);
}


#undef uthash_nonfatal_oom
#define uthash_nonfatal_oom(elt) ut_oom_recover(elt)

static bool oom = false;
static void ut_oom_recover(void *elem)
{
	oom = true;
}

static const char *connstate_s[] = { "SYN","ESTABLISHED","FIN" };

static void connswap(const t_conn *c, t_conn *c2)
{
	memset(c2, 0, sizeof(*c2));
	c2->l3proto = c->l3proto;
	c2->l4proto = c->l4proto;
	c2->src = c->dst;
	c2->dst = c->src;
	c2->sport = c->dport;
	c2->dport = c->sport;
}

void ConntrackClearHostname(t_ctrack *track)
{
	free(track->hostname);
	track->hostname = NULL;
	track->hostname_is_ip = false;
}
static void ConntrackClearTrack(t_ctrack *track)
{
	ConntrackClearHostname(track);
	ReasmClear(&track->reasm_client);
	rawpacket_queue_destroy(&track->delayed);
	luaL_unref(params.L, LUA_REGISTRYINDEX, track->lua_state);
	luaL_unref(params.L, LUA_REGISTRYINDEX, track->lua_instance_cutoff);
}

static void ConntrackFreeElem(t_conntrack_pool *elem)
{
	ConntrackClearTrack(&elem->track);
	free(elem);
}

static void ConntrackPoolDestroyPool(t_conntrack_pool **pp)
{
	t_conntrack_pool *elem, *tmp;
	HASH_ITER(hh, *pp, elem, tmp) {
		adaptive_emit(&elem->track, "FLOW_END", "process_exit");
		HASH_DEL(*pp, elem);
		ConntrackFreeElem(elem);
	}
}
void ConntrackPoolDestroy(t_conntrack *p)
{
	ConntrackPoolDestroyPool(&p->pool);
}

void ConntrackPoolInit(t_conntrack *p, time_t purge_interval, uint32_t timeout_syn, uint32_t timeout_established, uint32_t timeout_fin, uint32_t timeout_udp)
{
	p->timeout_syn = timeout_syn;
	p->timeout_established = timeout_established;
	p->timeout_fin = timeout_fin;
	p->timeout_udp = timeout_udp;
	p->t_purge_interval = purge_interval;
	p->t_last_purge = boottime();
	p->pool = NULL;
}

bool ConntrackExtractConn(t_conn *c, bool bReverse, const struct dissect *dis)
{
	memset(c, 0, sizeof(*c));
	if (dis->ip)
	{
		c->l3proto = IPPROTO_IP;
		c->dst.ip = bReverse ? dis->ip->ip_src : dis->ip->ip_dst;
		c->src.ip = bReverse ? dis->ip->ip_dst : dis->ip->ip_src;
	}
	else if (dis->ip6)
	{
		c->l3proto = IPPROTO_IPV6;
		c->dst.ip6 = bReverse ? dis->ip6->ip6_src : dis->ip6->ip6_dst;
		c->src.ip6 = bReverse ? dis->ip6->ip6_dst : dis->ip6->ip6_src;
	}
	else
		return false;
	extract_ports(dis->tcp, dis->udp, &c->l4proto, bReverse ? &c->dport : &c->sport, bReverse ? &c->sport : &c->dport);
	return c->l4proto!=IPPROTO_NONE;
}


static t_conntrack_pool *ConntrackPoolSearch(t_conntrack_pool *p, const t_conn *c)
{
	t_conntrack_pool *t;
	HASH_FIND(hh, p, c, sizeof(*c), t);
	return t;
}

static void ConntrackInitTrack(t_ctrack *t)
{
	memset(t, 0, sizeof(*t));
	t->l7proto = L7_UNKNOWN;
	t->reasm_client_payload = L7P_UNKNOWN;
	t->pos.client.scale = t->pos.server.scale = 0;
	rawpacket_queue_init(&t->delayed, RAW_PACKET_QUEUE_DELAYED_MAX);
	lua_newtable(params.L);
	t->lua_state = luaL_ref(params.L, LUA_REGISTRYINDEX);
	lua_newtable(params.L);
	t->lua_instance_cutoff = luaL_ref(params.L, LUA_REGISTRYINDEX);
}
static void ConntrackReInitTrack(t_ctrack *t)
{
	ConntrackClearTrack(t);
	ConntrackInitTrack(t);
}

static t_conntrack_pool *ConntrackNew(t_conntrack_pool **pp, const t_conn *c)
{
	t_conntrack_pool *ctnew;
	if (!(ctnew = malloc(sizeof(*ctnew)))) return NULL;
	ctnew->conn = *c;
	oom = false;
	HASH_ADD(hh, *pp, conn, sizeof(*c), ctnew);
	if (oom) { free(ctnew); return NULL; }
	ConntrackInitTrack(&ctnew->track);
	return ctnew;
}

static void ConntrackApplyPos(t_ctrack *t, bool bReverse, const struct dissect *dis)
{
	uint8_t scale;
	uint16_t mss;
	t_ctrack_position *direct, *reverse;

	direct = bReverse ? &t->pos.server : &t->pos.client;
	reverse = bReverse ? &t->pos.client : &t->pos.server;

	if (dis->ip6) direct->ip6flow = ntohl(dis->ip6->ip6_ctlun.ip6_un1.ip6_un1_flow);

	direct->winsize_calc = direct->winsize = ntohs(dis->tcp->th_win);
	if (t->pos.state == SYN)
	{
		// scale and mss only valid in syn packets
		scale = tcp_find_scale_factor(dis->tcp);
		if (scale != SCALE_NONE) direct->scale = scale;
		direct->mss = tcp_find_mss(dis->tcp);
	}
	else
		// apply scale only outside of the SYN stage
		direct->winsize_calc <<= direct->scale;

	direct->seq_last = ntohl(dis->tcp->th_seq);
	direct->pos = direct->seq_last + dis->len_payload;
	reverse->pos = reverse->seq_last = ntohl(dis->tcp->th_ack);
	if (t->pos.state == SYN)
		direct->uppos_prev = direct->uppos = direct->pos;
	else if (dis->len_payload)
	{
		direct->uppos_prev = direct->uppos;
		if (!((direct->pos - direct->uppos) & 0x80000000))
			direct->uppos = direct->pos;
	}

	if (!direct->rseq_over_2G && ((direct->seq_last - direct->seq0) & 0x80000000))
		direct->rseq_over_2G = true;
	if (!reverse->rseq_over_2G && ((reverse->seq_last - reverse->seq0) & 0x80000000))
		reverse->rseq_over_2G = true;
}

static void ConntrackFeedPacket(t_ctrack *t, bool bReverse, const struct dissect *dis)
{
	if (!bReverse && dis->tcp && dis->len_payload &&
		IsTLSClientHelloPartial(dis->data_payload, dis->len_payload))
	{
		uint32_t seq = ntohl(dis->tcp->th_seq);
		t->clienthello_count++;
		if (t->clienthello_seq_seen && seq == t->clienthello_first_seq)
			t->clienthello_retransmissions++;
		else if (!t->clienthello_seq_seen)
		{
			t->clienthello_seq_seen = true;
			t->clienthello_first_seq = seq;
		}
	}

	if (dis->tcp)
	{
		if (tcp_syn_segment(dis->tcp))
		{
			if (t->pos.state != SYN) {
				adaptive_emit(t, "FLOW_END", "tuple_reuse");
				ConntrackReInitTrack(t); // erase current entry
			}
			t->pos.client.seq0 = ntohl(dis->tcp->th_seq);
		}
		else if (tcp_synack_segment(dis->tcp))
		{
			// ignore SA dups
			uint32_t seq0 = ntohl(dis->tcp->th_ack) - 1;
			if (t->pos.state != SYN && t->pos.client.seq0 != seq0) {
				adaptive_emit(t, "FLOW_END", "tuple_reuse");
				ConntrackReInitTrack(t); // erase current entry
			}
			if (!t->pos.client.seq0) t->pos.client.seq0 = seq0;
			t->pos.server.seq0 = ntohl(dis->tcp->th_seq);
		}
		else if (dis->tcp->th_flags & (TH_FIN | TH_RST))
		{
			t->pos.state = FIN;
		}
		else
		{
			if (t->pos.state == SYN)
			{
				t->pos.state = ESTABLISHED;
				if (!bReverse && !t->pos.server.seq0) t->pos.server.seq0 = ntohl(dis->tcp->th_ack) - 1;
			}
		}

		ConntrackApplyPos(t, bReverse, dis);
	}
	if (bReverse)
	{
		t->pos.server.pcounter++;
		t->pos.server.pdcounter += !!dis->len_payload;
		t->pos.server.pbcounter += dis->len_payload;
		if (dis->tcp) {
			t->server_rst |= !!(dis->tcp->th_flags & TH_RST);
			t->server_fin |= !!(dis->tcp->th_flags & TH_FIN);
		}
	}
	else
	{
		t->pos.client.pcounter++;
		t->pos.client.pdcounter += !!dis->len_payload;
		t->pos.client.pbcounter += dis->len_payload;
		if (dis->tcp) {
			t->client_rst |= !!(dis->tcp->th_flags & TH_RST);
			t->client_fin |= !!(dis->tcp->th_flags & TH_FIN);
		}
	}

	clock_gettime(CLOCK_BOOT_OR_UPTIME, &t->pos.t_last);
	// make sure t_start gets exactly the same value as first t_last
	if (!t->t_start.tv_sec) t->t_start = t->pos.t_last;
}

static bool ConntrackPoolDoubleSearchPool(t_conntrack_pool **pp, const struct dissect *dis, t_ctrack **ctrack, bool *bReverse)
{
	t_conn conn, connswp;
	t_conntrack_pool *ctr;

	if (!ConntrackExtractConn(&conn, false, dis)) return false;
	if ((ctr = ConntrackPoolSearch(*pp, &conn)))
	{
		if (bReverse) *bReverse = false;
		if (ctrack) *ctrack = &ctr->track;
		return true;
	}
	else
	{
		connswap(&conn, &connswp);
		if ((ctr = ConntrackPoolSearch(*pp, &connswp)))
		{
			if (bReverse) *bReverse = true;
			if (ctrack) *ctrack = &ctr->track;
			return true;
		}
	}
	return false;
}
bool ConntrackPoolDoubleSearch(t_conntrack *p, const struct dissect *dis, t_ctrack **ctrack, bool *bReverse)
{
	return ConntrackPoolDoubleSearchPool(&p->pool, dis, ctrack, bReverse);
}

static bool ConntrackPoolFeedPool(t_conntrack_pool **pp, const struct dissect *dis, t_ctrack **ctrack, bool *bReverse)
{
	t_conn conn, connswp;
	t_conntrack_pool *ctr;
	bool b_rev;
	uint8_t proto = dis->tcp ? IPPROTO_TCP : dis->udp ? IPPROTO_UDP : IPPROTO_NONE;

	if (!ConntrackExtractConn(&conn, false, dis)) return false;
	if ((ctr = ConntrackPoolSearch(*pp, &conn)))
	{
		ConntrackFeedPacket(&ctr->track, (b_rev = false), dis);
		goto ok;
	}
	else
	{
		connswap(&conn, &connswp);
		if ((ctr = ConntrackPoolSearch(*pp, &connswp)))
		{
			ConntrackFeedPacket(&ctr->track, (b_rev = true), dis);
			goto ok;
		}
	}
	b_rev = dis->tcp && tcp_synack_segment(dis->tcp);
	if ((dis->tcp && tcp_syn_segment(dis->tcp)) || b_rev || dis->udp)
	{
		if ((ctr = ConntrackNew(pp, b_rev ? &connswp : &conn)))
		{
			ConntrackFeedPacket(&ctr->track, b_rev, dis);
			goto ok;
		}
	}
	return false;
ok:
	ctr->track.pos.ipproto = proto;
	if (!ctr->track.flow_id) {
		ctr->track.flow_id = ((uint64_t)(uint32_t)getpid() << 32) |
			(adaptive_flow_seq++ & UINT32_MAX);
		ctr->track.tuple = ctr->conn;
		adaptive_emit(&ctr->track, "FLOW_START", "");
	}
	if (ctrack) *ctrack = &ctr->track;
	if (bReverse) *bReverse = b_rev;
	return true;
}
bool ConntrackPoolFeed(t_conntrack *p, const struct dissect *dis, t_ctrack **ctrack, bool *bReverse)
{
	return ConntrackPoolFeedPool(&p->pool, dis, ctrack, bReverse);
}

static bool ConntrackPoolDropPool(t_conntrack_pool **pp, const struct dissect *dis)
{
	t_conn conn, connswp;
	t_conntrack_pool *t;
	if (!ConntrackExtractConn(&conn, false, dis)) return false;
	if (!(t = ConntrackPoolSearch(*pp, &conn)))
	{
		connswap(&conn, &connswp);
		t = ConntrackPoolSearch(*pp, &connswp);
	}
	if (!t) return false;
	adaptive_emit(&t->track, "FLOW_END", "drop");
	HASH_DEL(*pp, t); ConntrackFreeElem(t);
	return true;
}
bool ConntrackPoolDrop(t_conntrack *p, const struct dissect *dis)
{
	return ConntrackPoolDropPool(&p->pool, dis);
}

void ConntrackPoolPurge(t_conntrack *p)
{
	time_t tidle;
	time_t tnow;
	t_conntrack_pool *t, *tmp;

	if (!(tnow=boottime())) return;
	if ((tnow - p->t_last_purge) >= p->t_purge_interval)
	{
		HASH_ITER(hh, p->pool, t, tmp) {
			tidle = tnow - t->track.pos.t_last.tv_sec;
			if (t->track.b_cutoff ||
				(t->conn.l4proto == IPPROTO_TCP && (
				(t->track.pos.state == SYN && tidle >= p->timeout_syn) ||
					(t->track.pos.state == ESTABLISHED && tidle >= p->timeout_established) ||
					(t->track.pos.state == FIN && tidle >= p->timeout_fin))
					) || (t->conn.l4proto == IPPROTO_UDP && tidle >= p->timeout_udp)
				)
			{
				const char *reason = t->track.b_cutoff ? "cutoff" :
					(t->track.client_rst || t->track.server_rst ? "rst_timeout" :
					(t->conn.l4proto == IPPROTO_UDP ? "timeout_udp" :
					(t->track.pos.state == SYN ? "timeout_syn" :
					(t->track.pos.state == FIN ? "timeout_fin" : "timeout_established"))));
				adaptive_emit(&t->track, "FLOW_END", reason);
				HASH_DEL(p->pool, t); ConntrackFreeElem(t);
			}
		}
		p->t_last_purge = tnow;
	}
}

static void taddr2str(uint8_t l3proto, const t_addr *a, char *buf, size_t bufsize)
{
	if (!inet_ntop(family_from_proto(l3proto), a, buf, bufsize) && bufsize) *buf = 0;
}

void ConntrackPoolDump(const t_conntrack *p)
{
	t_conntrack_pool *t, *tmp;
	time_t tnow;
	char sa1[INET6_ADDRSTRLEN], sa2[INET6_ADDRSTRLEN];

	if (!(tnow=boottime())) return;
	HASH_ITER(hh, p->pool, t, tmp) {
		taddr2str(t->conn.l3proto, &t->conn.src, sa1, sizeof(sa1));
		taddr2str(t->conn.l3proto, &t->conn.dst, sa2, sizeof(sa2));
		printf("%s [%s]:%u => [%s]:%u : %s : t0=%llu last=t0+%llu now=last+%llu client=d%llu/n%llu/b%llu server=d%llu/n%llu/b%llu ",
			proto_name(t->conn.l4proto),
			sa1, t->conn.sport, sa2, t->conn.dport,
			t->conn.l4proto == IPPROTO_TCP ? connstate_s[t->track.pos.state] : "-",
			(unsigned long long)t->track.t_start.tv_sec, (unsigned long long)(t->track.pos.t_last.tv_sec - t->track.t_start.tv_sec), (unsigned long long)(tnow - t->track.pos.t_last.tv_sec),
			(unsigned long long)t->track.pos.client.pdcounter, (unsigned long long)t->track.pos.client.pcounter, (unsigned long long)t->track.pos.client.pbcounter,
			(unsigned long long)t->track.pos.server.pdcounter, (unsigned long long)t->track.pos.server.pcounter, (unsigned long long)t->track.pos.server.pbcounter);
		if (t->conn.l4proto == IPPROTO_TCP)
			printf("seq0=%u rseq=%u client.pos=%u ack0=%u rack=%u server.pos=%u client.mss=%u server.mss=%u client.wsize=%u:%d server.wsize=%u:%d",
				t->track.pos.client.seq0, t->track.pos.client.seq_last - t->track.pos.client.seq0, t->track.pos.client.pos - t->track.pos.client.seq0,
				t->track.pos.server.seq0, t->track.pos.server.seq_last - t->track.pos.server.seq0, t->track.pos.server.pos - t->track.pos.server.seq0,
				t->track.pos.client.mss, t->track.pos.server.mss,
				t->track.pos.client.winsize, t->track.pos.client.scale,
				t->track.pos.server.winsize, t->track.pos.server.scale);
		else
			printf("rseq=%u client.pos=%u rack=%u server.pos=%u",
				t->track.pos.client.seq_last, t->track.pos.client.pos,
				t->track.pos.server.seq_last, t->track.pos.server.pos);
		printf(" req_retrans=%u cutoff=%u lua_in_cutoff=%u lua_out_cutoff=%u hostname=%s l7proto=%s\n",
			t->track.req_retrans_counter, t->track.b_cutoff, t->track.b_lua_in_cutoff, t->track.b_lua_out_cutoff, t->track.hostname ? t->track.hostname : "", l7proto_str(t->track.l7proto));
	};
}


void ReasmClear(t_reassemble *reasm)
{
	free(reasm->packet);
	reasm->packet = NULL;
	reasm->size = reasm->size_present = 0;
}
bool ReasmInit(t_reassemble *reasm, size_t size_requested, uint32_t seq_start)
{
	reasm->packet = malloc(size_requested);
	if (!reasm->packet) return false;
	reasm->size = size_requested;
	reasm->size_present = 0;
	reasm->seq = seq_start;
	return true;
}
#define REASM_MAX_NEG 0x100000
bool ReasmFeed(t_reassemble *reasm, uint32_t seq, const void *payload, size_t len)
{
	uint32_t dseq = seq - reasm->seq;
	if (dseq && (dseq < REASM_MAX_NEG))
		return false; // fail session if a gap about to appear
	uint32_t neg_overlap = reasm->seq - seq;
	if (neg_overlap > REASM_MAX_NEG)
		return false; // too big minus

	size_t szcopy, szignore;
	szignore = (neg_overlap > reasm->size_present) ? neg_overlap - reasm->size_present : 0;
	if (szignore>=len) return true; // everyting is before the starting pos
	szcopy = len - szignore;
	neg_overlap -= szignore;
	if ((reasm->size_present - neg_overlap + szcopy) > reasm->size)
		return false; // buffer overflow
	// in case of seq overlap new data replaces old - unix behavior
	memcpy(reasm->packet + reasm->size_present - neg_overlap, (const uint8_t*)payload + szignore, szcopy);
	if (szcopy>neg_overlap)
	{
		reasm->size_present += szcopy - neg_overlap;
		reasm->seq += (uint32_t)szcopy - neg_overlap;
	}
	return true;
}
bool ReasmHasSpace(t_reassemble *reasm, size_t len)
{
	return (reasm->size_present + len) <= reasm->size;
}

bool ConntrackSetStrategy(t_ctrack *track, uint32_t profile_id, uint32_t strategy_id, const char *scope)
{
	if (!track || !track->flow_id || !profile_id || !strategy_id) return false;
	if (track->strategy_assigned) {
		if ((track->profile_id != profile_id || track->strategy_id != strategy_id ||
			strcmp(track->adaptive_scope, scope ? scope : "default")) && !track->strategy_conflict) {
			track->strategy_conflict = true;
			adaptive_emit(track, "STRATEGY_CONFLICT", "legacy_selection_changed");
		}
		return track->profile_id == profile_id && track->strategy_id == strategy_id;
	}
	track->profile_id = profile_id;
	track->strategy_id = strategy_id;
	snprintf(track->adaptive_scope, sizeof(track->adaptive_scope), "%s", scope ? scope : "default");
	track->strategy_generation = adaptive_strategy_seq++;
	track->strategy_assigned = true;
	adaptive_emit(track, "STRATEGY_APPLIED", "");
	return true;
}
