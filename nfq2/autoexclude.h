#pragma once

// autoexclude: detect hosts that are broken by our own desync tampering and
// temporarily exclude them from all processing. mirror of autohostlist:
// autohostlist adds hosts to the attack on failures, autoexclude removes them
// when the attack itself is the reason of the failure. state machine and
// persistence live inside the daemon, no config wiring is required.

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include "conntrack.h"

// host states
#define AE_ST_CLEAN	0	// idle, keeps recurrence history
#define AE_ST_COLLECT	1	// accumulating failed flows
#define AE_ST_PROBE	2	// differential check in progress
#define AE_ST_EXCLUDED	3	// pass only, until ttl expiry
#define AE_ST_NOTCAND	4	// cooldown after negative verdict

// probe phases (AE_ST_PROBE only)
#define AE_PH_NONE		0
#define AE_PH_PASSIVE_WAIT	1	// pass only, waiting for client success or probe deadline
#define AE_PH_CURL_B1		2	// curl probe without tampering
#define AE_PH_REATTACK		3	// tampering restored, waiting for client verdict or deadline
#define AE_PH_CURL_B2		4	// curl probe with tampering

bool ae_prepare(void);		// early init while root : create/check files. false = fatal
void ae_init(void);		// load persisted state, called before main loop
void ae_shutdown(void);		// save state, kill probe child
void ae_timer(void);		// state machine tick, call from main loop
bool ae_wants_ticks(void);	// true when state machine has entries and wants periodic wakeups
bool ae_is_pass_only(const char *hostname); // true when host must not be tampered at all
bool ae_ip_pass_only(const struct in_addr *ip4, const struct in6_addr *ip6); // ip of a pass-only host
bool ae_ip_get_hostname(const struct in_addr *ip4, const struct in6_addr *ip6, char *buf, size_t buflen); // copy the bound hostname
void ae_ip_remember(const struct in_addr *ip4, const struct in6_addr *ip6, const char *hostname); // bind ip to host
void ae_hook_attacked(t_ctrack *ctrack);				// flow was tampered
void ae_hook_incoming(t_ctrack *ctrack, const struct dissect *dis, const struct in_addr *sdip4, const struct in6_addr *sdip6); // server->client packet
void ae_hook_retrans(t_ctrack *ctrack, const struct dissect *dis);	// client data retransmission
void ae_hook_udp(t_ctrack *ctrack, const t_ctrack_positions *tpos);	// outgoing udp packet
void ae_l7_note(const char *hostname, t_l7proto l7proto);		// remember which l7 protocols this host speaks
void ae_passonly_attempt(t_ctrack *ctrack);		// outgoing data of a pass-only flow (once per flow)
void ae_passonly_rst(const char *hostname);		// clean traffic of this host got an early RST
void ae_dump(void);		// SIGUSR2 state dump
