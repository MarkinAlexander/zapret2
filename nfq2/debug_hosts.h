#pragma once

// per-domain debug driven by a host file read once at startup, no config involvement.
// file format : one hostname per line; '#' comments are skipped; the first
// comment carries the debug output path, e.g.
//     # /tmp/debug-test.txt
//     ya.ru
//     www.youtube.com
// if the file is missing, empty or comments-only, or no output path comment
// is present, the subsystem is disarmed and DLOG stays silent (exactly like
// no --debug). while armed, DLOG lines emitted while processing a flow whose
// hostname matches a listed domain (suffix/parent-domain match) are appended
// to the output file; everything else is suppressed. DLOG_ERR keeps going to
// the console regardless.

void dbg_hosts_set_default_file(const char *path);
void dbg_hosts_load(void);	// one-shot load at startup; later file changes need a restart
bool dbg_hosts_armed(void);
// hostname of the flow currently being processed (NULL = none). the context
// is set by the packet path and cleared when the next packet begins
void dbg_hosts_set_context(const char *host);
void dbg_hosts_clear_context(void);
bool dbg_hosts_context_match(void);
// append a timestamped line for the current context host to the output file
void dbg_hosts_log_va(const char *format, va_list args);
