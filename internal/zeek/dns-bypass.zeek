##! Detects TLS connections whose SNI was never seen in a prior DNS query
##! from the same client within the correlation window.
##!
##! Installed by `hexwall zeek-setup`, which embeds this file in the hexwall
##! binary. Re-run that command after upgrading hexwall rather than editing
##! this copy: hexwall reads the notices it writes, so the two must match.

module DNSBypass;

export {
    redef enum Notice::Type += {
        PossibleBypass
    };

    ## How far back to look for a matching DNS query.
    const correlation_window = 10min &redef;
}

# client_ip -> set of domains it has queried recently, with last-seen time
global recent_queries: table[addr] of table[string] of time &create_expire=correlation_window;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    local client = c$id$orig_h;
    local domain = to_lower(query);

    if ( client !in recent_queries )
        recent_queries[client] = table();

    recent_queries[client][domain] = network_time();
    }

event ssl_established(c: connection)
    {
    if ( ! c?$ssl || ! c$ssl?$server_name )
        return;

    local client = c$id$orig_h;
    local sni = to_lower(c$ssl$server_name);

    if ( client in recent_queries && sni in recent_queries[client] )
        return;

    # hexwall reads the SNI from $sub; $msg is for humans reading notice.log.
    NOTICE([$note=PossibleBypass,
            $msg=fmt("SNI %s from %s with no prior DNS query", sni, client),
            $sub=sni,
            $src=client,
            $dst=c$id$resp_h,
            $p=c$id$resp_p,
            $conn=c]);
    }
