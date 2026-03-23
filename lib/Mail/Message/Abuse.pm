package Mail::Message::Abuse;

use strict;
use warnings;

our $VERSION = '1.00';

=head1 NAME

Mail::Message::Abuse - Analyse spam email to identify originating hosts and
hosted URLs, similar to SpamCop

=head1 SYNOPSIS

    use Mail::Message::Abuse;

    my $analyser = Mail::Message::Abuse->new();

    # Feed it a raw email (string or file handle)
    $analyser->parse_email($raw_email_text);

    # Find the most-likely true originating IP
    my $origin = $analyser->originating_ip();
    print "Originating IP : ", $origin->{ip},        "\n";
    print "Reverse DNS    : ", $origin->{rdns},       "\n";
    print "Abuse contact  : ", $origin->{abuse},      "\n";
    print "Confidence     : ", $origin->{confidence}, "\n";

    # Find every URL embedded in the message body
    my @urls = $analyser->embedded_urls();
    for my $u (@urls) {
        print "URL     : $u->{url}\n";
        print "Host    : $u->{host}\n";
        print "IP      : $u->{ip}\n";
        print "Hoster  : $u->{abuse}\n\n";
    }

    # Convenience: full report as a text string
    print $analyser->report();

=head1 DESCRIPTION

C<Mail::Message::Abuse> examines the raw source of a spam e-mail and attempts
to answer the two questions that SpamCop answers:

=over 4

=item 1. Where did the message I<really> come from?

The module walks the C<Received:> header chain from the I<innermost> trusted
hop outward, skipping forged or internal headers, until it finds the first
I<external> IP address.  It then performs a reverse-DNS lookup and a WHOIS
query (or Team-Cymru / ARIN lookup) to find the abuse contact for that
network block.

=item 2. Who hosts the advertised websites?

Every hyperlink and bare URL found in the message body (plain-text and HTML)
is extracted, the hostname is resolved to an IP, and a WHOIS / RDAP query
identifies the hosting organisation and its abuse contact.

=back

=head1 REQUIRED MODULES

    Net::DNS
    Net::Whois::IP   (or Net::Whois::IANA)
    LWP::UserAgent
    HTML::LinkExtor
    Socket
    IO::Socket::INET

All are available from CPAN.

=cut

# -----------------------------------------------------------------------
# Core dependencies
# -----------------------------------------------------------------------
use Socket          qw( inet_aton inet_ntoa );
use IO::Socket::INET;

# Optional / gracefully degraded
my $HAS_NET_DNS;
BEGIN {
    $HAS_NET_DNS = eval { require Net::DNS; 1 };
}

my $HAS_LWP;
BEGIN {
    $HAS_LWP = eval { require LWP::UserAgent; 1 };
}

my $HAS_HTML_LINKEXTOR;
BEGIN {
    $HAS_HTML_LINKEXTOR = eval { require HTML::LinkExtor; 1 };
}

# -----------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------

# Private/reserved IPv4 ranges that should never appear as the true origin
my @PRIVATE_RANGES = (
    qr/^127\./,                    # loopback
    qr/^10\./,                     # RFC 1918
    qr/^192\.168\./,               # RFC 1918
    qr/^172\.(?:1[6-9]|2\d|3[01])\./,  # RFC 1918
    qr/^169\.254\./,               # link-local
    qr/^::1$/,                     # IPv6 loopback
    qr/^fc/i,                      # IPv6 ULA
    qr/^fd/i,                      # IPv6 ULA
);

# Received header patterns
# We parse the most common forms produced by Sendmail, Postfix, Exim, qmail
my @RECEIVED_IP_RE = (
    qr/\[\s*([\d.]+)\s*\]/,                          # [1.2.3.4]
    qr/\(\s*[\w.-]*\s*\[?\s*([\d.]+)\s*\]?\s*\)/,   # (hostname [1.2.3.4])
    qr/from\s+[\w.-]+\s+([\d.]+)/,                   # from hostname 1.2.3.4
    qr/([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})/,  # bare dotted-quad fallback
);

# Well-known internal / relay hostnames to skip
my @SKIP_HOSTNAMES = (
    qr/localhost/i,
    qr/127\.0\.0\.1/,
    qr/\binternal\b/i,
    qr/\blocal\b/i,
);

# -----------------------------------------------------------------------
# Constructor
# -----------------------------------------------------------------------

=head1 METHODS

=head2 new( %options )

Create a new analyser object.

    my $a = Mail::Message::Abuse->new(
        timeout      => 15,      # DNS/HTTP timeout in seconds (default 10)
        trusted_relays => [      # IPs/CIDRs you operate yourself
            '203.0.113.0/24',
        ],
        verbose      => 0,       # Set to 1 for progress messages on STDERR
    );

=cut

sub new {
    my ($class, %opts) = @_;
    return bless {
        timeout        => $opts{timeout}        || 10,
        trusted_relays => $opts{trusted_relays} || [],
        verbose        => $opts{verbose}        || 0,
        _raw           => '',
        _headers       => [],
        _body          => '',
        _received      => [],
        _origin        => undef,
        _urls          => [],
    }, $class;
}

# -----------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------

=head2 parse_email( $text )

Feed the raw RFC 2822 email source (headers + body) to the analyser.
C<$text> may be a scalar string or a reference to one.

=cut

sub parse_email {
    my ($self, $text) = @_;
    $text = $$text if ref $text;

    $self->{_raw}     = $text;
    $self->{_origin}  = undef;
    $self->{_urls}    = [];

    $self->_split_message($text);
    $self->_parse_received_headers();
    return $self;
}

=head2 originating_ip()

Returns a hash-reference describing the most-likely true sending host:

    {
        ip         => '198.51.100.42',
        rdns       => 'mail.spammer.example',
        abuse      => 'abuse@isp.example',
        org        => 'Dodgy Hosting Ltd',
        confidence => 'high',   # high | medium | low
        note       => 'First external hop in Received chain',
    }

Returns C<undef> if no usable IP could be found.

=cut

sub originating_ip {
    my ($self) = @_;
    unless (defined $self->{_origin}) {
        $self->{_origin} = $self->_find_origin();
    }
    return $self->{_origin};
}

=head2 embedded_urls()

Returns a list of hash-references, one per unique URL found in the body:

    {
        url   => 'http://www.spamsite.example/buy-now',
        host  => 'www.spamsite.example',
        ip    => '203.0.113.99',
        org   => 'Rogue Hosting Corp',
        abuse => 'abuse@rogue-host.example',
    }

=cut

sub embedded_urls {
    my ($self) = @_;
    unless (@{ $self->{_urls} }) {
        $self->{_urls} = $self->_extract_and_resolve_urls();
    }
    return @{ $self->{_urls} };
}

=head2 report()

Returns a human-readable plain-text abuse report string.

=cut

sub report {
    my ($self) = @_;
    my @out;

    push @out, "=" x 70;
    push @out, "  Mail::Message::Abuse Report";
    push @out, "=" x 70;
    push @out, "";

    # --- Origin ---
    push @out, "[ ORIGINATING HOST ]";
    my $orig = $self->originating_ip();
    if ($orig) {
        push @out, "  IP         : $orig->{ip}";
        push @out, "  rDNS       : $orig->{rdns}"       if $orig->{rdns};
        push @out, "  Org        : $orig->{org}"         if $orig->{org};
        push @out, "  Abuse addr : $orig->{abuse}"       if $orig->{abuse};
        push @out, "  Confidence : $orig->{confidence}";
        push @out, "  Note       : $orig->{note}"        if $orig->{note};
    } else {
        push @out, "  (could not determine originating IP)";
    }
    push @out, "";

    # --- URLs ---
    push @out, "[ EMBEDDED URLs ]";
    my @urls = $self->embedded_urls();
    if (@urls) {
        for my $u (@urls) {
            push @out, "  URL   : $u->{url}";
            push @out, "  Host  : $u->{host}";
            push @out, "  IP    : $u->{ip}"    if $u->{ip};
            push @out, "  Org   : $u->{org}"   if $u->{org};
            push @out, "  Abuse : $u->{abuse}" if $u->{abuse};
            push @out, "";
        }
    } else {
        push @out, "  (no URLs found in message body)";
        push @out, "";
    }

    push @out, "=" x 70;
    return join("\n", @out) . "\n";
}

# -----------------------------------------------------------------------
# Private: message splitting
# -----------------------------------------------------------------------

sub _split_message {
    my ($self, $text) = @_;

    # Split on the first blank line separating headers from body
    my ($header_block, $body) = split /\r?\n\r?\n/, $text, 2;
    $body //= '';

    # Unfold continuation lines (RFC 2822 §2.2.3)
    $header_block =~ s/\r?\n([ \t]+)/ $1/g;

    my @headers;
    for my $line (split /\r?\n/, $header_block) {
        if ($line =~ /^([\w-]+)\s*:\s*(.*)/) {
            push @headers, { name => lc($1), value => $2 };
        }
    }

    $self->{_headers} = \@headers;
    $self->{_body}    = $body;

    # Collect Received: headers in the order they appear in the raw source
    # (topmost = added by your MTA = most recent; bottommost = oldest/closest to sender)
    $self->{_received} = [
        map  { $_->{value} }
        grep { $_->{name} eq 'received' }
        @headers
    ];

    $self->_debug(sprintf "Parsed %d headers, %d Received lines, body %d bytes",
        scalar @headers, scalar @{ $self->{_received} }, length $body);
}

# -----------------------------------------------------------------------
# Private: Received-chain analysis
# -----------------------------------------------------------------------

sub _parse_received_headers {
    my ($self) = @_;
    # Nothing to do here yet — lazy evaluation via originating_ip()
}

sub _find_origin {
    my ($self) = @_;

    my @received = @{ $self->{_received} };

    # RFC 2822: Received headers are prepended, so the LAST one in the list
    # is the one added by the first MTA that touched the message (closest to
    # the sender).  We walk from last to first, skipping private/trusted IPs.

    my @candidates;
    for my $hdr (reverse @received) {
        my $ip = $self->_extract_ip_from_received($hdr);
        next unless defined $ip;
        next if $self->_is_private($ip);
        next if $self->_is_trusted($ip);
        push @candidates, { ip => $ip, header => $hdr };
    }

    # The first candidate after stripping private/trusted is the origin
    unless (@candidates) {
        # Fallback: try the X-Originating-IP header (webmail clients)
        my ($xoip) = map { $_->{value} }
                     grep { $_->{name} eq 'x-originating-ip' }
                     @{ $self->{_headers} };
        if ($xoip) {
            $xoip =~ s/[\[\]\s]//g;
            unless ($self->_is_private($xoip)) {
                return $self->_enrich_ip($xoip, 'low',
                    'Taken from X-Originating-IP (unverified)');
            }
        }
        return undef;
    }

    my $best = $candidates[0];
    my $confidence = @candidates > 1 ? 'high' : 'medium';
    return $self->_enrich_ip($best->{ip}, $confidence,
        'First external hop in Received: chain');
}

sub _extract_ip_from_received {
    my ($self, $hdr) = @_;

    # Try each pattern in order of reliability
    for my $re (@RECEIVED_IP_RE) {
        if ($hdr =~ $re) {
            my $ip = $1;
            # Very basic sanity check
            next unless $ip =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
            my @oct = split /\./, $ip;
            next if grep { $_ > 255 } @oct;
            return $ip;
        }
    }
    return undef;
}

sub _is_private {
    my ($self, $ip) = @_;
    for my $re (@PRIVATE_RANGES) {
        return 1 if $ip =~ $re;
    }
    return 0;
}

sub _is_trusted {
    my ($self, $ip) = @_;
    for my $cidr (@{ $self->{trusted_relays} }) {
        return 1 if $self->_ip_in_cidr($ip, $cidr);
    }
    return 0;
}

# -----------------------------------------------------------------------
# Private: URL extraction and resolution
# -----------------------------------------------------------------------

sub _extract_and_resolve_urls {
    my ($self) = @_;

    my %seen;
    my @results;

    my @raw_urls = $self->_extract_urls_from_body($self->{_body});

    for my $url (@raw_urls) {
        next if $seen{$url}++;

        my ($host) = $url =~ m{https?://([^/:?\s#]+)}i;
        next unless $host;

        $self->_debug("Resolving URL host: $host");
        my $ip    = $self->_resolve_host($host) // '(unresolved)';
        my $whois = $ip ne '(unresolved)' ? $self->_whois_ip($ip) : {};

        push @results, {
            url   => $url,
            host  => $host,
            ip    => $ip,
            org   => $whois->{org}   // '(unknown)',
            abuse => $whois->{abuse} // '(unknown)',
        };
    }
    return \@results;
}

sub _extract_urls_from_body {
    my ($self, $body) = @_;
    my @urls;

    # 1. Extract from HTML <a href>, <img src> etc. if HTML::LinkExtor is available
    if ($HAS_HTML_LINKEXTOR) {
        my $p = HTML::LinkExtor->new(sub {
            my ($tag, %attrs) = @_;
            for my $attr (qw(href src action)) {
                push @urls, $attrs{$attr}
                    if $attrs{$attr} && $attrs{$attr} =~ m{^https?://}i;
            }
        });
        $p->parse($body);
    }

    # 2. Bare URL regex (catches plain-text and any HTML::LinkExtor misses)
    my @bare;
    while ($body =~ m{(https?://[^\s<>"'\)\]]+)}gi) {
        push @bare, $1;
    }

    # 3. Combine, deduplicate
    my %seen;
    my @all = grep { !$seen{$_}++ } (@urls, @bare);

    # Tidy trailing punctuation that is unlikely to be part of the URL
    s/[.,;:!?\)>\]]+$// for @all;

    return @all;
}

# -----------------------------------------------------------------------
# Private: DNS helpers
# -----------------------------------------------------------------------

sub _resolve_host {
    my ($self, $host) = @_;

    # If it already looks like an IP, return it directly
    return $host if $host =~ /^\d{1,3}(?:\.\d{1,3}){3}$/;

    if ($HAS_NET_DNS) {
        my $res     = Net::DNS::Resolver->new(tcp_timeout => $self->{timeout},
                                              udp_timeout => $self->{timeout});
        my $query   = $res->search($host, 'A');
        if ($query) {
            for my $rr ($query->answer) {
                return $rr->address if $rr->type eq 'A';
            }
        }
        return undef;
    }

    # Fallback: gethostbyname via Socket
    my $packed = inet_aton($host);
    return $packed ? inet_ntoa($packed) : undef;
}

sub _reverse_dns {
    my ($self, $ip) = @_;
    return undef unless $ip;

    if ($HAS_NET_DNS) {
        my $res   = Net::DNS::Resolver->new(tcp_timeout => $self->{timeout});
        my $query = $res->search($ip, 'PTR');
        if ($query) {
            for my $rr ($query->answer) {
                return $rr->ptrdname if $rr->type eq 'PTR';
            }
        }
        return undef;
    }

    # Fallback via gethostbyaddr
    return scalar gethostbyaddr(inet_aton($ip), Socket::AF_INET());
}

# -----------------------------------------------------------------------
# Private: WHOIS/RDAP
# -----------------------------------------------------------------------

=begin comment

_whois_ip() is the heart of the "who is the hosting company" logic.

We use a layered strategy:

  1. Query the ARIN RDAP REST endpoint (works for all RIRs via referral).
     RDAP returns structured JSON, which is far easier to parse reliably
     than legacy WHOIS plain text.

  2. If RDAP fails (no LWP, timeout, etc.) fall back to a raw TCP WHOIS
     query against whois.iana.org to find the correct RIR, then query
     that RIR's whois server.

  3. Parse the abuse-c / OrgAbuseEmail fields from the WHOIS text.

=end comment

=cut

sub _whois_ip {
    my ($self, $ip) = @_;
    my $result = {};

    # Try RDAP first (structured JSON)
    $result = $self->_rdap_lookup($ip) if $HAS_LWP;

    # Fallback to plain WHOIS
    unless ($result->{org}) {
        my $raw = $self->_raw_whois($ip, 'whois.iana.org');
        if ($raw) {
            # Find referral whois server
            my ($ref_server) = $raw =~ /whois:\s*([\w.-]+)/i;
            if ($ref_server) {
                my $detail = $self->_raw_whois($ip, $ref_server);
                $result    = $self->_parse_whois_text($detail) if $detail;
            } else {
                $result = $self->_parse_whois_text($raw);
            }
        }
    }

    return $result;
}

sub _rdap_lookup {
    my ($self, $ip) = @_;
    return {} unless $HAS_LWP;

    my $ua  = LWP::UserAgent->new(timeout => $self->{timeout},
                                  agent   => "Mail-Message-Abuse/$VERSION");
    # ARIN's RDAP endpoint will redirect to the correct RIR
    my $url = "https://rdap.arin.net/registry/ip/$ip";
    my $res = eval { $ua->get($url) };
    return {} unless $res && $res->is_success;

    my $json_text = $res->decoded_content;

    # Minimal JSON parsing without a JSON module
    my %info;

    # Organisation name
    if ($json_text =~ /"name"\s*:\s*"([^"]+)"/) {
        $info{org} = $1;
    }

    # CIDR / network handle
    if ($json_text =~ /"handle"\s*:\s*"([^"]+)"/) {
        $info{handle} = $1;
    }

    # Abuse contact — buried in the entities array
    # Look for role":"abuse then nearby email
    if ($json_text =~ /"abuse".*?"email"\s*:\s*"([^"]+)"/s) {
        $info{abuse} = $1;
    } elsif ($json_text =~ /"email"\s*:\s*"([^"@"]+@[^"]+)"/) {
        $info{abuse} = $1;
    }

    return \%info;
}

sub _raw_whois {
    my ($self, $query, $server) = @_;
    $server //= 'whois.iana.org';

    $self->_debug("WHOIS $server -> $query");

    my $sock = eval {
        IO::Socket::INET->new(
            PeerAddr => $server,
            PeerPort => 43,
            Proto    => 'tcp',
            Timeout  => $self->{timeout},
        );
    };
    return undef unless $sock;

    print $sock "$query\r\n";

    my $response = '';
    local $/ = undef;
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm($self->{timeout});
        $response = <$sock>;
        alarm(0);
    };
    close $sock;
    return $response;
}

sub _parse_whois_text {
    my ($self, $text) = @_;
    return {} unless $text;

    my %info;

    # OrgName / org-name / owner / descr
    for my $pat (qr/^OrgName:\s*(.+)/mi,
                 qr/^org-name:\s*(.+)/mi,
                 qr/^owner:\s*(.+)/mi,
                 qr/^descr:\s*(.+)/mi) {
        if ($text =~ $pat) {
            $info{org} //= $1;
            $info{org} =~ s/\s+$//;
        }
    }

    # Abuse email
    for my $pat (qr/OrgAbuseEmail:\s*(\S+@\S+)/mi,
                 qr/abuse-mailbox:\s*(\S+@\S+)/mi,
                 qr/abuse@\S+/mi) {
        if ($text =~ $pat) {
            $info{abuse} //= $1 // $&;
            $info{abuse} =~ s/\s+$//;
        }
    }

    # CIDR / inetnum
    if ($text =~ /^inetnum:\s*(.+)/mi) {
        $info{cidr} = $1;
        $info{cidr} =~ s/\s+$//;
    }
    if ($text =~ /^CIDR:\s*(.+)/mi) {
        $info{cidr} //= $1;
        $info{cidr} =~ s/\s+$//;
    }

    return \%info;
}

# -----------------------------------------------------------------------
# Private: IP enrichment (rDNS + WHOIS in one step)
# -----------------------------------------------------------------------

sub _enrich_ip {
    my ($self, $ip, $confidence, $note) = @_;

    my $rdns  = $self->_reverse_dns($ip);
    my $whois = $self->_whois_ip($ip);

    return {
        ip         => $ip,
        rdns       => $rdns  // '(no reverse DNS)',
        org        => $whois->{org}   // '(unknown)',
        abuse      => $whois->{abuse} // '(unknown)',
        confidence => $confidence,
        note       => $note,
    };
}

# -----------------------------------------------------------------------
# Private: CIDR helper
# -----------------------------------------------------------------------

sub _ip_in_cidr {
    my ($self, $ip, $cidr) = @_;

    # If it's a plain IP (no slash), do exact match
    unless ($cidr =~ m{/}) {
        return $ip eq $cidr;
    }

    my ($net_addr, $prefix) = split m{/}, $cidr;
    my $mask  = ~0 << (32 - $prefix);
    my $net_n = unpack 'N', inet_aton($net_addr) // return 0;
    my $ip_n  = unpack 'N', inet_aton($ip)       // return 0;
    return ($ip_n & $mask) == ($net_n & $mask);
}

# -----------------------------------------------------------------------
# Private: debug helper
# -----------------------------------------------------------------------

sub _debug {
    my ($self, $msg) = @_;
    print STDERR "[Mail::Message::Abuse] $msg\n" if $self->{verbose};
}

1;

__END__

=head1 DETAILED ALGORITHM

=head2 Tracing the Originating Host

SpamCop's core insight — which this module replicates — is that
C<Received:> headers are I<prepended> by each MTA, so:

    Received: from external.attacker.example [198.51.100.42]  <- added by YOUR MTA
    Received: from internal.yourco.example [10.0.0.1]         <- added by your internal relay
    Received: from mail.spammer.example [203.0.113.7]         <- added by external.attacker.example

Reading from the I<bottom up> (innermost to outermost), the first IP
that is neither private (RFC 1918 / loopback / link-local) nor in your
declared C<trusted_relays> list is the most credible origin.  Because
spammers can forge headers I<below> the first trusted hop, everything
above the first trusted hop is considered reliable.

The module assigns a B<confidence> level:

=over 4

=item B<high>

Multiple external hops were found and they are consistent.

=item B<medium>

Only a single external Received line was found (common for direct
injection).

=item B<low>

The IP was taken from an ancillary header such as
C<X-Originating-IP> (set by webmail clients) because no usable
C<Received:> lines were present.

=back

=head2 URL Host Identification

1. All URLs are extracted from both the plain-text and HTML parts of the
   body.  HTML is parsed with L<HTML::LinkExtor> when available; a
   fallback regex handles plain-text and catches any links
   C<HTML::LinkExtor> misses.

2. The hostname of each unique URL is resolved to an IPv4 address via
   L<Net::DNS> (preferred) or C<gethostbyname>.

3. An RDAP query is sent to C<https://rdap.arin.net/registry/ip/{ip}>,
   which automatically refers to the correct Regional Internet Registry
   (ARIN, RIPE, APNIC, LACNIC, AFRINIC).  The JSON response is lightly
   parsed to extract the network name and abuse e-mail.

4. If RDAP fails, a traditional WHOIS TCP query (port 43) is made to
   C<whois.iana.org>, the referral server is extracted from the response,
   and a second query is made to that RIR's WHOIS server.  The plain-text
   response is regex-parsed for C<OrgName>/C<org-name>/C<descr> and
   C<OrgAbuseEmail>/C<abuse-mailbox> fields.

=head1 CAVEATS AND LIMITATIONS

=over 4

=item *

B<Header forgery.> Spammers can insert fake C<Received:> headers below
the injection point.  The module trusts only headers added by MTAs
I<you> control (listed in C<trusted_relays>).  Everything else is
treated as potentially forged.

=item *

B<URL redirection.> The module resolves the I<literal> hostname in the
URL.  It does not follow HTTP redirects.  Many spam campaigns use
disposable link-shorteners; you may wish to follow redirects with
L<LWP::UserAgent> and then re-analyse the final URL.

=item *

B<IPv6.> WHOIS lookups for IPv6 addresses are supported in the RDAP
path; the raw-WHOIS fallback handles IPv6 queries as text but has not
been as extensively tested.

=item *

B<Rate limiting.> ARIN RDAP is free for reasonable query volumes.
WHOIS servers may block or throttle automated queries.  Add delays
between calls if you are processing large volumes.

=item *

B<No authentication.> This module does not send reports.  It produces
information suitable for composing a report to the abuse contacts it
discovers; actually sending the report is left to the caller.

=back

=head1 EXTENDING THE MODULE

The two primary extension points are:

=over 4

=item C<_whois_ip( $ip )>

Override this method in a subclass to use a commercial IP-intelligence
feed (e.g. MaxMind, IPinfo.io) instead of public WHOIS/RDAP.

=item C<_extract_urls_from_body( $body )>

Override to add MIME decoding, base64 unwrapping, or URL-redirect
following before URL analysis.

=back

=head1 EXAMPLE SCRIPT

    #!/usr/bin/env perl
    use strict;
    use warnings;
    use Mail::Message::Abuse;

    local $/ = undef;
    my $raw = <STDIN>;          # pipe the raw .eml file on STDIN

    my $a = Mail::Message::Abuse->new( verbose => 1 );
    $a->parse_email($raw);
    print $a->report();

Run as:

    cat spam.eml | perl check_spam.pl

=head1 SEE ALSO

L<Mail::SpamAssassin>, L<Net::DNS>, L<Net::Whois::IP>,
L<LWP::UserAgent>, L<HTML::LinkExtor>

SpamCop: L<https://www.spamcop.net/>

ARIN RDAP: L<https://rdap.arin.net/>

=head1 AUTHOR

Generated by Mail::Message::Abuse

=head1 LICENSE

This module is released under the same terms as Perl itself
(Artistic License 2.0 / GPL v1+).

=cut
