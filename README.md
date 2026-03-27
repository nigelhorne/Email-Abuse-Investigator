# NAME

Mail::Message::Abuse - Analyse spam email to identify originating hosts,
hosted URLs, and suspicious domains

# SYNOPSIS

    use Mail::Message::Abuse;

    my $analyser = Mail::Message::Abuse->new( verbose => 1 );
    $analyser->parse_email($raw_email_text);

    # Originating IP and its network owner
    my $origin = $analyser->originating_ip();

    # All HTTP/HTTPS URLs found in the body
    my @urls  = $analyser->embedded_urls();

    # All domains extracted from mailto: links and bare addresses in the body
    my @mdoms = $analyser->mailto_domains();

    # All domains mentioned anywhere (union of the above)
    my @adoms = $analyser->all_domains();

    # Full printable report
    print $analyser->report();

# DESCRIPTION

`Mail::Message::Abuse` examines the raw source of a spam/phishing e-mail
and answers the questions abuse investigators ask:

- 1. Where did the message really come from?

    Walks the `Received:` chain, skips private/trusted IPs, and identifies the
    first external hop.  Enriches with rDNS, WHOIS/RDAP org name and abuse
    contact.

- 2. Who hosts the advertised web sites?

    Extracts every `http://` and `https://` URL from both plain-text and HTML
    parts, resolves each hostname to an IP, and looks up the network owner.

- 3. Who owns the reply-to / contact domains?

    Extracts domains from `mailto:` links, bare e-mail addresses in the body,
    the `From:`/`Reply-To:`/`Sender:`/`Return-Path:` headers, `DKIM-Signature: d=`
    (the signing domain), `List-Unsubscribe:` (the ESP or bulk-sender domain), and the
    `Message-ID:` domain.  For each unique domain it gathers:

    - Domain registrar and registrant (WHOIS)
    - Web-hosting IP and network owner (A record -> RDAP)
    - Mail-hosting IP and network owner (MX record -> RDAP)
    - DNS nameserver operator (NS record -> RDAP)
    - Whether the domain was recently registered (potential flag)

# REQUIRED MODULES

    Net::DNS
    LWP::UserAgent
    HTML::LinkExtor
    Socket
    IO::Socket::INET
    MIME::QuotedPrint  (core since Perl 5.8)
    MIME::Base64       (core since Perl 5.8)

All are available from CPAN.

# METHODS

## new( %options )

### Purpose

Constructs and returns a new `Mail::Message::Abuse` analyser object.  The
object is stateless until `parse_email()` is called; all analysis results
are stored on the object and retrieved via the public accessor methods
documented below.

A single object may be reused for multiple emails by calling `parse_email()`
again: all cached state from the previous message is discarded automatically.

### Usage

    # Minimal -- all options take safe defaults
    my $analyser = Mail::Message::Abuse->new();

    # With options
    my $analyser = Mail::Message::Abuse->new(
        timeout        => 15,
        trusted_relays => ['203.0.113.0/24', '10.0.0.0/8'],
        verbose        => 0,
    );

    $analyser->parse_email($raw_rfc2822_text);
    my $origin   = $analyser->originating_ip();
    my @urls     = $analyser->embedded_urls();
    my @domains  = $analyser->mailto_domains();
    my $risk     = $analyser->risk_assessment();
    my @contacts = $analyser->abuse_contacts();
    print $analyser->report();

### Arguments

All arguments are optional named parameters passed as a flat key-value list.

- `timeout` (integer, default 10)

    Maximum number of seconds to wait for any single network operation: DNS
    lookups, WHOIS TCP connections, and RDAP HTTP requests each respect this
    limit independently.  Set to 0 to disable timeouts (not recommended for
    production use).  Values must be non-negative integers.

- `trusted_relays` (arrayref of strings, default \[\])

    A list of IP addresses or CIDR blocks that are under your own
    administrative control and should be excluded from the Received: chain
    analysis.  Any hop whose IP matches an entry here is skipped when
    determining `originating_ip()`.

    Each element may be:

    - An exact IPv4 address: `'192.0.2.1'`
    - A CIDR block: `'192.0.2.0/24'`, `'10.0.0.0/8'`

    Use this to exclude your own mail relays, load balancers, and internal
    infrastructure so they are never mistaken for the spam origin.

    Example: if your inbound gateway at 203.0.113.5 adds a Received: header
    before passing the message to your mail server, pass
    `trusted_relays => ['203.0.113.5']` and that hop will be ignored.

- `verbose` (boolean, default 0)

    When true, diagnostic messages are written to STDERR as the object
    processes each email.  Messages are prefixed with `[Mail::Message::Abuse]`
    and describe each major analysis step (header parsing, DNS resolution,
    WHOIS queries, etc.).  Intended for development and debugging; leave false
    in production.

### Returns

A blessed `Mail::Message::Abuse` object.  The object is immediately usable;
no network I/O is performed during construction.

### Side Effects

None.  The constructor performs no I/O.  All network activity is deferred
until the first call to a method that requires it (`originating_ip()`,
`embedded_urls()`, `mailto_domains()`, or any method that calls them).

### Notes

- The `timeout` option uses `//` (defined-or), so `timeout => 0` is
stored correctly as zero.  All other constructor options also use `//`.
- Unknown option keys are silently ignored.
- The object is not thread-safe.  If you process multiple emails
concurrently, construct a separate `Mail::Message::Abuse` object per
thread or per-request.
- The `alarm()` mechanism used by the raw WHOIS client is not reliable on
Windows or inside threaded Perl interpreters.  All other functionality
works on those platforms; only WHOIS TCP connections may not respect the
timeout on affected platforms.

### API Specification

#### Input

    # Params::Validate::Strict compatible specification
    {
        timeout => {
            type     => SCALAR,
            regex    => qr/^\d+$/,
            optional => 1,
            default  => 10,
        },
        trusted_relays => {
            type     => ARRAYREF,
            optional => 1,
            default  => [],
            # Each element: exact IPv4 address or CIDR in the form a.b.c.d/n
            # where n is an integer in the range 0..32
        },
        verbose => {
            type     => SCALAR,
            regex    => qr/^[01]$/,
            optional => 1,
            default  => 0,
        },
    }

#### Output

    # Return::Set compatible specification
    {
        type  => 'Mail::Message::Abuse',  # blessed object
        isa   => 'Mail::Message::Abuse',

        # Guaranteed slots on the returned object (public API):
        #   timeout        => non-negative integer
        #   trusted_relays => arrayref of strings
        #   verbose        => 0 or 1
        #
        # All other slots are private (_raw, _headers, etc.) and
        # must not be accessed or modified by the caller.
    }

## parse\_email( $text )

### Purpose

Feeds a raw RFC 2822 email message to the analyser and prepares it for
subsequent interrogation.  This is the only method that must be called
before any other public method; all analysis is driven by the message
supplied here.

If the same object is used for a second message, calling `parse_email()`
again completely replaces all state from the first message.  No trace of
the previous email survives.

### Usage

    # From a scalar
    my $raw = do { local $/; <STDIN> };
    $analyser->parse_email($raw);

    # From a scalar reference (avoids copying large messages)
    $analyser->parse_email(\$raw);

    # Chained with new()
    my $analyser = Mail::Message::Abuse->new()->parse_email($raw);

    # Re-use the same object for multiple messages
    while (my $msg = $queue->next()) {
        $analyser->parse_email($msg->raw_text());
        my $risk = $analyser->risk_assessment();
        report_if_spam($analyser) if $risk->{level} ne 'INFO';
    }

### Arguments

- `$text` (scalar or scalar reference, required)

    The complete raw source of the email message as it arrived at your MTA,
    including all headers and the body, exactly as transferred over the wire.
    Both LF-only and CRLF line endings are accepted and handled transparently.

    A scalar reference is accepted as an alternative to a plain scalar.  The
    referent is dereferenced internally; the original variable is not modified.

    The following body encodings are decoded automatically:

    - `quoted-printable` (Content-Transfer-Encoding: quoted-printable)
    - `base64` (Content-Transfer-Encoding: base64)
    - `7bit` / `8bit` / `binary` (passed through as-is)

    Multipart messages (`multipart/alternative`, `multipart/mixed`, etc.)
    are split on their boundary and each text part decoded according to its
    own Content-Transfer-Encoding.  Non-text parts (attachments, inline images)
    are silently skipped.

### Returns

The object itself (`$self`), allowing method chaining:

    my $origin = Mail::Message::Abuse->new()->parse_email($raw)->originating_ip();

### Side Effects

The following work is performed synchronously, with no network I/O:

- Header parsing

    All RFC 2822 headers are parsed into an internal list.  Folded (multi-line)
    header values are unfolded per RFC 2822 section 2.2.3.  The `Received:`
    chain is extracted separately for origin analysis.  Header names are
    normalised to lower-case.  When duplicate headers are present, all copies
    are retained; accessor methods return the first occurrence.

- Body decoding

    The message body is decoded according to its Content-Transfer-Encoding and
    stored as plain text (`_body_plain`) and/or HTML (`_body_html`).
    Multipart messages have each qualifying part appended in order.

- Sending software extraction

    The headers `X-Mailer`, `User-Agent`, `X-PHP-Originating-Script`,
    `X-Source`, `X-Source-Args`, and `X-Source-Host` are extracted if
    present and stored for retrieval via `sending_software()`.

- Received chain tracking data

    Each `Received:` header is scanned for an IP address, an envelope
    recipient (`for <addr@domain.com>`), and a server tracking ID
    (`id token`).  Results are stored for retrieval via `received_trail()`,
    ordered oldest hop first.

- Cache invalidation

    All lazily-computed results from a previous call to `parse_email()` on
    the same object are discarded: `originating_ip()`, `embedded_urls()`,
    `mailto_domains()`, `risk_assessment()`, and the authentication-results
    cache are all reset to `undef` so the next call to any of them analyses
    the new message from scratch.

All network I/O (DNS lookups, WHOIS/RDAP queries) is deferred; it occurs
only when a caller first invokes `originating_ip()`, `embedded_urls()`,
or `mailto_domains()`.

### Notes

- If `$text` is an empty string, contains only whitespace, or contains no
header/body separator, the method returns `$self` without populating any
internal state.  All public methods will return empty lists, `undef`, or
safe zero-value results rather than dying.
- The raw text is stored verbatim (in `_raw`) and is reproduced in the
output of `abuse_report_text()`.  For very large messages this doubles
the memory used.  If memory is a concern, supply a scalar reference so at
least the method argument does not copy the string on the call stack.
- HTML bodies are stored separately from plain-text bodies.  URL and
email-address extraction runs across both.  A URL that appears only in the
HTML part and not in the plain-text part is still reported.
- Decoding errors in base64 or quoted-printable payloads are silenced; the
partially-decoded or raw bytes are used in place of correct output.  This
prevents malformed spam from causing exceptions during analysis.

### API Specification

#### Input

    # Params::Validate::Strict compatible specification
    # (positional argument, not named)
    [
        {
            type => SCALAR | SCALARREF,
            # SCALAR:    the complete raw email text
            # SCALARREF: reference to the complete raw email text;
            #            the referent must be a defined string
            # Both LF and CRLF line endings are accepted.
        },
    ]

#### Output

    # Return::Set compatible specification
    {
        type => 'Mail::Message::Abuse',  # the invocant, returned for chaining
        isa  => 'Mail::Message::Abuse',

        # Guaranteed post-conditions on the returned object:
        #   sending_software()  returns a (possibly empty) list
        #   received_trail()    returns a (possibly empty) list
        #   All lazy-analysis caches are reset (undef or empty)
        #   _raw contains the verbatim input text
    }

## originating\_ip()

Returns a hashref:

    {
        ip         => '209.85.218.67',
        rdns       => 'mail-ej1-f67.google.com',
        org        => 'Google LLC',
        abuse      => 'network-abuse@google.com',
        confidence => 'high',
        note       => 'First external hop in Received: chain',
    }

## embedded\_urls()

Returns a list of hashrefs for every HTTP/HTTPS URL in the body:

    {
        url   => 'https://spamsite.example/offer',
        host  => 'spamsite.example',
        ip    => '198.51.100.7',
        org   => 'Dodgy Hosting Ltd',
        abuse => 'abuse@dodgy.example',
    }

## mailto\_domains()

Returns a list of hashrefs, one per unique non-infrastructure domain found
in `mailto:` links, bare e-mail addresses in the body, and the envelope /
header fields `From:`, `Reply-To:`, `Sender:`, `Return-Path:`,
`DKIM-Signature: d=` (signing domain), `List-Unsubscribe:` (ESP domain),
and the domain portion of `Message-ID:`.

Each hashref contains:

    {
        domain      => 'sminvestmentsupplychain.com',
        source      => 'mailto in body',

        # Web hosting
        web_ip      => '104.21.30.10',
        web_org     => 'Cloudflare Inc',
        web_abuse   => 'abuse@cloudflare.com',

        # Mail hosting (MX)
        mx_host     => 'mail.example.com',
        mx_ip       => '198.51.100.5',
        mx_org      => 'Hosting Corp',
        mx_abuse    => 'abuse@hostingcorp.example',

        # DNS authority (NS)
        ns_host     => 'ns1.example.com',
        ns_ip       => '198.51.100.1',
        ns_org      => 'DNS Provider Inc',
        ns_abuse    => 'abuse@dnsprovider.example',

        # Domain registration (WHOIS)
        registrar   => 'GoDaddy.com LLC',
        registered  => '2024-11-01',
        expires     => '2025-11-01',
        recently_registered => 1,   # flag: < 180 days old

        # Raw domain WHOIS text (first 2 KB)
        whois_raw   => '...',
    }

## all\_domains()

Union of every domain seen across HTTP URLs and mailto/reply domains.

## sending\_software()

Returns a list of hashrefs identifying software or infrastructure
clues extracted from the email headers.  Each entry has:

    {
        header => 'X-PHP-Originating-Script',
        value  => '1000:newsletter.php',
        note   => 'PHP script on shared hosting - report to hosting abuse team',
    }

Headers examined: `X-Mailer`, `User-Agent`, `X-PHP-Originating-Script`,
`X-Source`, `X-Source-Args`, `X-Source-Host`.

## received\_trail()

Returns a list of hashrefs, one per `Received:` header (oldest first),
each containing the extracted IP, envelope recipient (`for` clause), and
the server's internal tracking ID (`id` clause).  These are the tracking
identifiers a receiving ISP's abuse team needs to look up the mail session
in their logs.

    (
      { received => '...raw header...', ip => '1.2.3.4',
        for => 'victim@example.com', id => 'ABC123' },
      ...
    )

## risk\_assessment()

Returns a hashref with an overall risk level and a list of specific
red flags found in the message:

    {
        level => 'HIGH',          # HIGH | MEDIUM | LOW | INFO
        score => 7,               # raw weighted score
        flags => [
            { severity => 'HIGH',   flag => 'recently_registered_domain',
              detail => 'firmluminary.com registered 2025-09-01 (< 180 days ago)' },
            { severity => 'MEDIUM', flag => 'residential_sending_ip',
              detail => 'rDNS 120-88-161-249.tpgi.com.au looks like a broadband line' },
            { severity => 'MEDIUM', flag => 'url_shortener',
              detail => 'bit.ly used - real destination hidden' },
            ...
        ],
    }

## abuse\_report\_text()

Returns a string suitable for pasting into an abuse report email.
It includes the risk summary, the key findings, and the full original
message headers.

    my $report = $analyser->abuse_report_text();
    # Then email to each address from $analyser->abuse_contacts()

## abuse\_contacts()

Returns a de-duplicated list of hashrefs, one per party that should
receive an abuse report, in priority order:

    {
        role    => 'Sending ISP',          # human-readable role
        address => 'abuse@senderisp.example',
        note    => 'IP block 120.88.0.0/14 owner',
        via     => 'ip-whois',             # ip-whois | domain-whois | provider-table | rdap
    }

Roles produced (in order):

    Sending ISP            - network owner of the originating IP
    URL host               - network owner of each unique web-server IP
    Mail host (MX)         - network owner of the domain's MX record IP
    DNS host (NS)          - network owner of the authoritative NS IP
    Domain registrar       - registrar abuse contact from domain WHOIS
    Account provider       - e.g. Gmail / Outlook for the From:/Sender: account
    DKIM signer            - the organisation whose key signed the message
    ESP / bulk sender      - identified via List-Unsubscribe: domain

Addresses are deduplicated so the same address never appears twice,
even if it is discovered through multiple routes.

## report()

Returns a formatted plain-text abuse report.

# ALGORITHM: DOMAIN INTELLIGENCE PIPELINE

For each unique non-infrastructure domain found in the email, the module
runs the following pipeline:

    Domain name
        |
        +-- A record  --> web hosting IP  --> RDAP --> org + abuse contact
        |
        +-- MX record --> mail server hostname --> A --> RDAP --> org + abuse
        |
        +-- NS record --> nameserver hostname  --> A --> RDAP --> org + abuse
        |
        +-- WHOIS (TLD whois server via IANA referral)
               +-- Registrar name + abuse contact
               +-- Creation date  (-> recently-registered flag if < 180 days)
               +-- Expiry date    (-> expires-soon or expired flags)

Domains are collected from:

    From:/Reply-To:/Sender:/Return-Path: headers
    DKIM-Signature: d=  (signing domain)
    List-Unsubscribe:   (ESP / bulk sender domain)
    Message-ID:         (often reveals real sending platform)
    mailto: links and bare addresses in the body

# WHY WEB HOSTING != MAIL HOSTING != DNS HOSTING

A fraudster registering `sminvestmentsupplychain.com` might:

- Register the domain at GoDaddy (registrar)
- Point the NS records at Cloudflare (DNS/CDN)
- Have no web server at all (A record absent)
- Route the MX records to Google Workspace or similar

Each of these parties has an abuse contact, and each can independently
take action to disrupt the spam/phishing operation.  The module reports
all of them separately.

# RECENTLY-REGISTERED FLAG

Phishing domains are very commonly registered hours or days before the
spam run.  The module flags any domain whose WHOIS creation date is
less than 180 days ago with `recently_registered => 1`.

# SEE ALSO

[Net::DNS](https://metacpan.org/pod/Net%3A%3ADNS), [LWP::UserAgent](https://metacpan.org/pod/LWP%3A%3AUserAgent), [HTML::LinkExtor](https://metacpan.org/pod/HTML%3A%3ALinkExtor), [MIME::QuotedPrint](https://metacpan.org/pod/MIME%3A%3AQuotedPrint)

ARIN RDAP: [https://rdap.arin.net/](https://rdap.arin.net/)

# LICENSE

Same terms as Perl itself (Artistic 2.0 / GPL v1+).
