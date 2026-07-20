#!/usr/bin/env perl
# Auto-generated mutant test stubs
# Generated: 2026-07-20 12:37:44
# Generator: scripts/test-generator-index
#
# DO NOT COMMIT without completing the TODO sections.
#
# HIGH/MEDIUM difficulty survivors have TODO stubs — these need real tests.
# LOW difficulty survivors appear as comment hints — worth improving.
#
# Stubs call new() for modules with a constructor, or show a class method
# placeholder for modules without one. Add arguments as needed.

use strict;
use warnings;
use Test::More;

use_ok('Email::Abuse::Investigator');

################################################################
# FILE: lib/Email/Abuse/Investigator.pm
################################################################
# --- SURVIVORS (TODO stubs) ---

# --- SURVIVOR: NUM_BOUNDARY_1688_25_< (HIGH) line 1688 in _risk_check_urls_and_domains() ---
# Source:  } elsif ($remaining <= 0) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1688_25_< line 1688 in _risk_check_urls_and_domains()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1688 in _risk_check_urls_and_domains() to detect the mutant
    fail('NUM_BOUNDARY_1688_25_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1793_2 (MEDIUM) line 1793 in abuse_report_text() ---
# Source:  if (@urls) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1793_2 line 1793 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1793 in abuse_report_text() to detect the mutant
    fail('COND_INV_1793_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1953_22_< (HIGH) line 1953 in _compute_abuse_contacts() ---
# Source:  $role_counts{$_} > 1 ? "$_ (x$role_counts{$_})" : $_
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1953_22_< line 1953 in _compute_abuse_contacts()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1953 in _compute_abuse_contacts() to detect the mutant
    fail('NUM_BOUNDARY_1953_22_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1975_5 (MEDIUM) line 1975 in _compute_abuse_contacts() ---
# Source:  if (@url_hosts) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1975_5 line 1975 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1975 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1975_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2051_4 (MEDIUM) line 2051 in _compute_abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2051_4 line 2051 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2051 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2051_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2152_2 (MEDIUM) line 2152 in _compute_abuse_contacts() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2152_2 line 2152 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2152 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2152_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2163_4 (MEDIUM) line 2163 in _compute_abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2163_4 line 2163 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2163 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2163_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2272_2 (MEDIUM) line 2272 in form_contacts() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2272_2 line 2272 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2272 in form_contacts() to detect the mutant
    fail('COND_INV_2272_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2274_3 (MEDIUM) line 2274 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2274_3 line 2274 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2274 in form_contacts() to detect the mutant
    fail('COND_INV_2274_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2308_3 (MEDIUM) line 2308 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2308_3 line 2308 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2308 in form_contacts() to detect the mutant
    fail('COND_INV_2308_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2363_2 (MEDIUM) line 2363 in form_contacts() ---
# Source:  if ($auth->{dkim_domain}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2363_2 line 2363 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2363 in form_contacts() to detect the mutant
    fail('COND_INV_2363_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2365_3 (MEDIUM) line 2365 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2365_3 line 2365 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2365 in form_contacts() to detect the mutant
    fail('COND_INV_2365_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2379_2 (MEDIUM) line 2379 in form_contacts() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2379_2 line 2379 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2379 in form_contacts() to detect the mutant
    fail('COND_INV_2379_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2386_4 (MEDIUM) line 2386 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2386_4 line 2386 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2386 in form_contacts() to detect the mutant
    fail('COND_INV_2386_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2651_46_< (HIGH) line 2651 in report() ---
# Source:  if (defined $line && length("$line $w") > $ROLE_WRAP_LEN) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2651_46_< line 2651 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2651 in report() to detect the mutant
    fail('NUM_BOUNDARY_2651_46_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3004_4 (MEDIUM) line 3004 in _extract_ip_from_received() ---
# Source:  return $ip if $ip =~ /:/;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3004_4 line 3004 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3004 in _extract_ip_from_received() to detect the mutant
    fail('BOOL_NEGATE_3004_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3117_57_< (HIGH) line 3117 in _extract_and_resolve_urls() ---
# Source:  if ($HAS_ANYEVENT_DNS && scalar(keys %hostname_needed) > 1) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3117_57_< line 3117 in _extract_and_resolve_urls()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3117 in _extract_and_resolve_urls() to detect the mutant
    fail('NUM_BOUNDARY_3117_57_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3181_29_< (HIGH) line 3181 in _is_redirect_cloaker() ---
# Source:  return 1 if length($host) > length($suffix)
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3181_29_< line 3181 in _is_redirect_cloaker()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3181 in _is_redirect_cloaker() to detect the mutant
    fail('NUM_BOUNDARY_3181_29_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3215_2 (MEDIUM) line 3215 in _follow_redirect_chain() ---
# Source:  return undef unless $HAS_LWP;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3215_2 line 3215 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3215 in _follow_redirect_chain() to detect the mutant
    fail('BOOL_NEGATE_3215_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3218_2 (MEDIUM) line 3218 in _follow_redirect_chain() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3218_2 line 3218 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3218 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3218_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3220_3 (MEDIUM) line 3220 in _follow_redirect_chain() ---
# Source:  return $cached if defined $cached;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3220_3 line 3220 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3220 in _follow_redirect_chain() to detect the mutant
    fail('BOOL_NEGATE_3220_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3225_2 (MEDIUM) line 3225 in _follow_redirect_chain() ---
# Source:  unless (defined $self->{_ua_nofollow}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_3225_2 line 3225 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3225 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3225_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3231_3 (MEDIUM) line 3231 in _follow_redirect_chain() ---
# Source:  if ($HAS_CONN_CACHE) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3231_3 line 3231 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3231 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3231_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3247_3 (MEDIUM) line 3247 in _follow_redirect_chain() ---
# Source:  if ($res->is_redirect()) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3247_3 line 3247 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3247 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3247_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3253_4 (MEDIUM) line 3253 in _follow_redirect_chain() ---
# Source:  if ($loc !~ m{^https?://}i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3253_4 line 3253 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3253 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3253_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3265_4 (MEDIUM) line 3265 in _follow_redirect_chain() ---
# Source:  if ($body =~ m{<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3265_4 line 3265 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3265 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3265_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3286_2 (MEDIUM) line 3286 in _follow_redirect_chain() ---
# Source:  return $final;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3286_2 line 3286 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3286 in _follow_redirect_chain() to detect the mutant
    fail('BOOL_NEGATE_3286_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3329_5 (MEDIUM) line 3329 in _parallel_resolve_hosts() ---
# Source:  if (@answers) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3329_5 line 3329 in _parallel_resolve_hosts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3329 in _parallel_resolve_hosts() to detect the mutant
    fail('COND_INV_3329_5: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3334_29_< (HIGH) line 3334 in _parallel_resolve_hosts() ---
# Source:  $cv->send if --$pending <= 0;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3334_29_< line 3334 in _parallel_resolve_hosts()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3334 in _parallel_resolve_hosts() to detect the mutant
    fail('NUM_BOUNDARY_3334_29_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3485_2 (MEDIUM) line 3485 in _extract_and_analyse_domains() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3485_2 line 3485 in _extract_and_analyse_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3485 in _extract_and_analyse_domains() to detect the mutant
    fail('COND_INV_3485_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3575_3 (MEDIUM) line 3575 in _analyse_domain() ---
# Source:  if ($cached) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3575_3 line 3575 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3575 in _analyse_domain() to detect the mutant
    fail('COND_INV_3575_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3577_4 (MEDIUM) line 3577 in _analyse_domain() ---
# Source:  return $cached;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3577_4 line 3577 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3577 in _analyse_domain() to detect the mutant
    fail('BOOL_NEGATE_3577_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3601_3 (MEDIUM) line 3601 in _analyse_domain() ---
# Source:  if(my $mxq = $res->search($domain, 'MX')) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3601_3 line 3601 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3601 in _analyse_domain() to detect the mutant
    fail('COND_INV_3601_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3604_4 (MEDIUM) line 3604 in _analyse_domain() ---
# Source:  if ($best) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3604_4 line 3604 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3604 in _analyse_domain() to detect the mutant
    fail('COND_INV_3604_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3608_5 (MEDIUM) line 3608 in _analyse_domain() ---
# Source:  if ($mx_ip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3608_5 line 3608 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3608 in _analyse_domain() to detect the mutant
    fail('COND_INV_3608_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3618_3 (MEDIUM) line 3618 in _analyse_domain() ---
# Source:  if(my $nsq = $res->search($domain, 'NS')) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3618_3 line 3618 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3618 in _analyse_domain() to detect the mutant
    fail('COND_INV_3618_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3622_4 (MEDIUM) line 3622 in _analyse_domain() ---
# Source:  if ($first) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3622_4 line 3622 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3622 in _analyse_domain() to detect the mutant
    fail('COND_INV_3622_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3626_5 (MEDIUM) line 3626 in _analyse_domain() ---
# Source:  if ($ns_ip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3626_5 line 3626 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3626 in _analyse_domain() to detect the mutant
    fail('COND_INV_3626_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3723_3 (MEDIUM) line 3723 in _resolve_host() ---
# Source:  return $cached_ip if defined $cached_ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3723_3 line 3723 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3723 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_3723_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3737_4 (MEDIUM) line 3737 in _resolve_host() ---
# Source:  if ($query) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3737_4 line 3737 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3737 in _resolve_host() to detect the mutant
    fail('COND_INV_3737_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3739_6 (MEDIUM) line 3739 in _resolve_host() ---
# Source:  if ($rr->type eq 'A') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3739_6 line 3739 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3739 in _resolve_host() to detect the mutant
    fail('COND_INV_3739_6: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3783_3 (MEDIUM) line 3783 in _reverse_dns() ---
# Source:  if ($query) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3783_3 line 3783 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3783 in _reverse_dns() to detect the mutant
    fail('COND_INV_3783_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3785_5 (MEDIUM) line 3785 in _reverse_dns() ---
# Source:  return $rr->ptrdname if $rr->type eq 'PTR';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3785_5 line 3785 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3785 in _reverse_dns() to detect the mutant
    fail('BOOL_NEGATE_3785_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3792_2 (MEDIUM) line 3792 in _reverse_dns() ---
# Source:  return scalar gethostbyaddr(inet_aton($ip), AF_INET);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3792_2 line 3792 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3792 in _reverse_dns() to detect the mutant
    fail('BOOL_NEGATE_3792_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3818_3 (MEDIUM) line 3818 in _whois_ip() ---
# Source:  return $cached if $cached;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3818_3 line 3818 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3818 in _whois_ip() to detect the mutant
    fail('BOOL_NEGATE_3818_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3920_2 (MEDIUM) line 3920 in _rdap_lookup() ---
# Source:  if(!defined($ua)) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3920_2 line 3920 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3920 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3920_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3926_3 (MEDIUM) line 3926 in _rdap_lookup() ---
# Source:  if($HAS_CONN_CACHE) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3926_3 line 3926 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3926 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3926_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3940_2 (MEDIUM) line 3940 in _rdap_lookup() ---
# Source:  unless ($safe_ip =~ /\A\d{1,3}(?:\.\d{1,3}){3}\z/
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_3940_2 line 3940 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3940 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3940_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3955_2 (MEDIUM) line 3955 in _rdap_lookup() ---
# Source:  if ($j =~ /"name"\s*:\s*"([^"]+)"/)   { $info{org}    = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3955_2 line 3955 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3955 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3955_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3956_2 (MEDIUM) line 3956 in _rdap_lookup() ---
# Source:  if ($j =~ /"handle"\s*:\s*"([^"]+)"/) { $info{handle} = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3956_2 line 3956 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3956 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3956_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3959_2 (MEDIUM) line 3959 in _rdap_lookup() ---
# Source:  if ($j =~ /"abuse".*?"email"\s*:\s*"([^"]+)"/s) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3959_2 line 3959 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3959 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3959_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3966_2 (MEDIUM) line 3966 in _rdap_lookup() ---
# Source:  if ($j =~ /"country"\s*:\s*"([A-Z]{2})"/) { $info{country} = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3966_2 line 3966 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3966 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3966_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3968_2 (MEDIUM) line 3968 in _rdap_lookup() ---
# Source:  return \%info;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3968_2 line 3968 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3968 in _rdap_lookup() to detect the mutant
    fail('BOOL_NEGATE_3968_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4045_31_< (HIGH) line 4045 in _raw_whois() ---
# Source:  if ($@ || !defined $n || $n <= 0) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4045_31_< line 4045 in _raw_whois()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4045 in _raw_whois() to detect the mutant
    fail('NUM_BOUNDARY_4045_31_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4049_30_< (HIGH) line 4049 in _raw_whois() ---
# Source:  last if !defined($n) || $n <= 0;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4049_30_< line 4049 in _raw_whois()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4049 in _raw_whois() to detect the mutant
    fail('NUM_BOUNDARY_4049_30_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4193_3 (MEDIUM) line 4193 in _provider_abuse_for_host() ---
# Source:  return $self->{provider_abuse}->{$host} if $self->{provider_abuse}->{$host};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4193_3 line 4193 in _provider_abuse_for_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4193 in _provider_abuse_for_host() to detect the mutant
    fail('BOOL_NEGATE_4193_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4249_3 (MEDIUM) line 4249 in _registrable() ---
# Source:  return $root if $root;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4249_3 line 4249 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4249 in _registrable() to detect the mutant
    fail('BOOL_NEGATE_4249_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4254_26_< (HIGH) line 4254 in _registrable() ---
# Source:  return $host if @labels <= 2;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4254_26_< line 4254 in _registrable()';
    # Suggested boundary values to test: 1, 2, 3
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4254 in _registrable() to detect the mutant
    fail('NUM_BOUNDARY_4254_26_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4514_2 (MEDIUM) line 4514 in _parse_date_to_epoch() ---
# Source:  return ($y-1970)*365.25*$SECS_PER_DAY + ($m-1)*30.5*$SECS_PER_DAY + ($d-1)*$SECS_PER_DAY;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4514_2 line 4514 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4514 in _parse_date_to_epoch() to detect the mutant
    fail('BOOL_NEGATE_4514_2: replace with real assertion');
}

# --- LOW DIFFICULTY HINTS (comment stubs) ---

# --- LOW HINT: RETURN_UNDEF_3004_4 line 3004 in _extract_ip_from_received() ---
# Source:  return $ip if $ip =~ /:/;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3004_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3181_3 line 3181 in _is_redirect_cloaker() ---
# Source:  return 1 if length($host) > length($suffix)
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3181_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3215_2 line 3215 in _follow_redirect_chain() ---
# Source:  return undef unless $HAS_LWP;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3215_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3220_3 line 3220 in _follow_redirect_chain() ---
# Source:  return $cached if defined $cached;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3220_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3286_2 line 3286 in _follow_redirect_chain() ---
# Source:  return $final;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3286_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3577_4 line 3577 in _analyse_domain() ---
# Source:  return $cached;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3577_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3723_3 line 3723 in _resolve_host() ---
# Source:  return $cached_ip if defined $cached_ip;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3723_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3785_5 line 3785 in _reverse_dns() ---
# Source:  return $rr->ptrdname if $rr->type eq 'PTR';
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3785_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3792_2 line 3792 in _reverse_dns() ---
# Source:  return scalar gethostbyaddr(inet_aton($ip), AF_INET);
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3792_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3818_3 line 3818 in _whois_ip() ---
# Source:  return $cached if $cached;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3818_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3968_2 line 3968 in _rdap_lookup() ---
# Source:  return \%info;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3968_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4193_3 line 4193 in _provider_abuse_for_host() ---
# Source:  return $self->{provider_abuse}->{$host} if $self->{provider_abuse}->{$host};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4193_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4249_3 line 4249 in _registrable() ---
# Source:  return $root if $root;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4249_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4514_2 line 4514 in _parse_date_to_epoch() ---
# Source:  return ($y-1970)*365.25*$SECS_PER_DAY + ($m-1)*30.5*$SECS_PER_DAY + ($d-1)*$SECS_PER_DAY;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4514_2: add assertion here');

done_testing();
