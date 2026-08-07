#!/usr/bin/env perl
# Auto-generated mutant test stubs
# Generated: 2026-08-07 19:44:10
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

# --- SURVIVOR: NUM_BOUNDARY_1696_25_< (HIGH) line 1696 in _risk_check_urls_and_domains() ---
# Source:  } elsif ($remaining <= 0) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1696_25_< line 1696 in _risk_check_urls_and_domains()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1696 in _risk_check_urls_and_domains() to detect the mutant
    fail('NUM_BOUNDARY_1696_25_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1801_2 (MEDIUM) line 1801 in abuse_report_text() ---
# Source:  if (@urls) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1801_2 line 1801 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1801 in abuse_report_text() to detect the mutant
    fail('COND_INV_1801_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1961_22_< (HIGH) line 1961 in _compute_abuse_contacts() ---
# Source:  $role_counts{$_} > 1 ? "$_ (x$role_counts{$_})" : $_
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1961_22_< line 1961 in _compute_abuse_contacts()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1961 in _compute_abuse_contacts() to detect the mutant
    fail('NUM_BOUNDARY_1961_22_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1983_5 (MEDIUM) line 1983 in _compute_abuse_contacts() ---
# Source:  if (@url_hosts) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1983_5 line 1983 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1983 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1983_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2059_4 (MEDIUM) line 2059 in _compute_abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2059_4 line 2059 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2059 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2059_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2160_2 (MEDIUM) line 2160 in _compute_abuse_contacts() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2160_2 line 2160 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2160 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2160_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2171_4 (MEDIUM) line 2171 in _compute_abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2171_4 line 2171 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2171 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2171_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2280_2 (MEDIUM) line 2280 in form_contacts() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2280_2 line 2280 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2280 in form_contacts() to detect the mutant
    fail('COND_INV_2280_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2282_3 (MEDIUM) line 2282 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2282_3 line 2282 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2282 in form_contacts() to detect the mutant
    fail('COND_INV_2282_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2316_3 (MEDIUM) line 2316 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2316_3 line 2316 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2316 in form_contacts() to detect the mutant
    fail('COND_INV_2316_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2371_2 (MEDIUM) line 2371 in form_contacts() ---
# Source:  if ($auth->{dkim_domain}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2371_2 line 2371 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2371 in form_contacts() to detect the mutant
    fail('COND_INV_2371_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2373_3 (MEDIUM) line 2373 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2373_3 line 2373 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2373 in form_contacts() to detect the mutant
    fail('COND_INV_2373_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2387_2 (MEDIUM) line 2387 in form_contacts() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2387_2 line 2387 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2387 in form_contacts() to detect the mutant
    fail('COND_INV_2387_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2394_4 (MEDIUM) line 2394 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2394_4 line 2394 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2394 in form_contacts() to detect the mutant
    fail('COND_INV_2394_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2659_46_< (HIGH) line 2659 in report() ---
# Source:  if (defined $line && length("$line $w") > $ROLE_WRAP_LEN) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2659_46_< line 2659 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2659 in report() to detect the mutant
    fail('NUM_BOUNDARY_2659_46_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3012_4 (MEDIUM) line 3012 in _extract_ip_from_received() ---
# Source:  return $ip if $ip =~ /:/;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3012_4 line 3012 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3012 in _extract_ip_from_received() to detect the mutant
    fail('BOOL_NEGATE_3012_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3125_57_< (HIGH) line 3125 in _extract_and_resolve_urls() ---
# Source:  if ($HAS_ANYEVENT_DNS && scalar(keys %hostname_needed) > 1) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3125_57_< line 3125 in _extract_and_resolve_urls()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3125 in _extract_and_resolve_urls() to detect the mutant
    fail('NUM_BOUNDARY_3125_57_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3189_29_< (HIGH) line 3189 in _is_redirect_cloaker() ---
# Source:  return 1 if length($host) > length($suffix)
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3189_29_< line 3189 in _is_redirect_cloaker()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3189 in _is_redirect_cloaker() to detect the mutant
    fail('NUM_BOUNDARY_3189_29_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3223_2 (MEDIUM) line 3223 in _follow_redirect_chain() ---
# Source:  return undef unless $HAS_LWP;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3223_2 line 3223 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3223 in _follow_redirect_chain() to detect the mutant
    fail('BOOL_NEGATE_3223_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3226_2 (MEDIUM) line 3226 in _follow_redirect_chain() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3226_2 line 3226 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3226 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3226_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3228_3 (MEDIUM) line 3228 in _follow_redirect_chain() ---
# Source:  return $cached if defined $cached;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3228_3 line 3228 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3228 in _follow_redirect_chain() to detect the mutant
    fail('BOOL_NEGATE_3228_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3233_2 (MEDIUM) line 3233 in _follow_redirect_chain() ---
# Source:  unless (defined $self->{_ua_nofollow}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_3233_2 line 3233 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3233 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3233_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3239_3 (MEDIUM) line 3239 in _follow_redirect_chain() ---
# Source:  if ($HAS_CONN_CACHE) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3239_3 line 3239 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3239 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3239_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3255_3 (MEDIUM) line 3255 in _follow_redirect_chain() ---
# Source:  if ($res->is_redirect()) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3255_3 line 3255 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3255 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3255_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3261_4 (MEDIUM) line 3261 in _follow_redirect_chain() ---
# Source:  if ($loc !~ m{^https?://}i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3261_4 line 3261 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3261 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3261_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3273_4 (MEDIUM) line 3273 in _follow_redirect_chain() ---
# Source:  if ($body =~ m{<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3273_4 line 3273 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3273 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3273_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3294_2 (MEDIUM) line 3294 in _follow_redirect_chain() ---
# Source:  return $final;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3294_2 line 3294 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3294 in _follow_redirect_chain() to detect the mutant
    fail('BOOL_NEGATE_3294_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3337_5 (MEDIUM) line 3337 in _parallel_resolve_hosts() ---
# Source:  if (@answers) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3337_5 line 3337 in _parallel_resolve_hosts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3337 in _parallel_resolve_hosts() to detect the mutant
    fail('COND_INV_3337_5: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3342_29_< (HIGH) line 3342 in _parallel_resolve_hosts() ---
# Source:  $cv->send if --$pending <= 0;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3342_29_< line 3342 in _parallel_resolve_hosts()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3342 in _parallel_resolve_hosts() to detect the mutant
    fail('NUM_BOUNDARY_3342_29_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3493_2 (MEDIUM) line 3493 in _extract_and_analyse_domains() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3493_2 line 3493 in _extract_and_analyse_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3493 in _extract_and_analyse_domains() to detect the mutant
    fail('COND_INV_3493_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3583_3 (MEDIUM) line 3583 in _analyse_domain() ---
# Source:  if ($cached) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3583_3 line 3583 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3583 in _analyse_domain() to detect the mutant
    fail('COND_INV_3583_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3585_4 (MEDIUM) line 3585 in _analyse_domain() ---
# Source:  return $cached;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3585_4 line 3585 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3585 in _analyse_domain() to detect the mutant
    fail('BOOL_NEGATE_3585_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3609_3 (MEDIUM) line 3609 in _analyse_domain() ---
# Source:  if(my $mxq = $res->search($domain, 'MX')) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3609_3 line 3609 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3609 in _analyse_domain() to detect the mutant
    fail('COND_INV_3609_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3612_4 (MEDIUM) line 3612 in _analyse_domain() ---
# Source:  if ($best) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3612_4 line 3612 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3612 in _analyse_domain() to detect the mutant
    fail('COND_INV_3612_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3616_5 (MEDIUM) line 3616 in _analyse_domain() ---
# Source:  if ($mx_ip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3616_5 line 3616 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3616 in _analyse_domain() to detect the mutant
    fail('COND_INV_3616_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3626_3 (MEDIUM) line 3626 in _analyse_domain() ---
# Source:  if(my $nsq = $res->search($domain, 'NS')) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3626_3 line 3626 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3626 in _analyse_domain() to detect the mutant
    fail('COND_INV_3626_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3630_4 (MEDIUM) line 3630 in _analyse_domain() ---
# Source:  if ($first) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3630_4 line 3630 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3630 in _analyse_domain() to detect the mutant
    fail('COND_INV_3630_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3634_5 (MEDIUM) line 3634 in _analyse_domain() ---
# Source:  if ($ns_ip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3634_5 line 3634 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3634 in _analyse_domain() to detect the mutant
    fail('COND_INV_3634_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3731_3 (MEDIUM) line 3731 in _resolve_host() ---
# Source:  return $cached_ip if defined $cached_ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3731_3 line 3731 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3731 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_3731_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3745_4 (MEDIUM) line 3745 in _resolve_host() ---
# Source:  if ($query) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3745_4 line 3745 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3745 in _resolve_host() to detect the mutant
    fail('COND_INV_3745_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3747_6 (MEDIUM) line 3747 in _resolve_host() ---
# Source:  if ($rr->type eq 'A') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3747_6 line 3747 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3747 in _resolve_host() to detect the mutant
    fail('COND_INV_3747_6: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3791_3 (MEDIUM) line 3791 in _reverse_dns() ---
# Source:  if ($query) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3791_3 line 3791 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3791 in _reverse_dns() to detect the mutant
    fail('COND_INV_3791_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3793_5 (MEDIUM) line 3793 in _reverse_dns() ---
# Source:  return $rr->ptrdname if $rr->type eq 'PTR';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3793_5 line 3793 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3793 in _reverse_dns() to detect the mutant
    fail('BOOL_NEGATE_3793_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3800_2 (MEDIUM) line 3800 in _reverse_dns() ---
# Source:  return scalar gethostbyaddr(inet_aton($ip), AF_INET);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3800_2 line 3800 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3800 in _reverse_dns() to detect the mutant
    fail('BOOL_NEGATE_3800_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3826_3 (MEDIUM) line 3826 in _whois_ip() ---
# Source:  return $cached if $cached;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3826_3 line 3826 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3826 in _whois_ip() to detect the mutant
    fail('BOOL_NEGATE_3826_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3928_2 (MEDIUM) line 3928 in _rdap_lookup() ---
# Source:  if(!defined($ua)) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3928_2 line 3928 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3928 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3928_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3934_3 (MEDIUM) line 3934 in _rdap_lookup() ---
# Source:  if($HAS_CONN_CACHE) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3934_3 line 3934 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3934 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3934_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3948_2 (MEDIUM) line 3948 in _rdap_lookup() ---
# Source:  unless ($safe_ip =~ /\A\d{1,3}(?:\.\d{1,3}){3}\z/
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_3948_2 line 3948 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3948 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3948_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3963_2 (MEDIUM) line 3963 in _rdap_lookup() ---
# Source:  if ($j =~ /"name"\s*:\s*"([^"]+)"/)   { $info{org}    = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3963_2 line 3963 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3963 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3963_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3964_2 (MEDIUM) line 3964 in _rdap_lookup() ---
# Source:  if ($j =~ /"handle"\s*:\s*"([^"]+)"/) { $info{handle} = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3964_2 line 3964 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3964 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3964_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3967_2 (MEDIUM) line 3967 in _rdap_lookup() ---
# Source:  if ($j =~ /"abuse".*?"email"\s*:\s*"([^"]+)"/s) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3967_2 line 3967 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3967 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3967_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3974_2 (MEDIUM) line 3974 in _rdap_lookup() ---
# Source:  if ($j =~ /"country"\s*:\s*"([A-Z]{2})"/) { $info{country} = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3974_2 line 3974 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3974 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3974_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3976_2 (MEDIUM) line 3976 in _rdap_lookup() ---
# Source:  return \%info;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3976_2 line 3976 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3976 in _rdap_lookup() to detect the mutant
    fail('BOOL_NEGATE_3976_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4053_31_< (HIGH) line 4053 in _raw_whois() ---
# Source:  if ($@ || !defined $n || $n <= 0) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4053_31_< line 4053 in _raw_whois()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4053 in _raw_whois() to detect the mutant
    fail('NUM_BOUNDARY_4053_31_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4057_30_< (HIGH) line 4057 in _raw_whois() ---
# Source:  last if !defined($n) || $n <= 0;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4057_30_< line 4057 in _raw_whois()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4057 in _raw_whois() to detect the mutant
    fail('NUM_BOUNDARY_4057_30_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4201_3 (MEDIUM) line 4201 in _provider_abuse_for_host() ---
# Source:  return $self->{provider_abuse}->{$host} if $self->{provider_abuse}->{$host};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4201_3 line 4201 in _provider_abuse_for_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4201 in _provider_abuse_for_host() to detect the mutant
    fail('BOOL_NEGATE_4201_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4257_3 (MEDIUM) line 4257 in _registrable() ---
# Source:  return $root if $root;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4257_3 line 4257 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4257 in _registrable() to detect the mutant
    fail('BOOL_NEGATE_4257_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4262_26_< (HIGH) line 4262 in _registrable() ---
# Source:  return $host if @labels <= 2;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4262_26_< line 4262 in _registrable()';
    # Suggested boundary values to test: 1, 2, 3
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4262 in _registrable() to detect the mutant
    fail('NUM_BOUNDARY_4262_26_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4522_2 (MEDIUM) line 4522 in _parse_date_to_epoch() ---
# Source:  return ($y-1970)*365.25*$SECS_PER_DAY + ($m-1)*30.5*$SECS_PER_DAY + ($d-1)*$SECS_PER_DAY;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4522_2 line 4522 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4522 in _parse_date_to_epoch() to detect the mutant
    fail('BOOL_NEGATE_4522_2: replace with real assertion');
}

# --- LOW DIFFICULTY HINTS (comment stubs) ---

# --- LOW HINT: RETURN_UNDEF_3012_4 line 3012 in _extract_ip_from_received() ---
# Source:  return $ip if $ip =~ /:/;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3012_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3189_3 line 3189 in _is_redirect_cloaker() ---
# Source:  return 1 if length($host) > length($suffix)
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3189_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3223_2 line 3223 in _follow_redirect_chain() ---
# Source:  return undef unless $HAS_LWP;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3223_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3228_3 line 3228 in _follow_redirect_chain() ---
# Source:  return $cached if defined $cached;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3228_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3294_2 line 3294 in _follow_redirect_chain() ---
# Source:  return $final;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3294_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3585_4 line 3585 in _analyse_domain() ---
# Source:  return $cached;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3585_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3731_3 line 3731 in _resolve_host() ---
# Source:  return $cached_ip if defined $cached_ip;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3731_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3793_5 line 3793 in _reverse_dns() ---
# Source:  return $rr->ptrdname if $rr->type eq 'PTR';
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3793_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3800_2 line 3800 in _reverse_dns() ---
# Source:  return scalar gethostbyaddr(inet_aton($ip), AF_INET);
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3800_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3826_3 line 3826 in _whois_ip() ---
# Source:  return $cached if $cached;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3826_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3976_2 line 3976 in _rdap_lookup() ---
# Source:  return \%info;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3976_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4201_3 line 4201 in _provider_abuse_for_host() ---
# Source:  return $self->{provider_abuse}->{$host} if $self->{provider_abuse}->{$host};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4201_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4257_3 line 4257 in _registrable() ---
# Source:  return $root if $root;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4257_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4522_2 line 4522 in _parse_date_to_epoch() ---
# Source:  return ($y-1970)*365.25*$SECS_PER_DAY + ($m-1)*30.5*$SECS_PER_DAY + ($d-1)*$SECS_PER_DAY;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4522_2: add assertion here');

done_testing();
