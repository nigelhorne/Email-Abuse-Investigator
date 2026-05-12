#!/usr/bin/env perl
# Auto-generated mutant test stubs
# Generated: 2026-05-12 15:31:51
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

# --- SURVIVOR: BOOL_NEGATE_784_2 (MEDIUM) line 784 in parse_email() ---
# Source:  return $self;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_784_2 line 784 in parse_email()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 784 in parse_email() to detect the mutant
    fail('BOOL_NEGATE_784_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1063_5 (MEDIUM) line 1063 in originating_ip() ---
# Source:  return $self->{_origin};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1063_5 line 1063 in originating_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1063 in originating_ip() to detect the mutant
    fail('BOOL_NEGATE_1063_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1899_5 (MEDIUM) line 1899 in all_domains() ---
# Source:  return @out;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1899_5 line 1899 in all_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1899 in all_domains() to detect the mutant
    fail('BOOL_NEGATE_1899_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1943_9 (MEDIUM) line 1943 in unresolved_contacts() ---
# Source:  unless ($dom) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_1943_9 line 1943 in unresolved_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1943 in unresolved_contacts() to detect the mutant
    fail('COND_INV_1943_9: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1983_5 (MEDIUM) line 1983 in unresolved_contacts() ---
# Source:  return @out;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1983_5 line 1983 in unresolved_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1983 in unresolved_contacts() to detect the mutant
    fail('BOOL_NEGATE_1983_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2461_5 (MEDIUM) line 2461 in _decode_mime_words() ---
# Source:  return '' unless defined $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2461_5 line 2461 in _decode_mime_words()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2461 in _decode_mime_words() to detect the mutant
    fail('BOOL_NEGATE_2461_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2463_5 (MEDIUM) line 2463 in _decode_mime_words() ---
# Source:  return $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2463_5 line 2463 in _decode_mime_words()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2463 in _decode_mime_words() to detect the mutant
    fail('BOOL_NEGATE_2463_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2469_5 (MEDIUM) line 2469 in _decode_ew() ---
# Source:  if (uc($enc) eq 'B') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2469_5 line 2469 in _decode_ew()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2469 in _decode_ew() to detect the mutant
    fail('COND_INV_2469_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2476_5 (MEDIUM) line 2476 in _decode_ew() ---
# Source:  if (lc($charset) ne 'utf-8') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2476_5 line 2476 in _decode_ew()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2476 in _decode_ew() to detect the mutant
    fail('COND_INV_2476_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2480_5 (MEDIUM) line 2480 in _decode_ew() ---
# Source:  return $raw;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2480_5 line 2480 in _decode_ew()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2480 in _decode_ew() to detect the mutant
    fail('BOOL_NEGATE_2480_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2880_5 (MEDIUM) line 2880 in risk_assessment() ---
# Source:  return $self->{_risk} if $self->{_risk};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2880_5 line 2880 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2880 in risk_assessment() to detect the mutant
    fail('BOOL_NEGATE_2880_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2894_5 (MEDIUM) line 2894 in risk_assessment() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2894_5 line 2894 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2894 in risk_assessment() to detect the mutant
    fail('COND_INV_2894_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2896_9 (MEDIUM) line 2896 in risk_assessment() ---
# Source:  if ($orig->{rdns} && $orig->{rdns} =~ /
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2896_9 line 2896 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2896 in risk_assessment() to detect the mutant
    fail('COND_INV_2896_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2907_9 (MEDIUM) line 2907 in risk_assessment() ---
# Source:  if (!$orig->{rdns} || $orig->{rdns} eq '(no reverse DNS)') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2907_9 line 2907 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2907 in risk_assessment() to detect the mutant
    fail('COND_INV_2907_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2913_9 (MEDIUM) line 2913 in risk_assessment() ---
# Source:  if ($orig->{confidence} eq 'low') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2913_9 line 2913 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2913 in risk_assessment() to detect the mutant
    fail('COND_INV_2913_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2919_9 (MEDIUM) line 2919 in risk_assessment() ---
# Source:  if ($orig->{country} && $orig->{country} =~ /^(?:CN|RU|NG|VN|IN|PK|BD)$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2919_9 line 2919 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2919 in risk_assessment() to detect the mutant
    fail('COND_INV_2919_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2928_5 (MEDIUM) line 2928 in risk_assessment() ---
# Source:  if (defined $auth->{spf}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2928_5 line 2928 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2928 in risk_assessment() to detect the mutant
    fail('COND_INV_2928_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2929_9 (MEDIUM) line 2929 in risk_assessment() ---
# Source:  if ($auth->{spf} =~ /^fail/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2929_9 line 2929 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2929 in risk_assessment() to detect the mutant
    fail('COND_INV_2929_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2940_5 (MEDIUM) line 2940 in risk_assessment() ---
# Source:  if (defined $auth->{dkim} && $auth->{dkim} !~ /^pass/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2940_5 line 2940 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2940 in risk_assessment() to detect the mutant
    fail('COND_INV_2940_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2944_5 (MEDIUM) line 2944 in risk_assessment() ---
# Source:  if (defined $auth->{dmarc} && $auth->{dmarc} !~ /^pass/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2944_5 line 2944 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2944 in risk_assessment() to detect the mutant
    fail('COND_INV_2944_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2950_5 (MEDIUM) line 2950 in risk_assessment() ---
# Source:  if ($auth->{dkim_domain}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2950_5 line 2950 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2950 in risk_assessment() to detect the mutant
    fail('COND_INV_2950_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2952_9 (MEDIUM) line 2952 in risk_assessment() ---
# Source:  if ($from_domain) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2952_9 line 2952 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2952 in risk_assessment() to detect the mutant
    fail('COND_INV_2952_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2955_13 (MEDIUM) line 2955 in risk_assessment() ---
# Source:  if ($reg_dkim ne $reg_from) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2955_13 line 2955 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2955 in risk_assessment() to detect the mutant
    fail('COND_INV_2955_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2956_17 (MEDIUM) line 2956 in risk_assessment() ---
# Source:  if ($auth->{dkim} && $auth->{dkim} =~ /^pass/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2956_17 line 2956 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2956 in risk_assessment() to detect the mutant
    fail('COND_INV_2956_17: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2974_5 (MEDIUM) line 2974 in risk_assessment() ---
# Source:  if (!$date_raw || $date_raw !~ /\S/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2974_5 line 2974 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2974 in risk_assessment() to detect the mutant
    fail('COND_INV_2974_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2982_9 (MEDIUM) line 2982 in risk_assessment() ---
# Source:  if ($date_raw =~ /([+-])(\d{2})(\d{2})\s*$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2982_9 line 2982 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2982 in risk_assessment() to detect the mutant
    fail('COND_INV_2982_9: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2991_35_> (HIGH) line 2991 in risk_assessment() ---
# Source:  my $implausible = $mm >= 60
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2991_35_> line 2991 in risk_assessment()';
    # Suggested boundary values to test: 59, 60, 61
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2991 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_2991_35_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2992_50_< (HIGH) line 2992 in risk_assessment() ---
# Source:  || ($sign eq '+' && $offset_mins > 840)
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2992_50_< line 2992 in risk_assessment()';
    # Suggested boundary values to test: 839, 840, 841
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2992 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_2992_50_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2993_50_< (HIGH) line 2993 in risk_assessment() ---
# Source:  || ($sign eq '-' && $offset_mins > 720);
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2993_50_< line 2993 in risk_assessment()';
    # Suggested boundary values to test: 719, 720, 721
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2993 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_2993_50_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2994_13 (MEDIUM) line 2994 in risk_assessment() ---
# Source:  if ($implausible) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2994_13 line 2994 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2994 in risk_assessment() to detect the mutant
    fail('COND_INV_2994_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3005_9 (MEDIUM) line 3005 in risk_assessment() ---
# Source:  if (defined $date_epoch) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3005_9 line 3005 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3005 in risk_assessment() to detect the mutant
    fail('COND_INV_3005_9: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3007_24_< (HIGH) line 3007 in risk_assessment() ---
# Source:  if ($delta > 7 * 86400) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3007_24_< line 3007 in risk_assessment()';
    # Suggested boundary values to test: 6, 7, 8
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3007 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_3007_24_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3010_29_> (HIGH) line 3010 in risk_assessment() ---
# Source:  } elsif ($delta < -(7 * 86400)) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip < to >
#   Numeric boundary flip < to <=
#   Numeric boundary flip < to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3010_29_> line 3010 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3010 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_3010_29_>: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3021_5 (MEDIUM) line 3021 in risk_assessment() ---
# Source:  if ($from_decoded =~ /^"?([^"<]+?)"?\s*<([^>]+)>/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3021_5 line 3021 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3021 in risk_assessment() to detect the mutant
    fail('COND_INV_3021_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3030_13 (MEDIUM) line 3030 in risk_assessment() ---
# Source:  if ($reg_disp && $reg_addr && $reg_disp ne $reg_addr) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3030_13 line 3030 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3030 in risk_assessment() to detect the mutant
    fail('COND_INV_3030_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3038_5 (MEDIUM) line 3038 in risk_assessment() ---
# Source:  if ($from_raw =~ /\@(gmail|yahoo|hotmail|outlook|live|aol|protonmail|yandex)\./i
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3038_5 line 3038 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3038 in risk_assessment() to detect the mutant
    fail('COND_INV_3038_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3046_5 (MEDIUM) line 3046 in risk_assessment() ---
# Source:  if ($reply_to) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3046_5 line 3046 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3046 in risk_assessment() to detect the mutant
    fail('COND_INV_3046_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3049_9 (MEDIUM) line 3049 in risk_assessment() ---
# Source:  if ($from_addr && $reply_addr &&
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3049_9 line 3049 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3049 in risk_assessment() to detect the mutant
    fail('COND_INV_3049_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3058_5 (MEDIUM) line 3058 in risk_assessment() ---
# Source:  if ($to =~ /undisclosed|:;/ || $to eq '') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3058_5 line 3058 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3058 in risk_assessment() to detect the mutant
    fail('COND_INV_3058_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3065_5 (MEDIUM) line 3065 in risk_assessment() ---
# Source:  if ($subj_raw =~ /=\?[^?]+\?[BQ]\?/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3065_5 line 3065 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3065 in risk_assessment() to detect the mutant
    fail('COND_INV_3065_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3082_9 (MEDIUM) line 3082 in risk_assessment() ---
# Source:  if ($URL_SHORTENERS{$bare} && !$shortener_seen{$bare}++) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3082_9 line 3082 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3082 in risk_assessment() to detect the mutant
    fail('COND_INV_3082_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3087_9 (MEDIUM) line 3087 in risk_assessment() ---
# Source:  if ($u->{url} =~ m{^http://}i && !$url_host_seen{ $u->{host} }++) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3087_9 line 3087 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3087 in risk_assessment() to detect the mutant
    fail('COND_INV_3087_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3095_9 (MEDIUM) line 3095 in risk_assessment() ---
# Source:  if ($d->{recently_registered}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3095_9 line 3095 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3095 in risk_assessment() to detect the mutant
    fail('COND_INV_3095_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3100_9 (MEDIUM) line 3100 in risk_assessment() ---
# Source:  if ($d->{expires}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3100_9 line 3100 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3100 in risk_assessment() to detect the mutant
    fail('COND_INV_3100_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3103_13 (MEDIUM) line 3103 in risk_assessment() ---
# Source:  if ($exp) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3103_13 line 3103 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3103 in risk_assessment() to detect the mutant
    fail('COND_INV_3103_13: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3105_32_< (HIGH) line 3105 in risk_assessment() ---
# Source:  if ($remaining > 0 && $remaining < 30 * 86400) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (7 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Numeric boundary flip < to >
#   Numeric boundary flip < to <=
#   Numeric boundary flip < to >=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3105_32_< line 3105 in risk_assessment()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3105 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_3105_32_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3109_35_< (HIGH) line 3109 in risk_assessment() ---
# Source:  elsif ($remaining <= 0) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3109_35_< line 3109 in risk_assessment()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3109 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_3109_35_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3119_13 (MEDIUM) line 3119 in risk_assessment() ---
# Source:  if ($d->{domain} =~ /\Q$brand\E/i &&
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3119_13 line 3119 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3119 in risk_assessment() to detect the mutant
    fail('COND_INV_3119_13: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3128_24_> (HIGH) line 3128 in risk_assessment() ---
# Source:  my $level = $score >= 9 ? 'HIGH'
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3128_24_> line 3128 in risk_assessment()';
    # Suggested boundary values to test: 8, 9, 10
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3128 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_3128_24_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3129_24_> (HIGH) line 3129 in risk_assessment() ---
# Source:  : $score >= 5 ? 'MEDIUM'
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3129_24_> line 3129 in risk_assessment()';
    # Suggested boundary values to test: 4, 5, 6
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3129 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_3129_24_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3130_24_> (HIGH) line 3130 in risk_assessment() ---
# Source:  : $score >= 2 ? 'LOW'
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3130_24_> line 3130 in risk_assessment()';
    # Suggested boundary values to test: 1, 2, 3
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3130 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_3130_24_>: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3134_5 (MEDIUM) line 3134 in risk_assessment() ---
# Source:  return $self->{_risk};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3134_5 line 3134 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3134 in risk_assessment() to detect the mutant
    fail('BOOL_NEGATE_3134_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3139_5 (MEDIUM) line 3139 in _parse_auth_results_cached() ---
# Source:  return $self->{_auth_results} if $self->{_auth_results};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3139_5 line 3139 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3139 in _parse_auth_results_cached() to detect the mutant
    fail('BOOL_NEGATE_3139_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3165_9 (MEDIUM) line 3165 in _parse_auth_results_cached() ---
# Source:  if ($h->{value} =~ /\bd=([^;,\s]+)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3165_9 line 3165 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3165 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_3165_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3169_5 (MEDIUM) line 3169 in _parse_auth_results_cached() ---
# Source:  if (@dkim_domains) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3169_5 line 3169 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3169 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_3169_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3173_13 (MEDIUM) line 3173 in _parse_auth_results_cached() ---
# Source:  if ($self->_provider_abuse_for_host($d)) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3173_13 line 3173 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3173 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_3173_13: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3188_5 (MEDIUM) line 3188 in _registrable() ---
# Source:  return undef unless $host && $host =~ /\./;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3188_5 line 3188 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3188 in _registrable() to detect the mutant
    fail('BOOL_NEGATE_3188_5: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3190_29_< (HIGH) line 3190 in _registrable() ---
# Source:  return $host if @labels <= 2;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3190_29_< line 3190 in _registrable()';
    # Suggested boundary values to test: 1, 2, 3
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3190 in _registrable() to detect the mutant
    fail('NUM_BOUNDARY_3190_29_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3191_5 (MEDIUM) line 3191 in _registrable() ---
# Source:  if ($labels[-1] =~ /^[a-z]{2}$/ &&
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3191_5 line 3191 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3191 in _registrable() to detect the mutant
    fail('COND_INV_3191_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3400_5 (MEDIUM) line 3400 in abuse_report_text() ---
# Source:  if (@{ $risk->{flags} }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3400_5 line 3400 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3400 in abuse_report_text() to detect the mutant
    fail('COND_INV_3400_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3409_5 (MEDIUM) line 3409 in abuse_report_text() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3409_5 line 3409 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3409 in abuse_report_text() to detect the mutant
    fail('COND_INV_3409_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3416_5 (MEDIUM) line 3416 in abuse_report_text() ---
# Source:  if (@contacts) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3416_5 line 3416 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3416 in abuse_report_text() to detect the mutant
    fail('COND_INV_3416_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3423_5 (MEDIUM) line 3423 in abuse_report_text() ---
# Source:  if (@form_cs) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3423_5 line 3423 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3423 in abuse_report_text() to detect the mutant
    fail('COND_INV_3423_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3785_9 (MEDIUM) line 3785 in abuse_contacts() ---
# Source:  if ($addr =~ /\@([\w.-]+)$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3785_9 line 3785 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3785 in abuse_contacts() to detect the mutant
    fail('COND_INV_3785_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3790_9 (MEDIUM) line 3790 in abuse_contacts() ---
# Source:  if (exists $seen_idx{$addr}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3790_9 line 3790 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3790 in abuse_contacts() to detect the mutant
    fail('COND_INV_3790_9: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3809_34_< (HIGH) line 3809 in abuse_contacts() ---
# Source:  $role_counts{$_} > 1 ? "$_ (x$role_counts{$_})" : $_
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3809_34_< line 3809 in abuse_contacts()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3809 in abuse_contacts() to detect the mutant
    fail('NUM_BOUNDARY_3809_34_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3817_33_< (HIGH) line 3817 in abuse_contacts() ---
# Source:  if (length($joined) > 80) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3817_33_< line 3817 in abuse_contacts()';
    # Suggested boundary values to test: 79, 80, 81
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3817 in abuse_contacts() to detect the mutant
    fail('NUM_BOUNDARY_3817_33_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3837_5 (MEDIUM) line 3837 in abuse_contacts() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3837_5 line 3837 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3837 in abuse_contacts() to detect the mutant
    fail('COND_INV_3837_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3839_9 (MEDIUM) line 3839 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3839_9 line 3839 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3839 in abuse_contacts() to detect the mutant
    fail('COND_INV_3839_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3845_9 (MEDIUM) line 3845 in abuse_contacts() ---
# Source:  if ($orig->{abuse} && $orig->{abuse} ne '(unknown)') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3845_9 line 3845 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3845 in abuse_contacts() to detect the mutant
    fail('COND_INV_3845_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3864_9 (MEDIUM) line 3864 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3864_9 line 3864 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3864 in abuse_contacts() to detect the mutant
    fail('COND_INV_3864_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3870_9 (MEDIUM) line 3870 in abuse_contacts() ---
# Source:  if ($u->{abuse} && $u->{abuse} ne '(unknown)') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3870_9 line 3870 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3870 in abuse_contacts() to detect the mutant
    fail('COND_INV_3870_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3883_9 (MEDIUM) line 3883 in abuse_contacts() ---
# Source:  if ($d->{web_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3883_9 line 3883 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3883 in abuse_contacts() to detect the mutant
    fail('COND_INV_3883_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3885_13 (MEDIUM) line 3885 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3885_13 line 3885 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3885 in abuse_contacts() to detect the mutant
    fail('COND_INV_3885_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3901_9 (MEDIUM) line 3901 in abuse_contacts() ---
# Source:  if ($d->{mx_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3901_9 line 3901 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3901 in abuse_contacts() to detect the mutant
    fail('COND_INV_3901_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3912_9 (MEDIUM) line 3912 in abuse_contacts() ---
# Source:  if ($d->{ns_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3912_9 line 3912 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3912 in abuse_contacts() to detect the mutant
    fail('COND_INV_3912_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3930_9 (MEDIUM) line 3930 in abuse_contacts() ---
# Source:  if ($d->{registrar_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3930_9 line 3930 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3930 in abuse_contacts() to detect the mutant
    fail('COND_INV_3930_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3936_13 (MEDIUM) line 3936 in abuse_contacts() ---
# Source:  unless ($spoofable_only) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_3936_13 line 3936 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3936 in abuse_contacts() to detect the mutant
    fail('COND_INV_3936_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3959_9 (MEDIUM) line 3959 in abuse_contacts() ---
# Source:  if ($val =~ /<([^>]*)>\s*$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3959_9 line 3959 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3959 in abuse_contacts() to detect the mutant
    fail('COND_INV_3959_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3984_9 (MEDIUM) line 3984 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3984_9 line 3984 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3984 in abuse_contacts() to detect the mutant
    fail('COND_INV_3984_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4003_5 (MEDIUM) line 4003 in abuse_contacts() ---
# Source:  if ($auth->{dkim_domain}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4003_5 line 4003 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4003 in abuse_contacts() to detect the mutant
    fail('COND_INV_4003_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4005_9 (MEDIUM) line 4005 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4005_9 line 4005 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4005 in abuse_contacts() to detect the mutant
    fail('COND_INV_4005_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4015_5 (MEDIUM) line 4015 in abuse_contacts() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4015_5 line 4015 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4015 in abuse_contacts() to detect the mutant
    fail('COND_INV_4015_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4027_13 (MEDIUM) line 4027 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4027_13 line 4027 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4027 in abuse_contacts() to detect the mutant
    fail('COND_INV_4027_13: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4062_5 (MEDIUM) line 4062 in abuse_contacts() ---
# Source:  return @contacts;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4062_5 line 4062 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4062 in abuse_contacts() to detect the mutant
    fail('BOOL_NEGATE_4062_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4074_5 (MEDIUM) line 4074 in _provider_abuse_for_host() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4074_5 line 4074 in _provider_abuse_for_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4074 in _provider_abuse_for_host() to detect the mutant
    fail('BOOL_NEGATE_4074_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4080_5 (MEDIUM) line 4080 in _provider_abuse_for_ip() ---
# Source:  return $self->_provider_abuse_for_host($rdns) if $rdns;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4080_5 line 4080 in _provider_abuse_for_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4080 in _provider_abuse_for_ip() to detect the mutant
    fail('BOOL_NEGATE_4080_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4081_5 (MEDIUM) line 4081 in _provider_abuse_for_ip() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4081_5 line 4081 in _provider_abuse_for_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4081 in _provider_abuse_for_ip() to detect the mutant
    fail('BOOL_NEGATE_4081_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4397_2 (MEDIUM) line 4397 in form_contacts() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4397_2 line 4397 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4397 in form_contacts() to detect the mutant
    fail('COND_INV_4397_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4399_3 (MEDIUM) line 4399 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4399_3 line 4399 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4399 in form_contacts() to detect the mutant
    fail('COND_INV_4399_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4416_3 (MEDIUM) line 4416 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4416_3 line 4416 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4416 in form_contacts() to detect the mutant
    fail('COND_INV_4416_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4433_3 (MEDIUM) line 4433 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4433_3 line 4433 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4433 in form_contacts() to detect the mutant
    fail('COND_INV_4433_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4451_3 (MEDIUM) line 4451 in form_contacts() ---
# Source:  if ($d->{registrar_abuse} && $d->{registrar_abuse} =~ /\@([\w.-]+)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4451_3 line 4451 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4451 in form_contacts() to detect the mutant
    fail('COND_INV_4451_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4454_4 (MEDIUM) line 4454 in form_contacts() ---
# Source:  if ($rpa && $rpa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4454_4 line 4454 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4454 in form_contacts() to detect the mutant
    fail('COND_INV_4454_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4476_3 (MEDIUM) line 4476 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4476_3 line 4476 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4476 in form_contacts() to detect the mutant
    fail('COND_INV_4476_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4492_2 (MEDIUM) line 4492 in form_contacts() ---
# Source:  if ($auth->{dkim_domain}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4492_2 line 4492 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4492 in form_contacts() to detect the mutant
    fail('COND_INV_4492_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4494_3 (MEDIUM) line 4494 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4494_3 line 4494 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4494 in form_contacts() to detect the mutant
    fail('COND_INV_4494_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4508_2 (MEDIUM) line 4508 in form_contacts() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4508_2 line 4508 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4508 in form_contacts() to detect the mutant
    fail('COND_INV_4508_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4515_4 (MEDIUM) line 4515 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4515_4 line 4515 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4515 in form_contacts() to detect the mutant
    fail('COND_INV_4515_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4528_2 (MEDIUM) line 4528 in form_contacts() ---
# Source:  return @contacts;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4528_2 line 4528 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4528 in form_contacts() to detect the mutant
    fail('BOOL_NEGATE_4528_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4554_5 (MEDIUM) line 4554 in report() ---
# Source:  if (@{ $risk->{flags} }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4554_5 line 4554 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4554 in report() to detect the mutant
    fail('COND_INV_4554_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4566_5 (MEDIUM) line 4566 in report() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4566_5 line 4566 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4566 in report() to detect the mutant
    fail('COND_INV_4566_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4581_5 (MEDIUM) line 4581 in report() ---
# Source:  if (@sw) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4581_5 line 4581 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4581 in report() to detect the mutant
    fail('COND_INV_4581_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4593_5 (MEDIUM) line 4593 in report() ---
# Source:  if (@trail) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4593_5 line 4593 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4593 in report() to detect the mutant
    fail('COND_INV_4593_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4608_5 (MEDIUM) line 4608 in report() ---
# Source:  if (@urls) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4608_5 line 4608 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4608 in report() to detect the mutant
    fail('COND_INV_4608_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4615_13 (MEDIUM) line 4615 in report() ---
# Source:  unless (exists $host_order{$h}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_4615_13 line 4615 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4615 in report() to detect the mutant
    fail('COND_INV_4615_13: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4633_24_!= (HIGH) line 4633 in report() ---
# Source:  if (@paths == 1) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (2 variants — one test should kill all):
#   Numeric boundary flip == to !=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4633_24_!= line 4633 in report()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4633 in report() to detect the mutant
    fail('NUM_BOUNDARY_4633_24_!=: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4649_5 (MEDIUM) line 4649 in report() ---
# Source:  if (@mdoms) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4649_5 line 4649 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4649 in report() to detect the mutant
    fail('COND_INV_4649_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4654_13 (MEDIUM) line 4654 in report() ---
# Source:  if ($d->{recently_registered}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4654_13 line 4654 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4654 in report() to detect the mutant
    fail('COND_INV_4654_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4662_13 (MEDIUM) line 4662 in report() ---
# Source:  if ($d->{web_ip}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4662_13 line 4662 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4662 in report() to detect the mutant
    fail('COND_INV_4662_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4670_13 (MEDIUM) line 4670 in report() ---
# Source:  if ($d->{mx_host}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4670_13 line 4670 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4670 in report() to detect the mutant
    fail('COND_INV_4670_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4679_13 (MEDIUM) line 4679 in report() ---
# Source:  if ($d->{ns_host}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4679_13 line 4679 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4679 in report() to detect the mutant
    fail('COND_INV_4679_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4696_5 (MEDIUM) line 4696 in report() ---
# Source:  if (@contacts) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4696_5 line 4696 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4696 in report() to detect the mutant
    fail('COND_INV_4696_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4711_5 (MEDIUM) line 4711 in report() ---
# Source:  if (@form_cs) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4711_5 line 4711 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4711 in report() to detect the mutant
    fail('COND_INV_4711_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4721_13 (MEDIUM) line 4721 in report() ---
# Source:  if ($c->{form_paste}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4721_13 line 4721 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4721 in report() to detect the mutant
    fail('COND_INV_4721_13: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4727_61_< (HIGH) line 4727 in report() ---
# Source:  if (defined $line && length("$line $w") > 66) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4727_61_< line 4727 in report()';
    # Suggested boundary values to test: 65, 66, 67
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4727 in report() to detect the mutant
    fail('NUM_BOUNDARY_4727_61_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4814_9 (MEDIUM) line 4814 in _split_message() ---
# Source:  if ($line =~ /^([\w-]+)\s*:\s*(.*)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4814_9 line 4814 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4814 in _split_message() to detect the mutant
    fail('COND_INV_4814_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4827_5 (MEDIUM) line 4827 in _split_message() ---
# Source:  if ($ct =~ /multipart/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4827_5 line 4827 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4827 in _split_message() to detect the mutant
    fail('COND_INV_4827_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4832_9 (MEDIUM) line 4832 in _split_message() ---
# Source:  if ($ct =~ /html/i) { $self->{_body_html}  = $decoded }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4832_9 line 4832 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4832 in _split_message() to detect the mutant
    fail('COND_INV_4832_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4905_9 (MEDIUM) line 4905 in _decode_multipart() ---
# Source:  if ($pct =~ /multipart/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4905_9 line 4905 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4905 in _decode_multipart() to detect the mutant
    fail('COND_INV_4905_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4909_13 (MEDIUM) line 4909 in _decode_multipart() ---
# Source:  if ($inner_boundary) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4909_13 line 4909 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4909 in _decode_multipart() to detect the mutant
    fail('COND_INV_4909_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4922_9 (MEDIUM) line 4922 in _decode_multipart() ---
# Source:  if    ($pct =~ /text\/html/i)    { $self->{_body_html}  .= $decoded }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4922_9 line 4922 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4922 in _decode_multipart() to detect the mutant
    fail('COND_INV_4922_9: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4932_5 (MEDIUM) line 4932 in _decode_body() ---
# Source:  return $body;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4932_5 line 4932 in _decode_body()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4932 in _decode_body() to detect the mutant
    fail('BOOL_NEGATE_4932_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5006_5 (MEDIUM) line 5006 in _find_origin() ---
# Source:  unless (@candidates) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_5006_5 line 5006 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5006 in _find_origin() to detect the mutant
    fail('COND_INV_5006_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5008_9 (MEDIUM) line 5008 in _find_origin() ---
# Source:  if ($xoip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5008_9 line 5008 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5008 in _find_origin() to detect the mutant
    fail('COND_INV_5008_9: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5010_13 (MEDIUM) line 5010 in _find_origin() ---
# Source:  return $self->_enrich_ip($xoip, 'low',
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5010_13 line 5010 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5010 in _find_origin() to detect the mutant
    fail('BOOL_NEGATE_5010_13: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5014_9 (MEDIUM) line 5014 in _find_origin() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5014_9 line 5014 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5014 in _find_origin() to detect the mutant
    fail('BOOL_NEGATE_5014_9: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5017_5 (MEDIUM) line 5017 in _find_origin() ---
# Source:  return $self->_enrich_ip(
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5017_5 line 5017 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5017 in _find_origin() to detect the mutant
    fail('BOOL_NEGATE_5017_5: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_5019_21_< (HIGH) line 5019 in _find_origin() ---
# Source:  @candidates > 1 ? 'high' : 'medium',
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_5019_21_< line 5019 in _find_origin()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5019 in _find_origin() to detect the mutant
    fail('NUM_BOUNDARY_5019_21_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5027_9 (MEDIUM) line 5027 in _extract_ip_from_received() ---
# Source:  if ($hdr =~ $re) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5027_9 line 5027 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5027 in _extract_ip_from_received() to detect the mutant
    fail('COND_INV_5027_9: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_5030_31_< (HIGH) line 5030 in _extract_ip_from_received() ---
# Source:  next if grep { $_ > 255 } split /\./, $ip;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_5030_31_< line 5030 in _extract_ip_from_received()';
    # Suggested boundary values to test: 254, 255, 256
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5030 in _extract_ip_from_received() to detect the mutant
    fail('NUM_BOUNDARY_5030_31_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5031_13 (MEDIUM) line 5031 in _extract_ip_from_received() ---
# Source:  return $ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5031_13 line 5031 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5031 in _extract_ip_from_received() to detect the mutant
    fail('BOOL_NEGATE_5031_13: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5034_5 (MEDIUM) line 5034 in _extract_ip_from_received() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5034_5 line 5034 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5034 in _extract_ip_from_received() to detect the mutant
    fail('BOOL_NEGATE_5034_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5046_5 (MEDIUM) line 5046 in _is_private() ---
# Source:  return 1 unless defined $ip && $ip ne '';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5046_5 line 5046 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5046 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_5046_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5047_36 (MEDIUM) line 5047 in _is_private() ---
# Source:  for my $re (@PRIVATE_RANGES) { return 1 if $ip =~ $re }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5047_36 line 5047 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5047 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_5047_36: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5048_5 (MEDIUM) line 5048 in _is_private() ---
# Source:  return 0;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5048_5 line 5048 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5048 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_5048_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5054_9 (MEDIUM) line 5054 in _is_trusted() ---
# Source:  return 1 if $self->_ip_in_cidr($ip, $cidr);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5054_9 line 5054 in _is_trusted()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5054 in _is_trusted() to detect the mutant
    fail('BOOL_NEGATE_5054_9: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5056_5 (MEDIUM) line 5056 in _is_trusted() ---
# Source:  return 0;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5056_5 line 5056 in _is_trusted()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5056 in _is_trusted() to detect the mutant
    fail('BOOL_NEGATE_5056_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5075_9 (MEDIUM) line 5075 in _extract_and_resolve_urls() ---
# Source:  unless (exists $host_cache{$host}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_5075_9 line 5075 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5075 in _extract_and_resolve_urls() to detect the mutant
    fail('COND_INV_5075_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5085_13 (MEDIUM) line 5085 in _extract_and_resolve_urls() ---
# Source:  if (!$whois->{abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5085_13 line 5085 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5085 in _extract_and_resolve_urls() to detect the mutant
    fail('COND_INV_5085_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5112_2 (MEDIUM) line 5112 in _extract_http_urls() ---
# Source:  if ($HAS_HTML_LINKEXTOR) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5112_2 line 5112 in _extract_http_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5112 in _extract_http_urls() to detect the mutant
    fail('COND_INV_5112_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5117_5 (MEDIUM) line 5117 in _extract_http_urls() ---
# Source:  if ($val =~ m{^https?://}i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5117_5 line 5117 in _extract_http_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5117 in _extract_http_urls() to detect the mutant
    fail('COND_INV_5117_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5145_2 (MEDIUM) line 5145 in _extract_http_urls() ---
# Source:  return @all;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5145_2 line 5145 in _extract_http_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5145 in _extract_http_urls() to detect the mutant
    fail('BOOL_NEGATE_5145_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5219_5 (MEDIUM) line 5219 in _extract_and_analyse_domains() ---
# Source:  if ($mid && $mid =~ /\@([\w.-]+)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5219_5 line 5219 in _extract_and_analyse_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5219 in _extract_and_analyse_domains() to detect the mutant
    fail('COND_INV_5219_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5235_5 (MEDIUM) line 5235 in _extract_and_analyse_domains() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5235_5 line 5235 in _extract_and_analyse_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5235 in _extract_and_analyse_domains() to detect the mutant
    fail('COND_INV_5235_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5276_5 (MEDIUM) line 5276 in _domains_from_text() ---
# Source:  return @out;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5276_5 line 5276 in _domains_from_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5276 in _domains_from_text() to detect the mutant
    fail('BOOL_NEGATE_5276_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5382_5 (MEDIUM) line 5382 in _analyse_domain() ---
# Source:  return $self->{_domain_info}{$domain}
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5382_5 line 5382 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5382 in _analyse_domain() to detect the mutant
    fail('BOOL_NEGATE_5382_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5390_5 (MEDIUM) line 5390 in _analyse_domain() ---
# Source:  if ($web_ip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5390_5 line 5390 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5390 in _analyse_domain() to detect the mutant
    fail('COND_INV_5390_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5397_5 (MEDIUM) line 5397 in _analyse_domain() ---
# Source:  if ($HAS_NET_DNS) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5397_5 line 5397 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5397 in _analyse_domain() to detect the mutant
    fail('COND_INV_5397_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5405_9 (MEDIUM) line 5405 in _analyse_domain() ---
# Source:  if ($mxq) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5405_9 line 5405 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5405 in _analyse_domain() to detect the mutant
    fail('COND_INV_5405_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5408_13 (MEDIUM) line 5408 in _analyse_domain() ---
# Source:  if ($best) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5408_13 line 5408 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5408 in _analyse_domain() to detect the mutant
    fail('COND_INV_5408_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5412_17 (MEDIUM) line 5412 in _analyse_domain() ---
# Source:  if ($mx_ip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5412_17 line 5412 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5412 in _analyse_domain() to detect the mutant
    fail('COND_INV_5412_17: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5423_9 (MEDIUM) line 5423 in _analyse_domain() ---
# Source:  if ($nsq) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5423_9 line 5423 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5423 in _analyse_domain() to detect the mutant
    fail('COND_INV_5423_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5425_13 (MEDIUM) line 5425 in _analyse_domain() ---
# Source:  if ($first) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5425_13 line 5425 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5425 in _analyse_domain() to detect the mutant
    fail('COND_INV_5425_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5429_17 (MEDIUM) line 5429 in _analyse_domain() ---
# Source:  if ($ns_ip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5429_17 line 5429 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5429 in _analyse_domain() to detect the mutant
    fail('COND_INV_5429_17: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5441_5 (MEDIUM) line 5441 in _analyse_domain() ---
# Source:  if ($domain_whois) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5441_5 line 5441 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5441 in _analyse_domain() to detect the mutant
    fail('COND_INV_5441_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5444_9 (MEDIUM) line 5444 in _analyse_domain() ---
# Source:  if ($domain_whois =~ /Registrar:\s*(.+)/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5444_9 line 5444 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5444 in _analyse_domain() to detect the mutant
    fail('COND_INV_5444_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5454_13 (MEDIUM) line 5454 in _analyse_domain() ---
# Source:  if (!$info{registrar_abuse} && $domain_whois =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5454_13 line 5454 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5454 in _analyse_domain() to detect the mutant
    fail('COND_INV_5454_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5465_13 (MEDIUM) line 5465 in _analyse_domain() ---
# Source:  if (!$info{registered} && $domain_whois =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5465_13 line 5465 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5465 in _analyse_domain() to detect the mutant
    fail('COND_INV_5465_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5475_13 (MEDIUM) line 5475 in _analyse_domain() ---
# Source:  if (!$info{expires} && $domain_whois =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5475_13 line 5475 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5475 in _analyse_domain() to detect the mutant
    fail('COND_INV_5475_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5481_9 (MEDIUM) line 5481 in _analyse_domain() ---
# Source:  if ($info{registered}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5481_9 line 5481 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5481 in _analyse_domain() to detect the mutant
    fail('COND_INV_5481_9: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_5484_48_> (HIGH) line 5484 in _analyse_domain() ---
# Source:  if $epoch && (time() - $epoch) < 180 * 86400;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip < to >
#   Numeric boundary flip < to <=
#   Numeric boundary flip < to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_5484_48_> line 5484 in _analyse_domain()';
    # Suggested boundary values to test: 179, 180, 181
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5484 in _analyse_domain() to detect the mutant
    fail('NUM_BOUNDARY_5484_48_>: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5498_5 (MEDIUM) line 5498 in _resolve_host() ---
# Source:  return $host if $host =~ /^\d{1,3}(?:\.\d{1,3}){3}$/;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5498_5 line 5498 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5498 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_5498_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5500_5 (MEDIUM) line 5500 in _resolve_host() ---
# Source:  if ($HAS_NET_DNS) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5500_5 line 5500 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5500 in _resolve_host() to detect the mutant
    fail('COND_INV_5500_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5506_9 (MEDIUM) line 5506 in _resolve_host() ---
# Source:  if ($query) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5506_9 line 5506 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5506 in _resolve_host() to detect the mutant
    fail('COND_INV_5506_9: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5508_17 (MEDIUM) line 5508 in _resolve_host() ---
# Source:  return $rr->address if $rr->type eq 'A';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5508_17 line 5508 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5508 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_5508_17: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5511_9 (MEDIUM) line 5511 in _resolve_host() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5511_9 line 5511 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5511 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_5511_9: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5515_5 (MEDIUM) line 5515 in _resolve_host() ---
# Source:  return $packed ? inet_ntoa($packed) : undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5515_5 line 5515 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5515 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_5515_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5520_5 (MEDIUM) line 5520 in _reverse_dns() ---
# Source:  return undef unless $ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5520_5 line 5520 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5520 in _reverse_dns() to detect the mutant
    fail('BOOL_NEGATE_5520_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5522_5 (MEDIUM) line 5522 in _reverse_dns() ---
# Source:  if ($HAS_NET_DNS) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5522_5 line 5522 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5522 in _reverse_dns() to detect the mutant
    fail('COND_INV_5522_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5525_9 (MEDIUM) line 5525 in _reverse_dns() ---
# Source:  if ($query) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5525_9 line 5525 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5525 in _reverse_dns() to detect the mutant
    fail('COND_INV_5525_9: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5527_17 (MEDIUM) line 5527 in _reverse_dns() ---
# Source:  return $rr->ptrdname if $rr->type eq 'PTR';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5527_17 line 5527 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5527 in _reverse_dns() to detect the mutant
    fail('BOOL_NEGATE_5527_17: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5530_9 (MEDIUM) line 5530 in _reverse_dns() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5530_9 line 5530 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5530 in _reverse_dns() to detect the mutant
    fail('BOOL_NEGATE_5530_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5544_5 (MEDIUM) line 5544 in _whois_ip() ---
# Source:  unless ($result->{org}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_5544_5 line 5544 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5544 in _whois_ip() to detect the mutant
    fail('COND_INV_5544_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5546_9 (MEDIUM) line 5546 in _whois_ip() ---
# Source:  if ($raw) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5546_9 line 5546 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5546 in _whois_ip() to detect the mutant
    fail('COND_INV_5546_9: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5552_5 (MEDIUM) line 5552 in _whois_ip() ---
# Source:  return $result;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5552_5 line 5552 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5552 in _whois_ip() to detect the mutant
    fail('BOOL_NEGATE_5552_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5560_5 (MEDIUM) line 5560 in _domain_whois() ---
# Source:  return undef unless $server;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5560_5 line 5560 in _domain_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5560 in _domain_whois() to detect the mutant
    fail('BOOL_NEGATE_5560_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5561_5 (MEDIUM) line 5561 in _domain_whois() ---
# Source:  return $self->_raw_whois($domain, $server);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5561_5 line 5561 in _domain_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5561 in _domain_whois() to detect the mutant
    fail('BOOL_NEGATE_5561_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5577_2 (MEDIUM) line 5577 in _parse_domain_whois_abuse() ---
# Source:  if ($raw =~ /Registrar:\s*(.+)/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5577_2 line 5577 in _parse_domain_whois_abuse()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5577 in _parse_domain_whois_abuse() to detect the mutant
    fail('COND_INV_5577_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5585_3 (MEDIUM) line 5585 in _parse_domain_whois_abuse() ---
# Source:  if (!$info{abuse} && $raw =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5585_3 line 5585 in _parse_domain_whois_abuse()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5585 in _parse_domain_whois_abuse() to detect the mutant
    fail('COND_INV_5585_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5603_5 (MEDIUM) line 5603 in _rdap_lookup() ---
# Source:  if ($j =~ /"abuse".*?"email"\s*:\s*"([^"]+)"/s) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5603_5 line 5603 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5603 in _rdap_lookup() to detect the mutant
    fail('COND_INV_5603_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5663_5 (MEDIUM) line 5663 in _raw_whois() ---
# Source:  return undef unless $sock;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5663_5 line 5663 in _raw_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5663 in _raw_whois() to detect the mutant
    fail('BOOL_NEGATE_5663_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5666_56 (MEDIUM) line 5666 in _raw_whois() ---
# Source:  $sock->print("$query\r\n") or do { $sock->close(); return undef };
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5666_56 line 5666 in _raw_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5666 in _raw_whois() to detect the mutant
    fail('BOOL_NEGATE_5666_56: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_5680_38_< (HIGH) line 5680 in _raw_whois() ---
# Source:  last unless defined $n && $n > 0;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_5680_38_< line 5680 in _raw_whois()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5680 in _raw_whois() to detect the mutant
    fail('NUM_BOUNDARY_5680_38_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5685_5 (MEDIUM) line 5685 in _raw_whois() ---
# Source:  return $response || undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5685_5 line 5685 in _raw_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5685 in _raw_whois() to detect the mutant
    fail('BOOL_NEGATE_5685_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5696_9 (MEDIUM) line 5696 in _parse_whois_text() ---
# Source:  if (!$info{org} && $text =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5696_9 line 5696 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5696 in _parse_whois_text() to detect the mutant
    fail('COND_INV_5696_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5704_9 (MEDIUM) line 5704 in _parse_whois_text() ---
# Source:  if (!$info{abuse} && $text =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5704_9 line 5704 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5704 in _parse_whois_text() to detect the mutant
    fail('COND_INV_5704_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5710_5 (MEDIUM) line 5710 in _parse_whois_text() ---
# Source:  if ($text =~ /^country:\s*([A-Za-z]{2})\s*$/m) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5710_5 line 5710 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5710 in _parse_whois_text() to detect the mutant
    fail('COND_INV_5710_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5738_9 (MEDIUM) line 5738 in _header_value() ---
# Source:  return $h->{value} if $h->{name} eq lc($name);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5738_9 line 5738 in _header_value()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5738 in _header_value() to detect the mutant
    fail('BOOL_NEGATE_5738_9: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5740_5 (MEDIUM) line 5740 in _header_value() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5740_5 line 5740 in _header_value()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5740 in _header_value() to detect the mutant
    fail('BOOL_NEGATE_5740_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5745_5 (MEDIUM) line 5745 in _ip_in_cidr() ---
# Source:  return $ip eq $cidr unless $cidr =~ m{/};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5745_5 line 5745 in _ip_in_cidr()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5745 in _ip_in_cidr() to detect the mutant
    fail('BOOL_NEGATE_5745_5: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_5747_70_< (HIGH) line 5747 in _ip_in_cidr() ---
# Source:  return 0 unless defined $prefix && $prefix =~ /^\d+$/ && $prefix <= 32;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_5747_70_< line 5747 in _ip_in_cidr()';
    # Suggested boundary values to test: 31, 32, 33
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5747 in _ip_in_cidr() to detect the mutant
    fail('NUM_BOUNDARY_5747_70_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_5751_28_!= (HIGH) line 5751 in _ip_in_cidr() ---
# Source:  return ($ip_n & $mask) == ($net_n & $mask);
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (1 variant):
#   Numeric boundary flip == to !=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_5751_28_!= line 5751 in _ip_in_cidr()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5751 in _ip_in_cidr() to detect the mutant
    fail('NUM_BOUNDARY_5751_28_!=: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5758_5 (MEDIUM) line 5758 in _parse_date_to_epoch() ---
# Source:  return undef unless $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5758_5 line 5758 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5758 in _parse_date_to_epoch() to detect the mutant
    fail('BOOL_NEGATE_5758_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5760_5 (MEDIUM) line 5760 in _parse_date_to_epoch() ---
# Source:  if    ($str =~ /^(\d{4})-(\d{2})-(\d{2})/)         { ($y,$m,$d)=($1,$2,$3) }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5760_5 line 5760 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5760 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_5760_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5763_5 (MEDIUM) line 5763 in _parse_date_to_epoch() ---
# Source:  return undef unless $y && $m && $d;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5763_5 line 5763 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5763 in _parse_date_to_epoch() to detect the mutant
    fail('BOOL_NEGATE_5763_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5764_5 (MEDIUM) line 5764 in _parse_date_to_epoch() ---
# Source:  if (eval { require Time::Local; 1 }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5764_5 line 5764 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5764 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_5764_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5780_5 (MEDIUM) line 5780 in _parse_rfc2822_date() ---
# Source:  return undef unless $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5780_5 line 5780 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5780 in _parse_rfc2822_date() to detect the mutant
    fail('BOOL_NEGATE_5780_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5781_5 (MEDIUM) line 5781 in _parse_rfc2822_date() ---
# Source:  if ($str =~ /(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5781_5 line 5781 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5781 in _parse_rfc2822_date() to detect the mutant
    fail('COND_INV_5781_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5784_9 (MEDIUM) line 5784 in _parse_rfc2822_date() ---
# Source:  return undef unless $m;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5784_9 line 5784 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5784 in _parse_rfc2822_date() to detect the mutant
    fail('BOOL_NEGATE_5784_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5785_9 (MEDIUM) line 5785 in _parse_rfc2822_date() ---
# Source:  if (eval { require Time::Local; 1 }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5785_9 line 5785 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5785 in _parse_rfc2822_date() to detect the mutant
    fail('COND_INV_5785_9: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5789_5 (MEDIUM) line 5789 in _parse_rfc2822_date() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5789_5 line 5789 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5789 in _parse_rfc2822_date() to detect the mutant
    fail('BOOL_NEGATE_5789_5: replace with real assertion');
}

# --- LOW DIFFICULTY HINTS (comment stubs) ---

# --- LOW HINT: RETURN_UNDEF_784_2 line 784 in parse_email() ---
# Source:  return $self;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_784_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1063_5 line 1063 in originating_ip() ---
# Source:  return $self->{_origin};
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1063_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1899_5 line 1899 in all_domains() ---
# Source:  return @out;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1899_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1983_5 line 1983 in unresolved_contacts() ---
# Source:  return @out;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1983_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2461_5 line 2461 in _decode_mime_words() ---
# Source:  return '' unless defined $str;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2461_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2463_5 line 2463 in _decode_mime_words() ---
# Source:  return $str;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2463_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2480_5 line 2480 in _decode_ew() ---
# Source:  return $raw;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2480_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2880_5 line 2880 in risk_assessment() ---
# Source:  return $self->{_risk} if $self->{_risk};
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2880_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3134_5 line 3134 in risk_assessment() ---
# Source:  return $self->{_risk};
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3134_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3139_5 line 3139 in _parse_auth_results_cached() ---
# Source:  return $self->{_auth_results} if $self->{_auth_results};
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3139_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3188_5 line 3188 in _registrable() ---
# Source:  return undef unless $host && $host =~ /\./;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3188_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3190_5 line 3190 in _registrable() ---
# Source:  return $host if @labels <= 2;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3190_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4062_5 line 4062 in abuse_contacts() ---
# Source:  return @contacts;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4062_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4074_5 line 4074 in _provider_abuse_for_host() ---
# Source:  return undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4074_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4080_5 line 4080 in _provider_abuse_for_ip() ---
# Source:  return $self->_provider_abuse_for_host($rdns) if $rdns;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4080_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4081_5 line 4081 in _provider_abuse_for_ip() ---
# Source:  return undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4081_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4528_2 line 4528 in form_contacts() ---
# Source:  return @contacts;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4528_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4932_5 line 4932 in _decode_body() ---
# Source:  return $body;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4932_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5010_13 line 5010 in _find_origin() ---
# Source:  return $self->_enrich_ip($xoip, 'low',
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5010_13: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5014_9 line 5014 in _find_origin() ---
# Source:  return undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5014_9: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5017_5 line 5017 in _find_origin() ---
# Source:  return $self->_enrich_ip(
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5017_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5031_13 line 5031 in _extract_ip_from_received() ---
# Source:  return $ip;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5031_13: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5034_5 line 5034 in _extract_ip_from_received() ---
# Source:  return undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5034_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5046_5 line 5046 in _is_private() ---
# Source:  return 1 unless defined $ip && $ip ne '';
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5046_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5047_36 line 5047 in _is_private() ---
# Source:  for my $re (@PRIVATE_RANGES) { return 1 if $ip =~ $re }
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5047_36: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5048_5 line 5048 in _is_private() ---
# Source:  return 0;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5048_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5054_9 line 5054 in _is_trusted() ---
# Source:  return 1 if $self->_ip_in_cidr($ip, $cidr);
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5054_9: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5056_5 line 5056 in _is_trusted() ---
# Source:  return 0;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5056_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5145_2 line 5145 in _extract_http_urls() ---
# Source:  return @all;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5145_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5276_5 line 5276 in _domains_from_text() ---
# Source:  return @out;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5276_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5382_5 line 5382 in _analyse_domain() ---
# Source:  return $self->{_domain_info}{$domain}
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5382_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5498_5 line 5498 in _resolve_host() ---
# Source:  return $host if $host =~ /^\d{1,3}(?:\.\d{1,3}){3}$/;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5498_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5508_17 line 5508 in _resolve_host() ---
# Source:  return $rr->address if $rr->type eq 'A';
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5508_17: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5511_9 line 5511 in _resolve_host() ---
# Source:  return undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5511_9: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5515_5 line 5515 in _resolve_host() ---
# Source:  return $packed ? inet_ntoa($packed) : undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5515_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5520_5 line 5520 in _reverse_dns() ---
# Source:  return undef unless $ip;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5520_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5527_17 line 5527 in _reverse_dns() ---
# Source:  return $rr->ptrdname if $rr->type eq 'PTR';
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5527_17: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5530_9 line 5530 in _reverse_dns() ---
# Source:  return undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5530_9: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5552_5 line 5552 in _whois_ip() ---
# Source:  return $result;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5552_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5560_5 line 5560 in _domain_whois() ---
# Source:  return undef unless $server;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5560_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5561_5 line 5561 in _domain_whois() ---
# Source:  return $self->_raw_whois($domain, $server);
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5561_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5663_5 line 5663 in _raw_whois() ---
# Source:  return undef unless $sock;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5663_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5666_56 line 5666 in _raw_whois() ---
# Source:  $sock->print("$query\r\n") or do { $sock->close(); return undef };
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5666_56: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5685_5 line 5685 in _raw_whois() ---
# Source:  return $response || undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5685_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5738_9 line 5738 in _header_value() ---
# Source:  return $h->{value} if $h->{name} eq lc($name);
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5738_9: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5740_5 line 5740 in _header_value() ---
# Source:  return undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5740_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5745_5 line 5745 in _ip_in_cidr() ---
# Source:  return $ip eq $cidr unless $cidr =~ m{/};
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5745_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5747_5 line 5747 in _ip_in_cidr() ---
# Source:  return 0 unless defined $prefix && $prefix =~ /^\d+$/ && $prefix <= 32;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5747_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5758_5 line 5758 in _parse_date_to_epoch() ---
# Source:  return undef unless $str;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5758_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5763_5 line 5763 in _parse_date_to_epoch() ---
# Source:  return undef unless $y && $m && $d;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5763_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5780_5 line 5780 in _parse_rfc2822_date() ---
# Source:  return undef unless $str;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5780_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5784_9 line 5784 in _parse_rfc2822_date() ---
# Source:  return undef unless $m;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5784_9: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5789_5 line 5789 in _parse_rfc2822_date() ---
# Source:  return undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5789_5: add assertion here');

done_testing();
