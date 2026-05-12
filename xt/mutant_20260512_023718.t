#!/usr/bin/env perl
# Auto-generated mutant test stubs
# Generated: 2026-05-12 02:37:18
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

# --- SURVIVOR: BOOL_NEGATE_748_2 (MEDIUM) line 748 in parse_email() ---
# Source:  return $self;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_748_2 line 748 in parse_email()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 748 in parse_email() to detect the mutant
    fail('BOOL_NEGATE_748_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1031_2 (MEDIUM) line 1031 in originating_ip() ---
# Source:  return $self->{_origin};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1031_2 line 1031 in originating_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1031 in originating_ip() to detect the mutant
    fail('BOOL_NEGATE_1031_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1895_2 (MEDIUM) line 1895 in all_domains() ---
# Source:  return @out;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1895_2 line 1895 in all_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1895 in all_domains() to detect the mutant
    fail('BOOL_NEGATE_1895_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1935_9 (MEDIUM) line 1935 in unresolved_contacts() ---
# Source:  unless ($dom) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_1935_9 line 1935 in unresolved_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1935 in unresolved_contacts() to detect the mutant
    fail('COND_INV_1935_9: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1975_5 (MEDIUM) line 1975 in unresolved_contacts() ---
# Source:  return @out;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1975_5 line 1975 in unresolved_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1975 in unresolved_contacts() to detect the mutant
    fail('BOOL_NEGATE_1975_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2854_2 (MEDIUM) line 2854 in risk_assessment() ---
# Source:  return $self->{_risk} if $self->{_risk};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2854_2 line 2854 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2854 in risk_assessment() to detect the mutant
    fail('BOOL_NEGATE_2854_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2868_5 (MEDIUM) line 2868 in risk_assessment() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2868_5 line 2868 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2868 in risk_assessment() to detect the mutant
    fail('COND_INV_2868_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2870_9 (MEDIUM) line 2870 in risk_assessment() ---
# Source:  if ($orig->{rdns} && $orig->{rdns} =~ /
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2870_9 line 2870 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2870 in risk_assessment() to detect the mutant
    fail('COND_INV_2870_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2881_9 (MEDIUM) line 2881 in risk_assessment() ---
# Source:  if (!$orig->{rdns} || $orig->{rdns} eq '(no reverse DNS)') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2881_9 line 2881 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2881 in risk_assessment() to detect the mutant
    fail('COND_INV_2881_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2887_9 (MEDIUM) line 2887 in risk_assessment() ---
# Source:  if ($orig->{confidence} eq 'low') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2887_9 line 2887 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2887 in risk_assessment() to detect the mutant
    fail('COND_INV_2887_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2893_9 (MEDIUM) line 2893 in risk_assessment() ---
# Source:  if ($orig->{country} && $orig->{country} =~ /^(?:CN|RU|NG|VN|IN|PK|BD)$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2893_9 line 2893 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2893 in risk_assessment() to detect the mutant
    fail('COND_INV_2893_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2902_5 (MEDIUM) line 2902 in risk_assessment() ---
# Source:  if (defined $auth->{spf}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2902_5 line 2902 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2902 in risk_assessment() to detect the mutant
    fail('COND_INV_2902_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2903_9 (MEDIUM) line 2903 in risk_assessment() ---
# Source:  if ($auth->{spf} =~ /^fail/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2903_9 line 2903 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2903 in risk_assessment() to detect the mutant
    fail('COND_INV_2903_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2914_5 (MEDIUM) line 2914 in risk_assessment() ---
# Source:  if (defined $auth->{dkim} && $auth->{dkim} !~ /^pass/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2914_5 line 2914 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2914 in risk_assessment() to detect the mutant
    fail('COND_INV_2914_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2918_5 (MEDIUM) line 2918 in risk_assessment() ---
# Source:  if (defined $auth->{dmarc} && $auth->{dmarc} !~ /^pass/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2918_5 line 2918 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2918 in risk_assessment() to detect the mutant
    fail('COND_INV_2918_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2924_5 (MEDIUM) line 2924 in risk_assessment() ---
# Source:  if ($auth->{dkim_domain}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2924_5 line 2924 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2924 in risk_assessment() to detect the mutant
    fail('COND_INV_2924_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2926_9 (MEDIUM) line 2926 in risk_assessment() ---
# Source:  if ($from_domain) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2926_9 line 2926 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2926 in risk_assessment() to detect the mutant
    fail('COND_INV_2926_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2929_13 (MEDIUM) line 2929 in risk_assessment() ---
# Source:  if ($reg_dkim ne $reg_from) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2929_13 line 2929 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2929 in risk_assessment() to detect the mutant
    fail('COND_INV_2929_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2930_17 (MEDIUM) line 2930 in risk_assessment() ---
# Source:  if ($auth->{dkim} && $auth->{dkim} =~ /^pass/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2930_17 line 2930 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2930 in risk_assessment() to detect the mutant
    fail('COND_INV_2930_17: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2948_5 (MEDIUM) line 2948 in risk_assessment() ---
# Source:  if (!$date_raw || $date_raw !~ /\S/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2948_5 line 2948 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2948 in risk_assessment() to detect the mutant
    fail('COND_INV_2948_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2956_9 (MEDIUM) line 2956 in risk_assessment() ---
# Source:  if ($date_raw =~ /([+-])(\d{2})(\d{2})\s*$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2956_9 line 2956 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2956 in risk_assessment() to detect the mutant
    fail('COND_INV_2956_9: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2965_35_> (HIGH) line 2965 in risk_assessment() ---
# Source:  my $implausible = $mm >= 60
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2965_35_> line 2965 in risk_assessment()';
    # Suggested boundary values to test: 59, 60, 61
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2965 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_2965_35_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2966_50_< (HIGH) line 2966 in risk_assessment() ---
# Source:  || ($sign eq '+' && $offset_mins > 840)
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2966_50_< line 2966 in risk_assessment()';
    # Suggested boundary values to test: 839, 840, 841
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2966 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_2966_50_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2967_50_< (HIGH) line 2967 in risk_assessment() ---
# Source:  || ($sign eq '-' && $offset_mins > 720);
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2967_50_< line 2967 in risk_assessment()';
    # Suggested boundary values to test: 719, 720, 721
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2967 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_2967_50_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2968_13 (MEDIUM) line 2968 in risk_assessment() ---
# Source:  if ($implausible) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2968_13 line 2968 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2968 in risk_assessment() to detect the mutant
    fail('COND_INV_2968_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2979_9 (MEDIUM) line 2979 in risk_assessment() ---
# Source:  if (defined $date_epoch) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2979_9 line 2979 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2979 in risk_assessment() to detect the mutant
    fail('COND_INV_2979_9: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2981_24_< (HIGH) line 2981 in risk_assessment() ---
# Source:  if ($delta > 7 * 86400) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2981_24_< line 2981 in risk_assessment()';
    # Suggested boundary values to test: 6, 7, 8
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2981 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_2981_24_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2984_29_> (HIGH) line 2984 in risk_assessment() ---
# Source:  } elsif ($delta < -(7 * 86400)) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip < to >
#   Numeric boundary flip < to <=
#   Numeric boundary flip < to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2984_29_> line 2984 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2984 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_2984_29_>: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2995_5 (MEDIUM) line 2995 in risk_assessment() ---
# Source:  if ($from_decoded =~ /^"?([^"<]+?)"?\s*<([^>]+)>/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2995_5 line 2995 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2995 in risk_assessment() to detect the mutant
    fail('COND_INV_2995_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3004_13 (MEDIUM) line 3004 in risk_assessment() ---
# Source:  if ($reg_disp && $reg_addr && $reg_disp ne $reg_addr) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3004_13 line 3004 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3004 in risk_assessment() to detect the mutant
    fail('COND_INV_3004_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3012_5 (MEDIUM) line 3012 in risk_assessment() ---
# Source:  if ($from_raw =~ /\@(gmail|yahoo|hotmail|outlook|live|aol|protonmail|yandex)\./i
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3012_5 line 3012 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3012 in risk_assessment() to detect the mutant
    fail('COND_INV_3012_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3020_5 (MEDIUM) line 3020 in risk_assessment() ---
# Source:  if ($reply_to) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3020_5 line 3020 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3020 in risk_assessment() to detect the mutant
    fail('COND_INV_3020_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3023_9 (MEDIUM) line 3023 in risk_assessment() ---
# Source:  if ($from_addr && $reply_addr &&
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3023_9 line 3023 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3023 in risk_assessment() to detect the mutant
    fail('COND_INV_3023_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3032_5 (MEDIUM) line 3032 in risk_assessment() ---
# Source:  if ($to =~ /undisclosed|:;/ || $to eq '') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3032_5 line 3032 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3032 in risk_assessment() to detect the mutant
    fail('COND_INV_3032_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3039_5 (MEDIUM) line 3039 in risk_assessment() ---
# Source:  if ($subj_raw =~ /=\?[^?]+\?[BQ]\?/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3039_5 line 3039 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3039 in risk_assessment() to detect the mutant
    fail('COND_INV_3039_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3056_9 (MEDIUM) line 3056 in risk_assessment() ---
# Source:  if ($URL_SHORTENERS{$bare} && !$shortener_seen{$bare}++) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3056_9 line 3056 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3056 in risk_assessment() to detect the mutant
    fail('COND_INV_3056_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3061_9 (MEDIUM) line 3061 in risk_assessment() ---
# Source:  if ($u->{url} =~ m{^http://}i && !$url_host_seen{ $u->{host} }++) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3061_9 line 3061 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3061 in risk_assessment() to detect the mutant
    fail('COND_INV_3061_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3069_9 (MEDIUM) line 3069 in risk_assessment() ---
# Source:  if ($d->{recently_registered}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3069_9 line 3069 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3069 in risk_assessment() to detect the mutant
    fail('COND_INV_3069_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3074_9 (MEDIUM) line 3074 in risk_assessment() ---
# Source:  if ($d->{expires}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3074_9 line 3074 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3074 in risk_assessment() to detect the mutant
    fail('COND_INV_3074_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3077_13 (MEDIUM) line 3077 in risk_assessment() ---
# Source:  if ($exp) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3077_13 line 3077 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3077 in risk_assessment() to detect the mutant
    fail('COND_INV_3077_13: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3079_50_> (HIGH) line 3079 in risk_assessment() ---
# Source:  if ($remaining > 0 && $remaining < 30 * 86400) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (7 variants — one test should kill all):
#   Numeric boundary flip < to >
#   Numeric boundary flip < to <=
#   Numeric boundary flip < to >=
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3079_50_> line 3079 in risk_assessment()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3079 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_3079_50_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3083_35_< (HIGH) line 3083 in risk_assessment() ---
# Source:  elsif ($remaining <= 0) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3083_35_< line 3083 in risk_assessment()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3083 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_3083_35_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3093_13 (MEDIUM) line 3093 in risk_assessment() ---
# Source:  if ($d->{domain} =~ /\Q$brand\E/i &&
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3093_13 line 3093 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3093 in risk_assessment() to detect the mutant
    fail('COND_INV_3093_13: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3102_24_> (HIGH) line 3102 in risk_assessment() ---
# Source:  my $level = $score >= 9 ? 'HIGH'
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3102_24_> line 3102 in risk_assessment()';
    # Suggested boundary values to test: 8, 9, 10
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3102 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_3102_24_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3103_24_> (HIGH) line 3103 in risk_assessment() ---
# Source:  : $score >= 5 ? 'MEDIUM'
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3103_24_> line 3103 in risk_assessment()';
    # Suggested boundary values to test: 4, 5, 6
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3103 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_3103_24_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3104_24_> (HIGH) line 3104 in risk_assessment() ---
# Source:  : $score >= 2 ? 'LOW'
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3104_24_> line 3104 in risk_assessment()';
    # Suggested boundary values to test: 1, 2, 3
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3104 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_3104_24_>: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3108_2 (MEDIUM) line 3108 in risk_assessment() ---
# Source:  return $self->{_risk};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3108_2 line 3108 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3108 in risk_assessment() to detect the mutant
    fail('BOOL_NEGATE_3108_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3299_5 (MEDIUM) line 3299 in abuse_report_text() ---
# Source:  if (@{ $risk->{flags} }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3299_5 line 3299 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3299 in abuse_report_text() to detect the mutant
    fail('COND_INV_3299_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3308_5 (MEDIUM) line 3308 in abuse_report_text() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3308_5 line 3308 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3308 in abuse_report_text() to detect the mutant
    fail('COND_INV_3308_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3315_5 (MEDIUM) line 3315 in abuse_report_text() ---
# Source:  if (@contacts) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3315_5 line 3315 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3315 in abuse_report_text() to detect the mutant
    fail('COND_INV_3315_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3322_5 (MEDIUM) line 3322 in abuse_report_text() ---
# Source:  if (@form_cs) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3322_5 line 3322 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3322 in abuse_report_text() to detect the mutant
    fail('COND_INV_3322_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3703_9 (MEDIUM) line 3703 in abuse_contacts() ---
# Source:  if ($addr =~ /\@([\w.-]+)$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3703_9 line 3703 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3703 in abuse_contacts() to detect the mutant
    fail('COND_INV_3703_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3708_9 (MEDIUM) line 3708 in abuse_contacts() ---
# Source:  if (exists $seen_idx{$addr}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3708_9 line 3708 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3708 in abuse_contacts() to detect the mutant
    fail('COND_INV_3708_9: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3727_34_< (HIGH) line 3727 in abuse_contacts() ---
# Source:  $role_counts{$_} > 1 ? "$_ (x$role_counts{$_})" : $_
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3727_34_< line 3727 in abuse_contacts()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3727 in abuse_contacts() to detect the mutant
    fail('NUM_BOUNDARY_3727_34_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3735_33_< (HIGH) line 3735 in abuse_contacts() ---
# Source:  if (length($joined) > 80) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3735_33_< line 3735 in abuse_contacts()';
    # Suggested boundary values to test: 79, 80, 81
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3735 in abuse_contacts() to detect the mutant
    fail('NUM_BOUNDARY_3735_33_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3755_5 (MEDIUM) line 3755 in abuse_contacts() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3755_5 line 3755 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3755 in abuse_contacts() to detect the mutant
    fail('COND_INV_3755_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3757_9 (MEDIUM) line 3757 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3757_9 line 3757 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3757 in abuse_contacts() to detect the mutant
    fail('COND_INV_3757_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3763_9 (MEDIUM) line 3763 in abuse_contacts() ---
# Source:  if ($orig->{abuse} && $orig->{abuse} ne '(unknown)') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3763_9 line 3763 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3763 in abuse_contacts() to detect the mutant
    fail('COND_INV_3763_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3784_9 (MEDIUM) line 3784 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3784_9 line 3784 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3784 in abuse_contacts() to detect the mutant
    fail('COND_INV_3784_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3790_9 (MEDIUM) line 3790 in abuse_contacts() ---
# Source:  if ($u->{abuse} && $u->{abuse} ne '(unknown)') {
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

# --- SURVIVOR: COND_INV_3803_9 (MEDIUM) line 3803 in abuse_contacts() ---
# Source:  if ($d->{web_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3803_9 line 3803 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3803 in abuse_contacts() to detect the mutant
    fail('COND_INV_3803_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3805_13 (MEDIUM) line 3805 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3805_13 line 3805 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3805 in abuse_contacts() to detect the mutant
    fail('COND_INV_3805_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3821_9 (MEDIUM) line 3821 in abuse_contacts() ---
# Source:  if ($d->{mx_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3821_9 line 3821 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3821 in abuse_contacts() to detect the mutant
    fail('COND_INV_3821_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3832_9 (MEDIUM) line 3832 in abuse_contacts() ---
# Source:  if ($d->{ns_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3832_9 line 3832 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3832 in abuse_contacts() to detect the mutant
    fail('COND_INV_3832_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3843_9 (MEDIUM) line 3843 in abuse_contacts() ---
# Source:  if ($d->{registrar_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3843_9 line 3843 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3843 in abuse_contacts() to detect the mutant
    fail('COND_INV_3843_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3846_3 (MEDIUM) line 3846 in abuse_contacts() ---
# Source:  unless ($spoofable_only) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_3846_3 line 3846 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3846 in abuse_contacts() to detect the mutant
    fail('COND_INV_3846_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3869_9 (MEDIUM) line 3869 in abuse_contacts() ---
# Source:  if ($val =~ /<([^>]*)>\s*$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3869_9 line 3869 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3869 in abuse_contacts() to detect the mutant
    fail('COND_INV_3869_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3887_9 (MEDIUM) line 3887 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3887_9 line 3887 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3887 in abuse_contacts() to detect the mutant
    fail('COND_INV_3887_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3902_5 (MEDIUM) line 3902 in abuse_contacts() ---
# Source:  if ($auth->{dkim_domain}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3902_5 line 3902 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3902 in abuse_contacts() to detect the mutant
    fail('COND_INV_3902_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3904_9 (MEDIUM) line 3904 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3904_9 line 3904 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3904 in abuse_contacts() to detect the mutant
    fail('COND_INV_3904_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3914_5 (MEDIUM) line 3914 in abuse_contacts() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3914_5 line 3914 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3914 in abuse_contacts() to detect the mutant
    fail('COND_INV_3914_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3926_13 (MEDIUM) line 3926 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3926_13 line 3926 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3926 in abuse_contacts() to detect the mutant
    fail('COND_INV_3926_13: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3960_5 (MEDIUM) line 3960 in abuse_contacts() ---
# Source:  return @contacts;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3960_5 line 3960 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3960 in abuse_contacts() to detect the mutant
    fail('BOOL_NEGATE_3960_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4009_2 (MEDIUM) line 4009 in form_contacts() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4009_2 line 4009 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4009 in form_contacts() to detect the mutant
    fail('COND_INV_4009_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4011_3 (MEDIUM) line 4011 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4011_3 line 4011 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4011 in form_contacts() to detect the mutant
    fail('COND_INV_4011_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4028_3 (MEDIUM) line 4028 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4028_3 line 4028 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4028 in form_contacts() to detect the mutant
    fail('COND_INV_4028_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4045_3 (MEDIUM) line 4045 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4045_3 line 4045 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4045 in form_contacts() to detect the mutant
    fail('COND_INV_4045_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4063_3 (MEDIUM) line 4063 in form_contacts() ---
# Source:  if ($d->{registrar_abuse} && $d->{registrar_abuse} =~ /\@([\w.-]+)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4063_3 line 4063 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4063 in form_contacts() to detect the mutant
    fail('COND_INV_4063_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4066_4 (MEDIUM) line 4066 in form_contacts() ---
# Source:  if ($rpa && $rpa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4066_4 line 4066 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4066 in form_contacts() to detect the mutant
    fail('COND_INV_4066_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4088_9 (MEDIUM) line 4088 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4088_9 line 4088 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4088 in form_contacts() to detect the mutant
    fail('COND_INV_4088_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4104_2 (MEDIUM) line 4104 in form_contacts() ---
# Source:  if ($auth->{dkim_domain}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4104_2 line 4104 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4104 in form_contacts() to detect the mutant
    fail('COND_INV_4104_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4106_3 (MEDIUM) line 4106 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4106_3 line 4106 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4106 in form_contacts() to detect the mutant
    fail('COND_INV_4106_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4120_2 (MEDIUM) line 4120 in form_contacts() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4120_2 line 4120 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4120 in form_contacts() to detect the mutant
    fail('COND_INV_4120_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4127_4 (MEDIUM) line 4127 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4127_4 line 4127 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4127 in form_contacts() to detect the mutant
    fail('COND_INV_4127_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4140_2 (MEDIUM) line 4140 in form_contacts() ---
# Source:  return @contacts;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4140_2 line 4140 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4140 in form_contacts() to detect the mutant
    fail('BOOL_NEGATE_4140_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4427_5 (MEDIUM) line 4427 in report() ---
# Source:  if (@{ $risk->{flags} }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4427_5 line 4427 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4427 in report() to detect the mutant
    fail('COND_INV_4427_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4439_5 (MEDIUM) line 4439 in report() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4439_5 line 4439 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4439 in report() to detect the mutant
    fail('COND_INV_4439_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4454_5 (MEDIUM) line 4454 in report() ---
# Source:  if (@sw) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4454_5 line 4454 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4454 in report() to detect the mutant
    fail('COND_INV_4454_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4466_5 (MEDIUM) line 4466 in report() ---
# Source:  if (@trail) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4466_5 line 4466 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4466 in report() to detect the mutant
    fail('COND_INV_4466_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4481_5 (MEDIUM) line 4481 in report() ---
# Source:  if (@urls) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4481_5 line 4481 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4481 in report() to detect the mutant
    fail('COND_INV_4481_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4488_13 (MEDIUM) line 4488 in report() ---
# Source:  unless (exists $host_order{$h}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_4488_13 line 4488 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4488 in report() to detect the mutant
    fail('COND_INV_4488_13: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4506_24_!= (HIGH) line 4506 in report() ---
# Source:  if (@paths == 1) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (2 variants — one test should kill all):
#   Numeric boundary flip == to !=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4506_24_!= line 4506 in report()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4506 in report() to detect the mutant
    fail('NUM_BOUNDARY_4506_24_!=: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4522_5 (MEDIUM) line 4522 in report() ---
# Source:  if (@mdoms) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4522_5 line 4522 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4522 in report() to detect the mutant
    fail('COND_INV_4522_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4527_13 (MEDIUM) line 4527 in report() ---
# Source:  if ($d->{recently_registered}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4527_13 line 4527 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4527 in report() to detect the mutant
    fail('COND_INV_4527_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4535_13 (MEDIUM) line 4535 in report() ---
# Source:  if ($d->{web_ip}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4535_13 line 4535 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4535 in report() to detect the mutant
    fail('COND_INV_4535_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4543_13 (MEDIUM) line 4543 in report() ---
# Source:  if ($d->{mx_host}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4543_13 line 4543 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4543 in report() to detect the mutant
    fail('COND_INV_4543_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4552_13 (MEDIUM) line 4552 in report() ---
# Source:  if ($d->{ns_host}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4552_13 line 4552 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4552 in report() to detect the mutant
    fail('COND_INV_4552_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4569_5 (MEDIUM) line 4569 in report() ---
# Source:  if (@contacts) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4569_5 line 4569 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4569 in report() to detect the mutant
    fail('COND_INV_4569_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4584_5 (MEDIUM) line 4584 in report() ---
# Source:  if (@form_cs) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4584_5 line 4584 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4584 in report() to detect the mutant
    fail('COND_INV_4584_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4594_13 (MEDIUM) line 4594 in report() ---
# Source:  if ($c->{form_paste}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4594_13 line 4594 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4594 in report() to detect the mutant
    fail('COND_INV_4594_13: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4599_61_< (HIGH) line 4599 in report() ---
# Source:  if (defined $line && length("$line $w") > 66) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4599_61_< line 4599 in report()';
    # Suggested boundary values to test: 65, 66, 67
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4599 in report() to detect the mutant
    fail('NUM_BOUNDARY_4599_61_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4682_9 (MEDIUM) line 4682 in _split_message() ---
# Source:  if ($line =~ /^([\w-]+)\s*:\s*(.*)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4682_9 line 4682 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4682 in _split_message() to detect the mutant
    fail('COND_INV_4682_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4695_5 (MEDIUM) line 4695 in _split_message() ---
# Source:  if ($ct =~ /multipart/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4695_5 line 4695 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4695 in _split_message() to detect the mutant
    fail('COND_INV_4695_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4700_9 (MEDIUM) line 4700 in _split_message() ---
# Source:  if ($ct =~ /html/i) { $self->{_body_html}  = $decoded }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4700_9 line 4700 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4700 in _split_message() to detect the mutant
    fail('COND_INV_4700_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4773_9 (MEDIUM) line 4773 in _decode_multipart() ---
# Source:  if ($pct =~ /multipart/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4773_9 line 4773 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4773 in _decode_multipart() to detect the mutant
    fail('COND_INV_4773_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4777_13 (MEDIUM) line 4777 in _decode_multipart() ---
# Source:  if ($inner_boundary) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4777_13 line 4777 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4777 in _decode_multipart() to detect the mutant
    fail('COND_INV_4777_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4790_9 (MEDIUM) line 4790 in _decode_multipart() ---
# Source:  if    ($pct =~ /text\/html/i)    { $self->{_body_html}  .= $decoded }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4790_9 line 4790 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4790 in _decode_multipart() to detect the mutant
    fail('COND_INV_4790_9: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4802_2 (MEDIUM) line 4802 in _decode_body() ---
# Source:  return $body;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4802_2 line 4802 in _decode_body()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4802 in _decode_body() to detect the mutant
    fail('BOOL_NEGATE_4802_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4871_5 (MEDIUM) line 4871 in _find_origin() ---
# Source:  unless (@candidates) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_4871_5 line 4871 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4871 in _find_origin() to detect the mutant
    fail('COND_INV_4871_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4873_9 (MEDIUM) line 4873 in _find_origin() ---
# Source:  if ($xoip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4873_9 line 4873 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4873 in _find_origin() to detect the mutant
    fail('COND_INV_4873_9: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4875_13 (MEDIUM) line 4875 in _find_origin() ---
# Source:  return $self->_enrich_ip($xoip, 'low',
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4875_13 line 4875 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4875 in _find_origin() to detect the mutant
    fail('BOOL_NEGATE_4875_13: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4879_9 (MEDIUM) line 4879 in _find_origin() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4879_9 line 4879 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4879 in _find_origin() to detect the mutant
    fail('BOOL_NEGATE_4879_9: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4882_5 (MEDIUM) line 4882 in _find_origin() ---
# Source:  return $self->_enrich_ip(
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4882_5 line 4882 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4882 in _find_origin() to detect the mutant
    fail('BOOL_NEGATE_4882_5: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4884_21_< (HIGH) line 4884 in _find_origin() ---
# Source:  @candidates > 1 ? 'high' : 'medium',
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4884_21_< line 4884 in _find_origin()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4884 in _find_origin() to detect the mutant
    fail('NUM_BOUNDARY_4884_21_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4892_9 (MEDIUM) line 4892 in _extract_ip_from_received() ---
# Source:  if ($hdr =~ $re) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4892_9 line 4892 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4892 in _extract_ip_from_received() to detect the mutant
    fail('COND_INV_4892_9: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4895_31_< (HIGH) line 4895 in _extract_ip_from_received() ---
# Source:  next if grep { $_ > 255 } split /\./, $ip;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4895_31_< line 4895 in _extract_ip_from_received()';
    # Suggested boundary values to test: 254, 255, 256
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4895 in _extract_ip_from_received() to detect the mutant
    fail('NUM_BOUNDARY_4895_31_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4896_13 (MEDIUM) line 4896 in _extract_ip_from_received() ---
# Source:  return $ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4896_13 line 4896 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4896 in _extract_ip_from_received() to detect the mutant
    fail('BOOL_NEGATE_4896_13: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4899_5 (MEDIUM) line 4899 in _extract_ip_from_received() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4899_5 line 4899 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4899 in _extract_ip_from_received() to detect the mutant
    fail('BOOL_NEGATE_4899_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4909_5 (MEDIUM) line 4909 in _is_private() ---
# Source:  return 1 unless defined $ip && $ip ne '';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4909_5 line 4909 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4909 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_4909_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4910_36 (MEDIUM) line 4910 in _is_private() ---
# Source:  for my $re (@PRIVATE_RANGES) { return 1 if $ip =~ $re }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4910_36 line 4910 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4910 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_4910_36: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4911_5 (MEDIUM) line 4911 in _is_private() ---
# Source:  return 0;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4911_5 line 4911 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4911 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_4911_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4917_9 (MEDIUM) line 4917 in _is_trusted() ---
# Source:  return 1 if $self->_ip_in_cidr($ip, $cidr);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4917_9 line 4917 in _is_trusted()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4917 in _is_trusted() to detect the mutant
    fail('BOOL_NEGATE_4917_9: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4919_5 (MEDIUM) line 4919 in _is_trusted() ---
# Source:  return 0;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4919_5 line 4919 in _is_trusted()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4919 in _is_trusted() to detect the mutant
    fail('BOOL_NEGATE_4919_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4934_9 (MEDIUM) line 4934 in _extract_and_resolve_urls() ---
# Source:  unless (exists $host_cache{$host}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_4934_9 line 4934 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4934 in _extract_and_resolve_urls() to detect the mutant
    fail('COND_INV_4934_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4943_13 (MEDIUM) line 4943 in _extract_and_resolve_urls() ---
# Source:  if (!$whois->{abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4943_13 line 4943 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4943 in _extract_and_resolve_urls() to detect the mutant
    fail('COND_INV_4943_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4970_2 (MEDIUM) line 4970 in _extract_http_urls() ---
# Source:  if ($HAS_HTML_LINKEXTOR) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4970_2 line 4970 in _extract_http_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4970 in _extract_http_urls() to detect the mutant
    fail('COND_INV_4970_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4975_5 (MEDIUM) line 4975 in _extract_http_urls() ---
# Source:  if ($val =~ m{^https?://}i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4975_5 line 4975 in _extract_http_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4975 in _extract_http_urls() to detect the mutant
    fail('COND_INV_4975_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5003_2 (MEDIUM) line 5003 in _extract_http_urls() ---
# Source:  return @all;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5003_2 line 5003 in _extract_http_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5003 in _extract_http_urls() to detect the mutant
    fail('BOOL_NEGATE_5003_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5075_5 (MEDIUM) line 5075 in _extract_and_analyse_domains() ---
# Source:  if ($mid && $mid =~ /\@([\w.-]+)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5075_5 line 5075 in _extract_and_analyse_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5075 in _extract_and_analyse_domains() to detect the mutant
    fail('COND_INV_5075_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5091_5 (MEDIUM) line 5091 in _extract_and_analyse_domains() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5091_5 line 5091 in _extract_and_analyse_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5091 in _extract_and_analyse_domains() to detect the mutant
    fail('COND_INV_5091_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5132_5 (MEDIUM) line 5132 in _domains_from_text() ---
# Source:  return @out;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5132_5 line 5132 in _domains_from_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5132 in _domains_from_text() to detect the mutant
    fail('BOOL_NEGATE_5132_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5237_2 (MEDIUM) line 5237 in _analyse_domain() ---
# Source:  return $self->{_domain_info}{$domain} if $self->{_domain_info}{$domain};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5237_2 line 5237 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5237 in _analyse_domain() to detect the mutant
    fail('BOOL_NEGATE_5237_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5244_5 (MEDIUM) line 5244 in _analyse_domain() ---
# Source:  if ($web_ip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5244_5 line 5244 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5244 in _analyse_domain() to detect the mutant
    fail('COND_INV_5244_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5251_5 (MEDIUM) line 5251 in _analyse_domain() ---
# Source:  if ($HAS_NET_DNS) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5251_5 line 5251 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5251 in _analyse_domain() to detect the mutant
    fail('COND_INV_5251_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5259_9 (MEDIUM) line 5259 in _analyse_domain() ---
# Source:  if ($mxq) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5259_9 line 5259 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5259 in _analyse_domain() to detect the mutant
    fail('COND_INV_5259_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5262_13 (MEDIUM) line 5262 in _analyse_domain() ---
# Source:  if ($best) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5262_13 line 5262 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5262 in _analyse_domain() to detect the mutant
    fail('COND_INV_5262_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5266_17 (MEDIUM) line 5266 in _analyse_domain() ---
# Source:  if ($mx_ip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5266_17 line 5266 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5266 in _analyse_domain() to detect the mutant
    fail('COND_INV_5266_17: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5277_9 (MEDIUM) line 5277 in _analyse_domain() ---
# Source:  if ($nsq) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5277_9 line 5277 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5277 in _analyse_domain() to detect the mutant
    fail('COND_INV_5277_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5279_13 (MEDIUM) line 5279 in _analyse_domain() ---
# Source:  if ($first) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5279_13 line 5279 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5279 in _analyse_domain() to detect the mutant
    fail('COND_INV_5279_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5283_17 (MEDIUM) line 5283 in _analyse_domain() ---
# Source:  if ($ns_ip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5283_17 line 5283 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5283 in _analyse_domain() to detect the mutant
    fail('COND_INV_5283_17: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5295_5 (MEDIUM) line 5295 in _analyse_domain() ---
# Source:  if ($domain_whois) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5295_5 line 5295 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5295 in _analyse_domain() to detect the mutant
    fail('COND_INV_5295_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5298_9 (MEDIUM) line 5298 in _analyse_domain() ---
# Source:  if ($domain_whois =~ /Registrar:\s*(.+)/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5298_9 line 5298 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5298 in _analyse_domain() to detect the mutant
    fail('COND_INV_5298_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5308_13 (MEDIUM) line 5308 in _analyse_domain() ---
# Source:  if (!$info{registrar_abuse} && $domain_whois =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5308_13 line 5308 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5308 in _analyse_domain() to detect the mutant
    fail('COND_INV_5308_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5319_13 (MEDIUM) line 5319 in _analyse_domain() ---
# Source:  if (!$info{registered} && $domain_whois =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5319_13 line 5319 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5319 in _analyse_domain() to detect the mutant
    fail('COND_INV_5319_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5329_13 (MEDIUM) line 5329 in _analyse_domain() ---
# Source:  if (!$info{expires} && $domain_whois =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5329_13 line 5329 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5329 in _analyse_domain() to detect the mutant
    fail('COND_INV_5329_13: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5335_9 (MEDIUM) line 5335 in _analyse_domain() ---
# Source:  if ($info{registered}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5335_9 line 5335 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5335 in _analyse_domain() to detect the mutant
    fail('COND_INV_5335_9: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_5338_48_> (HIGH) line 5338 in _analyse_domain() ---
# Source:  if $epoch && (time() - $epoch) < 180 * 86400;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip < to >
#   Numeric boundary flip < to <=
#   Numeric boundary flip < to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_5338_48_> line 5338 in _analyse_domain()';
    # Suggested boundary values to test: 179, 180, 181
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5338 in _analyse_domain() to detect the mutant
    fail('NUM_BOUNDARY_5338_48_>: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5348_5 (MEDIUM) line 5348 in _resolve_host() ---
# Source:  return $host if $host =~ /^\d{1,3}(?:\.\d{1,3}){3}$/;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5348_5 line 5348 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5348 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_5348_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5350_5 (MEDIUM) line 5350 in _resolve_host() ---
# Source:  if ($HAS_NET_DNS) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5350_5 line 5350 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5350 in _resolve_host() to detect the mutant
    fail('COND_INV_5350_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5356_9 (MEDIUM) line 5356 in _resolve_host() ---
# Source:  if ($query) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5356_9 line 5356 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5356 in _resolve_host() to detect the mutant
    fail('COND_INV_5356_9: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5358_17 (MEDIUM) line 5358 in _resolve_host() ---
# Source:  return $rr->address if $rr->type eq 'A';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5358_17 line 5358 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5358 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_5358_17: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5361_9 (MEDIUM) line 5361 in _resolve_host() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5361_9 line 5361 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5361 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_5361_9: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5365_5 (MEDIUM) line 5365 in _resolve_host() ---
# Source:  return $packed ? inet_ntoa($packed) : undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5365_5 line 5365 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5365 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_5365_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5370_5 (MEDIUM) line 5370 in _reverse_dns() ---
# Source:  return undef unless $ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5370_5 line 5370 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5370 in _reverse_dns() to detect the mutant
    fail('BOOL_NEGATE_5370_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5372_5 (MEDIUM) line 5372 in _reverse_dns() ---
# Source:  if ($HAS_NET_DNS) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5372_5 line 5372 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5372 in _reverse_dns() to detect the mutant
    fail('COND_INV_5372_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5375_9 (MEDIUM) line 5375 in _reverse_dns() ---
# Source:  if ($query) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5375_9 line 5375 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5375 in _reverse_dns() to detect the mutant
    fail('COND_INV_5375_9: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5377_17 (MEDIUM) line 5377 in _reverse_dns() ---
# Source:  return $rr->ptrdname if $rr->type eq 'PTR';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5377_17 line 5377 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5377 in _reverse_dns() to detect the mutant
    fail('BOOL_NEGATE_5377_17: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5380_9 (MEDIUM) line 5380 in _reverse_dns() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5380_9 line 5380 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5380 in _reverse_dns() to detect the mutant
    fail('BOOL_NEGATE_5380_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5390_5 (MEDIUM) line 5390 in _whois_ip() ---
# Source:  unless ($result->{org}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_5390_5 line 5390 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5390 in _whois_ip() to detect the mutant
    fail('COND_INV_5390_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5392_9 (MEDIUM) line 5392 in _whois_ip() ---
# Source:  if ($raw) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5392_9 line 5392 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5392 in _whois_ip() to detect the mutant
    fail('COND_INV_5392_9: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5398_5 (MEDIUM) line 5398 in _whois_ip() ---
# Source:  return $result;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5398_5 line 5398 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5398 in _whois_ip() to detect the mutant
    fail('BOOL_NEGATE_5398_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5406_5 (MEDIUM) line 5406 in _domain_whois() ---
# Source:  return undef unless $server;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5406_5 line 5406 in _domain_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5406 in _domain_whois() to detect the mutant
    fail('BOOL_NEGATE_5406_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5407_5 (MEDIUM) line 5407 in _domain_whois() ---
# Source:  return $self->_raw_whois($domain, $server);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5407_5 line 5407 in _domain_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5407 in _domain_whois() to detect the mutant
    fail('BOOL_NEGATE_5407_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5423_2 (MEDIUM) line 5423 in _parse_domain_whois_abuse() ---
# Source:  if ($raw =~ /Registrar:\s*(.+)/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5423_2 line 5423 in _parse_domain_whois_abuse()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5423 in _parse_domain_whois_abuse() to detect the mutant
    fail('COND_INV_5423_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5431_3 (MEDIUM) line 5431 in _parse_domain_whois_abuse() ---
# Source:  if (!$info{abuse} && $raw =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5431_3 line 5431 in _parse_domain_whois_abuse()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5431 in _parse_domain_whois_abuse() to detect the mutant
    fail('COND_INV_5431_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5453_2 (MEDIUM) line 5453 in _rdap_lookup() ---
# Source:  if ($j =~ /"abuse".*?"email"\s*:\s*"([^"]+)"/s) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5453_2 line 5453 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5453 in _rdap_lookup() to detect the mutant
    fail('COND_INV_5453_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5475_5 (MEDIUM) line 5475 in _raw_whois() ---
# Source:  return undef unless $sock;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5475_5 line 5475 in _raw_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5475 in _raw_whois() to detect the mutant
    fail('BOOL_NEGATE_5475_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5486_5 (MEDIUM) line 5486 in _raw_whois() ---
# Source:  return $response || undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5486_5 line 5486 in _raw_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5486 in _raw_whois() to detect the mutant
    fail('BOOL_NEGATE_5486_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5497_9 (MEDIUM) line 5497 in _parse_whois_text() ---
# Source:  if (!$info{org} && $text =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5497_9 line 5497 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5497 in _parse_whois_text() to detect the mutant
    fail('COND_INV_5497_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5505_9 (MEDIUM) line 5505 in _parse_whois_text() ---
# Source:  if (!$info{abuse} && $text =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5505_9 line 5505 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5505 in _parse_whois_text() to detect the mutant
    fail('COND_INV_5505_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5511_5 (MEDIUM) line 5511 in _parse_whois_text() ---
# Source:  if ($text =~ /^country:\s*([A-Za-z]{2})\s*$/m) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5511_5 line 5511 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5511 in _parse_whois_text() to detect the mutant
    fail('COND_INV_5511_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5535_9 (MEDIUM) line 5535 in _header_value() ---
# Source:  return $h->{value} if $h->{name} eq lc($name);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5535_9 line 5535 in _header_value()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5535 in _header_value() to detect the mutant
    fail('BOOL_NEGATE_5535_9: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5537_5 (MEDIUM) line 5537 in _header_value() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5537_5 line 5537 in _header_value()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5537 in _header_value() to detect the mutant
    fail('BOOL_NEGATE_5537_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5542_5 (MEDIUM) line 5542 in _ip_in_cidr() ---
# Source:  return $ip eq $cidr unless $cidr =~ m{/};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5542_5 line 5542 in _ip_in_cidr()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5542 in _ip_in_cidr() to detect the mutant
    fail('BOOL_NEGATE_5542_5: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_5544_70_< (HIGH) line 5544 in _ip_in_cidr() ---
# Source:  return 0 unless defined $prefix && $prefix =~ /^\d+$/ && $prefix <= 32;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_5544_70_< line 5544 in _ip_in_cidr()';
    # Suggested boundary values to test: 31, 32, 33
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5544 in _ip_in_cidr() to detect the mutant
    fail('NUM_BOUNDARY_5544_70_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_5548_28_!= (HIGH) line 5548 in _ip_in_cidr() ---
# Source:  return ($ip_n & $mask) == ($net_n & $mask);
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (1 variant):
#   Numeric boundary flip == to !=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_5548_28_!= line 5548 in _ip_in_cidr()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5548 in _ip_in_cidr() to detect the mutant
    fail('NUM_BOUNDARY_5548_28_!=: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5556_2 (MEDIUM) line 5556 in _parse_date_to_epoch() ---
# Source:  return undef unless $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5556_2 line 5556 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5556 in _parse_date_to_epoch() to detect the mutant
    fail('BOOL_NEGATE_5556_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5559_2 (MEDIUM) line 5559 in _parse_date_to_epoch() ---
# Source:  if    ($str =~ /^(\d{4})-(\d{2})-(\d{2})/)         { ($y,$m,$d)=($1,$2,$3) }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5559_2 line 5559 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5559 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_5559_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5565_2 (MEDIUM) line 5565 in _parse_date_to_epoch() ---
# Source:  if (eval { require Time::Local; 1 }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5565_2 line 5565 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5565 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_5565_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5583_2 (MEDIUM) line 5583 in _parse_rfc2822_date() ---
# Source:  return undef unless $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5583_2 line 5583 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5583 in _parse_rfc2822_date() to detect the mutant
    fail('BOOL_NEGATE_5583_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5585_2 (MEDIUM) line 5585 in _parse_rfc2822_date() ---
# Source:  if ($str =~ /(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5585_2 line 5585 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5585 in _parse_rfc2822_date() to detect the mutant
    fail('COND_INV_5585_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5588_3 (MEDIUM) line 5588 in _parse_rfc2822_date() ---
# Source:  return undef unless $m;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5588_3 line 5588 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5588 in _parse_rfc2822_date() to detect the mutant
    fail('BOOL_NEGATE_5588_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5589_3 (MEDIUM) line 5589 in _parse_rfc2822_date() ---
# Source:  if (eval { require Time::Local; 1 }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5589_3 line 5589 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5589 in _parse_rfc2822_date() to detect the mutant
    fail('COND_INV_5589_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5593_2 (MEDIUM) line 5593 in _parse_rfc2822_date() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5593_2 line 5593 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5593 in _parse_rfc2822_date() to detect the mutant
    fail('BOOL_NEGATE_5593_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5599_2 (MEDIUM) line 5599 in _decode_mime_words() ---
# Source:  return '' unless defined $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5599_2 line 5599 in _decode_mime_words()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5599 in _decode_mime_words() to detect the mutant
    fail('BOOL_NEGATE_5599_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5602_2 (MEDIUM) line 5602 in _decode_mime_words() ---
# Source:  return $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5602_2 line 5602 in _decode_mime_words()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5602 in _decode_mime_words() to detect the mutant
    fail('BOOL_NEGATE_5602_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5608_5 (MEDIUM) line 5608 in _decode_ew() ---
# Source:  if (uc($enc) eq 'B') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5608_5 line 5608 in _decode_ew()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5608 in _decode_ew() to detect the mutant
    fail('COND_INV_5608_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5615_5 (MEDIUM) line 5615 in _decode_ew() ---
# Source:  if (lc($charset) ne 'utf-8') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5615_5 line 5615 in _decode_ew()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5615 in _decode_ew() to detect the mutant
    fail('COND_INV_5615_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5619_2 (MEDIUM) line 5619 in _decode_ew() ---
# Source:  return $raw;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5619_2 line 5619 in _decode_ew()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5619 in _decode_ew() to detect the mutant
    fail('BOOL_NEGATE_5619_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5625_2 (MEDIUM) line 5625 in _parse_auth_results_cached() ---
# Source:  return $self->{_auth_results} if $self->{_auth_results};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5625_2 line 5625 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5625 in _parse_auth_results_cached() to detect the mutant
    fail('BOOL_NEGATE_5625_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5652_9 (MEDIUM) line 5652 in _parse_auth_results_cached() ---
# Source:  if ($h->{value} =~ /\bd=([^;,\s]+)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5652_9 line 5652 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5652 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_5652_9: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5656_5 (MEDIUM) line 5656 in _parse_auth_results_cached() ---
# Source:  if (@dkim_domains) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5656_5 line 5656 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5656 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_5656_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5660_13 (MEDIUM) line 5660 in _parse_auth_results_cached() ---
# Source:  if ($self->_provider_abuse_for_host($d)) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5660_13 line 5660 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5660 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_5660_13: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5675_5 (MEDIUM) line 5675 in _registrable() ---
# Source:  return undef unless $host && $host =~ /\./;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5675_5 line 5675 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5675 in _registrable() to detect the mutant
    fail('BOOL_NEGATE_5675_5: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_5677_29_< (HIGH) line 5677 in _registrable() ---
# Source:  return $host if @labels <= 2;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_5677_29_< line 5677 in _registrable()';
    # Suggested boundary values to test: 1, 2, 3
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5677 in _registrable() to detect the mutant
    fail('NUM_BOUNDARY_5677_29_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5678_5 (MEDIUM) line 5678 in _registrable() ---
# Source:  if ($labels[-1] =~ /^[a-z]{2}$/ &&
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5678_5 line 5678 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5678 in _registrable() to detect the mutant
    fail('COND_INV_5678_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5712_2 (MEDIUM) line 5712 in _provider_abuse_for_ip() ---
# Source:  return $self->_provider_abuse_for_host($rdns) if $rdns;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5712_2 line 5712 in _provider_abuse_for_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5712 in _provider_abuse_for_ip() to detect the mutant
    fail('BOOL_NEGATE_5712_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_5713_2 (MEDIUM) line 5713 in _provider_abuse_for_ip() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_5713_2 line 5713 in _provider_abuse_for_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5713 in _provider_abuse_for_ip() to detect the mutant
    fail('BOOL_NEGATE_5713_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_5719_2 (MEDIUM) line 5719 in _debug() ---
# Source:  if($self->{logger}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_5719_2 line 5719 in _debug()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 5719 in _debug() to detect the mutant
    fail('COND_INV_5719_2: replace with real assertion');
}

# --- LOW DIFFICULTY HINTS (comment stubs) ---

# --- LOW HINT: RETURN_UNDEF_748_2 line 748 in parse_email() ---
# Source:  return $self;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_748_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1031_2 line 1031 in originating_ip() ---
# Source:  return $self->{_origin};
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1031_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1895_2 line 1895 in all_domains() ---
# Source:  return @out;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1895_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1975_5 line 1975 in unresolved_contacts() ---
# Source:  return @out;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1975_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2854_2 line 2854 in risk_assessment() ---
# Source:  return $self->{_risk} if $self->{_risk};
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2854_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3108_2 line 3108 in risk_assessment() ---
# Source:  return $self->{_risk};
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3108_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3960_5 line 3960 in abuse_contacts() ---
# Source:  return @contacts;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3960_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4140_2 line 4140 in form_contacts() ---
# Source:  return @contacts;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4140_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4802_2 line 4802 in _decode_body() ---
# Source:  return $body;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4802_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4875_13 line 4875 in _find_origin() ---
# Source:  return $self->_enrich_ip($xoip, 'low',
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4875_13: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4879_9 line 4879 in _find_origin() ---
# Source:  return undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4879_9: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4882_5 line 4882 in _find_origin() ---
# Source:  return $self->_enrich_ip(
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4882_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4896_13 line 4896 in _extract_ip_from_received() ---
# Source:  return $ip;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4896_13: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4899_5 line 4899 in _extract_ip_from_received() ---
# Source:  return undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4899_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4909_5 line 4909 in _is_private() ---
# Source:  return 1 unless defined $ip && $ip ne '';
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4909_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4910_36 line 4910 in _is_private() ---
# Source:  for my $re (@PRIVATE_RANGES) { return 1 if $ip =~ $re }
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4910_36: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4911_5 line 4911 in _is_private() ---
# Source:  return 0;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4911_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4917_9 line 4917 in _is_trusted() ---
# Source:  return 1 if $self->_ip_in_cidr($ip, $cidr);
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4917_9: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4919_5 line 4919 in _is_trusted() ---
# Source:  return 0;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4919_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5003_2 line 5003 in _extract_http_urls() ---
# Source:  return @all;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5003_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5132_5 line 5132 in _domains_from_text() ---
# Source:  return @out;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5132_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5237_2 line 5237 in _analyse_domain() ---
# Source:  return $self->{_domain_info}{$domain} if $self->{_domain_info}{$domain};
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5237_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5348_5 line 5348 in _resolve_host() ---
# Source:  return $host if $host =~ /^\d{1,3}(?:\.\d{1,3}){3}$/;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5348_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5358_17 line 5358 in _resolve_host() ---
# Source:  return $rr->address if $rr->type eq 'A';
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5358_17: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5361_9 line 5361 in _resolve_host() ---
# Source:  return undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5361_9: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5365_5 line 5365 in _resolve_host() ---
# Source:  return $packed ? inet_ntoa($packed) : undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5365_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5370_5 line 5370 in _reverse_dns() ---
# Source:  return undef unless $ip;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5370_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5377_17 line 5377 in _reverse_dns() ---
# Source:  return $rr->ptrdname if $rr->type eq 'PTR';
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5377_17: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5380_9 line 5380 in _reverse_dns() ---
# Source:  return undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5380_9: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5398_5 line 5398 in _whois_ip() ---
# Source:  return $result;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5398_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5406_5 line 5406 in _domain_whois() ---
# Source:  return undef unless $server;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5406_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5407_5 line 5407 in _domain_whois() ---
# Source:  return $self->_raw_whois($domain, $server);
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5407_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5475_5 line 5475 in _raw_whois() ---
# Source:  return undef unless $sock;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5475_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5486_5 line 5486 in _raw_whois() ---
# Source:  return $response || undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5486_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5535_9 line 5535 in _header_value() ---
# Source:  return $h->{value} if $h->{name} eq lc($name);
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5535_9: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5537_5 line 5537 in _header_value() ---
# Source:  return undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5537_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5542_5 line 5542 in _ip_in_cidr() ---
# Source:  return $ip eq $cidr unless $cidr =~ m{/};
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5542_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5544_5 line 5544 in _ip_in_cidr() ---
# Source:  return 0 unless defined $prefix && $prefix =~ /^\d+$/ && $prefix <= 32;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5544_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5556_2 line 5556 in _parse_date_to_epoch() ---
# Source:  return undef unless $str;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5556_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5583_2 line 5583 in _parse_rfc2822_date() ---
# Source:  return undef unless $str;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5583_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5588_3 line 5588 in _parse_rfc2822_date() ---
# Source:  return undef unless $m;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5588_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5593_2 line 5593 in _parse_rfc2822_date() ---
# Source:  return undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5593_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5599_2 line 5599 in _decode_mime_words() ---
# Source:  return '' unless defined $str;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5599_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5602_2 line 5602 in _decode_mime_words() ---
# Source:  return $str;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5602_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5619_2 line 5619 in _decode_ew() ---
# Source:  return $raw;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5619_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5625_2 line 5625 in _parse_auth_results_cached() ---
# Source:  return $self->{_auth_results} if $self->{_auth_results};
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5625_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5675_5 line 5675 in _registrable() ---
# Source:  return undef unless $host && $host =~ /\./;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5675_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5677_5 line 5677 in _registrable() ---
# Source:  return $host if @labels <= 2;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5677_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5712_2 line 5712 in _provider_abuse_for_ip() ---
# Source:  return $self->_provider_abuse_for_host($rdns) if $rdns;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5712_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_5713_2 line 5713 in _provider_abuse_for_ip() ---
# Source:  return undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_5713_2: add assertion here');

done_testing();
