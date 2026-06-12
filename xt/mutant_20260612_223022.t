#!/usr/bin/env perl
# Auto-generated mutant test stubs
# Generated: 2026-06-12 22:30:22
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

# --- SURVIVOR: COND_INV_625_2 (MEDIUM) line 625 in new() ---
# Source:  if ($HAS_CHI && !$_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_625_2 line 625 in new()';
    # NOTE: new is a class method — call directly.
    my $result = Email::Abuse::Investigator->new(...);
    # ok($result, 'COND_INV_625_2: add assertion here');
    # TODO: exercise line 625 in new() to detect the mutant
    fail('COND_INV_625_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_771_2 (MEDIUM) line 771 in parse_email() ---
# Source:  return $self;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_771_2 line 771 in parse_email()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 771 in parse_email() to detect the mutant
    fail('BOOL_NEGATE_771_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_846_2 (MEDIUM) line 846 in originating_ip() ---
# Source:  return $self->{_origin};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_846_2 line 846 in originating_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 846 in originating_ip() to detect the mutant
    fail('BOOL_NEGATE_846_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1068_2 (MEDIUM) line 1068 in all_domains() ---
# Source:  return @out;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1068_2 line 1068 in all_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1068 in all_domains() to detect the mutant
    fail('BOOL_NEGATE_1068_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1133_3 (MEDIUM) line 1133 in unresolved_contacts() ---
# Source:  unless ($dom) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_1133_3 line 1133 in unresolved_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1133 in unresolved_contacts() to detect the mutant
    fail('COND_INV_1133_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1174_2 (MEDIUM) line 1174 in unresolved_contacts() ---
# Source:  return @out;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1174_2 line 1174 in unresolved_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1174 in unresolved_contacts() to detect the mutant
    fail('BOOL_NEGATE_1174_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1375_2 (MEDIUM) line 1375 in risk_assessment() ---
# Source:  return $self->{_risk} if $self->{_risk};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1375_2 line 1375 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1375 in risk_assessment() to detect the mutant
    fail('BOOL_NEGATE_1375_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1394_21_> (HIGH) line 1394 in risk_assessment() ---
# Source:  my $level = $score >= $SCORE_HIGH   ? 'HIGH'
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1394_21_> line 1394 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1394 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1394_21_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1395_21_> (HIGH) line 1395 in risk_assessment() ---
# Source:  : $score >= $SCORE_MEDIUM ? 'MEDIUM'
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1395_21_> line 1395 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1395 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1395_21_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1396_21_> (HIGH) line 1396 in risk_assessment() ---
# Source:  : $score >= $SCORE_LOW    ? 'LOW'
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1396_21_> line 1396 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1396 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1396_21_>: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1400_2 (MEDIUM) line 1400 in risk_assessment() ---
# Source:  return $self->{_risk};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1400_2 line 1400 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1400 in risk_assessment() to detect the mutant
    fail('BOOL_NEGATE_1400_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1421_2 (MEDIUM) line 1421 in _risk_check_origin() ---
# Source:  if ($orig->{rdns} && $orig->{rdns} =~ /
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1421_2 line 1421 in _risk_check_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1421 in _risk_check_origin() to detect the mutant
    fail('COND_INV_1421_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1432_2 (MEDIUM) line 1432 in _risk_check_origin() ---
# Source:  if (!$orig->{rdns} || $orig->{rdns} eq '(no reverse DNS)') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1432_2 line 1432 in _risk_check_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1432 in _risk_check_origin() to detect the mutant
    fail('COND_INV_1432_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1438_2 (MEDIUM) line 1438 in _risk_check_origin() ---
# Source:  if ($orig->{confidence} eq 'low') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1438_2 line 1438 in _risk_check_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1438 in _risk_check_origin() to detect the mutant
    fail('COND_INV_1438_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1444_2 (MEDIUM) line 1444 in _risk_check_origin() ---
# Source:  if ($orig->{country} && $orig->{country} =~ /^(?:CN|RU|NG|VN|IN|PK|BD)$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1444_2 line 1444 in _risk_check_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1444 in _risk_check_origin() to detect the mutant
    fail('COND_INV_1444_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1466_2 (MEDIUM) line 1466 in _risk_check_auth() ---
# Source:  if (defined $auth->{spf}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1466_2 line 1466 in _risk_check_auth()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1466 in _risk_check_auth() to detect the mutant
    fail('COND_INV_1466_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1467_3 (MEDIUM) line 1467 in _risk_check_auth() ---
# Source:  if ($auth->{spf} =~ /^fail/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1467_3 line 1467 in _risk_check_auth()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1467 in _risk_check_auth() to detect the mutant
    fail('COND_INV_1467_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1478_2 (MEDIUM) line 1478 in _risk_check_auth() ---
# Source:  if (defined $auth->{dkim} && $auth->{dkim} !~ /^pass/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1478_2 line 1478 in _risk_check_auth()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1478 in _risk_check_auth() to detect the mutant
    fail('COND_INV_1478_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1482_2 (MEDIUM) line 1482 in _risk_check_auth() ---
# Source:  if (defined $auth->{dmarc} && $auth->{dmarc} !~ /^pass/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1482_2 line 1482 in _risk_check_auth()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1482 in _risk_check_auth() to detect the mutant
    fail('COND_INV_1482_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1495_2 (MEDIUM) line 1495 in _risk_check_auth() ---
# Source:  if ($auth->{dkim} && $auth->{dkim} =~ /^pass/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1495_2 line 1495 in _risk_check_auth()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1495 in _risk_check_auth() to detect the mutant
    fail('COND_INV_1495_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1523_2 (MEDIUM) line 1523 in _risk_check_date() ---
# Source:  if (!$date_raw || $date_raw !~ /\S/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1523_2 line 1523 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1523 in _risk_check_date() to detect the mutant
    fail('COND_INV_1523_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1530_2 (MEDIUM) line 1530 in _risk_check_date() ---
# Source:  if ($date_raw =~ /([+-])(\d{2})(\d{2})\s*$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1530_2 line 1530 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1530 in _risk_check_date() to detect the mutant
    fail('COND_INV_1530_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1533_25_> (HIGH) line 1533 in _risk_check_date() ---
# Source:  my $implausible = $mm >= 60
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1533_25_> line 1533 in _risk_check_date()';
    # Suggested boundary values to test: 59, 60, 61
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1533 in _risk_check_date() to detect the mutant
    fail('NUM_BOUNDARY_1533_25_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1534_37_< (HIGH) line 1534 in _risk_check_date() ---
# Source:  || ($sign eq '+' && $offset_mins > $TZ_MAX_POS_MINS)
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1534_37_< line 1534 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1534 in _risk_check_date() to detect the mutant
    fail('NUM_BOUNDARY_1534_37_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1535_37_< (HIGH) line 1535 in _risk_check_date() ---
# Source:  || ($sign eq '-' && $offset_mins > $TZ_MAX_NEG_MINS);
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1535_37_< line 1535 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1535 in _risk_check_date() to detect the mutant
    fail('NUM_BOUNDARY_1535_37_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1536_3 (MEDIUM) line 1536 in _risk_check_date() ---
# Source:  if ($implausible) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1536_3 line 1536 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1536 in _risk_check_date() to detect the mutant
    fail('COND_INV_1536_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1547_13_< (HIGH) line 1547 in _risk_check_date() ---
# Source:  if ($delta > $DATE_SKEW_DAYS * $SECS_PER_DAY) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1547_13_< line 1547 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1547 in _risk_check_date() to detect the mutant
    fail('NUM_BOUNDARY_1547_13_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1550_18_> (HIGH) line 1550 in _risk_check_date() ---
# Source:  } elsif ($delta < -($DATE_SKEW_DAYS * $SECS_PER_DAY)) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip < to >
#   Numeric boundary flip < to <=
#   Numeric boundary flip < to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1550_18_> line 1550 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1550 in _risk_check_date() to detect the mutant
    fail('NUM_BOUNDARY_1550_18_>: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1574_2 (MEDIUM) line 1574 in _risk_check_identity() ---
# Source:  if ($from_decoded =~ /^"?([^"<]+?)"?\s*<([^>]+)>/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1574_2 line 1574 in _risk_check_identity()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1574 in _risk_check_identity() to detect the mutant
    fail('COND_INV_1574_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1582_4 (MEDIUM) line 1582 in _risk_check_identity() ---
# Source:  if ($reg_disp && $reg_addr && $reg_disp ne $reg_addr) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1582_4 line 1582 in _risk_check_identity()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1582 in _risk_check_identity() to detect the mutant
    fail('COND_INV_1582_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1590_2 (MEDIUM) line 1590 in _risk_check_identity() ---
# Source:  if ($from_raw =~ /\@(gmail|yahoo|hotmail|outlook|live|aol|protonmail|yandex)\./i
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1590_2 line 1590 in _risk_check_identity()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1590 in _risk_check_identity() to detect the mutant
    fail('COND_INV_1590_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1598_2 (MEDIUM) line 1598 in _risk_check_identity() ---
# Source:  if ($reply_to) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1598_2 line 1598 in _risk_check_identity()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1598 in _risk_check_identity() to detect the mutant
    fail('COND_INV_1598_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1601_3 (MEDIUM) line 1601 in _risk_check_identity() ---
# Source:  if ($from_addr && $reply_addr && lc($from_addr) ne lc($reply_addr)) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1601_3 line 1601 in _risk_check_identity()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1601 in _risk_check_identity() to detect the mutant
    fail('COND_INV_1601_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1609_2 (MEDIUM) line 1609 in _risk_check_identity() ---
# Source:  if ($to =~ /undisclosed|:;/ || $to eq '') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1609_2 line 1609 in _risk_check_identity()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1609 in _risk_check_identity() to detect the mutant
    fail('COND_INV_1609_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1616_2 (MEDIUM) line 1616 in _risk_check_identity() ---
# Source:  if ($subj_raw =~ /=\?[^?]+\?[BQ]\?/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1616_2 line 1616 in _risk_check_identity()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1616 in _risk_check_identity() to detect the mutant
    fail('COND_INV_1616_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1647_3 (MEDIUM) line 1647 in _risk_check_urls_and_domains() ---
# Source:  if(($URL_SHORTENERS{$bare} || $self->{url_shorteners}->{$bare}) && !$shortener_seen{$bare}++) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1647_3 line 1647 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1647 in _risk_check_urls_and_domains() to detect the mutant
    fail('COND_INV_1647_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1652_3 (MEDIUM) line 1652 in _risk_check_urls_and_domains() ---
# Source:  if ($self->_is_redirect_cloaker($bare) && !$cloaker_seen{$bare}++) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1652_3 line 1652 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1652 in _risk_check_urls_and_domains() to detect the mutant
    fail('COND_INV_1652_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1657_3 (MEDIUM) line 1657 in _risk_check_urls_and_domains() ---
# Source:  if ($u->{url} =~ m{^http://}i && !$url_host_seen{ $u->{host} }++) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1657_3 line 1657 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1657 in _risk_check_urls_and_domains() to detect the mutant
    fail('COND_INV_1657_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1666_3 (MEDIUM) line 1666 in _risk_check_urls_and_domains() ---
# Source:  if ($d->{recently_registered}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1666_3 line 1666 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1666 in _risk_check_urls_and_domains() to detect the mutant
    fail('COND_INV_1666_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1672_3 (MEDIUM) line 1672 in _risk_check_urls_and_domains() ---
# Source:  if ($d->{expires}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1672_3 line 1672 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1672 in _risk_check_urls_and_domains() to detect the mutant
    fail('COND_INV_1672_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1673_4 (MEDIUM) line 1673 in _risk_check_urls_and_domains() ---
# Source:  if(my $exp = $self->_parse_date_to_epoch($d->{expires})) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1673_4 line 1673 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1673 in _risk_check_urls_and_domains() to detect the mutant
    fail('COND_INV_1673_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1676_20_< (HIGH) line 1676 in _risk_check_urls_and_domains() ---
# Source:  if ($remaining > 0 && $remaining < $EXPIRY_WARN_DAYS * $SECS_PER_DAY) {
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
    local $TODO = 'Complete: NUM_BOUNDARY_1676_20_< line 1676 in _risk_check_urls_and_domains()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1676 in _risk_check_urls_and_domains() to detect the mutant
    fail('NUM_BOUNDARY_1676_20_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1679_25_< (HIGH) line 1679 in _risk_check_urls_and_domains() ---
# Source:  } elsif ($remaining <= 0) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1679_25_< line 1679 in _risk_check_urls_and_domains()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1679 in _risk_check_urls_and_domains() to detect the mutant
    fail('NUM_BOUNDARY_1679_25_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1688_4 (MEDIUM) line 1688 in _risk_check_urls_and_domains() ---
# Source:  if ($d->{domain} =~ /\Q$brand\E/i &&
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1688_4 line 1688 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1688 in _risk_check_urls_and_domains() to detect the mutant
    fail('COND_INV_1688_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1764_2 (MEDIUM) line 1764 in abuse_report_text() ---
# Source:  if (@{ $risk->{flags} }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1764_2 line 1764 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1764 in abuse_report_text() to detect the mutant
    fail('COND_INV_1764_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1774_2 (MEDIUM) line 1774 in abuse_report_text() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1774_2 line 1774 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1774 in abuse_report_text() to detect the mutant
    fail('COND_INV_1774_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1782_2 (MEDIUM) line 1782 in abuse_report_text() ---
# Source:  if (@contacts) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1782_2 line 1782 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1782 in abuse_report_text() to detect the mutant
    fail('COND_INV_1782_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1789_2 (MEDIUM) line 1789 in abuse_report_text() ---
# Source:  if(my @form_cs = $self->form_contacts()) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1789_2 line 1789 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1789 in abuse_report_text() to detect the mutant
    fail('COND_INV_1789_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1908_3 (MEDIUM) line 1908 in _compute_abuse_contacts() ---
# Source:  if ($addr =~ /\@([\w.-]+)$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1908_3 line 1908 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1908 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1908_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1914_3 (MEDIUM) line 1914 in _compute_abuse_contacts() ---
# Source:  if (exists $seen_idx{$addr}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1914_3 line 1914 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1914 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1914_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1925_22_< (HIGH) line 1925 in _compute_abuse_contacts() ---
# Source:  $role_counts{$_} > 1 ? "$_ (x$role_counts{$_})" : $_
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1925_22_< line 1925 in _compute_abuse_contacts()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1925 in _compute_abuse_contacts() to detect the mutant
    fail('NUM_BOUNDARY_1925_22_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1930_24_< (HIGH) line 1930 in _compute_abuse_contacts() ---
# Source:  if (length($joined) > $ROLE_MAX_LEN) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1930_24_< line 1930 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1930 in _compute_abuse_contacts() to detect the mutant
    fail('NUM_BOUNDARY_1930_24_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1951_2 (MEDIUM) line 1951 in _compute_abuse_contacts() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1951_2 line 1951 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1951 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1951_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1953_3 (MEDIUM) line 1953 in _compute_abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1953_3 line 1953 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1953 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1953_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1961_3 (MEDIUM) line 1961 in _compute_abuse_contacts() ---
# Source:  if ($orig->{abuse} && $orig->{abuse} ne '(unknown)') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1961_3 line 1961 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1961 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1961_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1981_3 (MEDIUM) line 1981 in _compute_abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1981_3 line 1981 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1981 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1981_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1989_3 (MEDIUM) line 1989 in _compute_abuse_contacts() ---
# Source:  if ($u->{abuse} && $u->{abuse} ne '(unknown)') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1989_3 line 1989 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1989 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1989_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2004_3 (MEDIUM) line 2004 in _compute_abuse_contacts() ---
# Source:  if ($d->{web_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2004_3 line 2004 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2004 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2004_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2006_4 (MEDIUM) line 2006 in _compute_abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2006_4 line 2006 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2006 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2006_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2022_3 (MEDIUM) line 2022 in _compute_abuse_contacts() ---
# Source:  if ($d->{mx_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2022_3 line 2022 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2022 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2022_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2035_3 (MEDIUM) line 2035 in _compute_abuse_contacts() ---
# Source:  if ($d->{ns_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2035_3 line 2035 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2035 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2035_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2048_3 (MEDIUM) line 2048 in _compute_abuse_contacts() ---
# Source:  if ($d->{registrar_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2048_3 line 2048 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2048 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2048_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2055_4 (MEDIUM) line 2055 in _compute_abuse_contacts() ---
# Source:  unless ($spoofable_only) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_2055_4 line 2055 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2055 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2055_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2079_3 (MEDIUM) line 2079 in _compute_abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2079_3 line 2079 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2079 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2079_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2093_2 (MEDIUM) line 2093 in _compute_abuse_contacts() ---
# Source:  if ($auth->{dkim_domain}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2093_2 line 2093 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2093 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2093_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2095_3 (MEDIUM) line 2095 in _compute_abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2095_3 line 2095 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2095 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2095_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2107_2 (MEDIUM) line 2107 in _compute_abuse_contacts() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2107_2 line 2107 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2107 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2107_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2118_4 (MEDIUM) line 2118 in _compute_abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2118_4 line 2118 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2118 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2118_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2146_2 (MEDIUM) line 2146 in _compute_abuse_contacts() ---
# Source:  return @contacts;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2146_2 line 2146 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2146 in _compute_abuse_contacts() to detect the mutant
    fail('BOOL_NEGATE_2146_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2227_2 (MEDIUM) line 2227 in form_contacts() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2227_2 line 2227 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2227 in form_contacts() to detect the mutant
    fail('COND_INV_2227_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2229_3 (MEDIUM) line 2229 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2229_3 line 2229 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2229 in form_contacts() to detect the mutant
    fail('COND_INV_2229_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2246_3 (MEDIUM) line 2246 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2246_3 line 2246 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2246 in form_contacts() to detect the mutant
    fail('COND_INV_2246_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2263_3 (MEDIUM) line 2263 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2263_3 line 2263 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2263 in form_contacts() to detect the mutant
    fail('COND_INV_2263_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2276_3 (MEDIUM) line 2276 in form_contacts() ---
# Source:  if ($d->{registrar_abuse} && $d->{registrar_abuse} =~ /\@([\w.-]+)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2276_3 line 2276 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2276 in form_contacts() to detect the mutant
    fail('COND_INV_2276_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2279_4 (MEDIUM) line 2279 in form_contacts() ---
# Source:  if ($rpa && $rpa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2279_4 line 2279 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2279 in form_contacts() to detect the mutant
    fail('COND_INV_2279_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2302_3 (MEDIUM) line 2302 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2302_3 line 2302 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2302 in form_contacts() to detect the mutant
    fail('COND_INV_2302_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2318_2 (MEDIUM) line 2318 in form_contacts() ---
# Source:  if ($auth->{dkim_domain}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2318_2 line 2318 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2318 in form_contacts() to detect the mutant
    fail('COND_INV_2318_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2320_3 (MEDIUM) line 2320 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2320_3 line 2320 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2320 in form_contacts() to detect the mutant
    fail('COND_INV_2320_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2334_2 (MEDIUM) line 2334 in form_contacts() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2334_2 line 2334 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2334 in form_contacts() to detect the mutant
    fail('COND_INV_2334_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2341_4 (MEDIUM) line 2341 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2341_4 line 2341 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2341 in form_contacts() to detect the mutant
    fail('COND_INV_2341_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2354_2 (MEDIUM) line 2354 in form_contacts() ---
# Source:  return @contacts;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2354_2 line 2354 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2354 in form_contacts() to detect the mutant
    fail('BOOL_NEGATE_2354_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2435_2 (MEDIUM) line 2435 in report() ---
# Source:  if (@{ $risk->{flags} }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2435_2 line 2435 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2435 in report() to detect the mutant
    fail('COND_INV_2435_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2447_2 (MEDIUM) line 2447 in report() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2447_2 line 2447 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2447 in report() to detect the mutant
    fail('COND_INV_2447_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2462_2 (MEDIUM) line 2462 in report() ---
# Source:  if (@sw) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2462_2 line 2462 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2462 in report() to detect the mutant
    fail('COND_INV_2462_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2474_2 (MEDIUM) line 2474 in report() ---
# Source:  if (@trail) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2474_2 line 2474 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2474 in report() to detect the mutant
    fail('COND_INV_2474_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2489_2 (MEDIUM) line 2489 in report() ---
# Source:  if (@urls) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2489_2 line 2489 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2489 in report() to detect the mutant
    fail('COND_INV_2489_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2494_4 (MEDIUM) line 2494 in report() ---
# Source:  unless (exists $host_order{$h}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_2494_4 line 2494 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2494 in report() to detect the mutant
    fail('COND_INV_2494_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2518_15_!= (HIGH) line 2518 in report() ---
# Source:  if (@paths == 1) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (2 variants — one test should kill all):
#   Numeric boundary flip == to !=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2518_15_!= line 2518 in report()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2518 in report() to detect the mutant
    fail('NUM_BOUNDARY_2518_15_!=: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2534_2 (MEDIUM) line 2534 in report() ---
# Source:  if (@mdoms) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2534_2 line 2534 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2534 in report() to detect the mutant
    fail('COND_INV_2534_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2538_4 (MEDIUM) line 2538 in report() ---
# Source:  if ($d->{recently_registered}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2538_4 line 2538 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2538 in report() to detect the mutant
    fail('COND_INV_2538_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2545_4 (MEDIUM) line 2545 in report() ---
# Source:  if ($d->{web_ip}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2545_4 line 2545 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2545 in report() to detect the mutant
    fail('COND_INV_2545_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2552_4 (MEDIUM) line 2552 in report() ---
# Source:  if ($d->{mx_host}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2552_4 line 2552 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2552 in report() to detect the mutant
    fail('COND_INV_2552_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2560_4 (MEDIUM) line 2560 in report() ---
# Source:  if ($d->{ns_host}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2560_4 line 2560 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2560 in report() to detect the mutant
    fail('COND_INV_2560_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2576_2 (MEDIUM) line 2576 in report() ---
# Source:  if (@contacts) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2576_2 line 2576 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2576 in report() to detect the mutant
    fail('COND_INV_2576_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2591_2 (MEDIUM) line 2591 in report() ---
# Source:  if (@form_cs) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2591_2 line 2591 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2591 in report() to detect the mutant
    fail('COND_INV_2591_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2601_4 (MEDIUM) line 2601 in report() ---
# Source:  if ($c->{form_paste}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2601_4 line 2601 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2601 in report() to detect the mutant
    fail('COND_INV_2601_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2607_46_< (HIGH) line 2607 in report() ---
# Source:  if (defined $line && length("$line $w") > $ROLE_WRAP_LEN) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2607_46_< line 2607 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2607 in report() to detect the mutant
    fail('NUM_BOUNDARY_2607_46_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2652_2 (MEDIUM) line 2652 in _sanitise_output() ---
# Source:  return '' unless defined $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2652_2 line 2652 in _sanitise_output()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2652 in _sanitise_output() to detect the mutant
    fail('BOOL_NEGATE_2652_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2655_2 (MEDIUM) line 2655 in _sanitise_output() ---
# Source:  return $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2655_2 line 2655 in _sanitise_output()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2655 in _sanitise_output() to detect the mutant
    fail('BOOL_NEGATE_2655_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2702_3 (MEDIUM) line 2702 in _split_message() ---
# Source:  if ($line =~ /^([\w-]+)\s*:\s*(.*)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2702_3 line 2702 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2702 in _split_message() to detect the mutant
    fail('COND_INV_2702_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2721_2 (MEDIUM) line 2721 in _split_message() ---
# Source:  if ($ct =~ /multipart/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2721_2 line 2721 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2721 in _split_message() to detect the mutant
    fail('COND_INV_2721_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2727_3 (MEDIUM) line 2727 in _split_message() ---
# Source:  if ($ct =~ /html/i) { $self->{_body_html}  = $decoded }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2727_3 line 2727 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2727 in _split_message() to detect the mutant
    fail('COND_INV_2727_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2801_13_> (HIGH) line 2801 in _decode_multipart() ---
# Source:  if ($depth >= $MAX_MULTIPART_DEPTH) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2801_13_> line 2801 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2801 in _decode_multipart() to detect the mutant
    fail('NUM_BOUNDARY_2801_13_>: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2834_3 (MEDIUM) line 2834 in _decode_multipart() ---
# Source:  if ($pct =~ /multipart/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2834_3 line 2834 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2834 in _decode_multipart() to detect the mutant
    fail('COND_INV_2834_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2836_4 (MEDIUM) line 2836 in _decode_multipart() ---
# Source:  if ($inner_boundary) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2836_4 line 2836 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2836 in _decode_multipart() to detect the mutant
    fail('COND_INV_2836_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2846_3 (MEDIUM) line 2846 in _decode_multipart() ---
# Source:  if    ($pct =~ /text\/html/i)    { $self->{_body_html}  .= $decoded }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2846_3 line 2846 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2846 in _decode_multipart() to detect the mutant
    fail('COND_INV_2846_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2873_2 (MEDIUM) line 2873 in _decode_body() ---
# Source:  return $body // '';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2873_2 line 2873 in _decode_body()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2873 in _decode_body() to detect the mutant
    fail('BOOL_NEGATE_2873_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2917_2 (MEDIUM) line 2917 in _find_origin() ---
# Source:  unless (@candidates) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_2917_2 line 2917 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2917 in _find_origin() to detect the mutant
    fail('COND_INV_2917_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2919_3 (MEDIUM) line 2919 in _find_origin() ---
# Source:  if ($xoip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2919_3 line 2919 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2919 in _find_origin() to detect the mutant
    fail('COND_INV_2919_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2921_4 (MEDIUM) line 2921 in _find_origin() ---
# Source:  return $self->_enrich_ip($xoip, 'low',
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2921_4 line 2921 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2921 in _find_origin() to detect the mutant
    fail('BOOL_NEGATE_2921_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2929_2 (MEDIUM) line 2929 in _find_origin() ---
# Source:  return $self->_enrich_ip(
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2929_2 line 2929 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2929 in _find_origin() to detect the mutant
    fail('BOOL_NEGATE_2929_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2931_15_< (HIGH) line 2931 in _find_origin() ---
# Source:  @candidates > 1 ? 'high' : 'medium',
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2931_15_< line 2931 in _find_origin()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2931 in _find_origin() to detect the mutant
    fail('NUM_BOUNDARY_2931_15_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2956_3 (MEDIUM) line 2956 in _extract_ip_from_received() ---
# Source:  if ($hdr =~ $re) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2956_3 line 2956 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2956 in _extract_ip_from_received() to detect the mutant
    fail('COND_INV_2956_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2960_4 (MEDIUM) line 2960 in _extract_ip_from_received() ---
# Source:  return $ip if $ip =~ /:/;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2960_4 line 2960 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2960 in _extract_ip_from_received() to detect the mutant
    fail('BOOL_NEGATE_2960_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2964_22_< (HIGH) line 2964 in _extract_ip_from_received() ---
# Source:  next if grep { $_ > 255 } split /\./, $ip;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2964_22_< line 2964 in _extract_ip_from_received()';
    # Suggested boundary values to test: 254, 255, 256
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2964 in _extract_ip_from_received() to detect the mutant
    fail('NUM_BOUNDARY_2964_22_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2965_4 (MEDIUM) line 2965 in _extract_ip_from_received() ---
# Source:  return $ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2965_4 line 2965 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2965 in _extract_ip_from_received() to detect the mutant
    fail('BOOL_NEGATE_2965_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2990_2 (MEDIUM) line 2990 in _is_private() ---
# Source:  return 1 if !defined($ip) || $ip eq '';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2990_2 line 2990 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2990 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_2990_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2991_33 (MEDIUM) line 2991 in _is_private() ---
# Source:  for my $re (@PRIVATE_RANGES) { return 1 if $ip =~ $re }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2991_33 line 2991 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2991 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_2991_33: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2992_2 (MEDIUM) line 2992 in _is_private() ---
# Source:  return 0;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2992_2 line 2992 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2992 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_2992_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3011_3 (MEDIUM) line 3011 in _is_trusted() ---
# Source:  return 1 if $self->_ip_in_cidr($ip, $cidr);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3011_3 line 3011 in _is_trusted()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3011 in _is_trusted() to detect the mutant
    fail('BOOL_NEGATE_3011_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3013_2 (MEDIUM) line 3013 in _is_trusted() ---
# Source:  return 0;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3013_2 line 3013 in _is_trusted()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3013 in _is_trusted() to detect the mutant
    fail('BOOL_NEGATE_3013_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3073_57_< (HIGH) line 3073 in _extract_and_resolve_urls() ---
# Source:  if ($HAS_ANYEVENT_DNS && scalar(keys %hostname_needed) > 1) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3073_57_< line 3073 in _extract_and_resolve_urls()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3073 in _extract_and_resolve_urls() to detect the mutant
    fail('NUM_BOUNDARY_3073_57_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3083_3 (MEDIUM) line 3083 in _extract_and_resolve_urls() ---
# Source:  unless (exists $host_cache{$host}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_3083_3 line 3083 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3083 in _extract_and_resolve_urls() to detect the mutant
    fail('COND_INV_3083_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3086_4 (MEDIUM) line 3086 in _extract_and_resolve_urls() ---
# Source:  if ($cached) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3086_4 line 3086 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3086 in _extract_and_resolve_urls() to detect the mutant
    fail('COND_INV_3086_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3095_5 (MEDIUM) line 3095 in _extract_and_resolve_urls() ---
# Source:  if (!$whois->{abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3095_5 line 3095 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3095 in _extract_and_resolve_urls() to detect the mutant
    fail('COND_INV_3095_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3135_2 (MEDIUM) line 3135 in _is_redirect_cloaker() ---
# Source:  return 1 if $REDIRECT_HOSTS{$host};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3135_2 line 3135 in _is_redirect_cloaker()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3135 in _is_redirect_cloaker() to detect the mutant
    fail('BOOL_NEGATE_3135_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3137_29_< (HIGH) line 3137 in _is_redirect_cloaker() ---
# Source:  return 1 if length($host) > length($suffix)
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3137_29_< line 3137 in _is_redirect_cloaker()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3137 in _is_redirect_cloaker() to detect the mutant
    fail('NUM_BOUNDARY_3137_29_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3140_2 (MEDIUM) line 3140 in _is_redirect_cloaker() ---
# Source:  return '';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3140_2 line 3140 in _is_redirect_cloaker()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3140 in _is_redirect_cloaker() to detect the mutant
    fail('BOOL_NEGATE_3140_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3171_2 (MEDIUM) line 3171 in _follow_redirect_chain() ---
# Source:  return undef unless $HAS_LWP;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3171_2 line 3171 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3171 in _follow_redirect_chain() to detect the mutant
    fail('BOOL_NEGATE_3171_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3174_2 (MEDIUM) line 3174 in _follow_redirect_chain() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3174_2 line 3174 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3174 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3174_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3176_3 (MEDIUM) line 3176 in _follow_redirect_chain() ---
# Source:  return $cached if defined $cached;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3176_3 line 3176 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3176 in _follow_redirect_chain() to detect the mutant
    fail('BOOL_NEGATE_3176_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3181_2 (MEDIUM) line 3181 in _follow_redirect_chain() ---
# Source:  unless (defined $self->{_ua_nofollow}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_3181_2 line 3181 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3181 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3181_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3187_3 (MEDIUM) line 3187 in _follow_redirect_chain() ---
# Source:  if ($HAS_CONN_CACHE) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3187_3 line 3187 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3187 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3187_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3203_3 (MEDIUM) line 3203 in _follow_redirect_chain() ---
# Source:  if ($res->is_redirect()) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3203_3 line 3203 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3203 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3203_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3209_4 (MEDIUM) line 3209 in _follow_redirect_chain() ---
# Source:  if ($loc !~ m{^https?://}i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3209_4 line 3209 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3209 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3209_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3222_4 (MEDIUM) line 3222 in _follow_redirect_chain() ---
# Source:  if ($body =~ m{<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3222_4 line 3222 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3222 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3222_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3244_2 (MEDIUM) line 3244 in _follow_redirect_chain() ---
# Source:  return $final;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3244_2 line 3244 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3244 in _follow_redirect_chain() to detect the mutant
    fail('BOOL_NEGATE_3244_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3280_5 (MEDIUM) line 3280 in _parallel_resolve_hosts() ---
# Source:  if (@answers) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3280_5 line 3280 in _parallel_resolve_hosts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3280 in _parallel_resolve_hosts() to detect the mutant
    fail('COND_INV_3280_5: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3285_29_< (HIGH) line 3285 in _parallel_resolve_hosts() ---
# Source:  $cv->send if --$pending <= 0;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3285_29_< line 3285 in _parallel_resolve_hosts()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3285 in _parallel_resolve_hosts() to detect the mutant
    fail('NUM_BOUNDARY_3285_29_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3312_2 (MEDIUM) line 3312 in _extract_http_urls() ---
# Source:  if ($HAS_HTML_LINKEXTOR) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3312_2 line 3312 in _extract_http_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3312 in _extract_http_urls() to detect the mutant
    fail('COND_INV_3312_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3317_5 (MEDIUM) line 3317 in _extract_http_urls() ---
# Source:  if ($val =~ m{^https?://}i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3317_5 line 3317 in _extract_http_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3317 in _extract_http_urls() to detect the mutant
    fail('COND_INV_3317_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3342_2 (MEDIUM) line 3342 in _extract_http_urls() ---
# Source:  return @all;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3342_2 line 3342 in _extract_http_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3342 in _extract_http_urls() to detect the mutant
    fail('BOOL_NEGATE_3342_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3421_2 (MEDIUM) line 3421 in _extract_and_analyse_domains() ---
# Source:  if ($mid && $mid =~ /\@([\w.-]+)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3421_2 line 3421 in _extract_and_analyse_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3421 in _extract_and_analyse_domains() to detect the mutant
    fail('COND_INV_3421_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3436_2 (MEDIUM) line 3436 in _extract_and_analyse_domains() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3436_2 line 3436 in _extract_and_analyse_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3436 in _extract_and_analyse_domains() to detect the mutant
    fail('COND_INV_3436_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3486_2 (MEDIUM) line 3486 in _domains_from_text() ---
# Source:  return @out;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3486_2 line 3486 in _domains_from_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3486 in _domains_from_text() to detect the mutant
    fail('BOOL_NEGATE_3486_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3520_2 (MEDIUM) line 3520 in _analyse_domain() ---
# Source:  return $self->{_domain_info}{$domain}
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3520_2 line 3520 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3520 in _analyse_domain() to detect the mutant
    fail('BOOL_NEGATE_3520_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3524_2 (MEDIUM) line 3524 in _analyse_domain() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3524_2 line 3524 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3524 in _analyse_domain() to detect the mutant
    fail('COND_INV_3524_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3526_3 (MEDIUM) line 3526 in _analyse_domain() ---
# Source:  if ($cached) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3526_3 line 3526 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3526 in _analyse_domain() to detect the mutant
    fail('COND_INV_3526_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3528_4 (MEDIUM) line 3528 in _analyse_domain() ---
# Source:  return $cached;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3528_4 line 3528 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3528 in _analyse_domain() to detect the mutant
    fail('BOOL_NEGATE_3528_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3537_2 (MEDIUM) line 3537 in _analyse_domain() ---
# Source:  if ($web_ip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3537_2 line 3537 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3537 in _analyse_domain() to detect the mutant
    fail('COND_INV_3537_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3545_2 (MEDIUM) line 3545 in _analyse_domain() ---
# Source:  if ($HAS_NET_DNS) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3545_2 line 3545 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3545 in _analyse_domain() to detect the mutant
    fail('COND_INV_3545_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3553_3 (MEDIUM) line 3553 in _analyse_domain() ---
# Source:  if ($mxq) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3553_3 line 3553 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3553 in _analyse_domain() to detect the mutant
    fail('COND_INV_3553_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3556_4 (MEDIUM) line 3556 in _analyse_domain() ---
# Source:  if ($best) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3556_4 line 3556 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3556 in _analyse_domain() to detect the mutant
    fail('COND_INV_3556_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3560_5 (MEDIUM) line 3560 in _analyse_domain() ---
# Source:  if ($mx_ip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3560_5 line 3560 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3560 in _analyse_domain() to detect the mutant
    fail('COND_INV_3560_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3571_3 (MEDIUM) line 3571 in _analyse_domain() ---
# Source:  if ($nsq) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3571_3 line 3571 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3571 in _analyse_domain() to detect the mutant
    fail('COND_INV_3571_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3573_4 (MEDIUM) line 3573 in _analyse_domain() ---
# Source:  if ($first) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3573_4 line 3573 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3573 in _analyse_domain() to detect the mutant
    fail('COND_INV_3573_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3577_5 (MEDIUM) line 3577 in _analyse_domain() ---
# Source:  if ($ns_ip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3577_5 line 3577 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3577 in _analyse_domain() to detect the mutant
    fail('COND_INV_3577_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3589_2 (MEDIUM) line 3589 in _analyse_domain() ---
# Source:  if ($domain_whois) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3589_2 line 3589 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3589 in _analyse_domain() to detect the mutant
    fail('COND_INV_3589_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3594_3 (MEDIUM) line 3594 in _analyse_domain() ---
# Source:  if ($domain_whois =~ /Registrar:\s*(.+)/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3594_3 line 3594 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3594 in _analyse_domain() to detect the mutant
    fail('COND_INV_3594_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3604_4 (MEDIUM) line 3604 in _analyse_domain() ---
# Source:  if (!$info{registrar_abuse} && $domain_whois =~ $pat) {
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

# --- SURVIVOR: COND_INV_3616_4 (MEDIUM) line 3616 in _analyse_domain() ---
# Source:  if (!$info{registered} && $domain_whois =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3616_4 line 3616 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3616 in _analyse_domain() to detect the mutant
    fail('COND_INV_3616_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3627_4 (MEDIUM) line 3627 in _analyse_domain() ---
# Source:  if (!$info{expires} && $domain_whois =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3627_4 line 3627 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3627 in _analyse_domain() to detect the mutant
    fail('COND_INV_3627_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3633_3 (MEDIUM) line 3633 in _analyse_domain() ---
# Source:  if ($info{registered}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3633_3 line 3633 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3633 in _analyse_domain() to detect the mutant
    fail('COND_INV_3633_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3636_36_> (HIGH) line 3636 in _analyse_domain() ---
# Source:  if $epoch && (time() - $epoch) < $RECENT_REG_DAYS * $SECS_PER_DAY;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip < to >
#   Numeric boundary flip < to <=
#   Numeric boundary flip < to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3636_36_> line 3636 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3636 in _analyse_domain() to detect the mutant
    fail('NUM_BOUNDARY_3636_36_>: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3670_2 (MEDIUM) line 3670 in _resolve_host() ---
# Source:  return $host if $host =~ /^\d{1,3}(?:\.\d{1,3}){3}$/;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3670_2 line 3670 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3670 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_3670_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3673_2 (MEDIUM) line 3673 in _resolve_host() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3673_2 line 3673 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3673 in _resolve_host() to detect the mutant
    fail('COND_INV_3673_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3675_3 (MEDIUM) line 3675 in _resolve_host() ---
# Source:  return $cached_ip if defined $cached_ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3675_3 line 3675 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3675 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_3675_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3680_2 (MEDIUM) line 3680 in _resolve_host() ---
# Source:  if ($HAS_NET_DNS) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3680_2 line 3680 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3680 in _resolve_host() to detect the mutant
    fail('COND_INV_3680_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3689_4 (MEDIUM) line 3689 in _resolve_host() ---
# Source:  if ($query) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3689_4 line 3689 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3689 in _resolve_host() to detect the mutant
    fail('COND_INV_3689_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3691_6 (MEDIUM) line 3691 in _resolve_host() ---
# Source:  if ($rr->type eq 'A') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3691_6 line 3691 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3691 in _resolve_host() to detect the mutant
    fail('COND_INV_3691_6: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3709_2 (MEDIUM) line 3709 in _resolve_host() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3709_2 line 3709 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3709 in _resolve_host() to detect the mutant
    fail('COND_INV_3709_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3713_2 (MEDIUM) line 3713 in _resolve_host() ---
# Source:  return $ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3713_2 line 3713 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3713 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_3713_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3732_2 (MEDIUM) line 3732 in _reverse_dns() ---
# Source:  if ($HAS_NET_DNS) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3732_2 line 3732 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3732 in _reverse_dns() to detect the mutant
    fail('COND_INV_3732_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3735_3 (MEDIUM) line 3735 in _reverse_dns() ---
# Source:  if ($query) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3735_3 line 3735 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3735 in _reverse_dns() to detect the mutant
    fail('COND_INV_3735_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3737_5 (MEDIUM) line 3737 in _reverse_dns() ---
# Source:  return $rr->ptrdname if $rr->type eq 'PTR';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3737_5 line 3737 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3737 in _reverse_dns() to detect the mutant
    fail('BOOL_NEGATE_3737_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3768_2 (MEDIUM) line 3768 in _whois_ip() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3768_2 line 3768 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3768 in _whois_ip() to detect the mutant
    fail('COND_INV_3768_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3770_3 (MEDIUM) line 3770 in _whois_ip() ---
# Source:  return $cached if $cached;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3770_3 line 3770 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3770 in _whois_ip() to detect the mutant
    fail('BOOL_NEGATE_3770_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3776_2 (MEDIUM) line 3776 in _whois_ip() ---
# Source:  unless ($result->{org}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_3776_2 line 3776 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3776 in _whois_ip() to detect the mutant
    fail('COND_INV_3776_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3778_3 (MEDIUM) line 3778 in _whois_ip() ---
# Source:  if ($raw) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3778_3 line 3778 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3778 in _whois_ip() to detect the mutant
    fail('COND_INV_3778_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3788_2 (MEDIUM) line 3788 in _whois_ip() ---
# Source:  return $result;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3788_2 line 3788 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3788 in _whois_ip() to detect the mutant
    fail('BOOL_NEGATE_3788_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3808_2 (MEDIUM) line 3808 in _domain_whois() ---
# Source:  return $self->_raw_whois($domain, $server);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3808_2 line 3808 in _domain_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3808 in _domain_whois() to detect the mutant
    fail('BOOL_NEGATE_3808_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3828_2 (MEDIUM) line 3828 in _parse_domain_whois_abuse() ---
# Source:  if ($raw =~ /Registrar:\s*(.+)/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3828_2 line 3828 in _parse_domain_whois_abuse()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3828 in _parse_domain_whois_abuse() to detect the mutant
    fail('COND_INV_3828_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3837_3 (MEDIUM) line 3837 in _parse_domain_whois_abuse() ---
# Source:  if (!$info{abuse} && $raw =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3837_3 line 3837 in _parse_domain_whois_abuse()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3837 in _parse_domain_whois_abuse() to detect the mutant
    fail('COND_INV_3837_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3862_2 (MEDIUM) line 3862 in _rdap_lookup() ---
# Source:  if(!defined($ua)) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3862_2 line 3862 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3862 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3862_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3868_3 (MEDIUM) line 3868 in _rdap_lookup() ---
# Source:  if($HAS_CONN_CACHE) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3868_3 line 3868 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3868 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3868_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3887_2 (MEDIUM) line 3887 in _rdap_lookup() ---
# Source:  if ($j =~ /"name"\s*:\s*"([^"]+)"/)   { $info{org}    = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3887_2 line 3887 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3887 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3887_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3888_2 (MEDIUM) line 3888 in _rdap_lookup() ---
# Source:  if ($j =~ /"handle"\s*:\s*"([^"]+)"/) { $info{handle} = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3888_2 line 3888 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3888 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3888_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3891_2 (MEDIUM) line 3891 in _rdap_lookup() ---
# Source:  if ($j =~ /"abuse".*?"email"\s*:\s*"([^"]+)"/s) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3891_2 line 3891 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3891 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3891_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3898_2 (MEDIUM) line 3898 in _rdap_lookup() ---
# Source:  if ($j =~ /"country"\s*:\s*"([A-Z]{2})"/) { $info{country} = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3898_2 line 3898 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3898 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3898_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3958_31_< (HIGH) line 3958 in _raw_whois() ---
# Source:  if ($@ || !defined $n || $n <= 0) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3958_31_< line 3958 in _raw_whois()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3958 in _raw_whois() to detect the mutant
    fail('NUM_BOUNDARY_3958_31_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3962_30_< (HIGH) line 3962 in _raw_whois() ---
# Source:  last if !defined($n) || $n <= 0;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3962_30_< line 3962 in _raw_whois()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3962 in _raw_whois() to detect the mutant
    fail('NUM_BOUNDARY_3962_30_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3967_2 (MEDIUM) line 3967 in _raw_whois() ---
# Source:  return $response || undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3967_2 line 3967 in _raw_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3967 in _raw_whois() to detect the mutant
    fail('BOOL_NEGATE_3967_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3992_3 (MEDIUM) line 3992 in _parse_whois_text() ---
# Source:  if (!$info{org} && $text =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3992_3 line 3992 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3992 in _parse_whois_text() to detect the mutant
    fail('COND_INV_3992_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4002_3 (MEDIUM) line 4002 in _parse_whois_text() ---
# Source:  if (!$info{abuse} && $text =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4002_3 line 4002 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4002 in _parse_whois_text() to detect the mutant
    fail('COND_INV_4002_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4008_2 (MEDIUM) line 4008 in _parse_whois_text() ---
# Source:  if (!$info{abuse} && $text =~ /(abuse\@[\w.-]+)/i) { $info{abuse} = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4008_2 line 4008 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4008 in _parse_whois_text() to detect the mutant
    fail('COND_INV_4008_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4011_2 (MEDIUM) line 4011 in _parse_whois_text() ---
# Source:  if ($text =~ /^country:\s*([A-Za-z]{2})\s*$/m) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4011_2 line 4011 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4011 in _parse_whois_text() to detect the mutant
    fail('COND_INV_4011_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4037_2 (MEDIUM) line 4037 in _parse_auth_results_cached() ---
# Source:  return $self->{_auth_results} if $self->{_auth_results};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4037_2 line 4037 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4037 in _parse_auth_results_cached() to detect the mutant
    fail('BOOL_NEGATE_4037_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4049_2 (MEDIUM) line 4049 in _parse_auth_results_cached() ---
# Source:  if ($raw =~ /\bspf=(\S+)/i)   { $auth{spf}   = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4049_2 line 4049 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4049 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_4049_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4050_2 (MEDIUM) line 4050 in _parse_auth_results_cached() ---
# Source:  if ($raw =~ /\bdkim=(\S+)/i)  { $auth{dkim}  = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4050_2 line 4050 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4050 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_4050_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4051_2 (MEDIUM) line 4051 in _parse_auth_results_cached() ---
# Source:  if ($raw =~ /\bdmarc=(\S+)/i) { $auth{dmarc} = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4051_2 line 4051 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4051 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_4051_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4052_2 (MEDIUM) line 4052 in _parse_auth_results_cached() ---
# Source:  if ($raw =~ /\barc=(\S+)/i)   { $auth{arc}   = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4052_2 line 4052 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4052 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_4052_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4063_3 (MEDIUM) line 4063 in _parse_auth_results_cached() ---
# Source:  if ($h->{value} =~ /\bd=([^;,\s]+)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4063_3 line 4063 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4063 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_4063_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4068_2 (MEDIUM) line 4068 in _parse_auth_results_cached() ---
# Source:  if (@dkim_domains) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4068_2 line 4068 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4068 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_4068_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4072_4 (MEDIUM) line 4072 in _parse_auth_results_cached() ---
# Source:  if ($self->_provider_abuse_for_host($d)) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4072_4 line 4072 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4072 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_4072_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4106_3 (MEDIUM) line 4106 in _provider_abuse_for_host() ---
# Source:  return $self->{provider_abuse}->{$host} if $self->{provider_abuse}->{$host};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4106_3 line 4106 in _provider_abuse_for_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4106 in _provider_abuse_for_host() to detect the mutant
    fail('BOOL_NEGATE_4106_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4128_2 (MEDIUM) line 4128 in _provider_abuse_for_ip() ---
# Source:  return $self->_provider_abuse_for_host($rdns) if $rdns;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4128_2 line 4128 in _provider_abuse_for_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4128 in _provider_abuse_for_ip() to detect the mutant
    fail('BOOL_NEGATE_4128_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4159_2 (MEDIUM) line 4159 in _registrable() ---
# Source:  if ($HAS_PUBLIC_SUFFIX) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4159_2 line 4159 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4159 in _registrable() to detect the mutant
    fail('COND_INV_4159_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4162_3 (MEDIUM) line 4162 in _registrable() ---
# Source:  return $root if $root;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4162_3 line 4162 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4162 in _registrable() to detect the mutant
    fail('BOOL_NEGATE_4162_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4167_26_< (HIGH) line 4167 in _registrable() ---
# Source:  return $host if @labels <= 2;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4167_26_< line 4167 in _registrable()';
    # Suggested boundary values to test: 1, 2, 3
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4167 in _registrable() to detect the mutant
    fail('NUM_BOUNDARY_4167_26_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4170_2 (MEDIUM) line 4170 in _registrable() ---
# Source:  if ($labels[-1] =~ /^[a-z]{2}$/ &&
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4170_2 line 4170 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4170 in _registrable() to detect the mutant
    fail('COND_INV_4170_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4233_2 (MEDIUM) line 4233 in header_value() ---
# Source:  return $self->_header_value($name);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4233_2 line 4233 in header_value()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4233 in header_value() to detect the mutant
    fail('BOOL_NEGATE_4233_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4253_3 (MEDIUM) line 4253 in _header_value() ---
# Source:  return $h->{value} if $h->{name} eq lc($name);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4253_3 line 4253 in _header_value()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4253 in _header_value() to detect the mutant
    fail('BOOL_NEGATE_4253_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4273_2 (MEDIUM) line 4273 in _ip_in_cidr() ---
# Source:  return $ip eq $cidr unless $cidr =~ m{/};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4273_2 line 4273 in _ip_in_cidr()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4273 in _ip_in_cidr() to detect the mutant
    fail('BOOL_NEGATE_4273_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4275_65_< (HIGH) line 4275 in _ip_in_cidr() ---
# Source:  return 0 if !defined($prefix) || $prefix !~ /^\d+$/ || $prefix > 32;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4275_65_< line 4275 in _ip_in_cidr()';
    # Suggested boundary values to test: 31, 32, 33
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4275 in _ip_in_cidr() to detect the mutant
    fail('NUM_BOUNDARY_4275_65_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4281_25_!= (HIGH) line 4281 in _ip_in_cidr() ---
# Source:  return ($ip_n & $mask) == ($net_n & $mask);
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (1 variant):
#   Numeric boundary flip == to !=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4281_25_!= line 4281 in _ip_in_cidr()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4281 in _ip_in_cidr() to detect the mutant
    fail('NUM_BOUNDARY_4281_25_!=: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4298_2 (MEDIUM) line 4298 in _decode_mime_words() ---
# Source:  return '' unless defined $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4298_2 line 4298 in _decode_mime_words()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4298 in _decode_mime_words() to detect the mutant
    fail('BOOL_NEGATE_4298_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4301_2 (MEDIUM) line 4301 in _decode_mime_words() ---
# Source:  return $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4301_2 line 4301 in _decode_mime_words()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4301 in _decode_mime_words() to detect the mutant
    fail('BOOL_NEGATE_4301_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4316_2 (MEDIUM) line 4316 in _decode_ew() ---
# Source:  if (uc($enc) eq 'B') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4316_2 line 4316 in _decode_ew()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4316 in _decode_ew() to detect the mutant
    fail('COND_INV_4316_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4323_2 (MEDIUM) line 4323 in _decode_ew() ---
# Source:  return $raw;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4323_2 line 4323 in _decode_ew()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4323 in _decode_ew() to detect the mutant
    fail('BOOL_NEGATE_4323_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4346_2 (MEDIUM) line 4346 in _parse_date_to_epoch() ---
# Source:  if ($str =~ /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?Z$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4346_2 line 4346 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4346 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_4346_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4358_4 (MEDIUM) line 4358 in _parse_date_to_epoch() ---
# Source:  return $t->epoch - $t->tzoffset->seconds;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4358_4 line 4358 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4358 in _parse_date_to_epoch() to detect the mutant
    fail('BOOL_NEGATE_4358_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4360_3 (MEDIUM) line 4360 in _parse_date_to_epoch() ---
# Source:  return $epoch if defined $epoch;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4360_3 line 4360 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4360 in _parse_date_to_epoch() to detect the mutant
    fail('BOOL_NEGATE_4360_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4364_2 (MEDIUM) line 4364 in _parse_date_to_epoch() ---
# Source:  if    ($str =~ /^(\d{4})-(\d{2})-(\d{2})/)         { ($y,$m,$d)=($1,$2,$3) }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4364_2 line 4364 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4364 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_4364_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4370_2 (MEDIUM) line 4370 in _parse_date_to_epoch() ---
# Source:  if (eval { require Time::Local; 1 }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4370_2 line 4370 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4370 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_4370_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4396_2 (MEDIUM) line 4396 in _parse_rfc2822_date() ---
# Source:  if ($str =~ /(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4396_2 line 4396 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4396 in _parse_rfc2822_date() to detect the mutant
    fail('COND_INV_4396_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4400_3 (MEDIUM) line 4400 in _parse_rfc2822_date() ---
# Source:  if (eval { require Time::Local; 1 }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4400_3 line 4400 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4400 in _parse_rfc2822_date() to detect the mutant
    fail('COND_INV_4400_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4444_2 (MEDIUM) line 4444 in _debug() ---
# Source:  if($self->{verbose}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4444_2 line 4444 in _debug()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4444 in _debug() to detect the mutant
    fail('COND_INV_4444_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4445_3 (MEDIUM) line 4445 in _debug() ---
# Source:  if (my $logger = $self->{logger}) { # Set via Object::Configure
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4445_3 line 4445 in _debug()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4445 in _debug() to detect the mutant
    fail('COND_INV_4445_3: replace with real assertion');
}

# --- LOW DIFFICULTY HINTS (comment stubs) ---

# --- LOW HINT: RETURN_UNDEF_771_2 line 771 in parse_email() ---
# Source:  return $self;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_771_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_846_2 line 846 in originating_ip() ---
# Source:  return $self->{_origin};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_846_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1068_2 line 1068 in all_domains() ---
# Source:  return @out;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1068_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1174_2 line 1174 in unresolved_contacts() ---
# Source:  return @out;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1174_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1375_2 line 1375 in risk_assessment() ---
# Source:  return $self->{_risk} if $self->{_risk};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1375_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1400_2 line 1400 in risk_assessment() ---
# Source:  return $self->{_risk};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1400_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2146_2 line 2146 in _compute_abuse_contacts() ---
# Source:  return @contacts;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2146_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2354_2 line 2354 in form_contacts() ---
# Source:  return @contacts;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2354_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2652_2 line 2652 in _sanitise_output() ---
# Source:  return '' unless defined $str;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2652_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2655_2 line 2655 in _sanitise_output() ---
# Source:  return $str;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2655_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2873_2 line 2873 in _decode_body() ---
# Source:  return $body // '';
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2873_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2921_4 line 2921 in _find_origin() ---
# Source:  return $self->_enrich_ip($xoip, 'low',
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2921_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2929_2 line 2929 in _find_origin() ---
# Source:  return $self->_enrich_ip(
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2929_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2960_4 line 2960 in _extract_ip_from_received() ---
# Source:  return $ip if $ip =~ /:/;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2960_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2965_4 line 2965 in _extract_ip_from_received() ---
# Source:  return $ip;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2965_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2990_2 line 2990 in _is_private() ---
# Source:  return 1 if !defined($ip) || $ip eq '';
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2990_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2991_33 line 2991 in _is_private() ---
# Source:  for my $re (@PRIVATE_RANGES) { return 1 if $ip =~ $re }
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2991_33: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2992_2 line 2992 in _is_private() ---
# Source:  return 0;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2992_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3011_3 line 3011 in _is_trusted() ---
# Source:  return 1 if $self->_ip_in_cidr($ip, $cidr);
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3011_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3013_2 line 3013 in _is_trusted() ---
# Source:  return 0;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3013_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3135_2 line 3135 in _is_redirect_cloaker() ---
# Source:  return 1 if $REDIRECT_HOSTS{$host};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3135_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3137_3 line 3137 in _is_redirect_cloaker() ---
# Source:  return 1 if length($host) > length($suffix)
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3137_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3140_2 line 3140 in _is_redirect_cloaker() ---
# Source:  return '';
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3140_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3171_2 line 3171 in _follow_redirect_chain() ---
# Source:  return undef unless $HAS_LWP;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3171_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3176_3 line 3176 in _follow_redirect_chain() ---
# Source:  return $cached if defined $cached;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3176_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3244_2 line 3244 in _follow_redirect_chain() ---
# Source:  return $final;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3244_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3342_2 line 3342 in _extract_http_urls() ---
# Source:  return @all;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3342_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3486_2 line 3486 in _domains_from_text() ---
# Source:  return @out;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3486_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3520_2 line 3520 in _analyse_domain() ---
# Source:  return $self->{_domain_info}{$domain}
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3520_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3528_4 line 3528 in _analyse_domain() ---
# Source:  return $cached;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3528_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3670_2 line 3670 in _resolve_host() ---
# Source:  return $host if $host =~ /^\d{1,3}(?:\.\d{1,3}){3}$/;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3670_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3675_3 line 3675 in _resolve_host() ---
# Source:  return $cached_ip if defined $cached_ip;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3675_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3713_2 line 3713 in _resolve_host() ---
# Source:  return $ip;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3713_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3737_5 line 3737 in _reverse_dns() ---
# Source:  return $rr->ptrdname if $rr->type eq 'PTR';
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3737_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3770_3 line 3770 in _whois_ip() ---
# Source:  return $cached if $cached;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3770_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3788_2 line 3788 in _whois_ip() ---
# Source:  return $result;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3788_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3808_2 line 3808 in _domain_whois() ---
# Source:  return $self->_raw_whois($domain, $server);
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3808_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3967_2 line 3967 in _raw_whois() ---
# Source:  return $response || undef;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3967_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4037_2 line 4037 in _parse_auth_results_cached() ---
# Source:  return $self->{_auth_results} if $self->{_auth_results};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4037_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4106_3 line 4106 in _provider_abuse_for_host() ---
# Source:  return $self->{provider_abuse}->{$host} if $self->{provider_abuse}->{$host};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4106_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4128_2 line 4128 in _provider_abuse_for_ip() ---
# Source:  return $self->_provider_abuse_for_host($rdns) if $rdns;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4128_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4162_3 line 4162 in _registrable() ---
# Source:  return $root if $root;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4162_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4167_2 line 4167 in _registrable() ---
# Source:  return $host if @labels <= 2;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4167_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4233_2 line 4233 in header_value() ---
# Source:  return $self->_header_value($name);
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4233_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4253_3 line 4253 in _header_value() ---
# Source:  return $h->{value} if $h->{name} eq lc($name);
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4253_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4273_2 line 4273 in _ip_in_cidr() ---
# Source:  return $ip eq $cidr unless $cidr =~ m{/};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4273_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4275_2 line 4275 in _ip_in_cidr() ---
# Source:  return 0 if !defined($prefix) || $prefix !~ /^\d+$/ || $prefix > 32;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4275_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4298_2 line 4298 in _decode_mime_words() ---
# Source:  return '' unless defined $str;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4298_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4301_2 line 4301 in _decode_mime_words() ---
# Source:  return $str;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4301_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4323_2 line 4323 in _decode_ew() ---
# Source:  return $raw;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4323_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4358_4 line 4358 in _parse_date_to_epoch() ---
# Source:  return $t->epoch - $t->tzoffset->seconds;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4358_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4360_3 line 4360 in _parse_date_to_epoch() ---
# Source:  return $epoch if defined $epoch;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4360_3: add assertion here');

done_testing();
