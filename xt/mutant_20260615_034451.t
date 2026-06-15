#!/usr/bin/env perl
# Auto-generated mutant test stubs
# Generated: 2026-06-15 03:44:51
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

# --- SURVIVOR: COND_INV_1648_3 (MEDIUM) line 1648 in _risk_check_urls_and_domains() ---
# Source:  if(($URL_SHORTENERS{$bare} || $self->{url_shorteners}->{$bare}) && !$shortener_seen{$bare}++) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1648_3 line 1648 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1648 in _risk_check_urls_and_domains() to detect the mutant
    fail('COND_INV_1648_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1653_3 (MEDIUM) line 1653 in _risk_check_urls_and_domains() ---
# Source:  if ($self->_is_redirect_cloaker($bare) && !$cloaker_seen{$bare}++) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1653_3 line 1653 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1653 in _risk_check_urls_and_domains() to detect the mutant
    fail('COND_INV_1653_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1658_3 (MEDIUM) line 1658 in _risk_check_urls_and_domains() ---
# Source:  if ($u->{url} =~ m{^http://}i && !$url_host_seen{ $u->{host} }++) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1658_3 line 1658 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1658 in _risk_check_urls_and_domains() to detect the mutant
    fail('COND_INV_1658_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1667_3 (MEDIUM) line 1667 in _risk_check_urls_and_domains() ---
# Source:  if ($d->{recently_registered}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1667_3 line 1667 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1667 in _risk_check_urls_and_domains() to detect the mutant
    fail('COND_INV_1667_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1673_3 (MEDIUM) line 1673 in _risk_check_urls_and_domains() ---
# Source:  if ($d->{expires}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1673_3 line 1673 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1673 in _risk_check_urls_and_domains() to detect the mutant
    fail('COND_INV_1673_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1674_4 (MEDIUM) line 1674 in _risk_check_urls_and_domains() ---
# Source:  if(my $exp = $self->_parse_date_to_epoch($d->{expires})) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1674_4 line 1674 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1674 in _risk_check_urls_and_domains() to detect the mutant
    fail('COND_INV_1674_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1677_20_< (HIGH) line 1677 in _risk_check_urls_and_domains() ---
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
    local $TODO = 'Complete: NUM_BOUNDARY_1677_20_< line 1677 in _risk_check_urls_and_domains()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1677 in _risk_check_urls_and_domains() to detect the mutant
    fail('NUM_BOUNDARY_1677_20_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1680_25_< (HIGH) line 1680 in _risk_check_urls_and_domains() ---
# Source:  } elsif ($remaining <= 0) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1680_25_< line 1680 in _risk_check_urls_and_domains()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1680 in _risk_check_urls_and_domains() to detect the mutant
    fail('NUM_BOUNDARY_1680_25_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1689_4 (MEDIUM) line 1689 in _risk_check_urls_and_domains() ---
# Source:  if ($d->{domain} =~ /\Q$brand\E/i &&
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1689_4 line 1689 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1689 in _risk_check_urls_and_domains() to detect the mutant
    fail('COND_INV_1689_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1765_2 (MEDIUM) line 1765 in abuse_report_text() ---
# Source:  if (@{ $risk->{flags} }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1765_2 line 1765 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1765 in abuse_report_text() to detect the mutant
    fail('COND_INV_1765_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1775_2 (MEDIUM) line 1775 in abuse_report_text() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1775_2 line 1775 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1775 in abuse_report_text() to detect the mutant
    fail('COND_INV_1775_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1784_2 (MEDIUM) line 1784 in abuse_report_text() ---
# Source:  if (@urls) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1784_2 line 1784 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1784 in abuse_report_text() to detect the mutant
    fail('COND_INV_1784_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1799_2 (MEDIUM) line 1799 in abuse_report_text() ---
# Source:  if (@contacts) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1799_2 line 1799 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1799 in abuse_report_text() to detect the mutant
    fail('COND_INV_1799_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1806_2 (MEDIUM) line 1806 in abuse_report_text() ---
# Source:  if(my @form_cs = $self->form_contacts()) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1806_2 line 1806 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1806 in abuse_report_text() to detect the mutant
    fail('COND_INV_1806_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1927_3 (MEDIUM) line 1927 in _compute_abuse_contacts() ---
# Source:  if ($addr =~ /\@([\w.-]+)$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1927_3 line 1927 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1927 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1927_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1933_3 (MEDIUM) line 1933 in _compute_abuse_contacts() ---
# Source:  if (exists $seen_idx{$addr}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1933_3 line 1933 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1933 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1933_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1944_22_< (HIGH) line 1944 in _compute_abuse_contacts() ---
# Source:  $role_counts{$_} > 1 ? "$_ (x$role_counts{$_})" : $_
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1944_22_< line 1944 in _compute_abuse_contacts()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1944 in _compute_abuse_contacts() to detect the mutant
    fail('NUM_BOUNDARY_1944_22_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1954_24_< (HIGH) line 1954 in _compute_abuse_contacts() ---
# Source:  if (length($joined) > $ROLE_MAX_LEN) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1954_24_< line 1954 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1954 in _compute_abuse_contacts() to detect the mutant
    fail('NUM_BOUNDARY_1954_24_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1957_6 (MEDIUM) line 1957 in _compute_abuse_contacts() ---
# Source:  if ($r =~ /^URL host:\s*(.+)$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1957_6 line 1957 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1957 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1957_6: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1966_5 (MEDIUM) line 1966 in _compute_abuse_contacts() ---
# Source:  if (@url_hosts) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1966_5 line 1966 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1966 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1966_5: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1967_29_< (HIGH) line 1967 in _compute_abuse_contacts() ---
# Source:  my $extra = @url_hosts > 3
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1967_29_< line 1967 in _compute_abuse_contacts()';
    # Suggested boundary values to test: 2, 3, 4
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1967 in _compute_abuse_contacts() to detect the mutant
    fail('NUM_BOUNDARY_1967_29_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1969_29_< (HIGH) line 1969 in _compute_abuse_contacts() ---
# Source:  my @shown = @url_hosts > 3 ? @url_hosts[0..2] : @url_hosts;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1969_29_< line 1969 in _compute_abuse_contacts()';
    # Suggested boundary values to test: 2, 3, 4
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1969 in _compute_abuse_contacts() to detect the mutant
    fail('NUM_BOUNDARY_1969_29_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1987_2 (MEDIUM) line 1987 in _compute_abuse_contacts() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1987_2 line 1987 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1987 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1987_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1989_3 (MEDIUM) line 1989 in _compute_abuse_contacts() ---
# Source:  if ($pa) {
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

# --- SURVIVOR: COND_INV_1997_3 (MEDIUM) line 1997 in _compute_abuse_contacts() ---
# Source:  if ($orig->{abuse} && $orig->{abuse} ne '(unknown)') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1997_3 line 1997 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1997 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1997_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2017_3 (MEDIUM) line 2017 in _compute_abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2017_3 line 2017 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2017 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2017_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2025_3 (MEDIUM) line 2025 in _compute_abuse_contacts() ---
# Source:  if ($u->{abuse} && $u->{abuse} ne '(unknown)') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2025_3 line 2025 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2025 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2025_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2040_3 (MEDIUM) line 2040 in _compute_abuse_contacts() ---
# Source:  if ($d->{web_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2040_3 line 2040 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2040 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2040_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2042_4 (MEDIUM) line 2042 in _compute_abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2042_4 line 2042 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2042 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2042_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2058_3 (MEDIUM) line 2058 in _compute_abuse_contacts() ---
# Source:  if ($d->{mx_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2058_3 line 2058 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2058 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2058_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2071_3 (MEDIUM) line 2071 in _compute_abuse_contacts() ---
# Source:  if ($d->{ns_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2071_3 line 2071 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2071 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2071_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2084_3 (MEDIUM) line 2084 in _compute_abuse_contacts() ---
# Source:  if ($d->{registrar_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2084_3 line 2084 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2084 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2084_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2091_4 (MEDIUM) line 2091 in _compute_abuse_contacts() ---
# Source:  unless ($spoofable_only) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_2091_4 line 2091 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2091 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2091_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2115_3 (MEDIUM) line 2115 in _compute_abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2115_3 line 2115 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2115 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2115_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2129_2 (MEDIUM) line 2129 in _compute_abuse_contacts() ---
# Source:  if ($auth->{dkim_domain}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2129_2 line 2129 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2129 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2129_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2131_3 (MEDIUM) line 2131 in _compute_abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2131_3 line 2131 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2131 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2131_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2143_2 (MEDIUM) line 2143 in _compute_abuse_contacts() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2143_2 line 2143 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2143 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2143_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2154_4 (MEDIUM) line 2154 in _compute_abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2154_4 line 2154 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2154 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2154_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2182_2 (MEDIUM) line 2182 in _compute_abuse_contacts() ---
# Source:  return @contacts;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2182_2 line 2182 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2182 in _compute_abuse_contacts() to detect the mutant
    fail('BOOL_NEGATE_2182_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2263_2 (MEDIUM) line 2263 in form_contacts() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2263_2 line 2263 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2263 in form_contacts() to detect the mutant
    fail('COND_INV_2263_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2265_3 (MEDIUM) line 2265 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2265_3 line 2265 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2265 in form_contacts() to detect the mutant
    fail('COND_INV_2265_3: replace with real assertion');
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

# --- SURVIVOR: COND_INV_2299_3 (MEDIUM) line 2299 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2299_3 line 2299 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2299 in form_contacts() to detect the mutant
    fail('COND_INV_2299_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2312_3 (MEDIUM) line 2312 in form_contacts() ---
# Source:  if ($d->{registrar_abuse} && $d->{registrar_abuse} =~ /\@([\w.-]+)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2312_3 line 2312 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2312 in form_contacts() to detect the mutant
    fail('COND_INV_2312_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2315_4 (MEDIUM) line 2315 in form_contacts() ---
# Source:  if ($rpa && $rpa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2315_4 line 2315 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2315 in form_contacts() to detect the mutant
    fail('COND_INV_2315_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2338_3 (MEDIUM) line 2338 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2338_3 line 2338 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2338 in form_contacts() to detect the mutant
    fail('COND_INV_2338_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2354_2 (MEDIUM) line 2354 in form_contacts() ---
# Source:  if ($auth->{dkim_domain}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2354_2 line 2354 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2354 in form_contacts() to detect the mutant
    fail('COND_INV_2354_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2356_3 (MEDIUM) line 2356 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2356_3 line 2356 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2356 in form_contacts() to detect the mutant
    fail('COND_INV_2356_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2370_2 (MEDIUM) line 2370 in form_contacts() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2370_2 line 2370 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2370 in form_contacts() to detect the mutant
    fail('COND_INV_2370_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2377_4 (MEDIUM) line 2377 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2377_4 line 2377 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2377 in form_contacts() to detect the mutant
    fail('COND_INV_2377_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2390_2 (MEDIUM) line 2390 in form_contacts() ---
# Source:  return @contacts;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2390_2 line 2390 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2390 in form_contacts() to detect the mutant
    fail('BOOL_NEGATE_2390_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2471_2 (MEDIUM) line 2471 in report() ---
# Source:  if (@{ $risk->{flags} }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2471_2 line 2471 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2471 in report() to detect the mutant
    fail('COND_INV_2471_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2483_2 (MEDIUM) line 2483 in report() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2483_2 line 2483 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2483 in report() to detect the mutant
    fail('COND_INV_2483_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2498_2 (MEDIUM) line 2498 in report() ---
# Source:  if (@sw) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2498_2 line 2498 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2498 in report() to detect the mutant
    fail('COND_INV_2498_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2510_2 (MEDIUM) line 2510 in report() ---
# Source:  if (@trail) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2510_2 line 2510 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2510 in report() to detect the mutant
    fail('COND_INV_2510_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2525_2 (MEDIUM) line 2525 in report() ---
# Source:  if (@urls) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2525_2 line 2525 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2525 in report() to detect the mutant
    fail('COND_INV_2525_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2530_4 (MEDIUM) line 2530 in report() ---
# Source:  unless (exists $host_order{$h}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_2530_4 line 2530 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2530 in report() to detect the mutant
    fail('COND_INV_2530_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2554_15_!= (HIGH) line 2554 in report() ---
# Source:  if (@paths == 1) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (2 variants — one test should kill all):
#   Numeric boundary flip == to !=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2554_15_!= line 2554 in report()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2554 in report() to detect the mutant
    fail('NUM_BOUNDARY_2554_15_!=: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2570_2 (MEDIUM) line 2570 in report() ---
# Source:  if (@mdoms) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2570_2 line 2570 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2570 in report() to detect the mutant
    fail('COND_INV_2570_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2574_4 (MEDIUM) line 2574 in report() ---
# Source:  if ($d->{recently_registered}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2574_4 line 2574 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2574 in report() to detect the mutant
    fail('COND_INV_2574_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2581_4 (MEDIUM) line 2581 in report() ---
# Source:  if ($d->{web_ip}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2581_4 line 2581 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2581 in report() to detect the mutant
    fail('COND_INV_2581_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2588_4 (MEDIUM) line 2588 in report() ---
# Source:  if ($d->{mx_host}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2588_4 line 2588 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2588 in report() to detect the mutant
    fail('COND_INV_2588_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2596_4 (MEDIUM) line 2596 in report() ---
# Source:  if ($d->{ns_host}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2596_4 line 2596 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2596 in report() to detect the mutant
    fail('COND_INV_2596_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2612_2 (MEDIUM) line 2612 in report() ---
# Source:  if (@contacts) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2612_2 line 2612 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2612 in report() to detect the mutant
    fail('COND_INV_2612_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2627_2 (MEDIUM) line 2627 in report() ---
# Source:  if (@form_cs) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2627_2 line 2627 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2627 in report() to detect the mutant
    fail('COND_INV_2627_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2637_4 (MEDIUM) line 2637 in report() ---
# Source:  if ($c->{form_paste}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2637_4 line 2637 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2637 in report() to detect the mutant
    fail('COND_INV_2637_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2643_46_< (HIGH) line 2643 in report() ---
# Source:  if (defined $line && length("$line $w") > $ROLE_WRAP_LEN) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2643_46_< line 2643 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2643 in report() to detect the mutant
    fail('NUM_BOUNDARY_2643_46_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2688_2 (MEDIUM) line 2688 in _sanitise_output() ---
# Source:  return '' unless defined $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2688_2 line 2688 in _sanitise_output()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2688 in _sanitise_output() to detect the mutant
    fail('BOOL_NEGATE_2688_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2691_2 (MEDIUM) line 2691 in _sanitise_output() ---
# Source:  return $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2691_2 line 2691 in _sanitise_output()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2691 in _sanitise_output() to detect the mutant
    fail('BOOL_NEGATE_2691_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2738_3 (MEDIUM) line 2738 in _split_message() ---
# Source:  if ($line =~ /^([\w-]+)\s*:\s*(.*)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2738_3 line 2738 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2738 in _split_message() to detect the mutant
    fail('COND_INV_2738_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2757_2 (MEDIUM) line 2757 in _split_message() ---
# Source:  if ($ct =~ /multipart/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2757_2 line 2757 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2757 in _split_message() to detect the mutant
    fail('COND_INV_2757_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2763_3 (MEDIUM) line 2763 in _split_message() ---
# Source:  if ($ct =~ /html/i) { $self->{_body_html}  = $decoded }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2763_3 line 2763 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2763 in _split_message() to detect the mutant
    fail('COND_INV_2763_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2837_13_> (HIGH) line 2837 in _decode_multipart() ---
# Source:  if ($depth >= $MAX_MULTIPART_DEPTH) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2837_13_> line 2837 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2837 in _decode_multipart() to detect the mutant
    fail('NUM_BOUNDARY_2837_13_>: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2870_3 (MEDIUM) line 2870 in _decode_multipart() ---
# Source:  if ($pct =~ /multipart/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2870_3 line 2870 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2870 in _decode_multipart() to detect the mutant
    fail('COND_INV_2870_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2872_4 (MEDIUM) line 2872 in _decode_multipart() ---
# Source:  if ($inner_boundary) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2872_4 line 2872 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2872 in _decode_multipart() to detect the mutant
    fail('COND_INV_2872_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2882_3 (MEDIUM) line 2882 in _decode_multipart() ---
# Source:  if    ($pct =~ /text\/html/i)    { $self->{_body_html}  .= $decoded }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2882_3 line 2882 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2882 in _decode_multipart() to detect the mutant
    fail('COND_INV_2882_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2909_2 (MEDIUM) line 2909 in _decode_body() ---
# Source:  return $body // '';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2909_2 line 2909 in _decode_body()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2909 in _decode_body() to detect the mutant
    fail('BOOL_NEGATE_2909_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2953_2 (MEDIUM) line 2953 in _find_origin() ---
# Source:  unless (@candidates) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_2953_2 line 2953 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2953 in _find_origin() to detect the mutant
    fail('COND_INV_2953_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2955_3 (MEDIUM) line 2955 in _find_origin() ---
# Source:  if ($xoip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2955_3 line 2955 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2955 in _find_origin() to detect the mutant
    fail('COND_INV_2955_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2957_4 (MEDIUM) line 2957 in _find_origin() ---
# Source:  return $self->_enrich_ip($xoip, 'low',
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2957_4 line 2957 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2957 in _find_origin() to detect the mutant
    fail('BOOL_NEGATE_2957_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2965_2 (MEDIUM) line 2965 in _find_origin() ---
# Source:  return $self->_enrich_ip(
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2965_2 line 2965 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2965 in _find_origin() to detect the mutant
    fail('BOOL_NEGATE_2965_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2967_15_< (HIGH) line 2967 in _find_origin() ---
# Source:  @candidates > 1 ? 'high' : 'medium',
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2967_15_< line 2967 in _find_origin()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2967 in _find_origin() to detect the mutant
    fail('NUM_BOUNDARY_2967_15_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2992_3 (MEDIUM) line 2992 in _extract_ip_from_received() ---
# Source:  if ($hdr =~ $re) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2992_3 line 2992 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2992 in _extract_ip_from_received() to detect the mutant
    fail('COND_INV_2992_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2996_4 (MEDIUM) line 2996 in _extract_ip_from_received() ---
# Source:  return $ip if $ip =~ /:/;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2996_4 line 2996 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2996 in _extract_ip_from_received() to detect the mutant
    fail('BOOL_NEGATE_2996_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3000_22_< (HIGH) line 3000 in _extract_ip_from_received() ---
# Source:  next if grep { $_ > 255 } split /\./, $ip;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3000_22_< line 3000 in _extract_ip_from_received()';
    # Suggested boundary values to test: 254, 255, 256
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3000 in _extract_ip_from_received() to detect the mutant
    fail('NUM_BOUNDARY_3000_22_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3001_4 (MEDIUM) line 3001 in _extract_ip_from_received() ---
# Source:  return $ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3001_4 line 3001 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3001 in _extract_ip_from_received() to detect the mutant
    fail('BOOL_NEGATE_3001_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3026_2 (MEDIUM) line 3026 in _is_private() ---
# Source:  return 1 if !defined($ip) || $ip eq '';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3026_2 line 3026 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3026 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_3026_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3027_33 (MEDIUM) line 3027 in _is_private() ---
# Source:  for my $re (@PRIVATE_RANGES) { return 1 if $ip =~ $re }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3027_33 line 3027 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3027 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_3027_33: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3028_2 (MEDIUM) line 3028 in _is_private() ---
# Source:  return 0;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3028_2 line 3028 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3028 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_3028_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3047_3 (MEDIUM) line 3047 in _is_trusted() ---
# Source:  return 1 if $self->_ip_in_cidr($ip, $cidr);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3047_3 line 3047 in _is_trusted()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3047 in _is_trusted() to detect the mutant
    fail('BOOL_NEGATE_3047_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3049_2 (MEDIUM) line 3049 in _is_trusted() ---
# Source:  return 0;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3049_2 line 3049 in _is_trusted()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3049 in _is_trusted() to detect the mutant
    fail('BOOL_NEGATE_3049_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3109_57_< (HIGH) line 3109 in _extract_and_resolve_urls() ---
# Source:  if ($HAS_ANYEVENT_DNS && scalar(keys %hostname_needed) > 1) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3109_57_< line 3109 in _extract_and_resolve_urls()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3109 in _extract_and_resolve_urls() to detect the mutant
    fail('NUM_BOUNDARY_3109_57_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3119_3 (MEDIUM) line 3119 in _extract_and_resolve_urls() ---
# Source:  unless (exists $host_cache{$host}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_3119_3 line 3119 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3119 in _extract_and_resolve_urls() to detect the mutant
    fail('COND_INV_3119_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3122_4 (MEDIUM) line 3122 in _extract_and_resolve_urls() ---
# Source:  if ($cached) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3122_4 line 3122 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3122 in _extract_and_resolve_urls() to detect the mutant
    fail('COND_INV_3122_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3131_5 (MEDIUM) line 3131 in _extract_and_resolve_urls() ---
# Source:  if (!$whois->{abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3131_5 line 3131 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3131 in _extract_and_resolve_urls() to detect the mutant
    fail('COND_INV_3131_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3171_2 (MEDIUM) line 3171 in _is_redirect_cloaker() ---
# Source:  return 1 if $REDIRECT_HOSTS{$host};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3171_2 line 3171 in _is_redirect_cloaker()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3171 in _is_redirect_cloaker() to detect the mutant
    fail('BOOL_NEGATE_3171_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3173_29_< (HIGH) line 3173 in _is_redirect_cloaker() ---
# Source:  return 1 if length($host) > length($suffix)
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3173_29_< line 3173 in _is_redirect_cloaker()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3173 in _is_redirect_cloaker() to detect the mutant
    fail('NUM_BOUNDARY_3173_29_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3176_2 (MEDIUM) line 3176 in _is_redirect_cloaker() ---
# Source:  return '';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3176_2 line 3176 in _is_redirect_cloaker()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3176 in _is_redirect_cloaker() to detect the mutant
    fail('BOOL_NEGATE_3176_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3207_2 (MEDIUM) line 3207 in _follow_redirect_chain() ---
# Source:  return undef unless $HAS_LWP;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3207_2 line 3207 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3207 in _follow_redirect_chain() to detect the mutant
    fail('BOOL_NEGATE_3207_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3210_2 (MEDIUM) line 3210 in _follow_redirect_chain() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3210_2 line 3210 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3210 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3210_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3212_3 (MEDIUM) line 3212 in _follow_redirect_chain() ---
# Source:  return $cached if defined $cached;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3212_3 line 3212 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3212 in _follow_redirect_chain() to detect the mutant
    fail('BOOL_NEGATE_3212_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3217_2 (MEDIUM) line 3217 in _follow_redirect_chain() ---
# Source:  unless (defined $self->{_ua_nofollow}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_3217_2 line 3217 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3217 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3217_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3223_3 (MEDIUM) line 3223 in _follow_redirect_chain() ---
# Source:  if ($HAS_CONN_CACHE) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3223_3 line 3223 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3223 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3223_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3239_3 (MEDIUM) line 3239 in _follow_redirect_chain() ---
# Source:  if ($res->is_redirect()) {
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

# --- SURVIVOR: COND_INV_3245_4 (MEDIUM) line 3245 in _follow_redirect_chain() ---
# Source:  if ($loc !~ m{^https?://}i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3245_4 line 3245 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3245 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3245_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3258_4 (MEDIUM) line 3258 in _follow_redirect_chain() ---
# Source:  if ($body =~ m{<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3258_4 line 3258 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3258 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3258_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3280_2 (MEDIUM) line 3280 in _follow_redirect_chain() ---
# Source:  return $final;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3280_2 line 3280 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3280 in _follow_redirect_chain() to detect the mutant
    fail('BOOL_NEGATE_3280_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3316_5 (MEDIUM) line 3316 in _parallel_resolve_hosts() ---
# Source:  if (@answers) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3316_5 line 3316 in _parallel_resolve_hosts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3316 in _parallel_resolve_hosts() to detect the mutant
    fail('COND_INV_3316_5: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3321_29_< (HIGH) line 3321 in _parallel_resolve_hosts() ---
# Source:  $cv->send if --$pending <= 0;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3321_29_< line 3321 in _parallel_resolve_hosts()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3321 in _parallel_resolve_hosts() to detect the mutant
    fail('NUM_BOUNDARY_3321_29_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3348_2 (MEDIUM) line 3348 in _extract_http_urls() ---
# Source:  if ($HAS_HTML_LINKEXTOR) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3348_2 line 3348 in _extract_http_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3348 in _extract_http_urls() to detect the mutant
    fail('COND_INV_3348_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3353_5 (MEDIUM) line 3353 in _extract_http_urls() ---
# Source:  if ($val =~ m{^https?://}i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3353_5 line 3353 in _extract_http_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3353 in _extract_http_urls() to detect the mutant
    fail('COND_INV_3353_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3378_2 (MEDIUM) line 3378 in _extract_http_urls() ---
# Source:  return @all;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3378_2 line 3378 in _extract_http_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3378 in _extract_http_urls() to detect the mutant
    fail('BOOL_NEGATE_3378_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3457_2 (MEDIUM) line 3457 in _extract_and_analyse_domains() ---
# Source:  if ($mid && $mid =~ /\@([\w.-]+)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3457_2 line 3457 in _extract_and_analyse_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3457 in _extract_and_analyse_domains() to detect the mutant
    fail('COND_INV_3457_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3472_2 (MEDIUM) line 3472 in _extract_and_analyse_domains() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3472_2 line 3472 in _extract_and_analyse_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3472 in _extract_and_analyse_domains() to detect the mutant
    fail('COND_INV_3472_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3522_2 (MEDIUM) line 3522 in _domains_from_text() ---
# Source:  return @out;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3522_2 line 3522 in _domains_from_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3522 in _domains_from_text() to detect the mutant
    fail('BOOL_NEGATE_3522_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3556_2 (MEDIUM) line 3556 in _analyse_domain() ---
# Source:  return $self->{_domain_info}{$domain}
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3556_2 line 3556 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3556 in _analyse_domain() to detect the mutant
    fail('BOOL_NEGATE_3556_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3560_2 (MEDIUM) line 3560 in _analyse_domain() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3560_2 line 3560 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3560 in _analyse_domain() to detect the mutant
    fail('COND_INV_3560_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3562_3 (MEDIUM) line 3562 in _analyse_domain() ---
# Source:  if ($cached) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3562_3 line 3562 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3562 in _analyse_domain() to detect the mutant
    fail('COND_INV_3562_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3564_4 (MEDIUM) line 3564 in _analyse_domain() ---
# Source:  return $cached;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3564_4 line 3564 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3564 in _analyse_domain() to detect the mutant
    fail('BOOL_NEGATE_3564_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3573_2 (MEDIUM) line 3573 in _analyse_domain() ---
# Source:  if ($web_ip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3573_2 line 3573 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3573 in _analyse_domain() to detect the mutant
    fail('COND_INV_3573_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3581_2 (MEDIUM) line 3581 in _analyse_domain() ---
# Source:  if ($HAS_NET_DNS) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3581_2 line 3581 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3581 in _analyse_domain() to detect the mutant
    fail('COND_INV_3581_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3589_3 (MEDIUM) line 3589 in _analyse_domain() ---
# Source:  if ($mxq) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3589_3 line 3589 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3589 in _analyse_domain() to detect the mutant
    fail('COND_INV_3589_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3592_4 (MEDIUM) line 3592 in _analyse_domain() ---
# Source:  if ($best) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3592_4 line 3592 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3592 in _analyse_domain() to detect the mutant
    fail('COND_INV_3592_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3596_5 (MEDIUM) line 3596 in _analyse_domain() ---
# Source:  if ($mx_ip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3596_5 line 3596 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3596 in _analyse_domain() to detect the mutant
    fail('COND_INV_3596_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3607_3 (MEDIUM) line 3607 in _analyse_domain() ---
# Source:  if ($nsq) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3607_3 line 3607 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3607 in _analyse_domain() to detect the mutant
    fail('COND_INV_3607_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3612_4 (MEDIUM) line 3612 in _analyse_domain() ---
# Source:  if ($first) {
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
# Source:  if ($ns_ip) {
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

# --- SURVIVOR: COND_INV_3628_2 (MEDIUM) line 3628 in _analyse_domain() ---
# Source:  if ($domain_whois) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3628_2 line 3628 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3628 in _analyse_domain() to detect the mutant
    fail('COND_INV_3628_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3633_3 (MEDIUM) line 3633 in _analyse_domain() ---
# Source:  if ($domain_whois =~ /Registrar:\s*(.+)/i) {
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

# --- SURVIVOR: COND_INV_3643_4 (MEDIUM) line 3643 in _analyse_domain() ---
# Source:  if (!$info{registrar_abuse} && $domain_whois =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3643_4 line 3643 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3643 in _analyse_domain() to detect the mutant
    fail('COND_INV_3643_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3655_4 (MEDIUM) line 3655 in _analyse_domain() ---
# Source:  if (!$info{registered} && $domain_whois =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3655_4 line 3655 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3655 in _analyse_domain() to detect the mutant
    fail('COND_INV_3655_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3666_4 (MEDIUM) line 3666 in _analyse_domain() ---
# Source:  if (!$info{expires} && $domain_whois =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3666_4 line 3666 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3666 in _analyse_domain() to detect the mutant
    fail('COND_INV_3666_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3672_3 (MEDIUM) line 3672 in _analyse_domain() ---
# Source:  if ($info{registered}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3672_3 line 3672 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3672 in _analyse_domain() to detect the mutant
    fail('COND_INV_3672_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3675_36_> (HIGH) line 3675 in _analyse_domain() ---
# Source:  if $epoch && (time() - $epoch) < $RECENT_REG_DAYS * $SECS_PER_DAY;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip < to >
#   Numeric boundary flip < to <=
#   Numeric boundary flip < to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3675_36_> line 3675 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3675 in _analyse_domain() to detect the mutant
    fail('NUM_BOUNDARY_3675_36_>: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3709_2 (MEDIUM) line 3709 in _resolve_host() ---
# Source:  return $host if $host =~ /^\d{1,3}(?:\.\d{1,3}){3}$/;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3709_2 line 3709 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3709 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_3709_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3712_2 (MEDIUM) line 3712 in _resolve_host() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3712_2 line 3712 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3712 in _resolve_host() to detect the mutant
    fail('COND_INV_3712_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3714_3 (MEDIUM) line 3714 in _resolve_host() ---
# Source:  return $cached_ip if defined $cached_ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3714_3 line 3714 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3714 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_3714_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3719_2 (MEDIUM) line 3719 in _resolve_host() ---
# Source:  if ($HAS_NET_DNS) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3719_2 line 3719 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3719 in _resolve_host() to detect the mutant
    fail('COND_INV_3719_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3728_4 (MEDIUM) line 3728 in _resolve_host() ---
# Source:  if ($query) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3728_4 line 3728 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3728 in _resolve_host() to detect the mutant
    fail('COND_INV_3728_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3730_6 (MEDIUM) line 3730 in _resolve_host() ---
# Source:  if ($rr->type eq 'A') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3730_6 line 3730 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3730 in _resolve_host() to detect the mutant
    fail('COND_INV_3730_6: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3748_2 (MEDIUM) line 3748 in _resolve_host() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3748_2 line 3748 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3748 in _resolve_host() to detect the mutant
    fail('COND_INV_3748_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3752_2 (MEDIUM) line 3752 in _resolve_host() ---
# Source:  return $ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3752_2 line 3752 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3752 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_3752_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3771_2 (MEDIUM) line 3771 in _reverse_dns() ---
# Source:  if ($HAS_NET_DNS) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3771_2 line 3771 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3771 in _reverse_dns() to detect the mutant
    fail('COND_INV_3771_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3774_3 (MEDIUM) line 3774 in _reverse_dns() ---
# Source:  if ($query) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3774_3 line 3774 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3774 in _reverse_dns() to detect the mutant
    fail('COND_INV_3774_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3776_5 (MEDIUM) line 3776 in _reverse_dns() ---
# Source:  return $rr->ptrdname if $rr->type eq 'PTR';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3776_5 line 3776 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3776 in _reverse_dns() to detect the mutant
    fail('BOOL_NEGATE_3776_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3807_2 (MEDIUM) line 3807 in _whois_ip() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3807_2 line 3807 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3807 in _whois_ip() to detect the mutant
    fail('COND_INV_3807_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3809_3 (MEDIUM) line 3809 in _whois_ip() ---
# Source:  return $cached if $cached;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3809_3 line 3809 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3809 in _whois_ip() to detect the mutant
    fail('BOOL_NEGATE_3809_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3815_2 (MEDIUM) line 3815 in _whois_ip() ---
# Source:  unless ($result->{org}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_3815_2 line 3815 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3815 in _whois_ip() to detect the mutant
    fail('COND_INV_3815_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3817_3 (MEDIUM) line 3817 in _whois_ip() ---
# Source:  if ($raw) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3817_3 line 3817 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3817 in _whois_ip() to detect the mutant
    fail('COND_INV_3817_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3827_2 (MEDIUM) line 3827 in _whois_ip() ---
# Source:  return $result;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3827_2 line 3827 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3827 in _whois_ip() to detect the mutant
    fail('BOOL_NEGATE_3827_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3847_2 (MEDIUM) line 3847 in _domain_whois() ---
# Source:  return $self->_raw_whois($domain, $server);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3847_2 line 3847 in _domain_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3847 in _domain_whois() to detect the mutant
    fail('BOOL_NEGATE_3847_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3867_2 (MEDIUM) line 3867 in _parse_domain_whois_abuse() ---
# Source:  if ($raw =~ /Registrar:\s*(.+)/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3867_2 line 3867 in _parse_domain_whois_abuse()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3867 in _parse_domain_whois_abuse() to detect the mutant
    fail('COND_INV_3867_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3876_3 (MEDIUM) line 3876 in _parse_domain_whois_abuse() ---
# Source:  if (!$info{abuse} && $raw =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3876_3 line 3876 in _parse_domain_whois_abuse()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3876 in _parse_domain_whois_abuse() to detect the mutant
    fail('COND_INV_3876_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3901_2 (MEDIUM) line 3901 in _rdap_lookup() ---
# Source:  if(!defined($ua)) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3901_2 line 3901 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3901 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3901_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3907_3 (MEDIUM) line 3907 in _rdap_lookup() ---
# Source:  if($HAS_CONN_CACHE) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3907_3 line 3907 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3907 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3907_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3926_2 (MEDIUM) line 3926 in _rdap_lookup() ---
# Source:  if ($j =~ /"name"\s*:\s*"([^"]+)"/)   { $info{org}    = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3926_2 line 3926 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3926 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3926_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3927_2 (MEDIUM) line 3927 in _rdap_lookup() ---
# Source:  if ($j =~ /"handle"\s*:\s*"([^"]+)"/) { $info{handle} = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3927_2 line 3927 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3927 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3927_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3937_2 (MEDIUM) line 3937 in _rdap_lookup() ---
# Source:  if ($j =~ /"country"\s*:\s*"([A-Z]{2})"/) { $info{country} = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3937_2 line 3937 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3937 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3937_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3997_31_< (HIGH) line 3997 in _raw_whois() ---
# Source:  if ($@ || !defined $n || $n <= 0) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3997_31_< line 3997 in _raw_whois()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3997 in _raw_whois() to detect the mutant
    fail('NUM_BOUNDARY_3997_31_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4001_30_< (HIGH) line 4001 in _raw_whois() ---
# Source:  last if !defined($n) || $n <= 0;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4001_30_< line 4001 in _raw_whois()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4001 in _raw_whois() to detect the mutant
    fail('NUM_BOUNDARY_4001_30_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4006_2 (MEDIUM) line 4006 in _raw_whois() ---
# Source:  return $response || undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4006_2 line 4006 in _raw_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4006 in _raw_whois() to detect the mutant
    fail('BOOL_NEGATE_4006_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4031_3 (MEDIUM) line 4031 in _parse_whois_text() ---
# Source:  if (!$info{org} && $text =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4031_3 line 4031 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4031 in _parse_whois_text() to detect the mutant
    fail('COND_INV_4031_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4041_3 (MEDIUM) line 4041 in _parse_whois_text() ---
# Source:  if (!$info{abuse} && $text =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4041_3 line 4041 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4041 in _parse_whois_text() to detect the mutant
    fail('COND_INV_4041_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4047_2 (MEDIUM) line 4047 in _parse_whois_text() ---
# Source:  if (!$info{abuse} && $text =~ /(abuse\@[\w.-]+)/i) { $info{abuse} = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4047_2 line 4047 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4047 in _parse_whois_text() to detect the mutant
    fail('COND_INV_4047_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4050_2 (MEDIUM) line 4050 in _parse_whois_text() ---
# Source:  if ($text =~ /^country:\s*([A-Za-z]{2})\s*$/m) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4050_2 line 4050 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4050 in _parse_whois_text() to detect the mutant
    fail('COND_INV_4050_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4076_2 (MEDIUM) line 4076 in _parse_auth_results_cached() ---
# Source:  return $self->{_auth_results} if $self->{_auth_results};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4076_2 line 4076 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4076 in _parse_auth_results_cached() to detect the mutant
    fail('BOOL_NEGATE_4076_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4088_2 (MEDIUM) line 4088 in _parse_auth_results_cached() ---
# Source:  if ($raw =~ /\bspf=(\S+)/i)   { $auth{spf}   = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4088_2 line 4088 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4088 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_4088_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4089_2 (MEDIUM) line 4089 in _parse_auth_results_cached() ---
# Source:  if ($raw =~ /\bdkim=(\S+)/i)  { $auth{dkim}  = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4089_2 line 4089 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4089 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_4089_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4090_2 (MEDIUM) line 4090 in _parse_auth_results_cached() ---
# Source:  if ($raw =~ /\bdmarc=(\S+)/i) { $auth{dmarc} = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4090_2 line 4090 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4090 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_4090_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4091_2 (MEDIUM) line 4091 in _parse_auth_results_cached() ---
# Source:  if ($raw =~ /\barc=(\S+)/i)   { $auth{arc}   = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4091_2 line 4091 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4091 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_4091_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4102_3 (MEDIUM) line 4102 in _parse_auth_results_cached() ---
# Source:  if ($h->{value} =~ /\bd=([^;,\s]+)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4102_3 line 4102 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4102 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_4102_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4107_2 (MEDIUM) line 4107 in _parse_auth_results_cached() ---
# Source:  if (@dkim_domains) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4107_2 line 4107 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4107 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_4107_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4111_4 (MEDIUM) line 4111 in _parse_auth_results_cached() ---
# Source:  if ($self->_provider_abuse_for_host($d)) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4111_4 line 4111 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4111 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_4111_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4145_3 (MEDIUM) line 4145 in _provider_abuse_for_host() ---
# Source:  return $self->{provider_abuse}->{$host} if $self->{provider_abuse}->{$host};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4145_3 line 4145 in _provider_abuse_for_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4145 in _provider_abuse_for_host() to detect the mutant
    fail('BOOL_NEGATE_4145_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4167_2 (MEDIUM) line 4167 in _provider_abuse_for_ip() ---
# Source:  return $self->_provider_abuse_for_host($rdns) if $rdns;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4167_2 line 4167 in _provider_abuse_for_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4167 in _provider_abuse_for_ip() to detect the mutant
    fail('BOOL_NEGATE_4167_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4198_2 (MEDIUM) line 4198 in _registrable() ---
# Source:  if ($HAS_PUBLIC_SUFFIX) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4198_2 line 4198 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4198 in _registrable() to detect the mutant
    fail('COND_INV_4198_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4201_3 (MEDIUM) line 4201 in _registrable() ---
# Source:  return $root if $root;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4201_3 line 4201 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4201 in _registrable() to detect the mutant
    fail('BOOL_NEGATE_4201_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4206_26_< (HIGH) line 4206 in _registrable() ---
# Source:  return $host if @labels <= 2;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4206_26_< line 4206 in _registrable()';
    # Suggested boundary values to test: 1, 2, 3
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4206 in _registrable() to detect the mutant
    fail('NUM_BOUNDARY_4206_26_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4209_2 (MEDIUM) line 4209 in _registrable() ---
# Source:  if ($labels[-1] =~ /^[a-z]{2}$/ &&
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4209_2 line 4209 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4209 in _registrable() to detect the mutant
    fail('COND_INV_4209_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4312_2 (MEDIUM) line 4312 in header_value() ---
# Source:  return $self->_header_value($name);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4312_2 line 4312 in header_value()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4312 in header_value() to detect the mutant
    fail('BOOL_NEGATE_4312_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4332_3 (MEDIUM) line 4332 in _header_value() ---
# Source:  return $h->{value} if $h->{name} eq lc($name);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4332_3 line 4332 in _header_value()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4332 in _header_value() to detect the mutant
    fail('BOOL_NEGATE_4332_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4352_2 (MEDIUM) line 4352 in _ip_in_cidr() ---
# Source:  return $ip eq $cidr unless $cidr =~ m{/};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4352_2 line 4352 in _ip_in_cidr()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4352 in _ip_in_cidr() to detect the mutant
    fail('BOOL_NEGATE_4352_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4354_65_< (HIGH) line 4354 in _ip_in_cidr() ---
# Source:  return 0 if !defined($prefix) || $prefix !~ /^\d+$/ || $prefix > 32;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4354_65_< line 4354 in _ip_in_cidr()';
    # Suggested boundary values to test: 31, 32, 33
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4354 in _ip_in_cidr() to detect the mutant
    fail('NUM_BOUNDARY_4354_65_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4360_25_!= (HIGH) line 4360 in _ip_in_cidr() ---
# Source:  return ($ip_n & $mask) == ($net_n & $mask);
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (1 variant):
#   Numeric boundary flip == to !=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4360_25_!= line 4360 in _ip_in_cidr()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4360 in _ip_in_cidr() to detect the mutant
    fail('NUM_BOUNDARY_4360_25_!=: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4377_2 (MEDIUM) line 4377 in _decode_mime_words() ---
# Source:  return '' unless defined $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4377_2 line 4377 in _decode_mime_words()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4377 in _decode_mime_words() to detect the mutant
    fail('BOOL_NEGATE_4377_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4380_2 (MEDIUM) line 4380 in _decode_mime_words() ---
# Source:  return $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4380_2 line 4380 in _decode_mime_words()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4380 in _decode_mime_words() to detect the mutant
    fail('BOOL_NEGATE_4380_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4395_2 (MEDIUM) line 4395 in _decode_ew() ---
# Source:  if (uc($enc) eq 'B') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4395_2 line 4395 in _decode_ew()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4395 in _decode_ew() to detect the mutant
    fail('COND_INV_4395_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4402_2 (MEDIUM) line 4402 in _decode_ew() ---
# Source:  return $raw;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4402_2 line 4402 in _decode_ew()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4402 in _decode_ew() to detect the mutant
    fail('BOOL_NEGATE_4402_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4425_2 (MEDIUM) line 4425 in _parse_date_to_epoch() ---
# Source:  if ($str =~ /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?Z$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4425_2 line 4425 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4425 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_4425_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4437_4 (MEDIUM) line 4437 in _parse_date_to_epoch() ---
# Source:  return $t->epoch - $t->tzoffset->seconds;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4437_4 line 4437 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4437 in _parse_date_to_epoch() to detect the mutant
    fail('BOOL_NEGATE_4437_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4439_3 (MEDIUM) line 4439 in _parse_date_to_epoch() ---
# Source:  return $epoch if defined $epoch;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4439_3 line 4439 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4439 in _parse_date_to_epoch() to detect the mutant
    fail('BOOL_NEGATE_4439_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4443_2 (MEDIUM) line 4443 in _parse_date_to_epoch() ---
# Source:  if    ($str =~ /^(\d{4})-(\d{2})-(\d{2})/)         { ($y,$m,$d)=($1,$2,$3) }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4443_2 line 4443 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4443 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_4443_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4449_2 (MEDIUM) line 4449 in _parse_date_to_epoch() ---
# Source:  if (eval { require Time::Local; 1 }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4449_2 line 4449 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4449 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_4449_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4475_2 (MEDIUM) line 4475 in _parse_rfc2822_date() ---
# Source:  if ($str =~ /(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4475_2 line 4475 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4475 in _parse_rfc2822_date() to detect the mutant
    fail('COND_INV_4475_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4479_3 (MEDIUM) line 4479 in _parse_rfc2822_date() ---
# Source:  if (eval { require Time::Local; 1 }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4479_3 line 4479 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4479 in _parse_rfc2822_date() to detect the mutant
    fail('COND_INV_4479_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4523_2 (MEDIUM) line 4523 in _debug() ---
# Source:  if($self->{verbose}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4523_2 line 4523 in _debug()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4523 in _debug() to detect the mutant
    fail('COND_INV_4523_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4524_3 (MEDIUM) line 4524 in _debug() ---
# Source:  if (my $logger = $self->{logger}) { # Set via Object::Configure
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4524_3 line 4524 in _debug()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4524 in _debug() to detect the mutant
    fail('COND_INV_4524_3: replace with real assertion');
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

# --- LOW HINT: RETURN_UNDEF_2182_2 line 2182 in _compute_abuse_contacts() ---
# Source:  return @contacts;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2182_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2390_2 line 2390 in form_contacts() ---
# Source:  return @contacts;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2390_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2688_2 line 2688 in _sanitise_output() ---
# Source:  return '' unless defined $str;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2688_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2691_2 line 2691 in _sanitise_output() ---
# Source:  return $str;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2691_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2909_2 line 2909 in _decode_body() ---
# Source:  return $body // '';
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2909_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2957_4 line 2957 in _find_origin() ---
# Source:  return $self->_enrich_ip($xoip, 'low',
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2957_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2965_2 line 2965 in _find_origin() ---
# Source:  return $self->_enrich_ip(
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2965_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2996_4 line 2996 in _extract_ip_from_received() ---
# Source:  return $ip if $ip =~ /:/;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2996_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3001_4 line 3001 in _extract_ip_from_received() ---
# Source:  return $ip;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3001_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3026_2 line 3026 in _is_private() ---
# Source:  return 1 if !defined($ip) || $ip eq '';
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3026_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3027_33 line 3027 in _is_private() ---
# Source:  for my $re (@PRIVATE_RANGES) { return 1 if $ip =~ $re }
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3027_33: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3028_2 line 3028 in _is_private() ---
# Source:  return 0;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3028_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3047_3 line 3047 in _is_trusted() ---
# Source:  return 1 if $self->_ip_in_cidr($ip, $cidr);
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3047_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3049_2 line 3049 in _is_trusted() ---
# Source:  return 0;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3049_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3171_2 line 3171 in _is_redirect_cloaker() ---
# Source:  return 1 if $REDIRECT_HOSTS{$host};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3171_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3173_3 line 3173 in _is_redirect_cloaker() ---
# Source:  return 1 if length($host) > length($suffix)
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3173_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3176_2 line 3176 in _is_redirect_cloaker() ---
# Source:  return '';
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3176_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3207_2 line 3207 in _follow_redirect_chain() ---
# Source:  return undef unless $HAS_LWP;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3207_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3212_3 line 3212 in _follow_redirect_chain() ---
# Source:  return $cached if defined $cached;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3212_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3280_2 line 3280 in _follow_redirect_chain() ---
# Source:  return $final;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3280_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3378_2 line 3378 in _extract_http_urls() ---
# Source:  return @all;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3378_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3522_2 line 3522 in _domains_from_text() ---
# Source:  return @out;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3522_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3556_2 line 3556 in _analyse_domain() ---
# Source:  return $self->{_domain_info}{$domain}
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3556_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3564_4 line 3564 in _analyse_domain() ---
# Source:  return $cached;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3564_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3709_2 line 3709 in _resolve_host() ---
# Source:  return $host if $host =~ /^\d{1,3}(?:\.\d{1,3}){3}$/;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3709_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3714_3 line 3714 in _resolve_host() ---
# Source:  return $cached_ip if defined $cached_ip;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3714_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3752_2 line 3752 in _resolve_host() ---
# Source:  return $ip;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3752_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3776_5 line 3776 in _reverse_dns() ---
# Source:  return $rr->ptrdname if $rr->type eq 'PTR';
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3776_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3809_3 line 3809 in _whois_ip() ---
# Source:  return $cached if $cached;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3809_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3827_2 line 3827 in _whois_ip() ---
# Source:  return $result;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3827_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3847_2 line 3847 in _domain_whois() ---
# Source:  return $self->_raw_whois($domain, $server);
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3847_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4006_2 line 4006 in _raw_whois() ---
# Source:  return $response || undef;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4006_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4076_2 line 4076 in _parse_auth_results_cached() ---
# Source:  return $self->{_auth_results} if $self->{_auth_results};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4076_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4145_3 line 4145 in _provider_abuse_for_host() ---
# Source:  return $self->{provider_abuse}->{$host} if $self->{provider_abuse}->{$host};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4145_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4167_2 line 4167 in _provider_abuse_for_ip() ---
# Source:  return $self->_provider_abuse_for_host($rdns) if $rdns;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4167_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4201_3 line 4201 in _registrable() ---
# Source:  return $root if $root;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4201_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4206_2 line 4206 in _registrable() ---
# Source:  return $host if @labels <= 2;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4206_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4312_2 line 4312 in header_value() ---
# Source:  return $self->_header_value($name);
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4312_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4332_3 line 4332 in _header_value() ---
# Source:  return $h->{value} if $h->{name} eq lc($name);
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4332_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4352_2 line 4352 in _ip_in_cidr() ---
# Source:  return $ip eq $cidr unless $cidr =~ m{/};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4352_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4354_2 line 4354 in _ip_in_cidr() ---
# Source:  return 0 if !defined($prefix) || $prefix !~ /^\d+$/ || $prefix > 32;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4354_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4377_2 line 4377 in _decode_mime_words() ---
# Source:  return '' unless defined $str;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4377_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4380_2 line 4380 in _decode_mime_words() ---
# Source:  return $str;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4380_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4402_2 line 4402 in _decode_ew() ---
# Source:  return $raw;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4402_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4437_4 line 4437 in _parse_date_to_epoch() ---
# Source:  return $t->epoch - $t->tzoffset->seconds;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4437_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4439_3 line 4439 in _parse_date_to_epoch() ---
# Source:  return $epoch if defined $epoch;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4439_3: add assertion here');

done_testing();
