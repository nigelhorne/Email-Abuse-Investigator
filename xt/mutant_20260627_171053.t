#!/usr/bin/env perl
# Auto-generated mutant test stubs
# Generated: 2026-06-27 17:10:53
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

# --- SURVIVOR: BOOL_NEGATE_634_2 (MEDIUM) line 634 in new() ---
# Source:  return bless {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_634_2 line 634 in new()';
    # NOTE: new is a class method — call directly.
    my $result = Email::Abuse::Investigator->new(...);
    # ok($result, 'BOOL_NEGATE_634_2: add assertion here');
    # TODO: exercise line 634 in new() to detect the mutant
    fail('BOOL_NEGATE_634_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_770_2 (MEDIUM) line 770 in parse_email() ---
# Source:  return $self;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_770_2 line 770 in parse_email()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 770 in parse_email() to detect the mutant
    fail('BOOL_NEGATE_770_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_845_2 (MEDIUM) line 845 in originating_ip() ---
# Source:  return $self->{_origin};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_845_2 line 845 in originating_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 845 in originating_ip() to detect the mutant
    fail('BOOL_NEGATE_845_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_932_2 (MEDIUM) line 932 in embedded_urls() ---
# Source:  return @{ $self->{_urls} };
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_932_2 line 932 in embedded_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 932 in embedded_urls() to detect the mutant
    fail('BOOL_NEGATE_932_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1003_2 (MEDIUM) line 1003 in mailto_domains() ---
# Source:  return @{ $self->{_mailto_domains} };
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1003_2 line 1003 in mailto_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1003 in mailto_domains() to detect the mutant
    fail('BOOL_NEGATE_1003_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1067_2 (MEDIUM) line 1067 in all_domains() ---
# Source:  return @out;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1067_2 line 1067 in all_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1067 in all_domains() to detect the mutant
    fail('BOOL_NEGATE_1067_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1132_3 (MEDIUM) line 1132 in unresolved_contacts() ---
# Source:  unless ($dom) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_1132_3 line 1132 in unresolved_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1132 in unresolved_contacts() to detect the mutant
    fail('COND_INV_1132_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1173_2 (MEDIUM) line 1173 in unresolved_contacts() ---
# Source:  return @out;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1173_2 line 1173 in unresolved_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1173 in unresolved_contacts() to detect the mutant
    fail('BOOL_NEGATE_1173_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1239_2 (MEDIUM) line 1239 in sending_software() ---
# Source:  return @{ $self->{_sending_sw} };
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1239_2 line 1239 in sending_software()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1239 in sending_software() to detect the mutant
    fail('BOOL_NEGATE_1239_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1307_2 (MEDIUM) line 1307 in received_trail() ---
# Source:  return @{ $self->{_rcvd_tracking} };
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1307_2 line 1307 in received_trail()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1307 in received_trail() to detect the mutant
    fail('BOOL_NEGATE_1307_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1374_2 (MEDIUM) line 1374 in risk_assessment() ---
# Source:  return $self->{_risk} if $self->{_risk};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1374_2 line 1374 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1374 in risk_assessment() to detect the mutant
    fail('BOOL_NEGATE_1374_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1393_21_> (HIGH) line 1393 in risk_assessment() ---
# Source:  my $level = $score >= $SCORE_HIGH   ? 'HIGH'
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1393_21_> line 1393 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1393 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1393_21_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1394_21_> (HIGH) line 1394 in risk_assessment() ---
# Source:  : $score >= $SCORE_MEDIUM ? 'MEDIUM'
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
# Source:  : $score >= $SCORE_LOW    ? 'LOW'
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

# --- SURVIVOR: BOOL_NEGATE_1399_2 (MEDIUM) line 1399 in risk_assessment() ---
# Source:  return $self->{_risk};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1399_2 line 1399 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1399 in risk_assessment() to detect the mutant
    fail('BOOL_NEGATE_1399_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1422_2 (MEDIUM) line 1422 in _risk_check_origin() ---
# Source:  if ($orig->{rdns} && $orig->{rdns} =~ /
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1422_2 line 1422 in _risk_check_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1422 in _risk_check_origin() to detect the mutant
    fail('COND_INV_1422_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1433_2 (MEDIUM) line 1433 in _risk_check_origin() ---
# Source:  if (!$orig->{rdns} || $orig->{rdns} eq '(no reverse DNS)') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1433_2 line 1433 in _risk_check_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1433 in _risk_check_origin() to detect the mutant
    fail('COND_INV_1433_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1439_2 (MEDIUM) line 1439 in _risk_check_origin() ---
# Source:  if ($orig->{confidence} eq 'low') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1439_2 line 1439 in _risk_check_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1439 in _risk_check_origin() to detect the mutant
    fail('COND_INV_1439_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1445_2 (MEDIUM) line 1445 in _risk_check_origin() ---
# Source:  if ($orig->{country} && $orig->{country} =~ /^(?:CN|RU|NG|VN|IN|PK|BD)$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1445_2 line 1445 in _risk_check_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1445 in _risk_check_origin() to detect the mutant
    fail('COND_INV_1445_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1467_2 (MEDIUM) line 1467 in _risk_check_auth() ---
# Source:  if (defined $auth->{spf}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1467_2 line 1467 in _risk_check_auth()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1467 in _risk_check_auth() to detect the mutant
    fail('COND_INV_1467_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1468_3 (MEDIUM) line 1468 in _risk_check_auth() ---
# Source:  if ($auth->{spf} =~ /^fail/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1468_3 line 1468 in _risk_check_auth()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1468 in _risk_check_auth() to detect the mutant
    fail('COND_INV_1468_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1479_2 (MEDIUM) line 1479 in _risk_check_auth() ---
# Source:  if (defined $auth->{dkim} && $auth->{dkim} !~ /^pass/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1479_2 line 1479 in _risk_check_auth()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1479 in _risk_check_auth() to detect the mutant
    fail('COND_INV_1479_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1483_2 (MEDIUM) line 1483 in _risk_check_auth() ---
# Source:  if (defined $auth->{dmarc} && $auth->{dmarc} !~ /^pass/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1483_2 line 1483 in _risk_check_auth()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1483 in _risk_check_auth() to detect the mutant
    fail('COND_INV_1483_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1496_2 (MEDIUM) line 1496 in _risk_check_auth() ---
# Source:  if ($auth->{dkim} && $auth->{dkim} =~ /^pass/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1496_2 line 1496 in _risk_check_auth()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1496 in _risk_check_auth() to detect the mutant
    fail('COND_INV_1496_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1524_2 (MEDIUM) line 1524 in _risk_check_date() ---
# Source:  if (!$date_raw || $date_raw !~ /\S/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1524_2 line 1524 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1524 in _risk_check_date() to detect the mutant
    fail('COND_INV_1524_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1531_2 (MEDIUM) line 1531 in _risk_check_date() ---
# Source:  if ($date_raw =~ /([+-])(\d{2})(\d{2})\s*$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1531_2 line 1531 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1531 in _risk_check_date() to detect the mutant
    fail('COND_INV_1531_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1534_25_> (HIGH) line 1534 in _risk_check_date() ---
# Source:  my $implausible = $mm >= 60
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1534_25_> line 1534 in _risk_check_date()';
    # Suggested boundary values to test: 59, 60, 61
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1534 in _risk_check_date() to detect the mutant
    fail('NUM_BOUNDARY_1534_25_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1535_37_< (HIGH) line 1535 in _risk_check_date() ---
# Source:  || ($sign eq '+' && $offset_mins > $TZ_MAX_POS_MINS)
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

# --- SURVIVOR: NUM_BOUNDARY_1536_37_< (HIGH) line 1536 in _risk_check_date() ---
# Source:  || ($sign eq '-' && $offset_mins > $TZ_MAX_NEG_MINS);
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1536_37_< line 1536 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1536 in _risk_check_date() to detect the mutant
    fail('NUM_BOUNDARY_1536_37_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1537_3 (MEDIUM) line 1537 in _risk_check_date() ---
# Source:  if ($implausible) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1537_3 line 1537 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1537 in _risk_check_date() to detect the mutant
    fail('COND_INV_1537_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1548_13_< (HIGH) line 1548 in _risk_check_date() ---
# Source:  if ($delta > $DATE_SKEW_DAYS * $SECS_PER_DAY) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1548_13_< line 1548 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1548 in _risk_check_date() to detect the mutant
    fail('NUM_BOUNDARY_1548_13_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1551_18_> (HIGH) line 1551 in _risk_check_date() ---
# Source:  } elsif ($delta < -($DATE_SKEW_DAYS * $SECS_PER_DAY)) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip < to >
#   Numeric boundary flip < to <=
#   Numeric boundary flip < to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1551_18_> line 1551 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1551 in _risk_check_date() to detect the mutant
    fail('NUM_BOUNDARY_1551_18_>: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1575_2 (MEDIUM) line 1575 in _risk_check_identity() ---
# Source:  if ($from_decoded =~ /^"?([^"<]+?)"?\s*<([^>]+)>/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1575_2 line 1575 in _risk_check_identity()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1575 in _risk_check_identity() to detect the mutant
    fail('COND_INV_1575_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1583_4 (MEDIUM) line 1583 in _risk_check_identity() ---
# Source:  if ($reg_disp && $reg_addr && $reg_disp ne $reg_addr) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1583_4 line 1583 in _risk_check_identity()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1583 in _risk_check_identity() to detect the mutant
    fail('COND_INV_1583_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1591_2 (MEDIUM) line 1591 in _risk_check_identity() ---
# Source:  if ($from_raw =~ /\@(gmail|yahoo|hotmail|outlook|live|aol|protonmail|yandex)\./i
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1591_2 line 1591 in _risk_check_identity()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1591 in _risk_check_identity() to detect the mutant
    fail('COND_INV_1591_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1599_2 (MEDIUM) line 1599 in _risk_check_identity() ---
# Source:  if ($reply_to) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1599_2 line 1599 in _risk_check_identity()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1599 in _risk_check_identity() to detect the mutant
    fail('COND_INV_1599_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1602_3 (MEDIUM) line 1602 in _risk_check_identity() ---
# Source:  if ($from_addr && $reply_addr && lc($from_addr) ne lc($reply_addr)) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1602_3 line 1602 in _risk_check_identity()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1602 in _risk_check_identity() to detect the mutant
    fail('COND_INV_1602_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1610_2 (MEDIUM) line 1610 in _risk_check_identity() ---
# Source:  if ($to =~ /undisclosed|:;/ || $to eq '') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1610_2 line 1610 in _risk_check_identity()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1610 in _risk_check_identity() to detect the mutant
    fail('COND_INV_1610_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1617_2 (MEDIUM) line 1617 in _risk_check_identity() ---
# Source:  if ($subj_raw =~ /=\?[^?]+\?[BQ]\?/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1617_2 line 1617 in _risk_check_identity()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1617 in _risk_check_identity() to detect the mutant
    fail('COND_INV_1617_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1650_3 (MEDIUM) line 1650 in _risk_check_urls_and_domains() ---
# Source:  if(($URL_SHORTENERS{$bare} || $self->{url_shorteners}->{$bare}) && !$shortener_seen{$bare}++) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1650_3 line 1650 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1650 in _risk_check_urls_and_domains() to detect the mutant
    fail('COND_INV_1650_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1655_3 (MEDIUM) line 1655 in _risk_check_urls_and_domains() ---
# Source:  if ($self->_is_redirect_cloaker($bare) && !$cloaker_seen{$bare}++) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1655_3 line 1655 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1655 in _risk_check_urls_and_domains() to detect the mutant
    fail('COND_INV_1655_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1660_3 (MEDIUM) line 1660 in _risk_check_urls_and_domains() ---
# Source:  if ($u->{url} =~ m{^http://}i && !$url_host_seen{ $u->{host} }++) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1660_3 line 1660 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1660 in _risk_check_urls_and_domains() to detect the mutant
    fail('COND_INV_1660_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1669_3 (MEDIUM) line 1669 in _risk_check_urls_and_domains() ---
# Source:  if ($d->{recently_registered}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1669_3 line 1669 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1669 in _risk_check_urls_and_domains() to detect the mutant
    fail('COND_INV_1669_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1675_3 (MEDIUM) line 1675 in _risk_check_urls_and_domains() ---
# Source:  if ($d->{expires}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1675_3 line 1675 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1675 in _risk_check_urls_and_domains() to detect the mutant
    fail('COND_INV_1675_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1676_4 (MEDIUM) line 1676 in _risk_check_urls_and_domains() ---
# Source:  if(my $exp = $self->_parse_date_to_epoch($d->{expires})) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1676_4 line 1676 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1676 in _risk_check_urls_and_domains() to detect the mutant
    fail('COND_INV_1676_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1679_38_> (HIGH) line 1679 in _risk_check_urls_and_domains() ---
# Source:  if ($remaining > 0 && $remaining < $EXPIRY_WARN_DAYS * $SECS_PER_DAY) {
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
    local $TODO = 'Complete: NUM_BOUNDARY_1679_38_> line 1679 in _risk_check_urls_and_domains()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1679 in _risk_check_urls_and_domains() to detect the mutant
    fail('NUM_BOUNDARY_1679_38_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1682_25_< (HIGH) line 1682 in _risk_check_urls_and_domains() ---
# Source:  } elsif ($remaining <= 0) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1682_25_< line 1682 in _risk_check_urls_and_domains()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1682 in _risk_check_urls_and_domains() to detect the mutant
    fail('NUM_BOUNDARY_1682_25_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1692_4 (MEDIUM) line 1692 in _risk_check_urls_and_domains() ---
# Source:  if ($d->{domain} =~ /\Q$brand\E/i &&
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1692_4 line 1692 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1692 in _risk_check_urls_and_domains() to detect the mutant
    fail('COND_INV_1692_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1768_2 (MEDIUM) line 1768 in abuse_report_text() ---
# Source:  if (@{ $risk->{flags} }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1768_2 line 1768 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1768 in abuse_report_text() to detect the mutant
    fail('COND_INV_1768_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1778_2 (MEDIUM) line 1778 in abuse_report_text() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1778_2 line 1778 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1778 in abuse_report_text() to detect the mutant
    fail('COND_INV_1778_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1787_2 (MEDIUM) line 1787 in abuse_report_text() ---
# Source:  if (@urls) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1787_2 line 1787 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1787 in abuse_report_text() to detect the mutant
    fail('COND_INV_1787_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1802_2 (MEDIUM) line 1802 in abuse_report_text() ---
# Source:  if (@contacts) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1802_2 line 1802 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1802 in abuse_report_text() to detect the mutant
    fail('COND_INV_1802_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1809_2 (MEDIUM) line 1809 in abuse_report_text() ---
# Source:  if(my @form_cs = $self->form_contacts()) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1809_2 line 1809 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1809 in abuse_report_text() to detect the mutant
    fail('COND_INV_1809_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1832_2 (MEDIUM) line 1832 in abuse_report_text() ---
# Source:  return join("\n", @out);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1832_2 line 1832 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1832 in abuse_report_text() to detect the mutant
    fail('BOOL_NEGATE_1832_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1903_2 (MEDIUM) line 1903 in abuse_contacts() ---
# Source:  return @{ $self->{_contacts} };
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1903_2 line 1903 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1903 in abuse_contacts() to detect the mutant
    fail('BOOL_NEGATE_1903_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1930_3 (MEDIUM) line 1930 in _compute_abuse_contacts() ---
# Source:  if ($addr =~ /\@([\w.-]+)$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1930_3 line 1930 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1930 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1930_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1936_3 (MEDIUM) line 1936 in _compute_abuse_contacts() ---
# Source:  if (exists $seen_idx{$addr}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1936_3 line 1936 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1936 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1936_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1947_22_< (HIGH) line 1947 in _compute_abuse_contacts() ---
# Source:  $role_counts{$_} > 1 ? "$_ (x$role_counts{$_})" : $_
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1947_22_< line 1947 in _compute_abuse_contacts()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1947 in _compute_abuse_contacts() to detect the mutant
    fail('NUM_BOUNDARY_1947_22_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1957_24_< (HIGH) line 1957 in _compute_abuse_contacts() ---
# Source:  if (length($joined) > $ROLE_MAX_LEN) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1957_24_< line 1957 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1957 in _compute_abuse_contacts() to detect the mutant
    fail('NUM_BOUNDARY_1957_24_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1960_6 (MEDIUM) line 1960 in _compute_abuse_contacts() ---
# Source:  if ($r =~ /^URL host:\s*(.+)$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1960_6 line 1960 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1960 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1960_6: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1969_5 (MEDIUM) line 1969 in _compute_abuse_contacts() ---
# Source:  if (@url_hosts) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1969_5 line 1969 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1969 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1969_5: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1970_29_< (HIGH) line 1970 in _compute_abuse_contacts() ---
# Source:  my $extra = @url_hosts > 3
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1970_29_< line 1970 in _compute_abuse_contacts()';
    # Suggested boundary values to test: 2, 3, 4
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1970 in _compute_abuse_contacts() to detect the mutant
    fail('NUM_BOUNDARY_1970_29_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1972_29_< (HIGH) line 1972 in _compute_abuse_contacts() ---
# Source:  my @shown = @url_hosts > 3 ? @url_hosts[0..2] : @url_hosts;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1972_29_< line 1972 in _compute_abuse_contacts()';
    # Suggested boundary values to test: 2, 3, 4
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1972 in _compute_abuse_contacts() to detect the mutant
    fail('NUM_BOUNDARY_1972_29_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1990_2 (MEDIUM) line 1990 in _compute_abuse_contacts() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1990_2 line 1990 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1990 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1990_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1992_3 (MEDIUM) line 1992 in _compute_abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1992_3 line 1992 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1992 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1992_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2000_3 (MEDIUM) line 2000 in _compute_abuse_contacts() ---
# Source:  if ($orig->{abuse} && $orig->{abuse} ne '(unknown)') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2000_3 line 2000 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2000 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2000_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2020_3 (MEDIUM) line 2020 in _compute_abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2020_3 line 2020 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2020 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2020_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2028_3 (MEDIUM) line 2028 in _compute_abuse_contacts() ---
# Source:  if ($u->{abuse} && $u->{abuse} ne '(unknown)') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2028_3 line 2028 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2028 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2028_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2043_3 (MEDIUM) line 2043 in _compute_abuse_contacts() ---
# Source:  if ($d->{web_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2043_3 line 2043 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2043 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2043_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2045_4 (MEDIUM) line 2045 in _compute_abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2045_4 line 2045 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2045 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2045_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2061_3 (MEDIUM) line 2061 in _compute_abuse_contacts() ---
# Source:  if ($d->{mx_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2061_3 line 2061 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2061 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2061_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2074_3 (MEDIUM) line 2074 in _compute_abuse_contacts() ---
# Source:  if ($d->{ns_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2074_3 line 2074 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2074 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2074_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2087_3 (MEDIUM) line 2087 in _compute_abuse_contacts() ---
# Source:  if ($d->{registrar_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2087_3 line 2087 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2087 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2087_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2094_4 (MEDIUM) line 2094 in _compute_abuse_contacts() ---
# Source:  unless ($spoofable_only) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_2094_4 line 2094 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2094 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2094_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2118_3 (MEDIUM) line 2118 in _compute_abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2118_3 line 2118 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2118 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2118_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2132_2 (MEDIUM) line 2132 in _compute_abuse_contacts() ---
# Source:  if ($auth->{dkim_domain}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2132_2 line 2132 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2132 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2132_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2134_3 (MEDIUM) line 2134 in _compute_abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2134_3 line 2134 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2134 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2134_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2146_2 (MEDIUM) line 2146 in _compute_abuse_contacts() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2146_2 line 2146 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2146 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2146_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2157_4 (MEDIUM) line 2157 in _compute_abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2157_4 line 2157 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2157 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2157_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2185_2 (MEDIUM) line 2185 in _compute_abuse_contacts() ---
# Source:  return @contacts;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2185_2 line 2185 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2185 in _compute_abuse_contacts() to detect the mutant
    fail('BOOL_NEGATE_2185_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2266_2 (MEDIUM) line 2266 in form_contacts() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2266_2 line 2266 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2266 in form_contacts() to detect the mutant
    fail('COND_INV_2266_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2268_3 (MEDIUM) line 2268 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2268_3 line 2268 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2268 in form_contacts() to detect the mutant
    fail('COND_INV_2268_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2285_3 (MEDIUM) line 2285 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2285_3 line 2285 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2285 in form_contacts() to detect the mutant
    fail('COND_INV_2285_3: replace with real assertion');
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

# --- SURVIVOR: COND_INV_2315_3 (MEDIUM) line 2315 in form_contacts() ---
# Source:  if ($d->{registrar_abuse} && $d->{registrar_abuse} =~ /\@([\w.-]+)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2315_3 line 2315 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2315 in form_contacts() to detect the mutant
    fail('COND_INV_2315_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2318_4 (MEDIUM) line 2318 in form_contacts() ---
# Source:  if ($rpa && $rpa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2318_4 line 2318 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2318 in form_contacts() to detect the mutant
    fail('COND_INV_2318_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2341_3 (MEDIUM) line 2341 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2341_3 line 2341 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2341 in form_contacts() to detect the mutant
    fail('COND_INV_2341_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2357_2 (MEDIUM) line 2357 in form_contacts() ---
# Source:  if ($auth->{dkim_domain}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2357_2 line 2357 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2357 in form_contacts() to detect the mutant
    fail('COND_INV_2357_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2359_3 (MEDIUM) line 2359 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2359_3 line 2359 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2359 in form_contacts() to detect the mutant
    fail('COND_INV_2359_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2373_2 (MEDIUM) line 2373 in form_contacts() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2373_2 line 2373 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2373 in form_contacts() to detect the mutant
    fail('COND_INV_2373_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2380_4 (MEDIUM) line 2380 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2380_4 line 2380 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2380 in form_contacts() to detect the mutant
    fail('COND_INV_2380_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2393_2 (MEDIUM) line 2393 in form_contacts() ---
# Source:  return @contacts;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2393_2 line 2393 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2393 in form_contacts() to detect the mutant
    fail('BOOL_NEGATE_2393_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2474_2 (MEDIUM) line 2474 in report() ---
# Source:  if (@{ $risk->{flags} }) {
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

# --- SURVIVOR: COND_INV_2485_2 (MEDIUM) line 2485 in report() ---
# Source:  if(my $orig = $self->originating_ip()) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2485_2 line 2485 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2485 in report() to detect the mutant
    fail('COND_INV_2485_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2500_2 (MEDIUM) line 2500 in report() ---
# Source:  if (@sw) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2500_2 line 2500 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2500 in report() to detect the mutant
    fail('COND_INV_2500_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2512_2 (MEDIUM) line 2512 in report() ---
# Source:  if (@trail) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2512_2 line 2512 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2512 in report() to detect the mutant
    fail('COND_INV_2512_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2527_2 (MEDIUM) line 2527 in report() ---
# Source:  if (@urls) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2527_2 line 2527 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2527 in report() to detect the mutant
    fail('COND_INV_2527_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2532_4 (MEDIUM) line 2532 in report() ---
# Source:  unless (exists $host_order{$h}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_2532_4 line 2532 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2532 in report() to detect the mutant
    fail('COND_INV_2532_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2556_15_!= (HIGH) line 2556 in report() ---
# Source:  if (@paths == 1) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (2 variants — one test should kill all):
#   Numeric boundary flip == to !=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2556_15_!= line 2556 in report()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2556 in report() to detect the mutant
    fail('NUM_BOUNDARY_2556_15_!=: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2572_2 (MEDIUM) line 2572 in report() ---
# Source:  if (@mdoms) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2572_2 line 2572 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2572 in report() to detect the mutant
    fail('COND_INV_2572_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2576_4 (MEDIUM) line 2576 in report() ---
# Source:  if ($d->{recently_registered}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2576_4 line 2576 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2576 in report() to detect the mutant
    fail('COND_INV_2576_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2583_4 (MEDIUM) line 2583 in report() ---
# Source:  if ($d->{web_ip}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2583_4 line 2583 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2583 in report() to detect the mutant
    fail('COND_INV_2583_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2590_4 (MEDIUM) line 2590 in report() ---
# Source:  if ($d->{mx_host}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2590_4 line 2590 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2590 in report() to detect the mutant
    fail('COND_INV_2590_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2598_4 (MEDIUM) line 2598 in report() ---
# Source:  if ($d->{ns_host}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2598_4 line 2598 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2598 in report() to detect the mutant
    fail('COND_INV_2598_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2614_2 (MEDIUM) line 2614 in report() ---
# Source:  if (@contacts) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2614_2 line 2614 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2614 in report() to detect the mutant
    fail('COND_INV_2614_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2629_2 (MEDIUM) line 2629 in report() ---
# Source:  if (@form_cs) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2629_2 line 2629 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2629 in report() to detect the mutant
    fail('COND_INV_2629_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2639_4 (MEDIUM) line 2639 in report() ---
# Source:  if ($c->{form_paste}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2639_4 line 2639 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2639 in report() to detect the mutant
    fail('COND_INV_2639_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2645_46_< (HIGH) line 2645 in report() ---
# Source:  if (defined $line && length("$line $w") > $ROLE_WRAP_LEN) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2645_46_< line 2645 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2645 in report() to detect the mutant
    fail('NUM_BOUNDARY_2645_46_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2662_2 (MEDIUM) line 2662 in report() ---
# Source:  return join("\n", @out) . "\n";
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2662_2 line 2662 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2662 in report() to detect the mutant
    fail('BOOL_NEGATE_2662_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2690_2 (MEDIUM) line 2690 in _sanitise_output() ---
# Source:  return '' unless defined $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2690_2 line 2690 in _sanitise_output()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2690 in _sanitise_output() to detect the mutant
    fail('BOOL_NEGATE_2690_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2693_2 (MEDIUM) line 2693 in _sanitise_output() ---
# Source:  return $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2693_2 line 2693 in _sanitise_output()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2693 in _sanitise_output() to detect the mutant
    fail('BOOL_NEGATE_2693_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2740_3 (MEDIUM) line 2740 in _split_message() ---
# Source:  if ($line =~ /^([\w-]+)\s*:\s*(.*)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2740_3 line 2740 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2740 in _split_message() to detect the mutant
    fail('COND_INV_2740_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2759_2 (MEDIUM) line 2759 in _split_message() ---
# Source:  if ($ct =~ /multipart/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2759_2 line 2759 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2759 in _split_message() to detect the mutant
    fail('COND_INV_2759_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2765_3 (MEDIUM) line 2765 in _split_message() ---
# Source:  if ($ct =~ /html/i) { $self->{_body_html}  = $decoded }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2765_3 line 2765 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2765 in _split_message() to detect the mutant
    fail('COND_INV_2765_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2839_13_> (HIGH) line 2839 in _decode_multipart() ---
# Source:  if ($depth >= $MAX_MULTIPART_DEPTH) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2839_13_> line 2839 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2839 in _decode_multipart() to detect the mutant
    fail('NUM_BOUNDARY_2839_13_>: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2872_3 (MEDIUM) line 2872 in _decode_multipart() ---
# Source:  if ($pct =~ /multipart/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2872_3 line 2872 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2872 in _decode_multipart() to detect the mutant
    fail('COND_INV_2872_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2874_4 (MEDIUM) line 2874 in _decode_multipart() ---
# Source:  if ($inner_boundary) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2874_4 line 2874 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2874 in _decode_multipart() to detect the mutant
    fail('COND_INV_2874_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2884_3 (MEDIUM) line 2884 in _decode_multipart() ---
# Source:  if    ($pct =~ /text\/html/i)    { $self->{_body_html}  .= $decoded }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2884_3 line 2884 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2884 in _decode_multipart() to detect the mutant
    fail('COND_INV_2884_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2909_2 (MEDIUM) line 2909 in _decode_body() ---
# Source:  return decode_qp($body)     if $cte =~ /quoted-printable/i;
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

# --- SURVIVOR: BOOL_NEGATE_2910_2 (MEDIUM) line 2910 in _decode_body() ---
# Source:  return decode_base64($body) if $cte =~ /base64/i;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2910_2 line 2910 in _decode_body()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2910 in _decode_body() to detect the mutant
    fail('BOOL_NEGATE_2910_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2911_2 (MEDIUM) line 2911 in _decode_body() ---
# Source:  return $body // '';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2911_2 line 2911 in _decode_body()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2911 in _decode_body() to detect the mutant
    fail('BOOL_NEGATE_2911_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2955_2 (MEDIUM) line 2955 in _find_origin() ---
# Source:  unless (@candidates) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_2955_2 line 2955 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2955 in _find_origin() to detect the mutant
    fail('COND_INV_2955_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2957_3 (MEDIUM) line 2957 in _find_origin() ---
# Source:  if ($xoip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2957_3 line 2957 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2957 in _find_origin() to detect the mutant
    fail('COND_INV_2957_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2959_4 (MEDIUM) line 2959 in _find_origin() ---
# Source:  return $self->_enrich_ip($xoip, 'low',
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2959_4 line 2959 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2959 in _find_origin() to detect the mutant
    fail('BOOL_NEGATE_2959_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2967_2 (MEDIUM) line 2967 in _find_origin() ---
# Source:  return $self->_enrich_ip(
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2967_2 line 2967 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2967 in _find_origin() to detect the mutant
    fail('BOOL_NEGATE_2967_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2969_15_< (HIGH) line 2969 in _find_origin() ---
# Source:  @candidates > 1 ? 'high' : 'medium',
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2969_15_< line 2969 in _find_origin()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2969 in _find_origin() to detect the mutant
    fail('NUM_BOUNDARY_2969_15_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2994_3 (MEDIUM) line 2994 in _extract_ip_from_received() ---
# Source:  if ($hdr =~ $re) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2994_3 line 2994 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2994 in _extract_ip_from_received() to detect the mutant
    fail('COND_INV_2994_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2998_4 (MEDIUM) line 2998 in _extract_ip_from_received() ---
# Source:  return $ip if $ip =~ /:/;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2998_4 line 2998 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2998 in _extract_ip_from_received() to detect the mutant
    fail('BOOL_NEGATE_2998_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3002_22_< (HIGH) line 3002 in _extract_ip_from_received() ---
# Source:  next if grep { $_ > 255 } split /\./, $ip;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3002_22_< line 3002 in _extract_ip_from_received()';
    # Suggested boundary values to test: 254, 255, 256
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3002 in _extract_ip_from_received() to detect the mutant
    fail('NUM_BOUNDARY_3002_22_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3003_4 (MEDIUM) line 3003 in _extract_ip_from_received() ---
# Source:  return $ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3003_4 line 3003 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3003 in _extract_ip_from_received() to detect the mutant
    fail('BOOL_NEGATE_3003_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3028_2 (MEDIUM) line 3028 in _is_private() ---
# Source:  return 1 if !defined($ip) || $ip eq '';
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

# --- SURVIVOR: BOOL_NEGATE_3029_33 (MEDIUM) line 3029 in _is_private() ---
# Source:  for my $re (@PRIVATE_RANGES) { return 1 if $ip =~ $re }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3029_33 line 3029 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3029 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_3029_33: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3030_2 (MEDIUM) line 3030 in _is_private() ---
# Source:  return 0;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3030_2 line 3030 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3030 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_3030_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3049_3 (MEDIUM) line 3049 in _is_trusted() ---
# Source:  return 1 if $self->_ip_in_cidr($ip, $cidr);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3049_3 line 3049 in _is_trusted()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3049 in _is_trusted() to detect the mutant
    fail('BOOL_NEGATE_3049_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3051_2 (MEDIUM) line 3051 in _is_trusted() ---
# Source:  return 0;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3051_2 line 3051 in _is_trusted()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3051 in _is_trusted() to detect the mutant
    fail('BOOL_NEGATE_3051_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3111_57_< (HIGH) line 3111 in _extract_and_resolve_urls() ---
# Source:  if ($HAS_ANYEVENT_DNS && scalar(keys %hostname_needed) > 1) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3111_57_< line 3111 in _extract_and_resolve_urls()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3111 in _extract_and_resolve_urls() to detect the mutant
    fail('NUM_BOUNDARY_3111_57_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3121_3 (MEDIUM) line 3121 in _extract_and_resolve_urls() ---
# Source:  unless (exists $host_cache{$host}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_3121_3 line 3121 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3121 in _extract_and_resolve_urls() to detect the mutant
    fail('COND_INV_3121_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3124_4 (MEDIUM) line 3124 in _extract_and_resolve_urls() ---
# Source:  if ($cached) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3124_4 line 3124 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3124 in _extract_and_resolve_urls() to detect the mutant
    fail('COND_INV_3124_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3133_5 (MEDIUM) line 3133 in _extract_and_resolve_urls() ---
# Source:  if (!$whois->{abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3133_5 line 3133 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3133 in _extract_and_resolve_urls() to detect the mutant
    fail('COND_INV_3133_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3154_2 (MEDIUM) line 3154 in _extract_and_resolve_urls() ---
# Source:  return \@results;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3154_2 line 3154 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3154 in _extract_and_resolve_urls() to detect the mutant
    fail('BOOL_NEGATE_3154_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3173_2 (MEDIUM) line 3173 in _is_redirect_cloaker() ---
# Source:  return 1 if $REDIRECT_HOSTS{$host};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3173_2 line 3173 in _is_redirect_cloaker()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3173 in _is_redirect_cloaker() to detect the mutant
    fail('BOOL_NEGATE_3173_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3175_29_< (HIGH) line 3175 in _is_redirect_cloaker() ---
# Source:  return 1 if length($host) > length($suffix)
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3175_29_< line 3175 in _is_redirect_cloaker()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3175 in _is_redirect_cloaker() to detect the mutant
    fail('NUM_BOUNDARY_3175_29_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3178_2 (MEDIUM) line 3178 in _is_redirect_cloaker() ---
# Source:  return '';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3178_2 line 3178 in _is_redirect_cloaker()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3178 in _is_redirect_cloaker() to detect the mutant
    fail('BOOL_NEGATE_3178_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3209_2 (MEDIUM) line 3209 in _follow_redirect_chain() ---
# Source:  return undef unless $HAS_LWP;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3209_2 line 3209 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3209 in _follow_redirect_chain() to detect the mutant
    fail('BOOL_NEGATE_3209_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3212_2 (MEDIUM) line 3212 in _follow_redirect_chain() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3212_2 line 3212 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3212 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3212_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3214_3 (MEDIUM) line 3214 in _follow_redirect_chain() ---
# Source:  return $cached if defined $cached;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3214_3 line 3214 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3214 in _follow_redirect_chain() to detect the mutant
    fail('BOOL_NEGATE_3214_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3219_2 (MEDIUM) line 3219 in _follow_redirect_chain() ---
# Source:  unless (defined $self->{_ua_nofollow}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_3219_2 line 3219 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3219 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3219_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3225_3 (MEDIUM) line 3225 in _follow_redirect_chain() ---
# Source:  if ($HAS_CONN_CACHE) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3225_3 line 3225 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3225 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3225_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3241_3 (MEDIUM) line 3241 in _follow_redirect_chain() ---
# Source:  if ($res->is_redirect()) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3241_3 line 3241 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3241 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3241_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3247_4 (MEDIUM) line 3247 in _follow_redirect_chain() ---
# Source:  if ($loc !~ m{^https?://}i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3247_4 line 3247 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3247 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3247_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3259_4 (MEDIUM) line 3259 in _follow_redirect_chain() ---
# Source:  if ($body =~ m{<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3259_4 line 3259 in _follow_redirect_chain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3259 in _follow_redirect_chain() to detect the mutant
    fail('COND_INV_3259_4: replace with real assertion');
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
# Source:  sub {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3321_29_< line 3321 in _parallel_resolve_hosts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3321 in _parallel_resolve_hosts() to detect the mutant
    fail('NUM_BOUNDARY_3321_29_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3348_2 (MEDIUM) line 3348 in _parallel_resolve_hosts() ---
# Source:  #   Returns a list of URL strings (possibly empty), deduplicated.
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3348_2 line 3348 in _parallel_resolve_hosts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3348 in _parallel_resolve_hosts() to detect the mutant
    fail('COND_INV_3348_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3353_5 (MEDIUM) line 3353 in _extract_http_urls() ---
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
# Source:  push @urls, 'https:' . $1;
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
# Source:  my $val = $self->_header_value($hname) // next;
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
# Source:  my $auth = $self->_parse_auth_results_cached();
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

# --- SURVIVOR: BOOL_NEGATE_3492_2 (MEDIUM) line 3492 in _extract_and_analyse_domains() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3492_2 line 3492 in _extract_and_analyse_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3492 in _extract_and_analyse_domains() to detect the mutant
    fail('BOOL_NEGATE_3492_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3522_2 (MEDIUM) line 3522 in _domains_from_text() ---
# Source:  }
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

# --- SURVIVOR: BOOL_NEGATE_3556_2 (MEDIUM) line 3556 in _domains_from_text() ---
# Source:  #   recently_registered is set to 1 (not 0) when the threshold is met.
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3556_2 line 3556 in _domains_from_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3556 in _domains_from_text() to detect the mutant
    fail('BOOL_NEGATE_3556_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3560_2 (MEDIUM) line 3560 in _analyse_domain() ---
# Source:  my ($self, $domain) = @_;
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
# Source:  # Return the per-message cached result if already analysed
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
# Source:  if $self->{_domain_info}{$domain};
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
# Source:  }
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
# Source:  $info{web_ip} = $web_ip;
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

# --- SURVIVOR: COND_INV_3588_3 (MEDIUM) line 3588 in _analyse_domain() ---
# Source:  if ($HAS_NET_DNS) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3588_3 line 3588 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3588 in _analyse_domain() to detect the mutant
    fail('COND_INV_3588_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3591_4 (MEDIUM) line 3591 in _analyse_domain() ---
# Source:  udp_timeout => $self->{timeout},
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3591_4 line 3591 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3591 in _analyse_domain() to detect the mutant
    fail('COND_INV_3591_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3595_5 (MEDIUM) line 3595 in _analyse_domain() ---
# Source:  if(my $mxq = $res->search($domain, 'MX')) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3595_5 line 3595 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3595 in _analyse_domain() to detect the mutant
    fail('COND_INV_3595_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3605_3 (MEDIUM) line 3605 in _analyse_domain() ---
# Source:  $info{mx_org}   = $mw->{org}   if $mw->{org};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3605_3 line 3605 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3605 in _analyse_domain() to detect the mutant
    fail('COND_INV_3605_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3609_4 (MEDIUM) line 3609 in _analyse_domain() ---
# Source:  }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3609_4 line 3609 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3609 in _analyse_domain() to detect the mutant
    fail('COND_INV_3609_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3613_5 (MEDIUM) line 3613 in _analyse_domain() ---
# Source:  # Sort alphabetically so DNS round-robin ordering never changes which
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3613_5 line 3613 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3613 in _analyse_domain() to detect the mutant
    fail('COND_INV_3613_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3624_2 (MEDIUM) line 3624 in _analyse_domain() ---
# Source:  $info{ns_abuse} = $nw->{abuse} if $nw->{abuse};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3624_2 line 3624 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3624 in _analyse_domain() to detect the mutant
    fail('COND_INV_3624_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3629_3 (MEDIUM) line 3629 in _analyse_domain() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3629_3 line 3629 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3629 in _analyse_domain() to detect the mutant
    fail('COND_INV_3629_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3639_4 (MEDIUM) line 3639 in _analyse_domain() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3639_4 line 3639 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3639 in _analyse_domain() to detect the mutant
    fail('COND_INV_3639_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3651_4 (MEDIUM) line 3651 in _analyse_domain() ---
# Source:  # Domain creation date (multiple registrar field name variations)
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3651_4 line 3651 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3651 in _analyse_domain() to detect the mutant
    fail('COND_INV_3651_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3662_4 (MEDIUM) line 3662 in _analyse_domain() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3662_4 line 3662 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3662 in _analyse_domain() to detect the mutant
    fail('COND_INV_3662_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3668_3 (MEDIUM) line 3668 in _analyse_domain() ---
# Source:  ) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3668_3 line 3668 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3668 in _analyse_domain() to detect the mutant
    fail('COND_INV_3668_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3671_36_> (HIGH) line 3671 in _analyse_domain() ---
# Source:  }
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip < to >
#   Numeric boundary flip < to <=
#   Numeric boundary flip < to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3671_36_> line 3671 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3671 in _analyse_domain() to detect the mutant
    fail('NUM_BOUNDARY_3671_36_>: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3679_2 (MEDIUM) line 3679 in _analyse_domain() ---
# Source:  }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3679_2 line 3679 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3679 in _analyse_domain() to detect the mutant
    fail('BOOL_NEGATE_3679_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3705_2 (MEDIUM) line 3705 in _analyse_domain() ---
# Source:  #
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3705_2 line 3705 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3705 in _analyse_domain() to detect the mutant
    fail('BOOL_NEGATE_3705_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3708_2 (MEDIUM) line 3708 in _analyse_domain() ---
# Source:  #   AAAA records are tried if the A query fails and Net::DNS is available.
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3708_2 line 3708 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3708 in _analyse_domain() to detect the mutant
    fail('COND_INV_3708_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3710_3 (MEDIUM) line 3710 in _resolve_host() ---
# Source:  sub _resolve_host :Protected {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3710_3 line 3710 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3710 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_3710_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3715_2 (MEDIUM) line 3715 in _resolve_host() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3715_2 line 3715 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3715 in _resolve_host() to detect the mutant
    fail('COND_INV_3715_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3724_4 (MEDIUM) line 3724 in _resolve_host() ---
# Source:  tcp_timeout => $self->{timeout},
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3724_4 line 3724 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3724 in _resolve_host() to detect the mutant
    fail('COND_INV_3724_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3726_6 (MEDIUM) line 3726 in _resolve_host() ---
# Source:  );
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3726_6 line 3726 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3726 in _resolve_host() to detect the mutant
    fail('COND_INV_3726_6: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3744_2 (MEDIUM) line 3744 in _resolve_host() ---
# Source:  } else {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3744_2 line 3744 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3744 in _resolve_host() to detect the mutant
    fail('COND_INV_3744_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3748_2 (MEDIUM) line 3748 in _resolve_host() ---
# Source:  }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3748_2 line 3748 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3748 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_3748_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3767_2 (MEDIUM) line 3767 in _resolve_host() ---
# Source:  # Exit status:
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3767_2 line 3767 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3767 in _resolve_host() to detect the mutant
    fail('COND_INV_3767_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3770_3 (MEDIUM) line 3770 in _reverse_dns() ---
# Source:  sub _reverse_dns :Protected {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3770_3 line 3770 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3770 in _reverse_dns() to detect the mutant
    fail('COND_INV_3770_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3772_5 (MEDIUM) line 3772 in _reverse_dns() ---
# Source:  return unless $ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3772_5 line 3772 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3772 in _reverse_dns() to detect the mutant
    fail('BOOL_NEGATE_3772_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3779_2 (MEDIUM) line 3779 in _reverse_dns() ---
# Source:  return $rr->ptrdname if $rr->type eq 'PTR';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3779_2 line 3779 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3779 in _reverse_dns() to detect the mutant
    fail('BOOL_NEGATE_3779_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3803_2 (MEDIUM) line 3803 in _reverse_dns() ---
# Source:  # Exit status:
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3803_2 line 3803 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3803 in _reverse_dns() to detect the mutant
    fail('COND_INV_3803_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3805_3 (MEDIUM) line 3805 in _reverse_dns() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3805_3 line 3805 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3805 in _reverse_dns() to detect the mutant
    fail('BOOL_NEGATE_3805_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3811_2 (MEDIUM) line 3811 in _whois_ip() ---
# Source:  my $cached = $_cache->get("whois_ip:$ip");
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_3811_2 line 3811 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3811 in _whois_ip() to detect the mutant
    fail('COND_INV_3811_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3813_3 (MEDIUM) line 3813 in _whois_ip() ---
# Source:  }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3813_3 line 3813 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3813 in _whois_ip() to detect the mutant
    fail('COND_INV_3813_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3823_2 (MEDIUM) line 3823 in _whois_ip() ---
# Source:  $result = $self->_parse_whois_text($detail) if $detail;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3823_2 line 3823 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3823 in _whois_ip() to detect the mutant
    fail('BOOL_NEGATE_3823_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3843_2 (MEDIUM) line 3843 in _whois_ip() ---
# Source:  #   Returns the raw WHOIS response string, or undef on failure.
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3843_2 line 3843 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3843 in _whois_ip() to detect the mutant
    fail('BOOL_NEGATE_3843_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3863_2 (MEDIUM) line 3863 in _domain_whois() ---
# Source:  # Exit status:
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3863_2 line 3863 in _domain_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3863 in _domain_whois() to detect the mutant
    fail('COND_INV_3863_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3872_3 (MEDIUM) line 3872 in _parse_domain_whois_abuse() ---
# Source:  }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3872_3 line 3872 in _parse_domain_whois_abuse()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3872 in _parse_domain_whois_abuse() to detect the mutant
    fail('COND_INV_3872_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3876_2 (MEDIUM) line 3876 in _parse_domain_whois_abuse() ---
# Source:  qr/Abuse Contact Email:\s*(\S+\@\S+)/i,
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3876_2 line 3876 in _parse_domain_whois_abuse()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3876 in _parse_domain_whois_abuse() to detect the mutant
    fail('BOOL_NEGATE_3876_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3897_2 (MEDIUM) line 3897 in _parse_domain_whois_abuse() ---
# Source:  #   Returns { org, abuse, country } hashref; empty hashref on failure.
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3897_2 line 3897 in _parse_domain_whois_abuse()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3897 in _parse_domain_whois_abuse() to detect the mutant
    fail('COND_INV_3897_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3903_3 (MEDIUM) line 3903 in _rdap_lookup() ---
# Source:  my $ua = $self->{ua};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3903_3 line 3903 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3903 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3903_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3922_2 (MEDIUM) line 3922 in _rdap_lookup() ---
# Source:  my $res = eval { $ua->get("https://rdap.arin.net/registry/ip/$ip") };
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3922_2 line 3922 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3922 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3922_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3923_2 (MEDIUM) line 3923 in _rdap_lookup() ---
# Source:  return {} unless $res && $res->is_success();
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3923_2 line 3923 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3923 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3923_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3926_2 (MEDIUM) line 3926 in _rdap_lookup() ---
# Source:  my %info;
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

# --- SURVIVOR: COND_INV_3933_2 (MEDIUM) line 3933 in _rdap_lookup() ---
# Source:  if ($j =~ /"abuse".*?"email"\s*:\s*"([^"]+)"/s) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3933_2 line 3933 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3933 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3933_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3935_2 (MEDIUM) line 3935 in _rdap_lookup() ---
# Source:  } elsif ($j =~ /"email"\s*:\s*"([^@"]+@[^"]+)"/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3935_2 line 3935 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3935 in _rdap_lookup() to detect the mutant
    fail('BOOL_NEGATE_3935_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3993_31_< (HIGH) line 3993 in _raw_whois() ---
# Source:  my $buf      = '';
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3993_31_< line 3993 in _raw_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3993 in _raw_whois() to detect the mutant
    fail('NUM_BOUNDARY_3993_31_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3997_30_< (HIGH) line 3997 in _raw_whois() ---
# Source:  # Wrap in eval to catch 'Connection reset by peer' thrown by Fatal/autodie
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3997_30_< line 3997 in _raw_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3997 in _raw_whois() to detect the mutant
    fail('NUM_BOUNDARY_3997_30_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4002_2 (MEDIUM) line 4002 in _raw_whois() ---
# Source:  last;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4002_2 line 4002 in _raw_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4002 in _raw_whois() to detect the mutant
    fail('BOOL_NEGATE_4002_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4027_3 (MEDIUM) line 4027 in _parse_whois_text() ---
# Source:  my %info;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4027_3 line 4027 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4027 in _parse_whois_text() to detect the mutant
    fail('COND_INV_4027_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4037_3 (MEDIUM) line 4037 in _parse_whois_text() ---
# Source:  }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4037_3 line 4037 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4037 in _parse_whois_text() to detect the mutant
    fail('COND_INV_4037_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4043_2 (MEDIUM) line 4043 in _parse_whois_text() ---
# Source:  ) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4043_2 line 4043 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4043 in _parse_whois_text() to detect the mutant
    fail('COND_INV_4043_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4046_2 (MEDIUM) line 4046 in _parse_whois_text() ---
# Source:  }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4046_2 line 4046 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4046 in _parse_whois_text() to detect the mutant
    fail('COND_INV_4046_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4049_2 (MEDIUM) line 4049 in _parse_whois_text() ---
# Source:  # Last-resort: any abuse@ address in the response
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4049_2 line 4049 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4049 in _parse_whois_text() to detect the mutant
    fail('BOOL_NEGATE_4049_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4072_2 (MEDIUM) line 4072 in _parse_whois_text() ---
# Source:  #
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4072_2 line 4072 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4072 in _parse_whois_text() to detect the mutant
    fail('BOOL_NEGATE_4072_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4084_2 (MEDIUM) line 4084 in _parse_auth_results_cached() ---
# Source:  my $raw = join('; ',
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4084_2 line 4084 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4084 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_4084_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4085_2 (MEDIUM) line 4085 in _parse_auth_results_cached() ---
# Source:  map  { $_->{value} }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4085_2 line 4085 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4085 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_4085_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4086_2 (MEDIUM) line 4086 in _parse_auth_results_cached() ---
# Source:  grep { $_->{name} eq 'authentication-results' }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4086_2 line 4086 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4086 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_4086_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4087_2 (MEDIUM) line 4087 in _parse_auth_results_cached() ---
# Source:  @{ $self->{_headers} }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4087_2 line 4087 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4087 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_4087_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4098_3 (MEDIUM) line 4098 in _parse_auth_results_cached() ---
# Source:  $auth{$k} =~ s/[;,\s]+$// if defined $auth{$k};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4098_3 line 4098 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4098 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_4098_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4103_2 (MEDIUM) line 4103 in _parse_auth_results_cached() ---
# Source:  my @dkim_domains;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4103_2 line 4103 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4103 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_4103_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4107_4 (MEDIUM) line 4107 in _parse_auth_results_cached() ---
# Source:  }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4107_4 line 4107 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4107 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_4107_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4117_2 (MEDIUM) line 4117 in _parse_auth_results_cached() ---
# Source:  }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4117_2 line 4117 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4117 in _parse_auth_results_cached() to detect the mutant
    fail('BOOL_NEGATE_4117_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4141_3 (MEDIUM) line 4141 in _parse_auth_results_cached() ---
# Source:  #   Returns the %PROVIDER_ABUSE entry hashref on match, undef otherwise.
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4141_3 line 4141 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4141 in _parse_auth_results_cached() to detect the mutant
    fail('BOOL_NEGATE_4141_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4142_3 (MEDIUM) line 4142 in _parse_auth_results_cached() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4142_3 line 4142 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4142 in _parse_auth_results_cached() to detect the mutant
    fail('BOOL_NEGATE_4142_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4163_2 (MEDIUM) line 4163 in _provider_abuse_for_host() ---
# Source:  #   $rdns -- optional rDNS hostname string.
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4163_2 line 4163 in _provider_abuse_for_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4163 in _provider_abuse_for_host() to detect the mutant
    fail('BOOL_NEGATE_4163_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4194_2 (MEDIUM) line 4194 in _provider_abuse_for_ip() ---
# Source:  #   uncommon second-level delegations like ltd.uk or plc.uk.
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4194_2 line 4194 in _provider_abuse_for_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4194 in _provider_abuse_for_ip() to detect the mutant
    fail('COND_INV_4194_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4197_3 (MEDIUM) line 4197 in _registrable() ---
# Source:  my $host = $_[0];
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4197_3 line 4197 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4197 in _registrable() to detect the mutant
    fail('BOOL_NEGATE_4197_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4202_26_< (HIGH) line 4202 in _registrable() ---
# Source:  my $psl = Domain::PublicSuffix->new();
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4202_26_< line 4202 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4202 in _registrable() to detect the mutant
    fail('NUM_BOUNDARY_4202_26_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4205_2 (MEDIUM) line 4205 in _registrable() ---
# Source:  }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4205_2 line 4205 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4205 in _registrable() to detect the mutant
    fail('COND_INV_4205_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4207_3 (MEDIUM) line 4207 in _registrable() ---
# Source:  # Built-in heuristic fallback
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4207_3 line 4207 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4207 in _registrable() to detect the mutant
    fail('BOOL_NEGATE_4207_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4209_2 (MEDIUM) line 4209 in _registrable() ---
# Source:  return $host if @labels <= 2;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4209_2 line 4209 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4209 in _registrable() to detect the mutant
    fail('BOOL_NEGATE_4209_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4321_2 (MEDIUM) line 4321 in header_value() ---
# Source:  'optional' => 0,
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4321_2 line 4321 in header_value()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4321 in header_value() to detect the mutant
    fail('BOOL_NEGATE_4321_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4341_3 (MEDIUM) line 4341 in header_value() ---
# Source:  #
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4341_3 line 4341 in header_value()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4341 in header_value() to detect the mutant
    fail('BOOL_NEGATE_4341_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4361_2 (MEDIUM) line 4361 in _header_value() ---
# Source:  #   $cidr -- a CIDR string like '10.0.0.0/8' or an exact IP.
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4361_2 line 4361 in _header_value()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4361 in _header_value() to detect the mutant
    fail('BOOL_NEGATE_4361_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4363_65_< (HIGH) line 4363 in _header_value() ---
# Source:  # Exit status:
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4363_65_< line 4363 in _header_value()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4363 in _header_value() to detect the mutant
    fail('NUM_BOUNDARY_4363_65_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4369_25_!= (HIGH) line 4369 in _ip_in_cidr() ---
# Source:  my ($net_addr, $prefix) = split m{/}, $cidr;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (2 variants — one test should kill all):
#   Numeric boundary flip == to !=
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4369_25_!= line 4369 in _ip_in_cidr()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4369 in _ip_in_cidr() to detect the mutant
    fail('NUM_BOUNDARY_4369_25_!=: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4386_2 (MEDIUM) line 4386 in _ip_in_cidr() ---
# Source:  #   $str -- a defined header value string; may be undef.
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4386_2 line 4386 in _ip_in_cidr()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4386 in _ip_in_cidr() to detect the mutant
    fail('BOOL_NEGATE_4386_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4389_2 (MEDIUM) line 4389 in _ip_in_cidr() ---
# Source:  #   Returns the decoded string, or '' if $str is undef.
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4389_2 line 4389 in _ip_in_cidr()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4389 in _ip_in_cidr() to detect the mutant
    fail('BOOL_NEGATE_4389_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4404_2 (MEDIUM) line 4404 in _decode_mime_words() ---
# Source:  # Notes:
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4404_2 line 4404 in _decode_mime_words()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4404 in _decode_mime_words() to detect the mutant
    fail('COND_INV_4404_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4411_2 (MEDIUM) line 4411 in _decode_ew() ---
# Source:  if (uc($enc) eq 'B') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4411_2 line 4411 in _decode_ew()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4411 in _decode_ew() to detect the mutant
    fail('BOOL_NEGATE_4411_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4434_2 (MEDIUM) line 4434 in _parse_date_to_epoch() ---
# Source:  my ($self, $str) = @_;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4434_2 line 4434 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4434 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_4434_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4446_4 (MEDIUM) line 4446 in _parse_date_to_epoch() ---
# Source:  my $t = Time::Piece->strptime($1, '%Y-%m-%dT%H:%M:%S');
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4446_4 line 4446 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4446 in _parse_date_to_epoch() to detect the mutant
    fail('BOOL_NEGATE_4446_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4448_3 (MEDIUM) line 4448 in _parse_date_to_epoch() ---
# Source:  # Return seconds since the epoch
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4448_3 line 4448 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4448 in _parse_date_to_epoch() to detect the mutant
    fail('BOOL_NEGATE_4448_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4452_2 (MEDIUM) line 4452 in _parse_date_to_epoch() ---
# Source:  # We must subtract the local timezone offset to get the true UTC epoch.
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4452_2 line 4452 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4452 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_4452_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4458_2 (MEDIUM) line 4458 in _parse_date_to_epoch() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4458_2 line 4458 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4458 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_4458_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4459_3 (MEDIUM) line 4459 in _parse_date_to_epoch() ---
# Source:  if    ($str =~ /^(\d{4})-(\d{2})-(\d{2})/)         { ($y,$m,$d)=($1,$2,$3) }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4459_3 line 4459 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4459 in _parse_date_to_epoch() to detect the mutant
    fail('BOOL_NEGATE_4459_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4462_2 (MEDIUM) line 4462 in _parse_date_to_epoch() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4462_2 line 4462 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4462 in _parse_date_to_epoch() to detect the mutant
    fail('BOOL_NEGATE_4462_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4484_2 (MEDIUM) line 4484 in _parse_date_to_epoch() ---
# Source:  #   Returns epoch integer on success, undef if the string cannot be parsed.
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4484_2 line 4484 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4484 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_4484_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4488_3 (MEDIUM) line 4488 in _parse_rfc2822_date() ---
# Source:  return unless $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4488_3 line 4488 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4488 in _parse_rfc2822_date() to detect the mutant
    fail('COND_INV_4488_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4489_4 (MEDIUM) line 4489 in _parse_rfc2822_date() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4489_4 line 4489 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4489 in _parse_rfc2822_date() to detect the mutant
    fail('BOOL_NEGATE_4489_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4515_2 (MEDIUM) line 4515 in _country_name() ---
# Source:  sub _country_name :Private {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4515_2 line 4515 in _country_name()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4515 in _country_name() to detect the mutant
    fail('BOOL_NEGATE_4515_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4532_2 (MEDIUM) line 4532 in _country_name() ---
# Source:  #
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4532_2 line 4532 in _country_name()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4532 in _country_name() to detect the mutant
    fail('COND_INV_4532_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4533_3 (MEDIUM) line 4533 in _country_name() ---
# Source:  # Notes:
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4533_3 line 4533 in _country_name()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4533 in _country_name() to detect the mutant
    fail('COND_INV_4533_3: replace with real assertion');
}

# --- LOW DIFFICULTY HINTS (comment stubs) ---

# --- LOW HINT: RETURN_UNDEF_634_2 line 634 in new() ---
# Source:  return bless {
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new is a class method — call directly.
# e.g. my $result = Email::Abuse::Investigator->new(...);
# ok($result, 'RETURN_UNDEF_634_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_770_2 line 770 in parse_email() ---
# Source:  return $self;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_770_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_845_2 line 845 in originating_ip() ---
# Source:  return $self->{_origin};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_845_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_932_2 line 932 in embedded_urls() ---
# Source:  return @{ $self->{_urls} };
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_932_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1003_2 line 1003 in mailto_domains() ---
# Source:  return @{ $self->{_mailto_domains} };
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1003_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1067_2 line 1067 in all_domains() ---
# Source:  return @out;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1067_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1173_2 line 1173 in unresolved_contacts() ---
# Source:  return @out;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1173_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1239_2 line 1239 in sending_software() ---
# Source:  return @{ $self->{_sending_sw} };
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1239_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1307_2 line 1307 in received_trail() ---
# Source:  return @{ $self->{_rcvd_tracking} };
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1307_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1374_2 line 1374 in risk_assessment() ---
# Source:  return $self->{_risk} if $self->{_risk};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1374_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1399_2 line 1399 in risk_assessment() ---
# Source:  return $self->{_risk};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1399_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1832_2 line 1832 in abuse_report_text() ---
# Source:  return join("\n", @out);
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1832_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1903_2 line 1903 in abuse_contacts() ---
# Source:  return @{ $self->{_contacts} };
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1903_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2185_2 line 2185 in _compute_abuse_contacts() ---
# Source:  return @contacts;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2185_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2393_2 line 2393 in form_contacts() ---
# Source:  return @contacts;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2393_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2662_2 line 2662 in report() ---
# Source:  return join("\n", @out) . "\n";
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2662_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2690_2 line 2690 in _sanitise_output() ---
# Source:  return '' unless defined $str;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2690_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2693_2 line 2693 in _sanitise_output() ---
# Source:  return $str;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2693_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2909_2 line 2909 in _decode_body() ---
# Source:  return decode_qp($body)     if $cte =~ /quoted-printable/i;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2909_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2910_2 line 2910 in _decode_body() ---
# Source:  return decode_base64($body) if $cte =~ /base64/i;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2910_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2911_2 line 2911 in _decode_body() ---
# Source:  return $body // '';
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2911_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2959_4 line 2959 in _find_origin() ---
# Source:  return $self->_enrich_ip($xoip, 'low',
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2959_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2967_2 line 2967 in _find_origin() ---
# Source:  return $self->_enrich_ip(
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2967_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2998_4 line 2998 in _extract_ip_from_received() ---
# Source:  return $ip if $ip =~ /:/;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2998_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3003_4 line 3003 in _extract_ip_from_received() ---
# Source:  return $ip;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3003_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3028_2 line 3028 in _is_private() ---
# Source:  return 1 if !defined($ip) || $ip eq '';
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3028_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3029_33 line 3029 in _is_private() ---
# Source:  for my $re (@PRIVATE_RANGES) { return 1 if $ip =~ $re }
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3029_33: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3030_2 line 3030 in _is_private() ---
# Source:  return 0;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3030_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3049_3 line 3049 in _is_trusted() ---
# Source:  return 1 if $self->_ip_in_cidr($ip, $cidr);
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3049_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3051_2 line 3051 in _is_trusted() ---
# Source:  return 0;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3051_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3154_2 line 3154 in _extract_and_resolve_urls() ---
# Source:  return \@results;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3154_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3173_2 line 3173 in _is_redirect_cloaker() ---
# Source:  return 1 if $REDIRECT_HOSTS{$host};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3173_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3175_3 line 3175 in _is_redirect_cloaker() ---
# Source:  return 1 if length($host) > length($suffix)
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3175_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3178_2 line 3178 in _is_redirect_cloaker() ---
# Source:  return '';
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3178_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3209_2 line 3209 in _follow_redirect_chain() ---
# Source:  return undef unless $HAS_LWP;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3209_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3214_3 line 3214 in _follow_redirect_chain() ---
# Source:  return $cached if defined $cached;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3214_3: add assertion here');

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
# Source:  push @urls, 'https:' . $1;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3378_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3492_2 line 3492 in _extract_and_analyse_domains() ---
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3492_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3522_2 line 3522 in _domains_from_text() ---
# Source:  }
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3522_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3556_2 line 3556 in _domains_from_text() ---
# Source:  #   recently_registered is set to 1 (not 0) when the threshold is met.
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3556_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3564_4 line 3564 in _analyse_domain() ---
# Source:  if $self->{_domain_info}{$domain};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3564_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3679_2 line 3679 in _analyse_domain() ---
# Source:  }
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3679_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3705_2 line 3705 in _analyse_domain() ---
# Source:  #
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3705_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3710_3 line 3710 in _resolve_host() ---
# Source:  sub _resolve_host :Protected {
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3710_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3748_2 line 3748 in _resolve_host() ---
# Source:  }
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3748_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3772_5 line 3772 in _reverse_dns() ---
# Source:  return unless $ip;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3772_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3779_2 line 3779 in _reverse_dns() ---
# Source:  return $rr->ptrdname if $rr->type eq 'PTR';
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3779_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3805_3 line 3805 in _reverse_dns() ---
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3805_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3823_2 line 3823 in _whois_ip() ---
# Source:  $result = $self->_parse_whois_text($detail) if $detail;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3823_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3843_2 line 3843 in _whois_ip() ---
# Source:  #   Returns the raw WHOIS response string, or undef on failure.
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3843_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3876_2 line 3876 in _parse_domain_whois_abuse() ---
# Source:  qr/Abuse Contact Email:\s*(\S+\@\S+)/i,
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3876_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3935_2 line 3935 in _rdap_lookup() ---
# Source:  } elsif ($j =~ /"email"\s*:\s*"([^@"]+@[^"]+)"/) {
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3935_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4002_2 line 4002 in _raw_whois() ---
# Source:  last;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4002_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4049_2 line 4049 in _parse_whois_text() ---
# Source:  # Last-resort: any abuse@ address in the response
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4049_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4072_2 line 4072 in _parse_whois_text() ---
# Source:  #
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4072_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4117_2 line 4117 in _parse_auth_results_cached() ---
# Source:  }
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4117_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4141_3 line 4141 in _parse_auth_results_cached() ---
# Source:  #   Returns the %PROVIDER_ABUSE entry hashref on match, undef otherwise.
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4141_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4142_3 line 4142 in _parse_auth_results_cached() ---
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4142_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4163_2 line 4163 in _provider_abuse_for_host() ---
# Source:  #   $rdns -- optional rDNS hostname string.
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4163_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4197_3 line 4197 in _registrable() ---
# Source:  my $host = $_[0];
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4197_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4202_2 line 4202 in _registrable() ---
# Source:  my $psl = Domain::PublicSuffix->new();
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4202_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4207_3 line 4207 in _registrable() ---
# Source:  # Built-in heuristic fallback
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4207_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4209_2 line 4209 in _registrable() ---
# Source:  return $host if @labels <= 2;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4209_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4321_2 line 4321 in header_value() ---
# Source:  'optional' => 0,
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4321_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4341_3 line 4341 in header_value() ---
# Source:  #
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4341_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4361_2 line 4361 in _header_value() ---
# Source:  #   $cidr -- a CIDR string like '10.0.0.0/8' or an exact IP.
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4361_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4363_2 line 4363 in _header_value() ---
# Source:  # Exit status:
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4363_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4369_2 line 4369 in _ip_in_cidr() ---
# Source:  my ($net_addr, $prefix) = split m{/}, $cidr;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4369_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4386_2 line 4386 in _ip_in_cidr() ---
# Source:  #   $str -- a defined header value string; may be undef.
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4386_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4389_2 line 4389 in _ip_in_cidr() ---
# Source:  #   Returns the decoded string, or '' if $str is undef.
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4389_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4411_2 line 4411 in _decode_ew() ---
# Source:  if (uc($enc) eq 'B') {
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4411_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4446_4 line 4446 in _parse_date_to_epoch() ---
# Source:  my $t = Time::Piece->strptime($1, '%Y-%m-%dT%H:%M:%S');
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4446_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4448_3 line 4448 in _parse_date_to_epoch() ---
# Source:  # Return seconds since the epoch
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4448_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4459_3 line 4459 in _parse_date_to_epoch() ---
# Source:  if    ($str =~ /^(\d{4})-(\d{2})-(\d{2})/)         { ($y,$m,$d)=($1,$2,$3) }
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4459_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4462_2 line 4462 in _parse_date_to_epoch() ---
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4462_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4489_4 line 4489 in _parse_rfc2822_date() ---
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4489_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4515_2 line 4515 in _country_name() ---
# Source:  sub _country_name :Private {
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4515_2: add assertion here');

done_testing();
