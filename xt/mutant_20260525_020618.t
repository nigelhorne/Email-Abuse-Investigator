#!/usr/bin/env perl
# Auto-generated mutant test stubs
# Generated: 2026-05-25 02:06:18
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

# --- SURVIVOR: COND_INV_619_2 (MEDIUM) line 619 in new() ---
# Source:  if ($HAS_CHI && !$_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_619_2 line 619 in new()';
    # NOTE: new is a class method — call directly.
    my $result = Email::Abuse::Investigator->new(...);
    # ok($result, 'COND_INV_619_2: add assertion here');
    # TODO: exercise line 619 in new() to detect the mutant
    fail('COND_INV_619_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_753_2 (MEDIUM) line 753 in parse_email() ---
# Source:  if(ref($text)) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_753_2 line 753 in parse_email()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 753 in parse_email() to detect the mutant
    fail('COND_INV_753_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_754_3 (MEDIUM) line 754 in parse_email() ---
# Source:  if(ref($text) eq 'SCALAR') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_754_3 line 754 in parse_email()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 754 in parse_email() to detect the mutant
    fail('COND_INV_754_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_757_3 (MEDIUM) line 757 in parse_email() ---
# Source:  if(ref($text)) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_757_3 line 757 in parse_email()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 757 in parse_email() to detect the mutant
    fail('COND_INV_757_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_781_2 (MEDIUM) line 781 in parse_email() ---
# Source:  return $self;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_781_2 line 781 in parse_email()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 781 in parse_email() to detect the mutant
    fail('BOOL_NEGATE_781_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_867_2 (MEDIUM) line 867 in originating_ip() ---
# Source:  return $self->{_origin};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_867_2 line 867 in originating_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 867 in originating_ip() to detect the mutant
    fail('BOOL_NEGATE_867_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1112_2 (MEDIUM) line 1112 in all_domains() ---
# Source:  return @out;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1112_2 line 1112 in all_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1112 in all_domains() to detect the mutant
    fail('BOOL_NEGATE_1112_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1187_3 (MEDIUM) line 1187 in unresolved_contacts() ---
# Source:  unless ($dom) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_1187_3 line 1187 in unresolved_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1187 in unresolved_contacts() to detect the mutant
    fail('COND_INV_1187_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1228_2 (MEDIUM) line 1228 in unresolved_contacts() ---
# Source:  return @out;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1228_2 line 1228 in unresolved_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1228 in unresolved_contacts() to detect the mutant
    fail('BOOL_NEGATE_1228_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1463_2 (MEDIUM) line 1463 in risk_assessment() ---
# Source:  return $self->{_risk} if $self->{_risk};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1463_2 line 1463 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1463 in risk_assessment() to detect the mutant
    fail('BOOL_NEGATE_1463_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1477_2 (MEDIUM) line 1477 in risk_assessment() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1477_2 line 1477 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1477 in risk_assessment() to detect the mutant
    fail('COND_INV_1477_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1479_3 (MEDIUM) line 1479 in risk_assessment() ---
# Source:  if ($orig->{rdns} && $orig->{rdns} =~ /
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1479_3 line 1479 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1479 in risk_assessment() to detect the mutant
    fail('COND_INV_1479_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1490_3 (MEDIUM) line 1490 in risk_assessment() ---
# Source:  if (!$orig->{rdns} || $orig->{rdns} eq '(no reverse DNS)') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1490_3 line 1490 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1490 in risk_assessment() to detect the mutant
    fail('COND_INV_1490_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1496_3 (MEDIUM) line 1496 in risk_assessment() ---
# Source:  if ($orig->{confidence} eq 'low') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1496_3 line 1496 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1496 in risk_assessment() to detect the mutant
    fail('COND_INV_1496_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1502_3 (MEDIUM) line 1502 in risk_assessment() ---
# Source:  if ($orig->{country} && $orig->{country} =~ /^(?:CN|RU|NG|VN|IN|PK|BD)$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1502_3 line 1502 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1502 in risk_assessment() to detect the mutant
    fail('COND_INV_1502_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1511_2 (MEDIUM) line 1511 in risk_assessment() ---
# Source:  if (defined $auth->{spf}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1511_2 line 1511 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1511 in risk_assessment() to detect the mutant
    fail('COND_INV_1511_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1512_3 (MEDIUM) line 1512 in risk_assessment() ---
# Source:  if ($auth->{spf} =~ /^fail/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1512_3 line 1512 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1512 in risk_assessment() to detect the mutant
    fail('COND_INV_1512_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1523_2 (MEDIUM) line 1523 in risk_assessment() ---
# Source:  if (defined $auth->{dkim} && $auth->{dkim} !~ /^pass/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1523_2 line 1523 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1523 in risk_assessment() to detect the mutant
    fail('COND_INV_1523_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1527_2 (MEDIUM) line 1527 in risk_assessment() ---
# Source:  if (defined $auth->{dmarc} && $auth->{dmarc} !~ /^pass/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1527_2 line 1527 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1527 in risk_assessment() to detect the mutant
    fail('COND_INV_1527_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1532_2 (MEDIUM) line 1532 in risk_assessment() ---
# Source:  if ($auth->{dkim_domain}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1532_2 line 1532 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1532 in risk_assessment() to detect the mutant
    fail('COND_INV_1532_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1534_3 (MEDIUM) line 1534 in risk_assessment() ---
# Source:  if ($from_domain) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1534_3 line 1534 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1534 in risk_assessment() to detect the mutant
    fail('COND_INV_1534_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1537_4 (MEDIUM) line 1537 in risk_assessment() ---
# Source:  if ($reg_dkim ne $reg_from) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1537_4 line 1537 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1537 in risk_assessment() to detect the mutant
    fail('COND_INV_1537_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1539_5 (MEDIUM) line 1539 in risk_assessment() ---
# Source:  if ($auth->{dkim} && $auth->{dkim} =~ /^pass/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1539_5 line 1539 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1539 in risk_assessment() to detect the mutant
    fail('COND_INV_1539_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1555_2 (MEDIUM) line 1555 in risk_assessment() ---
# Source:  if (!$date_raw || $date_raw !~ /\S/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1555_2 line 1555 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1555 in risk_assessment() to detect the mutant
    fail('COND_INV_1555_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1560_3 (MEDIUM) line 1560 in risk_assessment() ---
# Source:  if ($date_raw =~ /([+-])(\d{2})(\d{2})\s*$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1560_3 line 1560 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1560 in risk_assessment() to detect the mutant
    fail('COND_INV_1560_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1563_26_> (HIGH) line 1563 in risk_assessment() ---
# Source:  my $implausible = $mm >= 60
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1563_26_> line 1563 in risk_assessment()';
    # Suggested boundary values to test: 59, 60, 61
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1563 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1563_26_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1564_38_< (HIGH) line 1564 in risk_assessment() ---
# Source:  || ($sign eq '+' && $offset_mins > $TZ_MAX_POS_MINS)
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1564_38_< line 1564 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1564 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1564_38_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1565_38_< (HIGH) line 1565 in risk_assessment() ---
# Source:  || ($sign eq '-' && $offset_mins > $TZ_MAX_NEG_MINS);
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1565_38_< line 1565 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1565 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1565_38_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1566_4 (MEDIUM) line 1566 in risk_assessment() ---
# Source:  if ($implausible) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1566_4 line 1566 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1566 in risk_assessment() to detect the mutant
    fail('COND_INV_1566_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1575_3 (MEDIUM) line 1575 in risk_assessment() ---
# Source:  if (defined $date_epoch) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1575_3 line 1575 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1575 in risk_assessment() to detect the mutant
    fail('COND_INV_1575_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1577_15_< (HIGH) line 1577 in risk_assessment() ---
# Source:  if ($delta > $DATE_SKEW_DAYS * $SECS_PER_DAY) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1577_15_< line 1577 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1577 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1577_15_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1580_20_> (HIGH) line 1580 in risk_assessment() ---
# Source:  } elsif ($delta < -($DATE_SKEW_DAYS * $SECS_PER_DAY)) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip < to >
#   Numeric boundary flip < to <=
#   Numeric boundary flip < to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1580_20_> line 1580 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1580 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1580_20_>: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1592_2 (MEDIUM) line 1592 in risk_assessment() ---
# Source:  if ($from_decoded =~ /^"?([^"<]+?)"?\s*<([^>]+)>/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1592_2 line 1592 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1592 in risk_assessment() to detect the mutant
    fail('COND_INV_1592_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1600_4 (MEDIUM) line 1600 in risk_assessment() ---
# Source:  if ($reg_disp && $reg_addr && $reg_disp ne $reg_addr) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1600_4 line 1600 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1600 in risk_assessment() to detect the mutant
    fail('COND_INV_1600_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1608_2 (MEDIUM) line 1608 in risk_assessment() ---
# Source:  if ($from_raw =~ /\@(gmail|yahoo|hotmail|outlook|live|aol|protonmail|yandex)\./i
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1608_2 line 1608 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1608 in risk_assessment() to detect the mutant
    fail('COND_INV_1608_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1616_2 (MEDIUM) line 1616 in risk_assessment() ---
# Source:  if ($reply_to) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1616_2 line 1616 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1616 in risk_assessment() to detect the mutant
    fail('COND_INV_1616_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1619_3 (MEDIUM) line 1619 in risk_assessment() ---
# Source:  if ($from_addr && $reply_addr && lc($from_addr) ne lc($reply_addr)) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1619_3 line 1619 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1619 in risk_assessment() to detect the mutant
    fail('COND_INV_1619_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1627_2 (MEDIUM) line 1627 in risk_assessment() ---
# Source:  if ($to =~ /undisclosed|:;/ || $to eq '') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1627_2 line 1627 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1627 in risk_assessment() to detect the mutant
    fail('COND_INV_1627_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1634_2 (MEDIUM) line 1634 in risk_assessment() ---
# Source:  if ($subj_raw =~ /=\?[^?]+\?[BQ]\?/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1634_2 line 1634 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1634 in risk_assessment() to detect the mutant
    fail('COND_INV_1634_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1650_3 (MEDIUM) line 1650 in risk_assessment() ---
# Source:  if(($URL_SHORTENERS{$bare} || $self->{url_shorteners}->{$bare}) && !$shortener_seen{$bare}++) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1650_3 line 1650 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1650 in risk_assessment() to detect the mutant
    fail('COND_INV_1650_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1655_3 (MEDIUM) line 1655 in risk_assessment() ---
# Source:  if ($u->{url} =~ m{^http://}i && !$url_host_seen{ $u->{host} }++) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1655_3 line 1655 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1655 in risk_assessment() to detect the mutant
    fail('COND_INV_1655_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1664_3 (MEDIUM) line 1664 in risk_assessment() ---
# Source:  if ($d->{recently_registered}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1664_3 line 1664 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1664 in risk_assessment() to detect the mutant
    fail('COND_INV_1664_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1670_3 (MEDIUM) line 1670 in risk_assessment() ---
# Source:  if ($d->{expires}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1670_3 line 1670 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1670 in risk_assessment() to detect the mutant
    fail('COND_INV_1670_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1671_4 (MEDIUM) line 1671 in risk_assessment() ---
# Source:  if(my $exp = $self->_parse_date_to_epoch($d->{expires})) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1671_4 line 1671 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1671 in risk_assessment() to detect the mutant
    fail('COND_INV_1671_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1674_38_> (HIGH) line 1674 in risk_assessment() ---
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
    local $TODO = 'Complete: NUM_BOUNDARY_1674_38_> line 1674 in risk_assessment()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1674 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1674_38_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1677_25_< (HIGH) line 1677 in risk_assessment() ---
# Source:  } elsif ($remaining <= 0) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1677_25_< line 1677 in risk_assessment()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1677 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1677_25_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1688_4 (MEDIUM) line 1688 in risk_assessment() ---
# Source:  if ($d->{domain} =~ /\Q$brand\E/i &&
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1688_4 line 1688 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1688 in risk_assessment() to detect the mutant
    fail('COND_INV_1688_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1698_21_> (HIGH) line 1698 in risk_assessment() ---
# Source:  my $level = $score >= $SCORE_HIGH   ? 'HIGH'
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1698_21_> line 1698 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1698 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1698_21_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1699_21_> (HIGH) line 1699 in risk_assessment() ---
# Source:  : $score >= $SCORE_MEDIUM ? 'MEDIUM'
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1699_21_> line 1699 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1699 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1699_21_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1700_21_> (HIGH) line 1700 in risk_assessment() ---
# Source:  : $score >= $SCORE_LOW    ? 'LOW'
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1700_21_> line 1700 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1700 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1700_21_>: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1704_2 (MEDIUM) line 1704 in risk_assessment() ---
# Source:  return $self->{_risk};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1704_2 line 1704 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1704 in risk_assessment() to detect the mutant
    fail('BOOL_NEGATE_1704_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1782_2 (MEDIUM) line 1782 in abuse_report_text() ---
# Source:  if (@{ $risk->{flags} }) {
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

# --- SURVIVOR: COND_INV_1792_2 (MEDIUM) line 1792 in abuse_report_text() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1792_2 line 1792 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1792 in abuse_report_text() to detect the mutant
    fail('COND_INV_1792_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1800_2 (MEDIUM) line 1800 in abuse_report_text() ---
# Source:  if (@contacts) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1800_2 line 1800 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1800 in abuse_report_text() to detect the mutant
    fail('COND_INV_1800_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1807_2 (MEDIUM) line 1807 in abuse_report_text() ---
# Source:  if(my @form_cs = $self->form_contacts()) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1807_2 line 1807 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1807 in abuse_report_text() to detect the mutant
    fail('COND_INV_1807_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1918_3 (MEDIUM) line 1918 in abuse_contacts() ---
# Source:  if ($addr =~ /\@([\w.-]+)$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1918_3 line 1918 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1918 in abuse_contacts() to detect the mutant
    fail('COND_INV_1918_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1924_3 (MEDIUM) line 1924 in abuse_contacts() ---
# Source:  if (exists $seen_idx{$addr}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1924_3 line 1924 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1924 in abuse_contacts() to detect the mutant
    fail('COND_INV_1924_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1935_22_< (HIGH) line 1935 in abuse_contacts() ---
# Source:  $role_counts{$_} > 1 ? "$_ (x$role_counts{$_})" : $_
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1935_22_< line 1935 in abuse_contacts()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1935 in abuse_contacts() to detect the mutant
    fail('NUM_BOUNDARY_1935_22_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1940_24_< (HIGH) line 1940 in abuse_contacts() ---
# Source:  if (length($joined) > $ROLE_MAX_LEN) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1940_24_< line 1940 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1940 in abuse_contacts() to detect the mutant
    fail('NUM_BOUNDARY_1940_24_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1960_2 (MEDIUM) line 1960 in abuse_contacts() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1960_2 line 1960 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1960 in abuse_contacts() to detect the mutant
    fail('COND_INV_1960_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1962_3 (MEDIUM) line 1962 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1962_3 line 1962 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1962 in abuse_contacts() to detect the mutant
    fail('COND_INV_1962_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1970_3 (MEDIUM) line 1970 in abuse_contacts() ---
# Source:  if ($orig->{abuse} && $orig->{abuse} ne '(unknown)') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1970_3 line 1970 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1970 in abuse_contacts() to detect the mutant
    fail('COND_INV_1970_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1990_3 (MEDIUM) line 1990 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1990_3 line 1990 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1990 in abuse_contacts() to detect the mutant
    fail('COND_INV_1990_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1998_3 (MEDIUM) line 1998 in abuse_contacts() ---
# Source:  if ($u->{abuse} && $u->{abuse} ne '(unknown)') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1998_3 line 1998 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1998 in abuse_contacts() to detect the mutant
    fail('COND_INV_1998_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2013_3 (MEDIUM) line 2013 in abuse_contacts() ---
# Source:  if ($d->{web_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2013_3 line 2013 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2013 in abuse_contacts() to detect the mutant
    fail('COND_INV_2013_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2015_4 (MEDIUM) line 2015 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2015_4 line 2015 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2015 in abuse_contacts() to detect the mutant
    fail('COND_INV_2015_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2031_3 (MEDIUM) line 2031 in abuse_contacts() ---
# Source:  if ($d->{mx_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2031_3 line 2031 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2031 in abuse_contacts() to detect the mutant
    fail('COND_INV_2031_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2044_3 (MEDIUM) line 2044 in abuse_contacts() ---
# Source:  if ($d->{ns_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2044_3 line 2044 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2044 in abuse_contacts() to detect the mutant
    fail('COND_INV_2044_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2057_3 (MEDIUM) line 2057 in abuse_contacts() ---
# Source:  if ($d->{registrar_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2057_3 line 2057 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2057 in abuse_contacts() to detect the mutant
    fail('COND_INV_2057_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2064_4 (MEDIUM) line 2064 in abuse_contacts() ---
# Source:  unless ($spoofable_only) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_2064_4 line 2064 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2064 in abuse_contacts() to detect the mutant
    fail('COND_INV_2064_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2088_3 (MEDIUM) line 2088 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2088_3 line 2088 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2088 in abuse_contacts() to detect the mutant
    fail('COND_INV_2088_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2102_2 (MEDIUM) line 2102 in abuse_contacts() ---
# Source:  if ($auth->{dkim_domain}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2102_2 line 2102 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2102 in abuse_contacts() to detect the mutant
    fail('COND_INV_2102_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2104_3 (MEDIUM) line 2104 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2104_3 line 2104 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2104 in abuse_contacts() to detect the mutant
    fail('COND_INV_2104_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2116_2 (MEDIUM) line 2116 in abuse_contacts() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2116_2 line 2116 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2116 in abuse_contacts() to detect the mutant
    fail('COND_INV_2116_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2127_4 (MEDIUM) line 2127 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2127_4 line 2127 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2127 in abuse_contacts() to detect the mutant
    fail('COND_INV_2127_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2155_2 (MEDIUM) line 2155 in abuse_contacts() ---
# Source:  return @contacts;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2155_2 line 2155 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2155 in abuse_contacts() to detect the mutant
    fail('BOOL_NEGATE_2155_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2246_2 (MEDIUM) line 2246 in form_contacts() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2246_2 line 2246 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2246 in form_contacts() to detect the mutant
    fail('COND_INV_2246_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2248_3 (MEDIUM) line 2248 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2248_3 line 2248 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2248 in form_contacts() to detect the mutant
    fail('COND_INV_2248_3: replace with real assertion');
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

# --- SURVIVOR: COND_INV_2295_3 (MEDIUM) line 2295 in form_contacts() ---
# Source:  if ($d->{registrar_abuse} && $d->{registrar_abuse} =~ /\@([\w.-]+)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2295_3 line 2295 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2295 in form_contacts() to detect the mutant
    fail('COND_INV_2295_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2298_4 (MEDIUM) line 2298 in form_contacts() ---
# Source:  if ($rpa && $rpa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2298_4 line 2298 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2298 in form_contacts() to detect the mutant
    fail('COND_INV_2298_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2321_3 (MEDIUM) line 2321 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2321_3 line 2321 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2321 in form_contacts() to detect the mutant
    fail('COND_INV_2321_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2337_2 (MEDIUM) line 2337 in form_contacts() ---
# Source:  if ($auth->{dkim_domain}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2337_2 line 2337 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2337 in form_contacts() to detect the mutant
    fail('COND_INV_2337_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2339_3 (MEDIUM) line 2339 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2339_3 line 2339 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2339 in form_contacts() to detect the mutant
    fail('COND_INV_2339_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2353_2 (MEDIUM) line 2353 in form_contacts() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2353_2 line 2353 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2353 in form_contacts() to detect the mutant
    fail('COND_INV_2353_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2360_4 (MEDIUM) line 2360 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2360_4 line 2360 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2360 in form_contacts() to detect the mutant
    fail('COND_INV_2360_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2373_2 (MEDIUM) line 2373 in form_contacts() ---
# Source:  return @contacts;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2373_2 line 2373 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2373 in form_contacts() to detect the mutant
    fail('BOOL_NEGATE_2373_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2463_2 (MEDIUM) line 2463 in report() ---
# Source:  if (@{ $risk->{flags} }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2463_2 line 2463 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2463 in report() to detect the mutant
    fail('COND_INV_2463_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2475_2 (MEDIUM) line 2475 in report() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2475_2 line 2475 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2475 in report() to detect the mutant
    fail('COND_INV_2475_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2490_2 (MEDIUM) line 2490 in report() ---
# Source:  if (@sw) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2490_2 line 2490 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2490 in report() to detect the mutant
    fail('COND_INV_2490_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2502_2 (MEDIUM) line 2502 in report() ---
# Source:  if (@trail) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2502_2 line 2502 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2502 in report() to detect the mutant
    fail('COND_INV_2502_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2517_2 (MEDIUM) line 2517 in report() ---
# Source:  if (@urls) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2517_2 line 2517 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2517 in report() to detect the mutant
    fail('COND_INV_2517_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2522_4 (MEDIUM) line 2522 in report() ---
# Source:  unless (exists $host_order{$h}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_2522_4 line 2522 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2522 in report() to detect the mutant
    fail('COND_INV_2522_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2546_15_!= (HIGH) line 2546 in report() ---
# Source:  if (@paths == 1) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (2 variants — one test should kill all):
#   Numeric boundary flip == to !=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2546_15_!= line 2546 in report()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2546 in report() to detect the mutant
    fail('NUM_BOUNDARY_2546_15_!=: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2562_2 (MEDIUM) line 2562 in report() ---
# Source:  if (@mdoms) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2562_2 line 2562 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2562 in report() to detect the mutant
    fail('COND_INV_2562_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2566_4 (MEDIUM) line 2566 in report() ---
# Source:  if ($d->{recently_registered}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2566_4 line 2566 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2566 in report() to detect the mutant
    fail('COND_INV_2566_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2573_4 (MEDIUM) line 2573 in report() ---
# Source:  if ($d->{web_ip}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2573_4 line 2573 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2573 in report() to detect the mutant
    fail('COND_INV_2573_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2580_4 (MEDIUM) line 2580 in report() ---
# Source:  if ($d->{mx_host}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2580_4 line 2580 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2580 in report() to detect the mutant
    fail('COND_INV_2580_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2588_4 (MEDIUM) line 2588 in report() ---
# Source:  if ($d->{ns_host}) {
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

# --- SURVIVOR: COND_INV_2604_2 (MEDIUM) line 2604 in report() ---
# Source:  if (@contacts) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2604_2 line 2604 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2604 in report() to detect the mutant
    fail('COND_INV_2604_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2619_2 (MEDIUM) line 2619 in report() ---
# Source:  if (@form_cs) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2619_2 line 2619 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2619 in report() to detect the mutant
    fail('COND_INV_2619_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2629_4 (MEDIUM) line 2629 in report() ---
# Source:  if ($c->{form_paste}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2629_4 line 2629 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2629 in report() to detect the mutant
    fail('COND_INV_2629_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2635_46_< (HIGH) line 2635 in report() ---
# Source:  if (defined $line && length("$line $w") > $ROLE_WRAP_LEN) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2635_46_< line 2635 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2635 in report() to detect the mutant
    fail('NUM_BOUNDARY_2635_46_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2680_2 (MEDIUM) line 2680 in _sanitise_output() ---
# Source:  return '' unless defined $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2680_2 line 2680 in _sanitise_output()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2680 in _sanitise_output() to detect the mutant
    fail('BOOL_NEGATE_2680_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2683_2 (MEDIUM) line 2683 in _sanitise_output() ---
# Source:  return $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2683_2 line 2683 in _sanitise_output()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2683 in _sanitise_output() to detect the mutant
    fail('BOOL_NEGATE_2683_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2730_3 (MEDIUM) line 2730 in _split_message() ---
# Source:  if ($line =~ /^([\w-]+)\s*:\s*(.*)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2730_3 line 2730 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2730 in _split_message() to detect the mutant
    fail('COND_INV_2730_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2749_2 (MEDIUM) line 2749 in _split_message() ---
# Source:  if ($ct =~ /multipart/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2749_2 line 2749 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2749 in _split_message() to detect the mutant
    fail('COND_INV_2749_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2755_3 (MEDIUM) line 2755 in _split_message() ---
# Source:  if ($ct =~ /html/i) { $self->{_body_html}  = $decoded }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2755_3 line 2755 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2755 in _split_message() to detect the mutant
    fail('COND_INV_2755_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2829_13_> (HIGH) line 2829 in _decode_multipart() ---
# Source:  if ($depth >= $MAX_MULTIPART_DEPTH) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2829_13_> line 2829 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2829 in _decode_multipart() to detect the mutant
    fail('NUM_BOUNDARY_2829_13_>: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2862_3 (MEDIUM) line 2862 in _decode_multipart() ---
# Source:  if ($pct =~ /multipart/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2862_3 line 2862 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2862 in _decode_multipart() to detect the mutant
    fail('COND_INV_2862_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2864_4 (MEDIUM) line 2864 in _decode_multipart() ---
# Source:  if ($inner_boundary) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2864_4 line 2864 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2864 in _decode_multipart() to detect the mutant
    fail('COND_INV_2864_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2874_3 (MEDIUM) line 2874 in _decode_multipart() ---
# Source:  if    ($pct =~ /text\/html/i)    { $self->{_body_html}  .= $decoded }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2874_3 line 2874 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2874 in _decode_multipart() to detect the mutant
    fail('COND_INV_2874_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2901_2 (MEDIUM) line 2901 in _decode_body() ---
# Source:  return $body // '';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2901_2 line 2901 in _decode_body()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2901 in _decode_body() to detect the mutant
    fail('BOOL_NEGATE_2901_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2945_2 (MEDIUM) line 2945 in _find_origin() ---
# Source:  unless (@candidates) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_2945_2 line 2945 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2945 in _find_origin() to detect the mutant
    fail('COND_INV_2945_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2947_3 (MEDIUM) line 2947 in _find_origin() ---
# Source:  if ($xoip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2947_3 line 2947 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2947 in _find_origin() to detect the mutant
    fail('COND_INV_2947_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2949_4 (MEDIUM) line 2949 in _find_origin() ---
# Source:  return $self->_enrich_ip($xoip, 'low',
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2949_4 line 2949 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2949 in _find_origin() to detect the mutant
    fail('BOOL_NEGATE_2949_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2953_3 (MEDIUM) line 2953 in _find_origin() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2953_3 line 2953 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2953 in _find_origin() to detect the mutant
    fail('BOOL_NEGATE_2953_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2957_2 (MEDIUM) line 2957 in _find_origin() ---
# Source:  return $self->_enrich_ip(
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2957_2 line 2957 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2957 in _find_origin() to detect the mutant
    fail('BOOL_NEGATE_2957_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2959_15_< (HIGH) line 2959 in _find_origin() ---
# Source:  @candidates > 1 ? 'high' : 'medium',
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2959_15_< line 2959 in _find_origin()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2959 in _find_origin() to detect the mutant
    fail('NUM_BOUNDARY_2959_15_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2984_3 (MEDIUM) line 2984 in _extract_ip_from_received() ---
# Source:  if ($hdr =~ $re) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2984_3 line 2984 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2984 in _extract_ip_from_received() to detect the mutant
    fail('COND_INV_2984_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2988_4 (MEDIUM) line 2988 in _extract_ip_from_received() ---
# Source:  return $ip if $ip =~ /:/;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2988_4 line 2988 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2988 in _extract_ip_from_received() to detect the mutant
    fail('BOOL_NEGATE_2988_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2992_22_< (HIGH) line 2992 in _extract_ip_from_received() ---
# Source:  next if grep { $_ > 255 } split /\./, $ip;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2992_22_< line 2992 in _extract_ip_from_received()';
    # Suggested boundary values to test: 254, 255, 256
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2992 in _extract_ip_from_received() to detect the mutant
    fail('NUM_BOUNDARY_2992_22_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2993_4 (MEDIUM) line 2993 in _extract_ip_from_received() ---
# Source:  return $ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2993_4 line 2993 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2993 in _extract_ip_from_received() to detect the mutant
    fail('BOOL_NEGATE_2993_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2996_2 (MEDIUM) line 2996 in _extract_ip_from_received() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2996_2 line 2996 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2996 in _extract_ip_from_received() to detect the mutant
    fail('BOOL_NEGATE_2996_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3018_2 (MEDIUM) line 3018 in _is_private() ---
# Source:  return 1 unless defined $ip && $ip ne '';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3018_2 line 3018 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3018 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_3018_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3019_33 (MEDIUM) line 3019 in _is_private() ---
# Source:  for my $re (@PRIVATE_RANGES) { return 1 if $ip =~ $re }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3019_33 line 3019 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3019 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_3019_33: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3020_2 (MEDIUM) line 3020 in _is_private() ---
# Source:  return 0;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3020_2 line 3020 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3020 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_3020_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3039_3 (MEDIUM) line 3039 in _is_trusted() ---
# Source:  return 1 if $self->_ip_in_cidr($ip, $cidr);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3039_3 line 3039 in _is_trusted()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3039 in _is_trusted() to detect the mutant
    fail('BOOL_NEGATE_3039_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3041_2 (MEDIUM) line 3041 in _is_trusted() ---
# Source:  return 0;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3041_2 line 3041 in _is_trusted()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3041 in _is_trusted() to detect the mutant
    fail('BOOL_NEGATE_3041_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3082_57_< (HIGH) line 3082 in _extract_and_resolve_urls() ---
# Source:  if ($HAS_ANYEVENT_DNS && scalar(keys %hostname_needed) > 1) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3082_57_< line 3082 in _extract_and_resolve_urls()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3082 in _extract_and_resolve_urls() to detect the mutant
    fail('NUM_BOUNDARY_3082_57_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3092_3 (MEDIUM) line 3092 in _extract_and_resolve_urls() ---
# Source:  unless (exists $host_cache{$host}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_3092_3 line 3092 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3092 in _extract_and_resolve_urls() to detect the mutant
    fail('COND_INV_3092_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3095_4 (MEDIUM) line 3095 in _extract_and_resolve_urls() ---
# Source:  if ($cached) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3095_4 line 3095 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3095 in _extract_and_resolve_urls() to detect the mutant
    fail('COND_INV_3095_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3104_5 (MEDIUM) line 3104 in _extract_and_resolve_urls() ---
# Source:  if (!$whois->{abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3104_5 line 3104 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3104 in _extract_and_resolve_urls() to detect the mutant
    fail('COND_INV_3104_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3161_5 (MEDIUM) line 3161 in _parallel_resolve_hosts() ---
# Source:  if (@answers) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3161_5 line 3161 in _parallel_resolve_hosts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3161 in _parallel_resolve_hosts() to detect the mutant
    fail('COND_INV_3161_5: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3166_29_< (HIGH) line 3166 in _parallel_resolve_hosts() ---
# Source:  $cv->send if --$pending <= 0;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3166_29_< line 3166 in _parallel_resolve_hosts()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3166 in _parallel_resolve_hosts() to detect the mutant
    fail('NUM_BOUNDARY_3166_29_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3193_2 (MEDIUM) line 3193 in _extract_http_urls() ---
# Source:  if ($HAS_HTML_LINKEXTOR) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3193_2 line 3193 in _extract_http_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3193 in _extract_http_urls() to detect the mutant
    fail('COND_INV_3193_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3198_5 (MEDIUM) line 3198 in _extract_http_urls() ---
# Source:  if ($val =~ m{^https?://}i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3198_5 line 3198 in _extract_http_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3198 in _extract_http_urls() to detect the mutant
    fail('COND_INV_3198_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3223_2 (MEDIUM) line 3223 in _extract_http_urls() ---
# Source:  return @all;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3223_2 line 3223 in _extract_http_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3223 in _extract_http_urls() to detect the mutant
    fail('BOOL_NEGATE_3223_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3302_2 (MEDIUM) line 3302 in _extract_and_analyse_domains() ---
# Source:  if ($mid && $mid =~ /\@([\w.-]+)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3302_2 line 3302 in _extract_and_analyse_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3302 in _extract_and_analyse_domains() to detect the mutant
    fail('COND_INV_3302_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3317_2 (MEDIUM) line 3317 in _extract_and_analyse_domains() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3317_2 line 3317 in _extract_and_analyse_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3317 in _extract_and_analyse_domains() to detect the mutant
    fail('COND_INV_3317_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3367_2 (MEDIUM) line 3367 in _domains_from_text() ---
# Source:  return @out;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3367_2 line 3367 in _domains_from_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3367 in _domains_from_text() to detect the mutant
    fail('BOOL_NEGATE_3367_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3401_2 (MEDIUM) line 3401 in _analyse_domain() ---
# Source:  return $self->{_domain_info}{$domain}
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3401_2 line 3401 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3401 in _analyse_domain() to detect the mutant
    fail('BOOL_NEGATE_3401_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3405_2 (MEDIUM) line 3405 in _analyse_domain() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3405_2 line 3405 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3405 in _analyse_domain() to detect the mutant
    fail('COND_INV_3405_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3407_3 (MEDIUM) line 3407 in _analyse_domain() ---
# Source:  if ($cached) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3407_3 line 3407 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3407 in _analyse_domain() to detect the mutant
    fail('COND_INV_3407_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3409_4 (MEDIUM) line 3409 in _analyse_domain() ---
# Source:  return $cached;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3409_4 line 3409 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3409 in _analyse_domain() to detect the mutant
    fail('BOOL_NEGATE_3409_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3418_2 (MEDIUM) line 3418 in _analyse_domain() ---
# Source:  if ($web_ip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3418_2 line 3418 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3418 in _analyse_domain() to detect the mutant
    fail('COND_INV_3418_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3426_2 (MEDIUM) line 3426 in _analyse_domain() ---
# Source:  if ($HAS_NET_DNS) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3426_2 line 3426 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3426 in _analyse_domain() to detect the mutant
    fail('COND_INV_3426_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3434_3 (MEDIUM) line 3434 in _analyse_domain() ---
# Source:  if ($mxq) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3434_3 line 3434 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3434 in _analyse_domain() to detect the mutant
    fail('COND_INV_3434_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3437_4 (MEDIUM) line 3437 in _analyse_domain() ---
# Source:  if ($best) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3437_4 line 3437 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3437 in _analyse_domain() to detect the mutant
    fail('COND_INV_3437_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3441_5 (MEDIUM) line 3441 in _analyse_domain() ---
# Source:  if ($mx_ip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3441_5 line 3441 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3441 in _analyse_domain() to detect the mutant
    fail('COND_INV_3441_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3452_3 (MEDIUM) line 3452 in _analyse_domain() ---
# Source:  if ($nsq) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3452_3 line 3452 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3452 in _analyse_domain() to detect the mutant
    fail('COND_INV_3452_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3454_4 (MEDIUM) line 3454 in _analyse_domain() ---
# Source:  if ($first) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3454_4 line 3454 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3454 in _analyse_domain() to detect the mutant
    fail('COND_INV_3454_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3458_5 (MEDIUM) line 3458 in _analyse_domain() ---
# Source:  if ($ns_ip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3458_5 line 3458 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3458 in _analyse_domain() to detect the mutant
    fail('COND_INV_3458_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3470_2 (MEDIUM) line 3470 in _analyse_domain() ---
# Source:  if ($domain_whois) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3470_2 line 3470 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3470 in _analyse_domain() to detect the mutant
    fail('COND_INV_3470_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3475_3 (MEDIUM) line 3475 in _analyse_domain() ---
# Source:  if ($domain_whois =~ /Registrar:\s*(.+)/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3475_3 line 3475 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3475 in _analyse_domain() to detect the mutant
    fail('COND_INV_3475_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3485_4 (MEDIUM) line 3485 in _analyse_domain() ---
# Source:  if (!$info{registrar_abuse} && $domain_whois =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3485_4 line 3485 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3485 in _analyse_domain() to detect the mutant
    fail('COND_INV_3485_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3497_4 (MEDIUM) line 3497 in _analyse_domain() ---
# Source:  if (!$info{registered} && $domain_whois =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3497_4 line 3497 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3497 in _analyse_domain() to detect the mutant
    fail('COND_INV_3497_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3508_4 (MEDIUM) line 3508 in _analyse_domain() ---
# Source:  if (!$info{expires} && $domain_whois =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3508_4 line 3508 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3508 in _analyse_domain() to detect the mutant
    fail('COND_INV_3508_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3514_3 (MEDIUM) line 3514 in _analyse_domain() ---
# Source:  if ($info{registered}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3514_3 line 3514 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3514 in _analyse_domain() to detect the mutant
    fail('COND_INV_3514_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3517_36_> (HIGH) line 3517 in _analyse_domain() ---
# Source:  if $epoch && (time() - $epoch) < $RECENT_REG_DAYS * $SECS_PER_DAY;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip < to >
#   Numeric boundary flip < to <=
#   Numeric boundary flip < to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3517_36_> line 3517 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3517 in _analyse_domain() to detect the mutant
    fail('NUM_BOUNDARY_3517_36_>: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3551_2 (MEDIUM) line 3551 in _resolve_host() ---
# Source:  return $host if $host =~ /^\d{1,3}(?:\.\d{1,3}){3}$/;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3551_2 line 3551 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3551 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_3551_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3554_2 (MEDIUM) line 3554 in _resolve_host() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3554_2 line 3554 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3554 in _resolve_host() to detect the mutant
    fail('COND_INV_3554_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3556_3 (MEDIUM) line 3556 in _resolve_host() ---
# Source:  return $cached_ip if defined $cached_ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3556_3 line 3556 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3556 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_3556_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3561_2 (MEDIUM) line 3561 in _resolve_host() ---
# Source:  if ($HAS_NET_DNS) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3561_2 line 3561 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3561 in _resolve_host() to detect the mutant
    fail('COND_INV_3561_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3570_4 (MEDIUM) line 3570 in _resolve_host() ---
# Source:  if ($query) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3570_4 line 3570 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3570 in _resolve_host() to detect the mutant
    fail('COND_INV_3570_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3572_6 (MEDIUM) line 3572 in _resolve_host() ---
# Source:  if ($rr->type eq 'A') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3572_6 line 3572 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3572 in _resolve_host() to detect the mutant
    fail('COND_INV_3572_6: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3590_2 (MEDIUM) line 3590 in _resolve_host() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3590_2 line 3590 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3590 in _resolve_host() to detect the mutant
    fail('COND_INV_3590_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3594_2 (MEDIUM) line 3594 in _resolve_host() ---
# Source:  return $ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3594_2 line 3594 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3594 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_3594_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3611_2 (MEDIUM) line 3611 in _reverse_dns() ---
# Source:  return undef unless $ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3611_2 line 3611 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3611 in _reverse_dns() to detect the mutant
    fail('BOOL_NEGATE_3611_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3613_2 (MEDIUM) line 3613 in _reverse_dns() ---
# Source:  if ($HAS_NET_DNS) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3613_2 line 3613 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3613 in _reverse_dns() to detect the mutant
    fail('COND_INV_3613_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3616_3 (MEDIUM) line 3616 in _reverse_dns() ---
# Source:  if ($query) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3616_3 line 3616 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3616 in _reverse_dns() to detect the mutant
    fail('COND_INV_3616_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3618_5 (MEDIUM) line 3618 in _reverse_dns() ---
# Source:  return $rr->ptrdname if $rr->type eq 'PTR';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3618_5 line 3618 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3618 in _reverse_dns() to detect the mutant
    fail('BOOL_NEGATE_3618_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3621_3 (MEDIUM) line 3621 in _reverse_dns() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3621_3 line 3621 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3621 in _reverse_dns() to detect the mutant
    fail('BOOL_NEGATE_3621_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3649_2 (MEDIUM) line 3649 in _whois_ip() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3649_2 line 3649 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3649 in _whois_ip() to detect the mutant
    fail('COND_INV_3649_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3651_3 (MEDIUM) line 3651 in _whois_ip() ---
# Source:  return $cached if $cached;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3651_3 line 3651 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3651 in _whois_ip() to detect the mutant
    fail('BOOL_NEGATE_3651_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3657_2 (MEDIUM) line 3657 in _whois_ip() ---
# Source:  unless ($result->{org}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_3657_2 line 3657 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3657 in _whois_ip() to detect the mutant
    fail('COND_INV_3657_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3659_3 (MEDIUM) line 3659 in _whois_ip() ---
# Source:  if ($raw) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3659_3 line 3659 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3659 in _whois_ip() to detect the mutant
    fail('COND_INV_3659_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3669_2 (MEDIUM) line 3669 in _whois_ip() ---
# Source:  return $result;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3669_2 line 3669 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3669 in _whois_ip() to detect the mutant
    fail('BOOL_NEGATE_3669_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3688_2 (MEDIUM) line 3688 in _domain_whois() ---
# Source:  return undef unless $server;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3688_2 line 3688 in _domain_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3688 in _domain_whois() to detect the mutant
    fail('BOOL_NEGATE_3688_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3689_2 (MEDIUM) line 3689 in _domain_whois() ---
# Source:  return $self->_raw_whois($domain, $server);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3689_2 line 3689 in _domain_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3689 in _domain_whois() to detect the mutant
    fail('BOOL_NEGATE_3689_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3709_2 (MEDIUM) line 3709 in _parse_domain_whois_abuse() ---
# Source:  if ($raw =~ /Registrar:\s*(.+)/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3709_2 line 3709 in _parse_domain_whois_abuse()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3709 in _parse_domain_whois_abuse() to detect the mutant
    fail('COND_INV_3709_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3718_3 (MEDIUM) line 3718 in _parse_domain_whois_abuse() ---
# Source:  if (!$info{abuse} && $raw =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3718_3 line 3718 in _parse_domain_whois_abuse()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3718 in _parse_domain_whois_abuse() to detect the mutant
    fail('COND_INV_3718_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3743_2 (MEDIUM) line 3743 in _rdap_lookup() ---
# Source:  if(!defined($ua)) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3743_2 line 3743 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3743 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3743_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3749_3 (MEDIUM) line 3749 in _rdap_lookup() ---
# Source:  if($HAS_CONN_CACHE) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3749_3 line 3749 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3749 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3749_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3772_2 (MEDIUM) line 3772 in _rdap_lookup() ---
# Source:  if ($j =~ /"abuse".*?"email"\s*:\s*"([^"]+)"/s) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3772_2 line 3772 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3772 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3772_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3824_2 (MEDIUM) line 3824 in _raw_whois() ---
# Source:  return undef unless $sock;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3824_2 line 3824 in _raw_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3824 in _raw_whois() to detect the mutant
    fail('BOOL_NEGATE_3824_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3827_53 (MEDIUM) line 3827 in _raw_whois() ---
# Source:  $sock->print("$query\r\n") or do { $sock->close(); return undef };
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3827_53 line 3827 in _raw_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3827 in _raw_whois() to detect the mutant
    fail('BOOL_NEGATE_3827_53: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3839_31_< (HIGH) line 3839 in _raw_whois() ---
# Source:  if ($@ || !defined $n || $n <= 0) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3839_31_< line 3839 in _raw_whois()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3839 in _raw_whois() to detect the mutant
    fail('NUM_BOUNDARY_3839_31_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3843_32_< (HIGH) line 3843 in _raw_whois() ---
# Source:  last unless defined $n && $n > 0;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3843_32_< line 3843 in _raw_whois()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3843 in _raw_whois() to detect the mutant
    fail('NUM_BOUNDARY_3843_32_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3848_2 (MEDIUM) line 3848 in _raw_whois() ---
# Source:  return $response || undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3848_2 line 3848 in _raw_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3848 in _raw_whois() to detect the mutant
    fail('BOOL_NEGATE_3848_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3873_3 (MEDIUM) line 3873 in _parse_whois_text() ---
# Source:  if (!$info{org} && $text =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3873_3 line 3873 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3873 in _parse_whois_text() to detect the mutant
    fail('COND_INV_3873_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3883_3 (MEDIUM) line 3883 in _parse_whois_text() ---
# Source:  if (!$info{abuse} && $text =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3883_3 line 3883 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3883 in _parse_whois_text() to detect the mutant
    fail('COND_INV_3883_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3892_2 (MEDIUM) line 3892 in _parse_whois_text() ---
# Source:  if ($text =~ /^country:\s*([A-Za-z]{2})\s*$/m) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3892_2 line 3892 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3892 in _parse_whois_text() to detect the mutant
    fail('COND_INV_3892_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3918_2 (MEDIUM) line 3918 in _parse_auth_results_cached() ---
# Source:  return $self->{_auth_results} if $self->{_auth_results};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3918_2 line 3918 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3918 in _parse_auth_results_cached() to detect the mutant
    fail('BOOL_NEGATE_3918_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3944_3 (MEDIUM) line 3944 in _parse_auth_results_cached() ---
# Source:  if ($h->{value} =~ /\bd=([^;,\s]+)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3944_3 line 3944 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3944 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_3944_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3949_2 (MEDIUM) line 3949 in _parse_auth_results_cached() ---
# Source:  if (@dkim_domains) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3949_2 line 3949 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3949 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_3949_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3953_4 (MEDIUM) line 3953 in _parse_auth_results_cached() ---
# Source:  if ($self->_provider_abuse_for_host($d)) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3953_4 line 3953 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3953 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_3953_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3987_3 (MEDIUM) line 3987 in _provider_abuse_for_host() ---
# Source:  return $self->{provider_abuse}->{$host} if $self->{provider_abuse}->{$host};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3987_3 line 3987 in _provider_abuse_for_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3987 in _provider_abuse_for_host() to detect the mutant
    fail('BOOL_NEGATE_3987_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3991_2 (MEDIUM) line 3991 in _provider_abuse_for_host() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3991_2 line 3991 in _provider_abuse_for_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3991 in _provider_abuse_for_host() to detect the mutant
    fail('BOOL_NEGATE_3991_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4009_2 (MEDIUM) line 4009 in _provider_abuse_for_ip() ---
# Source:  return $self->_provider_abuse_for_host($rdns) if $rdns;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4009_2 line 4009 in _provider_abuse_for_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4009 in _provider_abuse_for_ip() to detect the mutant
    fail('BOOL_NEGATE_4009_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4010_2 (MEDIUM) line 4010 in _provider_abuse_for_ip() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4010_2 line 4010 in _provider_abuse_for_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4010 in _provider_abuse_for_ip() to detect the mutant
    fail('BOOL_NEGATE_4010_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4037_2 (MEDIUM) line 4037 in _registrable() ---
# Source:  return undef unless $host && $host =~ /\./;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4037_2 line 4037 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4037 in _registrable() to detect the mutant
    fail('BOOL_NEGATE_4037_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4040_2 (MEDIUM) line 4040 in _registrable() ---
# Source:  if ($HAS_PUBLIC_SUFFIX) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4040_2 line 4040 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4040 in _registrable() to detect the mutant
    fail('COND_INV_4040_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4043_3 (MEDIUM) line 4043 in _registrable() ---
# Source:  return $root if $root;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4043_3 line 4043 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4043 in _registrable() to detect the mutant
    fail('BOOL_NEGATE_4043_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4048_26_< (HIGH) line 4048 in _registrable() ---
# Source:  return $host if @labels <= 2;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4048_26_< line 4048 in _registrable()';
    # Suggested boundary values to test: 1, 2, 3
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4048 in _registrable() to detect the mutant
    fail('NUM_BOUNDARY_4048_26_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4051_2 (MEDIUM) line 4051 in _registrable() ---
# Source:  if ($labels[-1] =~ /^[a-z]{2}$/ &&
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4051_2 line 4051 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4051 in _registrable() to detect the mutant
    fail('COND_INV_4051_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4107_3 (MEDIUM) line 4107 in _header_value() ---
# Source:  return $h->{value} if $h->{name} eq lc($name);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4107_3 line 4107 in _header_value()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4107 in _header_value() to detect the mutant
    fail('BOOL_NEGATE_4107_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4109_2 (MEDIUM) line 4109 in _header_value() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4109_2 line 4109 in _header_value()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4109 in _header_value() to detect the mutant
    fail('BOOL_NEGATE_4109_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4127_2 (MEDIUM) line 4127 in _ip_in_cidr() ---
# Source:  return $ip eq $cidr unless $cidr =~ m{/};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4127_2 line 4127 in _ip_in_cidr()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4127 in _ip_in_cidr() to detect the mutant
    fail('BOOL_NEGATE_4127_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4129_67_< (HIGH) line 4129 in _ip_in_cidr() ---
# Source:  return 0 unless defined $prefix && $prefix =~ /^\d+$/ && $prefix <= 32;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4129_67_< line 4129 in _ip_in_cidr()';
    # Suggested boundary values to test: 31, 32, 33
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4129 in _ip_in_cidr() to detect the mutant
    fail('NUM_BOUNDARY_4129_67_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4135_25_!= (HIGH) line 4135 in _ip_in_cidr() ---
# Source:  return ($ip_n & $mask) == ($net_n & $mask);
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (1 variant):
#   Numeric boundary flip == to !=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4135_25_!= line 4135 in _ip_in_cidr()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4135 in _ip_in_cidr() to detect the mutant
    fail('NUM_BOUNDARY_4135_25_!=: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4152_2 (MEDIUM) line 4152 in _decode_mime_words() ---
# Source:  return '' unless defined $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4152_2 line 4152 in _decode_mime_words()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4152 in _decode_mime_words() to detect the mutant
    fail('BOOL_NEGATE_4152_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4155_2 (MEDIUM) line 4155 in _decode_mime_words() ---
# Source:  return $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4155_2 line 4155 in _decode_mime_words()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4155 in _decode_mime_words() to detect the mutant
    fail('BOOL_NEGATE_4155_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4170_2 (MEDIUM) line 4170 in _decode_ew() ---
# Source:  if (uc($enc) eq 'B') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4170_2 line 4170 in _decode_ew()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4170 in _decode_ew() to detect the mutant
    fail('COND_INV_4170_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4177_2 (MEDIUM) line 4177 in _decode_ew() ---
# Source:  return $raw;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4177_2 line 4177 in _decode_ew()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4177 in _decode_ew() to detect the mutant
    fail('BOOL_NEGATE_4177_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4194_2 (MEDIUM) line 4194 in _parse_date_to_epoch() ---
# Source:  return undef unless $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4194_2 line 4194 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4194 in _parse_date_to_epoch() to detect the mutant
    fail('BOOL_NEGATE_4194_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4200_2 (MEDIUM) line 4200 in _parse_date_to_epoch() ---
# Source:  if ($str =~ /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?Z$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4200_2 line 4200 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4200 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_4200_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4212_4 (MEDIUM) line 4212 in _parse_date_to_epoch() ---
# Source:  return $t->epoch - $t->tzoffset->seconds;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4212_4 line 4212 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4212 in _parse_date_to_epoch() to detect the mutant
    fail('BOOL_NEGATE_4212_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4214_3 (MEDIUM) line 4214 in _parse_date_to_epoch() ---
# Source:  return $epoch if defined $epoch;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4214_3 line 4214 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4214 in _parse_date_to_epoch() to detect the mutant
    fail('BOOL_NEGATE_4214_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4218_2 (MEDIUM) line 4218 in _parse_date_to_epoch() ---
# Source:  if    ($str =~ /^(\d{4})-(\d{2})-(\d{2})/)         { ($y,$m,$d)=($1,$2,$3) }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4218_2 line 4218 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4218 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_4218_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4222_2 (MEDIUM) line 4222 in _parse_date_to_epoch() ---
# Source:  return undef unless $y && $m && $d;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4222_2 line 4222 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4222 in _parse_date_to_epoch() to detect the mutant
    fail('BOOL_NEGATE_4222_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4224_2 (MEDIUM) line 4224 in _parse_date_to_epoch() ---
# Source:  if (eval { require Time::Local; 1 }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4224_2 line 4224 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4224 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_4224_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4247_2 (MEDIUM) line 4247 in _parse_rfc2822_date() ---
# Source:  return undef unless $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4247_2 line 4247 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4247 in _parse_rfc2822_date() to detect the mutant
    fail('BOOL_NEGATE_4247_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4250_2 (MEDIUM) line 4250 in _parse_rfc2822_date() ---
# Source:  if ($str =~ /(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4250_2 line 4250 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4250 in _parse_rfc2822_date() to detect the mutant
    fail('COND_INV_4250_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4253_3 (MEDIUM) line 4253 in _parse_rfc2822_date() ---
# Source:  return undef unless $m;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4253_3 line 4253 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4253 in _parse_rfc2822_date() to detect the mutant
    fail('BOOL_NEGATE_4253_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4254_3 (MEDIUM) line 4254 in _parse_rfc2822_date() ---
# Source:  if (eval { require Time::Local; 1 }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4254_3 line 4254 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4254 in _parse_rfc2822_date() to detect the mutant
    fail('COND_INV_4254_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4258_2 (MEDIUM) line 4258 in _parse_rfc2822_date() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4258_2 line 4258 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4258 in _parse_rfc2822_date() to detect the mutant
    fail('BOOL_NEGATE_4258_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4298_2 (MEDIUM) line 4298 in _debug() ---
# Source:  if($self->{verbose}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4298_2 line 4298 in _debug()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4298 in _debug() to detect the mutant
    fail('COND_INV_4298_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4299_3 (MEDIUM) line 4299 in _debug() ---
# Source:  if(my $logger = $self->{logger}) {	# May have been set in Object::Configure
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4299_3 line 4299 in _debug()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4299 in _debug() to detect the mutant
    fail('COND_INV_4299_3: replace with real assertion');
}

# --- LOW DIFFICULTY HINTS (comment stubs) ---

# --- LOW HINT: RETURN_UNDEF_781_2 line 781 in parse_email() ---
# Source:  return $self;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_781_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_867_2 line 867 in originating_ip() ---
# Source:  return $self->{_origin};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_867_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1112_2 line 1112 in all_domains() ---
# Source:  return @out;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1112_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1228_2 line 1228 in unresolved_contacts() ---
# Source:  return @out;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1228_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1463_2 line 1463 in risk_assessment() ---
# Source:  return $self->{_risk} if $self->{_risk};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1463_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1704_2 line 1704 in risk_assessment() ---
# Source:  return $self->{_risk};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1704_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2155_2 line 2155 in abuse_contacts() ---
# Source:  return @contacts;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2155_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2373_2 line 2373 in form_contacts() ---
# Source:  return @contacts;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2373_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2680_2 line 2680 in _sanitise_output() ---
# Source:  return '' unless defined $str;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2680_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2683_2 line 2683 in _sanitise_output() ---
# Source:  return $str;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2683_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2901_2 line 2901 in _decode_body() ---
# Source:  return $body // '';
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2901_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2949_4 line 2949 in _find_origin() ---
# Source:  return $self->_enrich_ip($xoip, 'low',
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2949_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2953_3 line 2953 in _find_origin() ---
# Source:  return undef;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2953_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2957_2 line 2957 in _find_origin() ---
# Source:  return $self->_enrich_ip(
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2957_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2988_4 line 2988 in _extract_ip_from_received() ---
# Source:  return $ip if $ip =~ /:/;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2988_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2993_4 line 2993 in _extract_ip_from_received() ---
# Source:  return $ip;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2993_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2996_2 line 2996 in _extract_ip_from_received() ---
# Source:  return undef;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2996_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3018_2 line 3018 in _is_private() ---
# Source:  return 1 unless defined $ip && $ip ne '';
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3018_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3019_33 line 3019 in _is_private() ---
# Source:  for my $re (@PRIVATE_RANGES) { return 1 if $ip =~ $re }
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3019_33: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3020_2 line 3020 in _is_private() ---
# Source:  return 0;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3020_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3039_3 line 3039 in _is_trusted() ---
# Source:  return 1 if $self->_ip_in_cidr($ip, $cidr);
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3039_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3041_2 line 3041 in _is_trusted() ---
# Source:  return 0;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3041_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3223_2 line 3223 in _extract_http_urls() ---
# Source:  return @all;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3223_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3367_2 line 3367 in _domains_from_text() ---
# Source:  return @out;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3367_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3401_2 line 3401 in _analyse_domain() ---
# Source:  return $self->{_domain_info}{$domain}
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3401_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3409_4 line 3409 in _analyse_domain() ---
# Source:  return $cached;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3409_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3551_2 line 3551 in _resolve_host() ---
# Source:  return $host if $host =~ /^\d{1,3}(?:\.\d{1,3}){3}$/;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3551_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3556_3 line 3556 in _resolve_host() ---
# Source:  return $cached_ip if defined $cached_ip;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3556_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3594_2 line 3594 in _resolve_host() ---
# Source:  return $ip;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3594_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3611_2 line 3611 in _reverse_dns() ---
# Source:  return undef unless $ip;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3611_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3618_5 line 3618 in _reverse_dns() ---
# Source:  return $rr->ptrdname if $rr->type eq 'PTR';
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3618_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3621_3 line 3621 in _reverse_dns() ---
# Source:  return undef;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3621_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3651_3 line 3651 in _whois_ip() ---
# Source:  return $cached if $cached;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3651_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3669_2 line 3669 in _whois_ip() ---
# Source:  return $result;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3669_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3688_2 line 3688 in _domain_whois() ---
# Source:  return undef unless $server;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3688_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3689_2 line 3689 in _domain_whois() ---
# Source:  return $self->_raw_whois($domain, $server);
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3689_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3824_2 line 3824 in _raw_whois() ---
# Source:  return undef unless $sock;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3824_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3827_53 line 3827 in _raw_whois() ---
# Source:  $sock->print("$query\r\n") or do { $sock->close(); return undef };
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3827_53: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3848_2 line 3848 in _raw_whois() ---
# Source:  return $response || undef;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3848_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3918_2 line 3918 in _parse_auth_results_cached() ---
# Source:  return $self->{_auth_results} if $self->{_auth_results};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3918_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3987_3 line 3987 in _provider_abuse_for_host() ---
# Source:  return $self->{provider_abuse}->{$host} if $self->{provider_abuse}->{$host};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3987_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3991_2 line 3991 in _provider_abuse_for_host() ---
# Source:  return undef;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3991_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4009_2 line 4009 in _provider_abuse_for_ip() ---
# Source:  return $self->_provider_abuse_for_host($rdns) if $rdns;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4009_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4010_2 line 4010 in _provider_abuse_for_ip() ---
# Source:  return undef;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4010_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4037_2 line 4037 in _registrable() ---
# Source:  return undef unless $host && $host =~ /\./;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4037_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4043_3 line 4043 in _registrable() ---
# Source:  return $root if $root;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4043_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4048_2 line 4048 in _registrable() ---
# Source:  return $host if @labels <= 2;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4048_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4107_3 line 4107 in _header_value() ---
# Source:  return $h->{value} if $h->{name} eq lc($name);
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4107_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4109_2 line 4109 in _header_value() ---
# Source:  return undef;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4109_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4127_2 line 4127 in _ip_in_cidr() ---
# Source:  return $ip eq $cidr unless $cidr =~ m{/};
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4127_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4129_2 line 4129 in _ip_in_cidr() ---
# Source:  return 0 unless defined $prefix && $prefix =~ /^\d+$/ && $prefix <= 32;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4129_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4152_2 line 4152 in _decode_mime_words() ---
# Source:  return '' unless defined $str;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4152_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4155_2 line 4155 in _decode_mime_words() ---
# Source:  return $str;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4155_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4177_2 line 4177 in _decode_ew() ---
# Source:  return $raw;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4177_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4194_2 line 4194 in _parse_date_to_epoch() ---
# Source:  return undef unless $str;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4194_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4212_4 line 4212 in _parse_date_to_epoch() ---
# Source:  return $t->epoch - $t->tzoffset->seconds;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4212_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4214_3 line 4214 in _parse_date_to_epoch() ---
# Source:  return $epoch if defined $epoch;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4214_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4222_2 line 4222 in _parse_date_to_epoch() ---
# Source:  return undef unless $y && $m && $d;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4222_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4247_2 line 4247 in _parse_rfc2822_date() ---
# Source:  return undef unless $str;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4247_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4253_3 line 4253 in _parse_rfc2822_date() ---
# Source:  return undef unless $m;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4253_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4258_2 line 4258 in _parse_rfc2822_date() ---
# Source:  return undef;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4258_2: add assertion here');

done_testing();
