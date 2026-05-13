#!/usr/bin/env perl
# Auto-generated mutant test stubs
# Generated: 2026-05-13 14:14:03
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

# --- SURVIVOR: COND_INV_622_2 (MEDIUM) line 622 in new() ---
# Source:  if ($HAS_CHI && !$_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_622_2 line 622 in new()';
    # NOTE: new is a class method — call directly.
    my $result = Email::Abuse::Investigator->new(...);
    # ok($result, 'COND_INV_622_2: add assertion here');
    # TODO: exercise line 622 in new() to detect the mutant
    fail('COND_INV_622_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_775_2 (MEDIUM) line 775 in parse_email() ---
# Source:  return $self;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_775_2 line 775 in parse_email()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 775 in parse_email() to detect the mutant
    fail('BOOL_NEGATE_775_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_860_2 (MEDIUM) line 860 in originating_ip() ---
# Source:  return $self->{_origin};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_860_2 line 860 in originating_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 860 in originating_ip() to detect the mutant
    fail('BOOL_NEGATE_860_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1103_2 (MEDIUM) line 1103 in all_domains() ---
# Source:  return @out;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1103_2 line 1103 in all_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1103 in all_domains() to detect the mutant
    fail('BOOL_NEGATE_1103_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1178_3 (MEDIUM) line 1178 in unresolved_contacts() ---
# Source:  unless ($dom) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_1178_3 line 1178 in unresolved_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1178 in unresolved_contacts() to detect the mutant
    fail('COND_INV_1178_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1219_2 (MEDIUM) line 1219 in unresolved_contacts() ---
# Source:  return @out;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1219_2 line 1219 in unresolved_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1219 in unresolved_contacts() to detect the mutant
    fail('BOOL_NEGATE_1219_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1451_2 (MEDIUM) line 1451 in risk_assessment() ---
# Source:  return $self->{_risk} if $self->{_risk};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1451_2 line 1451 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1451 in risk_assessment() to detect the mutant
    fail('BOOL_NEGATE_1451_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1465_2 (MEDIUM) line 1465 in risk_assessment() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1465_2 line 1465 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1465 in risk_assessment() to detect the mutant
    fail('COND_INV_1465_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1467_3 (MEDIUM) line 1467 in risk_assessment() ---
# Source:  if ($orig->{rdns} && $orig->{rdns} =~ /
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1467_3 line 1467 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1467 in risk_assessment() to detect the mutant
    fail('COND_INV_1467_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1478_3 (MEDIUM) line 1478 in risk_assessment() ---
# Source:  if (!$orig->{rdns} || $orig->{rdns} eq '(no reverse DNS)') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1478_3 line 1478 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1478 in risk_assessment() to detect the mutant
    fail('COND_INV_1478_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1484_3 (MEDIUM) line 1484 in risk_assessment() ---
# Source:  if ($orig->{confidence} eq 'low') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1484_3 line 1484 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1484 in risk_assessment() to detect the mutant
    fail('COND_INV_1484_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1490_3 (MEDIUM) line 1490 in risk_assessment() ---
# Source:  if ($orig->{country} && $orig->{country} =~ /^(?:CN|RU|NG|VN|IN|PK|BD)$/) {
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

# --- SURVIVOR: COND_INV_1499_2 (MEDIUM) line 1499 in risk_assessment() ---
# Source:  if (defined $auth->{spf}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1499_2 line 1499 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1499 in risk_assessment() to detect the mutant
    fail('COND_INV_1499_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1500_3 (MEDIUM) line 1500 in risk_assessment() ---
# Source:  if ($auth->{spf} =~ /^fail/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1500_3 line 1500 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1500 in risk_assessment() to detect the mutant
    fail('COND_INV_1500_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1511_2 (MEDIUM) line 1511 in risk_assessment() ---
# Source:  if (defined $auth->{dkim} && $auth->{dkim} !~ /^pass/i) {
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

# --- SURVIVOR: COND_INV_1515_2 (MEDIUM) line 1515 in risk_assessment() ---
# Source:  if (defined $auth->{dmarc} && $auth->{dmarc} !~ /^pass/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1515_2 line 1515 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1515 in risk_assessment() to detect the mutant
    fail('COND_INV_1515_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1520_2 (MEDIUM) line 1520 in risk_assessment() ---
# Source:  if ($auth->{dkim_domain}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1520_2 line 1520 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1520 in risk_assessment() to detect the mutant
    fail('COND_INV_1520_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1522_3 (MEDIUM) line 1522 in risk_assessment() ---
# Source:  if ($from_domain) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1522_3 line 1522 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1522 in risk_assessment() to detect the mutant
    fail('COND_INV_1522_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1525_4 (MEDIUM) line 1525 in risk_assessment() ---
# Source:  if ($reg_dkim ne $reg_from) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1525_4 line 1525 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1525 in risk_assessment() to detect the mutant
    fail('COND_INV_1525_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1527_5 (MEDIUM) line 1527 in risk_assessment() ---
# Source:  if ($auth->{dkim} && $auth->{dkim} =~ /^pass/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1527_5 line 1527 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1527 in risk_assessment() to detect the mutant
    fail('COND_INV_1527_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1543_2 (MEDIUM) line 1543 in risk_assessment() ---
# Source:  if (!$date_raw || $date_raw !~ /\S/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1543_2 line 1543 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1543 in risk_assessment() to detect the mutant
    fail('COND_INV_1543_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1548_3 (MEDIUM) line 1548 in risk_assessment() ---
# Source:  if ($date_raw =~ /([+-])(\d{2})(\d{2})\s*$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1548_3 line 1548 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1548 in risk_assessment() to detect the mutant
    fail('COND_INV_1548_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1551_26_> (HIGH) line 1551 in risk_assessment() ---
# Source:  my $implausible = $mm >= 60
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1551_26_> line 1551 in risk_assessment()';
    # Suggested boundary values to test: 59, 60, 61
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1551 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1551_26_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1552_38_< (HIGH) line 1552 in risk_assessment() ---
# Source:  || ($sign eq '+' && $offset_mins > $TZ_MAX_POS_MINS)
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1552_38_< line 1552 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1552 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1552_38_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1553_38_< (HIGH) line 1553 in risk_assessment() ---
# Source:  || ($sign eq '-' && $offset_mins > $TZ_MAX_NEG_MINS);
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1553_38_< line 1553 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1553 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1553_38_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1554_4 (MEDIUM) line 1554 in risk_assessment() ---
# Source:  if ($implausible) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1554_4 line 1554 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1554 in risk_assessment() to detect the mutant
    fail('COND_INV_1554_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1563_3 (MEDIUM) line 1563 in risk_assessment() ---
# Source:  if (defined $date_epoch) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1563_3 line 1563 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1563 in risk_assessment() to detect the mutant
    fail('COND_INV_1563_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1565_15_< (HIGH) line 1565 in risk_assessment() ---
# Source:  if ($delta > $DATE_SKEW_DAYS * $SECS_PER_DAY) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1565_15_< line 1565 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1565 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1565_15_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1568_20_> (HIGH) line 1568 in risk_assessment() ---
# Source:  } elsif ($delta < -($DATE_SKEW_DAYS * $SECS_PER_DAY)) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip < to >
#   Numeric boundary flip < to <=
#   Numeric boundary flip < to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1568_20_> line 1568 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1568 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1568_20_>: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1580_2 (MEDIUM) line 1580 in risk_assessment() ---
# Source:  if ($from_decoded =~ /^"?([^"<]+?)"?\s*<([^>]+)>/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1580_2 line 1580 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1580 in risk_assessment() to detect the mutant
    fail('COND_INV_1580_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1588_4 (MEDIUM) line 1588 in risk_assessment() ---
# Source:  if ($reg_disp && $reg_addr && $reg_disp ne $reg_addr) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1588_4 line 1588 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1588 in risk_assessment() to detect the mutant
    fail('COND_INV_1588_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1596_2 (MEDIUM) line 1596 in risk_assessment() ---
# Source:  if ($from_raw =~ /\@(gmail|yahoo|hotmail|outlook|live|aol|protonmail|yandex)\./i
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1596_2 line 1596 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1596 in risk_assessment() to detect the mutant
    fail('COND_INV_1596_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1604_2 (MEDIUM) line 1604 in risk_assessment() ---
# Source:  if ($reply_to) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1604_2 line 1604 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1604 in risk_assessment() to detect the mutant
    fail('COND_INV_1604_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1607_3 (MEDIUM) line 1607 in risk_assessment() ---
# Source:  if ($from_addr && $reply_addr && lc($from_addr) ne lc($reply_addr)) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1607_3 line 1607 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1607 in risk_assessment() to detect the mutant
    fail('COND_INV_1607_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1615_2 (MEDIUM) line 1615 in risk_assessment() ---
# Source:  if ($to =~ /undisclosed|:;/ || $to eq '') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1615_2 line 1615 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1615 in risk_assessment() to detect the mutant
    fail('COND_INV_1615_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1622_2 (MEDIUM) line 1622 in risk_assessment() ---
# Source:  if ($subj_raw =~ /=\?[^?]+\?[BQ]\?/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1622_2 line 1622 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1622 in risk_assessment() to detect the mutant
    fail('COND_INV_1622_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1637_3 (MEDIUM) line 1637 in risk_assessment() ---
# Source:  if ($URL_SHORTENERS{$bare} && !$shortener_seen{$bare}++) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1637_3 line 1637 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1637 in risk_assessment() to detect the mutant
    fail('COND_INV_1637_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1642_3 (MEDIUM) line 1642 in risk_assessment() ---
# Source:  if ($u->{url} =~ m{^http://}i && !$url_host_seen{ $u->{host} }++) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1642_3 line 1642 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1642 in risk_assessment() to detect the mutant
    fail('COND_INV_1642_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1651_3 (MEDIUM) line 1651 in risk_assessment() ---
# Source:  if ($d->{recently_registered}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1651_3 line 1651 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1651 in risk_assessment() to detect the mutant
    fail('COND_INV_1651_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1657_3 (MEDIUM) line 1657 in risk_assessment() ---
# Source:  if ($d->{expires}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1657_3 line 1657 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1657 in risk_assessment() to detect the mutant
    fail('COND_INV_1657_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1658_4 (MEDIUM) line 1658 in risk_assessment() ---
# Source:  if(my $exp = $self->_parse_date_to_epoch($d->{expires})) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1658_4 line 1658 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1658 in risk_assessment() to detect the mutant
    fail('COND_INV_1658_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1661_20_< (HIGH) line 1661 in risk_assessment() ---
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
    local $TODO = 'Complete: NUM_BOUNDARY_1661_20_< line 1661 in risk_assessment()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1661 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1661_20_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1664_25_< (HIGH) line 1664 in risk_assessment() ---
# Source:  } elsif ($remaining <= 0) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1664_25_< line 1664 in risk_assessment()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1664 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1664_25_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1675_4 (MEDIUM) line 1675 in risk_assessment() ---
# Source:  if ($d->{domain} =~ /\Q$brand\E/i &&
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1675_4 line 1675 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1675 in risk_assessment() to detect the mutant
    fail('COND_INV_1675_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1685_21_> (HIGH) line 1685 in risk_assessment() ---
# Source:  my $level = $score >= $SCORE_HIGH   ? 'HIGH'
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1685_21_> line 1685 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1685 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1685_21_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1686_21_> (HIGH) line 1686 in risk_assessment() ---
# Source:  : $score >= $SCORE_MEDIUM ? 'MEDIUM'
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1686_21_> line 1686 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1686 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1686_21_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1687_21_> (HIGH) line 1687 in risk_assessment() ---
# Source:  : $score >= $SCORE_LOW    ? 'LOW'
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1687_21_> line 1687 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1687 in risk_assessment() to detect the mutant
    fail('NUM_BOUNDARY_1687_21_>: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1691_2 (MEDIUM) line 1691 in risk_assessment() ---
# Source:  return $self->{_risk};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1691_2 line 1691 in risk_assessment()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1691 in risk_assessment() to detect the mutant
    fail('BOOL_NEGATE_1691_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1769_2 (MEDIUM) line 1769 in abuse_report_text() ---
# Source:  if (@{ $risk->{flags} }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1769_2 line 1769 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1769 in abuse_report_text() to detect the mutant
    fail('COND_INV_1769_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1779_2 (MEDIUM) line 1779 in abuse_report_text() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1779_2 line 1779 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1779 in abuse_report_text() to detect the mutant
    fail('COND_INV_1779_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1787_2 (MEDIUM) line 1787 in abuse_report_text() ---
# Source:  if (@contacts) {
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

# --- SURVIVOR: COND_INV_1795_2 (MEDIUM) line 1795 in abuse_report_text() ---
# Source:  if (@form_cs) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1795_2 line 1795 in abuse_report_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1795 in abuse_report_text() to detect the mutant
    fail('COND_INV_1795_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1904_3 (MEDIUM) line 1904 in abuse_contacts() ---
# Source:  if ($addr =~ /\@([\w.-]+)$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1904_3 line 1904 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1904 in abuse_contacts() to detect the mutant
    fail('COND_INV_1904_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1910_3 (MEDIUM) line 1910 in abuse_contacts() ---
# Source:  if (exists $seen_idx{$addr}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1910_3 line 1910 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1910 in abuse_contacts() to detect the mutant
    fail('COND_INV_1910_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1921_22_< (HIGH) line 1921 in abuse_contacts() ---
# Source:  $role_counts{$_} > 1 ? "$_ (x$role_counts{$_})" : $_
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1921_22_< line 1921 in abuse_contacts()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1921 in abuse_contacts() to detect the mutant
    fail('NUM_BOUNDARY_1921_22_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1926_24_< (HIGH) line 1926 in abuse_contacts() ---
# Source:  if (length($joined) > $ROLE_MAX_LEN) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1926_24_< line 1926 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1926 in abuse_contacts() to detect the mutant
    fail('NUM_BOUNDARY_1926_24_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1946_2 (MEDIUM) line 1946 in abuse_contacts() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1946_2 line 1946 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1946 in abuse_contacts() to detect the mutant
    fail('COND_INV_1946_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1948_3 (MEDIUM) line 1948 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1948_3 line 1948 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1948 in abuse_contacts() to detect the mutant
    fail('COND_INV_1948_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1956_3 (MEDIUM) line 1956 in abuse_contacts() ---
# Source:  if ($orig->{abuse} && $orig->{abuse} ne '(unknown)') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1956_3 line 1956 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1956 in abuse_contacts() to detect the mutant
    fail('COND_INV_1956_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1975_3 (MEDIUM) line 1975 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1975_3 line 1975 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1975 in abuse_contacts() to detect the mutant
    fail('COND_INV_1975_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1983_3 (MEDIUM) line 1983 in abuse_contacts() ---
# Source:  if ($u->{abuse} && $u->{abuse} ne '(unknown)') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1983_3 line 1983 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1983 in abuse_contacts() to detect the mutant
    fail('COND_INV_1983_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1998_3 (MEDIUM) line 1998 in abuse_contacts() ---
# Source:  if ($d->{web_abuse}) {
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

# --- SURVIVOR: COND_INV_2000_4 (MEDIUM) line 2000 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2000_4 line 2000 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2000 in abuse_contacts() to detect the mutant
    fail('COND_INV_2000_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2016_3 (MEDIUM) line 2016 in abuse_contacts() ---
# Source:  if ($d->{mx_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2016_3 line 2016 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2016 in abuse_contacts() to detect the mutant
    fail('COND_INV_2016_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2029_3 (MEDIUM) line 2029 in abuse_contacts() ---
# Source:  if ($d->{ns_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2029_3 line 2029 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2029 in abuse_contacts() to detect the mutant
    fail('COND_INV_2029_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2042_3 (MEDIUM) line 2042 in abuse_contacts() ---
# Source:  if ($d->{registrar_abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2042_3 line 2042 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2042 in abuse_contacts() to detect the mutant
    fail('COND_INV_2042_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2049_4 (MEDIUM) line 2049 in abuse_contacts() ---
# Source:  unless ($spoofable_only) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_2049_4 line 2049 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2049 in abuse_contacts() to detect the mutant
    fail('COND_INV_2049_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2073_3 (MEDIUM) line 2073 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2073_3 line 2073 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2073 in abuse_contacts() to detect the mutant
    fail('COND_INV_2073_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2087_2 (MEDIUM) line 2087 in abuse_contacts() ---
# Source:  if ($auth->{dkim_domain}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2087_2 line 2087 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2087 in abuse_contacts() to detect the mutant
    fail('COND_INV_2087_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2089_3 (MEDIUM) line 2089 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2089_3 line 2089 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2089 in abuse_contacts() to detect the mutant
    fail('COND_INV_2089_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2101_2 (MEDIUM) line 2101 in abuse_contacts() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2101_2 line 2101 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2101 in abuse_contacts() to detect the mutant
    fail('COND_INV_2101_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2112_4 (MEDIUM) line 2112 in abuse_contacts() ---
# Source:  if ($pa) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2112_4 line 2112 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2112 in abuse_contacts() to detect the mutant
    fail('COND_INV_2112_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2140_2 (MEDIUM) line 2140 in abuse_contacts() ---
# Source:  return @contacts;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2140_2 line 2140 in abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2140 in abuse_contacts() to detect the mutant
    fail('BOOL_NEGATE_2140_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2230_2 (MEDIUM) line 2230 in form_contacts() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2230_2 line 2230 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2230 in form_contacts() to detect the mutant
    fail('COND_INV_2230_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2232_3 (MEDIUM) line 2232 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2232_3 line 2232 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2232 in form_contacts() to detect the mutant
    fail('COND_INV_2232_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2249_3 (MEDIUM) line 2249 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2249_3 line 2249 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2249 in form_contacts() to detect the mutant
    fail('COND_INV_2249_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2266_3 (MEDIUM) line 2266 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2266_3 line 2266 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2266 in form_contacts() to detect the mutant
    fail('COND_INV_2266_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2279_3 (MEDIUM) line 2279 in form_contacts() ---
# Source:  if ($d->{registrar_abuse} && $d->{registrar_abuse} =~ /\@([\w.-]+)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2279_3 line 2279 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2279 in form_contacts() to detect the mutant
    fail('COND_INV_2279_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2282_4 (MEDIUM) line 2282 in form_contacts() ---
# Source:  if ($rpa && $rpa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2282_4 line 2282 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2282 in form_contacts() to detect the mutant
    fail('COND_INV_2282_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2305_3 (MEDIUM) line 2305 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2305_3 line 2305 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2305 in form_contacts() to detect the mutant
    fail('COND_INV_2305_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2321_2 (MEDIUM) line 2321 in form_contacts() ---
# Source:  if ($auth->{dkim_domain}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2321_2 line 2321 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2321 in form_contacts() to detect the mutant
    fail('COND_INV_2321_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2323_3 (MEDIUM) line 2323 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2323_3 line 2323 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2323 in form_contacts() to detect the mutant
    fail('COND_INV_2323_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2337_2 (MEDIUM) line 2337 in form_contacts() ---
# Source:  if ($unsub) {
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

# --- SURVIVOR: COND_INV_2344_4 (MEDIUM) line 2344 in form_contacts() ---
# Source:  if ($pa && $pa->{form}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2344_4 line 2344 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2344 in form_contacts() to detect the mutant
    fail('COND_INV_2344_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2357_2 (MEDIUM) line 2357 in form_contacts() ---
# Source:  return @contacts;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2357_2 line 2357 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2357 in form_contacts() to detect the mutant
    fail('BOOL_NEGATE_2357_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2446_2 (MEDIUM) line 2446 in report() ---
# Source:  if (@{ $risk->{flags} }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2446_2 line 2446 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2446 in report() to detect the mutant
    fail('COND_INV_2446_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2458_2 (MEDIUM) line 2458 in report() ---
# Source:  if ($orig) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2458_2 line 2458 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2458 in report() to detect the mutant
    fail('COND_INV_2458_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2473_2 (MEDIUM) line 2473 in report() ---
# Source:  if (@sw) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2473_2 line 2473 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2473 in report() to detect the mutant
    fail('COND_INV_2473_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2485_2 (MEDIUM) line 2485 in report() ---
# Source:  if (@trail) {
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
# Source:  if (@urls) {
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

# --- SURVIVOR: COND_INV_2505_4 (MEDIUM) line 2505 in report() ---
# Source:  unless (exists $host_order{$h}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_2505_4 line 2505 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2505 in report() to detect the mutant
    fail('COND_INV_2505_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2529_15_!= (HIGH) line 2529 in report() ---
# Source:  if (@paths == 1) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (2 variants — one test should kill all):
#   Numeric boundary flip == to !=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2529_15_!= line 2529 in report()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2529 in report() to detect the mutant
    fail('NUM_BOUNDARY_2529_15_!=: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2545_2 (MEDIUM) line 2545 in report() ---
# Source:  if (@mdoms) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2545_2 line 2545 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2545 in report() to detect the mutant
    fail('COND_INV_2545_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2549_4 (MEDIUM) line 2549 in report() ---
# Source:  if ($d->{recently_registered}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2549_4 line 2549 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2549 in report() to detect the mutant
    fail('COND_INV_2549_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2556_4 (MEDIUM) line 2556 in report() ---
# Source:  if ($d->{web_ip}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2556_4 line 2556 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2556 in report() to detect the mutant
    fail('COND_INV_2556_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2563_4 (MEDIUM) line 2563 in report() ---
# Source:  if ($d->{mx_host}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2563_4 line 2563 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2563 in report() to detect the mutant
    fail('COND_INV_2563_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2571_4 (MEDIUM) line 2571 in report() ---
# Source:  if ($d->{ns_host}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2571_4 line 2571 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2571 in report() to detect the mutant
    fail('COND_INV_2571_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2587_2 (MEDIUM) line 2587 in report() ---
# Source:  if (@contacts) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2587_2 line 2587 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2587 in report() to detect the mutant
    fail('COND_INV_2587_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2602_2 (MEDIUM) line 2602 in report() ---
# Source:  if (@form_cs) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2602_2 line 2602 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2602 in report() to detect the mutant
    fail('COND_INV_2602_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2612_4 (MEDIUM) line 2612 in report() ---
# Source:  if ($c->{form_paste}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2612_4 line 2612 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2612 in report() to detect the mutant
    fail('COND_INV_2612_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2618_46_< (HIGH) line 2618 in report() ---
# Source:  if (defined $line && length("$line $w") > $ROLE_WRAP_LEN) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2618_46_< line 2618 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2618 in report() to detect the mutant
    fail('NUM_BOUNDARY_2618_46_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2663_2 (MEDIUM) line 2663 in _sanitise_output() ---
# Source:  return '' unless defined $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2663_2 line 2663 in _sanitise_output()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2663 in _sanitise_output() to detect the mutant
    fail('BOOL_NEGATE_2663_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2666_2 (MEDIUM) line 2666 in _sanitise_output() ---
# Source:  return $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2666_2 line 2666 in _sanitise_output()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2666 in _sanitise_output() to detect the mutant
    fail('BOOL_NEGATE_2666_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2713_3 (MEDIUM) line 2713 in _split_message() ---
# Source:  if ($line =~ /^([\w-]+)\s*:\s*(.*)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2713_3 line 2713 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2713 in _split_message() to detect the mutant
    fail('COND_INV_2713_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2732_2 (MEDIUM) line 2732 in _split_message() ---
# Source:  if ($ct =~ /multipart/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2732_2 line 2732 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2732 in _split_message() to detect the mutant
    fail('COND_INV_2732_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2738_3 (MEDIUM) line 2738 in _split_message() ---
# Source:  if ($ct =~ /html/i) { $self->{_body_html}  = $decoded }
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

# --- SURVIVOR: NUM_BOUNDARY_2812_13_> (HIGH) line 2812 in _decode_multipart() ---
# Source:  if ($depth >= $MAX_MULTIPART_DEPTH) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2812_13_> line 2812 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2812 in _decode_multipart() to detect the mutant
    fail('NUM_BOUNDARY_2812_13_>: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2845_3 (MEDIUM) line 2845 in _decode_multipart() ---
# Source:  if ($pct =~ /multipart/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2845_3 line 2845 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2845 in _decode_multipart() to detect the mutant
    fail('COND_INV_2845_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2847_4 (MEDIUM) line 2847 in _decode_multipart() ---
# Source:  if ($inner_boundary) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2847_4 line 2847 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2847 in _decode_multipart() to detect the mutant
    fail('COND_INV_2847_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2857_3 (MEDIUM) line 2857 in _decode_multipart() ---
# Source:  if    ($pct =~ /text\/html/i)    { $self->{_body_html}  .= $decoded }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2857_3 line 2857 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2857 in _decode_multipart() to detect the mutant
    fail('COND_INV_2857_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2884_2 (MEDIUM) line 2884 in _decode_body() ---
# Source:  return $body // '';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2884_2 line 2884 in _decode_body()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2884 in _decode_body() to detect the mutant
    fail('BOOL_NEGATE_2884_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2927_2 (MEDIUM) line 2927 in _find_origin() ---
# Source:  unless (@candidates) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_2927_2 line 2927 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2927 in _find_origin() to detect the mutant
    fail('COND_INV_2927_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2929_3 (MEDIUM) line 2929 in _find_origin() ---
# Source:  if ($xoip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2929_3 line 2929 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2929 in _find_origin() to detect the mutant
    fail('COND_INV_2929_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2931_4 (MEDIUM) line 2931 in _find_origin() ---
# Source:  return $self->_enrich_ip($xoip, 'low',
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2931_4 line 2931 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2931 in _find_origin() to detect the mutant
    fail('BOOL_NEGATE_2931_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2935_3 (MEDIUM) line 2935 in _find_origin() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2935_3 line 2935 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2935 in _find_origin() to detect the mutant
    fail('BOOL_NEGATE_2935_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2939_2 (MEDIUM) line 2939 in _find_origin() ---
# Source:  return $self->_enrich_ip(
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2939_2 line 2939 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2939 in _find_origin() to detect the mutant
    fail('BOOL_NEGATE_2939_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2941_15_< (HIGH) line 2941 in _find_origin() ---
# Source:  @candidates > 1 ? 'high' : 'medium',
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2941_15_< line 2941 in _find_origin()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2941 in _find_origin() to detect the mutant
    fail('NUM_BOUNDARY_2941_15_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2966_3 (MEDIUM) line 2966 in _extract_ip_from_received() ---
# Source:  if ($hdr =~ $re) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2966_3 line 2966 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2966 in _extract_ip_from_received() to detect the mutant
    fail('COND_INV_2966_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2970_4 (MEDIUM) line 2970 in _extract_ip_from_received() ---
# Source:  return $ip if $ip =~ /:/;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2970_4 line 2970 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2970 in _extract_ip_from_received() to detect the mutant
    fail('BOOL_NEGATE_2970_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2974_22_< (HIGH) line 2974 in _extract_ip_from_received() ---
# Source:  next if grep { $_ > 255 } split /\./, $ip;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2974_22_< line 2974 in _extract_ip_from_received()';
    # Suggested boundary values to test: 254, 255, 256
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2974 in _extract_ip_from_received() to detect the mutant
    fail('NUM_BOUNDARY_2974_22_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2975_4 (MEDIUM) line 2975 in _extract_ip_from_received() ---
# Source:  return $ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2975_4 line 2975 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2975 in _extract_ip_from_received() to detect the mutant
    fail('BOOL_NEGATE_2975_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2978_2 (MEDIUM) line 2978 in _extract_ip_from_received() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2978_2 line 2978 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2978 in _extract_ip_from_received() to detect the mutant
    fail('BOOL_NEGATE_2978_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3000_2 (MEDIUM) line 3000 in _is_private() ---
# Source:  return 1 unless defined $ip && $ip ne '';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3000_2 line 3000 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3000 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_3000_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3001_33 (MEDIUM) line 3001 in _is_private() ---
# Source:  for my $re (@PRIVATE_RANGES) { return 1 if $ip =~ $re }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3001_33 line 3001 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3001 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_3001_33: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3002_2 (MEDIUM) line 3002 in _is_private() ---
# Source:  return 0;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3002_2 line 3002 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3002 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_3002_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3021_3 (MEDIUM) line 3021 in _is_trusted() ---
# Source:  return 1 if $self->_ip_in_cidr($ip, $cidr);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3021_3 line 3021 in _is_trusted()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3021 in _is_trusted() to detect the mutant
    fail('BOOL_NEGATE_3021_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3023_2 (MEDIUM) line 3023 in _is_trusted() ---
# Source:  return 0;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3023_2 line 3023 in _is_trusted()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3023 in _is_trusted() to detect the mutant
    fail('BOOL_NEGATE_3023_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3064_57_< (HIGH) line 3064 in _extract_and_resolve_urls() ---
# Source:  if ($HAS_ANYEVENT_DNS && scalar(keys %hostname_needed) > 1) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3064_57_< line 3064 in _extract_and_resolve_urls()';
    # Suggested boundary values to test: 0, 1, 2
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3064 in _extract_and_resolve_urls() to detect the mutant
    fail('NUM_BOUNDARY_3064_57_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3074_3 (MEDIUM) line 3074 in _extract_and_resolve_urls() ---
# Source:  unless (exists $host_cache{$host}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_3074_3 line 3074 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3074 in _extract_and_resolve_urls() to detect the mutant
    fail('COND_INV_3074_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3077_4 (MEDIUM) line 3077 in _extract_and_resolve_urls() ---
# Source:  if ($cached) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3077_4 line 3077 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3077 in _extract_and_resolve_urls() to detect the mutant
    fail('COND_INV_3077_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3086_5 (MEDIUM) line 3086 in _extract_and_resolve_urls() ---
# Source:  if (!$whois->{abuse}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3086_5 line 3086 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3086 in _extract_and_resolve_urls() to detect the mutant
    fail('COND_INV_3086_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3143_5 (MEDIUM) line 3143 in _parallel_resolve_hosts() ---
# Source:  if (@answers) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3143_5 line 3143 in _parallel_resolve_hosts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3143 in _parallel_resolve_hosts() to detect the mutant
    fail('COND_INV_3143_5: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3148_29_< (HIGH) line 3148 in _parallel_resolve_hosts() ---
# Source:  $cv->send if --$pending <= 0;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3148_29_< line 3148 in _parallel_resolve_hosts()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3148 in _parallel_resolve_hosts() to detect the mutant
    fail('NUM_BOUNDARY_3148_29_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3175_2 (MEDIUM) line 3175 in _extract_http_urls() ---
# Source:  if ($HAS_HTML_LINKEXTOR) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3175_2 line 3175 in _extract_http_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3175 in _extract_http_urls() to detect the mutant
    fail('COND_INV_3175_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3180_5 (MEDIUM) line 3180 in _extract_http_urls() ---
# Source:  if ($val =~ m{^https?://}i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3180_5 line 3180 in _extract_http_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3180 in _extract_http_urls() to detect the mutant
    fail('COND_INV_3180_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3205_2 (MEDIUM) line 3205 in _extract_http_urls() ---
# Source:  return @all;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3205_2 line 3205 in _extract_http_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3205 in _extract_http_urls() to detect the mutant
    fail('BOOL_NEGATE_3205_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3283_2 (MEDIUM) line 3283 in _extract_and_analyse_domains() ---
# Source:  if ($mid && $mid =~ /\@([\w.-]+)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3283_2 line 3283 in _extract_and_analyse_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3283 in _extract_and_analyse_domains() to detect the mutant
    fail('COND_INV_3283_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3298_2 (MEDIUM) line 3298 in _extract_and_analyse_domains() ---
# Source:  if ($unsub) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3298_2 line 3298 in _extract_and_analyse_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3298 in _extract_and_analyse_domains() to detect the mutant
    fail('COND_INV_3298_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3348_2 (MEDIUM) line 3348 in _domains_from_text() ---
# Source:  return @out;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3348_2 line 3348 in _domains_from_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3348 in _domains_from_text() to detect the mutant
    fail('BOOL_NEGATE_3348_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3382_2 (MEDIUM) line 3382 in _analyse_domain() ---
# Source:  return $self->{_domain_info}{$domain}
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3382_2 line 3382 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3382 in _analyse_domain() to detect the mutant
    fail('BOOL_NEGATE_3382_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3386_2 (MEDIUM) line 3386 in _analyse_domain() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3386_2 line 3386 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3386 in _analyse_domain() to detect the mutant
    fail('COND_INV_3386_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3388_3 (MEDIUM) line 3388 in _analyse_domain() ---
# Source:  if ($cached) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3388_3 line 3388 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3388 in _analyse_domain() to detect the mutant
    fail('COND_INV_3388_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3390_4 (MEDIUM) line 3390 in _analyse_domain() ---
# Source:  return $cached;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3390_4 line 3390 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3390 in _analyse_domain() to detect the mutant
    fail('BOOL_NEGATE_3390_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3399_2 (MEDIUM) line 3399 in _analyse_domain() ---
# Source:  if ($web_ip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3399_2 line 3399 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3399 in _analyse_domain() to detect the mutant
    fail('COND_INV_3399_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3407_2 (MEDIUM) line 3407 in _analyse_domain() ---
# Source:  if ($HAS_NET_DNS) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3407_2 line 3407 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3407 in _analyse_domain() to detect the mutant
    fail('COND_INV_3407_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3415_3 (MEDIUM) line 3415 in _analyse_domain() ---
# Source:  if ($mxq) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3415_3 line 3415 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3415 in _analyse_domain() to detect the mutant
    fail('COND_INV_3415_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3418_4 (MEDIUM) line 3418 in _analyse_domain() ---
# Source:  if ($best) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3418_4 line 3418 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3418 in _analyse_domain() to detect the mutant
    fail('COND_INV_3418_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3422_5 (MEDIUM) line 3422 in _analyse_domain() ---
# Source:  if ($mx_ip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3422_5 line 3422 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3422 in _analyse_domain() to detect the mutant
    fail('COND_INV_3422_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3433_3 (MEDIUM) line 3433 in _analyse_domain() ---
# Source:  if ($nsq) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3433_3 line 3433 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3433 in _analyse_domain() to detect the mutant
    fail('COND_INV_3433_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3435_4 (MEDIUM) line 3435 in _analyse_domain() ---
# Source:  if ($first) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3435_4 line 3435 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3435 in _analyse_domain() to detect the mutant
    fail('COND_INV_3435_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3439_5 (MEDIUM) line 3439 in _analyse_domain() ---
# Source:  if ($ns_ip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3439_5 line 3439 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3439 in _analyse_domain() to detect the mutant
    fail('COND_INV_3439_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3451_2 (MEDIUM) line 3451 in _analyse_domain() ---
# Source:  if ($domain_whois) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3451_2 line 3451 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3451 in _analyse_domain() to detect the mutant
    fail('COND_INV_3451_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3456_3 (MEDIUM) line 3456 in _analyse_domain() ---
# Source:  if ($domain_whois =~ /Registrar:\s*(.+)/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3456_3 line 3456 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3456 in _analyse_domain() to detect the mutant
    fail('COND_INV_3456_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3466_4 (MEDIUM) line 3466 in _analyse_domain() ---
# Source:  if (!$info{registrar_abuse} && $domain_whois =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3466_4 line 3466 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3466 in _analyse_domain() to detect the mutant
    fail('COND_INV_3466_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3478_4 (MEDIUM) line 3478 in _analyse_domain() ---
# Source:  if (!$info{registered} && $domain_whois =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3478_4 line 3478 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3478 in _analyse_domain() to detect the mutant
    fail('COND_INV_3478_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3489_4 (MEDIUM) line 3489 in _analyse_domain() ---
# Source:  if (!$info{expires} && $domain_whois =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3489_4 line 3489 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3489 in _analyse_domain() to detect the mutant
    fail('COND_INV_3489_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3495_3 (MEDIUM) line 3495 in _analyse_domain() ---
# Source:  if ($info{registered}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3495_3 line 3495 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3495 in _analyse_domain() to detect the mutant
    fail('COND_INV_3495_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3498_36_> (HIGH) line 3498 in _analyse_domain() ---
# Source:  if $epoch && (time() - $epoch) < $RECENT_REG_DAYS * $SECS_PER_DAY;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip < to >
#   Numeric boundary flip < to <=
#   Numeric boundary flip < to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3498_36_> line 3498 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3498 in _analyse_domain() to detect the mutant
    fail('NUM_BOUNDARY_3498_36_>: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3532_2 (MEDIUM) line 3532 in _resolve_host() ---
# Source:  return $host if $host =~ /^\d{1,3}(?:\.\d{1,3}){3}$/;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3532_2 line 3532 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3532 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_3532_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3535_2 (MEDIUM) line 3535 in _resolve_host() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3535_2 line 3535 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3535 in _resolve_host() to detect the mutant
    fail('COND_INV_3535_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3537_3 (MEDIUM) line 3537 in _resolve_host() ---
# Source:  return $cached_ip if defined $cached_ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3537_3 line 3537 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3537 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_3537_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3542_2 (MEDIUM) line 3542 in _resolve_host() ---
# Source:  if ($HAS_NET_DNS) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3542_2 line 3542 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3542 in _resolve_host() to detect the mutant
    fail('COND_INV_3542_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3551_4 (MEDIUM) line 3551 in _resolve_host() ---
# Source:  if ($query) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3551_4 line 3551 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3551 in _resolve_host() to detect the mutant
    fail('COND_INV_3551_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3553_6 (MEDIUM) line 3553 in _resolve_host() ---
# Source:  if ($rr->type eq 'A') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3553_6 line 3553 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3553 in _resolve_host() to detect the mutant
    fail('COND_INV_3553_6: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3571_2 (MEDIUM) line 3571 in _resolve_host() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3571_2 line 3571 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3571 in _resolve_host() to detect the mutant
    fail('COND_INV_3571_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3575_2 (MEDIUM) line 3575 in _resolve_host() ---
# Source:  return $ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3575_2 line 3575 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3575 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_3575_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3592_2 (MEDIUM) line 3592 in _reverse_dns() ---
# Source:  return undef unless $ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3592_2 line 3592 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3592 in _reverse_dns() to detect the mutant
    fail('BOOL_NEGATE_3592_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3594_2 (MEDIUM) line 3594 in _reverse_dns() ---
# Source:  if ($HAS_NET_DNS) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3594_2 line 3594 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3594 in _reverse_dns() to detect the mutant
    fail('COND_INV_3594_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3597_3 (MEDIUM) line 3597 in _reverse_dns() ---
# Source:  if ($query) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3597_3 line 3597 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3597 in _reverse_dns() to detect the mutant
    fail('COND_INV_3597_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3599_5 (MEDIUM) line 3599 in _reverse_dns() ---
# Source:  return $rr->ptrdname if $rr->type eq 'PTR';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3599_5 line 3599 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3599 in _reverse_dns() to detect the mutant
    fail('BOOL_NEGATE_3599_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3602_3 (MEDIUM) line 3602 in _reverse_dns() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3602_3 line 3602 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3602 in _reverse_dns() to detect the mutant
    fail('BOOL_NEGATE_3602_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3630_2 (MEDIUM) line 3630 in _whois_ip() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3630_2 line 3630 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3630 in _whois_ip() to detect the mutant
    fail('COND_INV_3630_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3632_3 (MEDIUM) line 3632 in _whois_ip() ---
# Source:  return $cached if $cached;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3632_3 line 3632 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3632 in _whois_ip() to detect the mutant
    fail('BOOL_NEGATE_3632_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3638_2 (MEDIUM) line 3638 in _whois_ip() ---
# Source:  unless ($result->{org}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_3638_2 line 3638 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3638 in _whois_ip() to detect the mutant
    fail('COND_INV_3638_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3640_3 (MEDIUM) line 3640 in _whois_ip() ---
# Source:  if ($raw) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3640_3 line 3640 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3640 in _whois_ip() to detect the mutant
    fail('COND_INV_3640_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3650_2 (MEDIUM) line 3650 in _whois_ip() ---
# Source:  return $result;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3650_2 line 3650 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3650 in _whois_ip() to detect the mutant
    fail('BOOL_NEGATE_3650_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3669_2 (MEDIUM) line 3669 in _domain_whois() ---
# Source:  return undef unless $server;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3669_2 line 3669 in _domain_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3669 in _domain_whois() to detect the mutant
    fail('BOOL_NEGATE_3669_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3670_2 (MEDIUM) line 3670 in _domain_whois() ---
# Source:  return $self->_raw_whois($domain, $server);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3670_2 line 3670 in _domain_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3670 in _domain_whois() to detect the mutant
    fail('BOOL_NEGATE_3670_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3690_2 (MEDIUM) line 3690 in _parse_domain_whois_abuse() ---
# Source:  if ($raw =~ /Registrar:\s*(.+)/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3690_2 line 3690 in _parse_domain_whois_abuse()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3690 in _parse_domain_whois_abuse() to detect the mutant
    fail('COND_INV_3690_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3699_3 (MEDIUM) line 3699 in _parse_domain_whois_abuse() ---
# Source:  if (!$info{abuse} && $raw =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3699_3 line 3699 in _parse_domain_whois_abuse()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3699 in _parse_domain_whois_abuse() to detect the mutant
    fail('COND_INV_3699_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3742_2 (MEDIUM) line 3742 in _rdap_lookup() ---
# Source:  if ($j =~ /"abuse".*?"email"\s*:\s*"([^"]+)"/s) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3742_2 line 3742 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3742 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3742_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3794_2 (MEDIUM) line 3794 in _raw_whois() ---
# Source:  return undef unless $sock;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3794_2 line 3794 in _raw_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3794 in _raw_whois() to detect the mutant
    fail('BOOL_NEGATE_3794_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3797_53 (MEDIUM) line 3797 in _raw_whois() ---
# Source:  $sock->print("$query\r\n") or do { $sock->close(); return undef };
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3797_53 line 3797 in _raw_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3797 in _raw_whois() to detect the mutant
    fail('BOOL_NEGATE_3797_53: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3809_31_< (HIGH) line 3809 in _raw_whois() ---
# Source:  if ($@ || !defined $n || $n <= 0) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3809_31_< line 3809 in _raw_whois()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3809 in _raw_whois() to detect the mutant
    fail('NUM_BOUNDARY_3809_31_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3813_32_< (HIGH) line 3813 in _raw_whois() ---
# Source:  last unless defined $n && $n > 0;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3813_32_< line 3813 in _raw_whois()';
    # Suggested boundary values to test: -1, 0, 1
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3813 in _raw_whois() to detect the mutant
    fail('NUM_BOUNDARY_3813_32_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3818_2 (MEDIUM) line 3818 in _raw_whois() ---
# Source:  return $response || undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3818_2 line 3818 in _raw_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3818 in _raw_whois() to detect the mutant
    fail('BOOL_NEGATE_3818_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3843_3 (MEDIUM) line 3843 in _parse_whois_text() ---
# Source:  if (!$info{org} && $text =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3843_3 line 3843 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3843 in _parse_whois_text() to detect the mutant
    fail('COND_INV_3843_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3853_3 (MEDIUM) line 3853 in _parse_whois_text() ---
# Source:  if (!$info{abuse} && $text =~ $pat) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3853_3 line 3853 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3853 in _parse_whois_text() to detect the mutant
    fail('COND_INV_3853_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3862_2 (MEDIUM) line 3862 in _parse_whois_text() ---
# Source:  if ($text =~ /^country:\s*([A-Za-z]{2})\s*$/m) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3862_2 line 3862 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3862 in _parse_whois_text() to detect the mutant
    fail('COND_INV_3862_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3888_2 (MEDIUM) line 3888 in _parse_auth_results_cached() ---
# Source:  return $self->{_auth_results} if $self->{_auth_results};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3888_2 line 3888 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3888 in _parse_auth_results_cached() to detect the mutant
    fail('BOOL_NEGATE_3888_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3914_3 (MEDIUM) line 3914 in _parse_auth_results_cached() ---
# Source:  if ($h->{value} =~ /\bd=([^;,\s]+)/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3914_3 line 3914 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3914 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_3914_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3919_2 (MEDIUM) line 3919 in _parse_auth_results_cached() ---
# Source:  if (@dkim_domains) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3919_2 line 3919 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3919 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_3919_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3923_4 (MEDIUM) line 3923 in _parse_auth_results_cached() ---
# Source:  if ($self->_provider_abuse_for_host($d)) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3923_4 line 3923 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3923 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_3923_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3960_2 (MEDIUM) line 3960 in _provider_abuse_for_host() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3960_2 line 3960 in _provider_abuse_for_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3960 in _provider_abuse_for_host() to detect the mutant
    fail('BOOL_NEGATE_3960_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3978_2 (MEDIUM) line 3978 in _provider_abuse_for_ip() ---
# Source:  return $self->_provider_abuse_for_host($rdns) if $rdns;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3978_2 line 3978 in _provider_abuse_for_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3978 in _provider_abuse_for_ip() to detect the mutant
    fail('BOOL_NEGATE_3978_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3979_2 (MEDIUM) line 3979 in _provider_abuse_for_ip() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3979_2 line 3979 in _provider_abuse_for_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3979 in _provider_abuse_for_ip() to detect the mutant
    fail('BOOL_NEGATE_3979_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4006_2 (MEDIUM) line 4006 in _registrable() ---
# Source:  return undef unless $host && $host =~ /\./;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4006_2 line 4006 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4006 in _registrable() to detect the mutant
    fail('BOOL_NEGATE_4006_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4009_2 (MEDIUM) line 4009 in _registrable() ---
# Source:  if ($HAS_PUBLIC_SUFFIX) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4009_2 line 4009 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4009 in _registrable() to detect the mutant
    fail('COND_INV_4009_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4012_3 (MEDIUM) line 4012 in _registrable() ---
# Source:  return $root if $root;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4012_3 line 4012 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4012 in _registrable() to detect the mutant
    fail('BOOL_NEGATE_4012_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4017_26_< (HIGH) line 4017 in _registrable() ---
# Source:  return $host if @labels <= 2;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4017_26_< line 4017 in _registrable()';
    # Suggested boundary values to test: 1, 2, 3
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4017 in _registrable() to detect the mutant
    fail('NUM_BOUNDARY_4017_26_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4020_2 (MEDIUM) line 4020 in _registrable() ---
# Source:  if ($labels[-1] =~ /^[a-z]{2}$/ &&
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4020_2 line 4020 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4020 in _registrable() to detect the mutant
    fail('COND_INV_4020_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4076_3 (MEDIUM) line 4076 in _header_value() ---
# Source:  return $h->{value} if $h->{name} eq lc($name);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4076_3 line 4076 in _header_value()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4076 in _header_value() to detect the mutant
    fail('BOOL_NEGATE_4076_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4078_2 (MEDIUM) line 4078 in _header_value() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4078_2 line 4078 in _header_value()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4078 in _header_value() to detect the mutant
    fail('BOOL_NEGATE_4078_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4096_2 (MEDIUM) line 4096 in _ip_in_cidr() ---
# Source:  return $ip eq $cidr unless $cidr =~ m{/};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4096_2 line 4096 in _ip_in_cidr()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4096 in _ip_in_cidr() to detect the mutant
    fail('BOOL_NEGATE_4096_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4098_67_< (HIGH) line 4098 in _ip_in_cidr() ---
# Source:  return 0 unless defined $prefix && $prefix =~ /^\d+$/ && $prefix <= 32;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4098_67_< line 4098 in _ip_in_cidr()';
    # Suggested boundary values to test: 31, 32, 33
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4098 in _ip_in_cidr() to detect the mutant
    fail('NUM_BOUNDARY_4098_67_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4104_25_!= (HIGH) line 4104 in _ip_in_cidr() ---
# Source:  return ($ip_n & $mask) == ($net_n & $mask);
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (1 variant):
#   Numeric boundary flip == to !=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4104_25_!= line 4104 in _ip_in_cidr()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4104 in _ip_in_cidr() to detect the mutant
    fail('NUM_BOUNDARY_4104_25_!=: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4121_2 (MEDIUM) line 4121 in _decode_mime_words() ---
# Source:  return '' unless defined $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4121_2 line 4121 in _decode_mime_words()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4121 in _decode_mime_words() to detect the mutant
    fail('BOOL_NEGATE_4121_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4124_2 (MEDIUM) line 4124 in _decode_mime_words() ---
# Source:  return $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4124_2 line 4124 in _decode_mime_words()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4124 in _decode_mime_words() to detect the mutant
    fail('BOOL_NEGATE_4124_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4139_2 (MEDIUM) line 4139 in _decode_ew() ---
# Source:  if (uc($enc) eq 'B') {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4139_2 line 4139 in _decode_ew()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4139 in _decode_ew() to detect the mutant
    fail('COND_INV_4139_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4146_2 (MEDIUM) line 4146 in _decode_ew() ---
# Source:  return $raw;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4146_2 line 4146 in _decode_ew()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4146 in _decode_ew() to detect the mutant
    fail('BOOL_NEGATE_4146_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4163_2 (MEDIUM) line 4163 in _parse_date_to_epoch() ---
# Source:  return undef unless $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4163_2 line 4163 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4163 in _parse_date_to_epoch() to detect the mutant
    fail('BOOL_NEGATE_4163_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4169_2 (MEDIUM) line 4169 in _parse_date_to_epoch() ---
# Source:  if ($str =~ /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?Z$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4169_2 line 4169 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4169 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_4169_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4181_4 (MEDIUM) line 4181 in _parse_date_to_epoch() ---
# Source:  return $t->epoch - $t->tzoffset->seconds;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4181_4 line 4181 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4181 in _parse_date_to_epoch() to detect the mutant
    fail('BOOL_NEGATE_4181_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4183_3 (MEDIUM) line 4183 in _parse_date_to_epoch() ---
# Source:  return $epoch if defined $epoch;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4183_3 line 4183 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4183 in _parse_date_to_epoch() to detect the mutant
    fail('BOOL_NEGATE_4183_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4187_2 (MEDIUM) line 4187 in _parse_date_to_epoch() ---
# Source:  if    ($str =~ /^(\d{4})-(\d{2})-(\d{2})/)         { ($y,$m,$d)=($1,$2,$3) }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4187_2 line 4187 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4187 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_4187_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4191_2 (MEDIUM) line 4191 in _parse_date_to_epoch() ---
# Source:  return undef unless $y && $m && $d;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4191_2 line 4191 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4191 in _parse_date_to_epoch() to detect the mutant
    fail('BOOL_NEGATE_4191_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4193_2 (MEDIUM) line 4193 in _parse_date_to_epoch() ---
# Source:  if (eval { require Time::Local; 1 }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4193_2 line 4193 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4193 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_4193_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4216_2 (MEDIUM) line 4216 in _parse_rfc2822_date() ---
# Source:  return undef unless $str;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4216_2 line 4216 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4216 in _parse_rfc2822_date() to detect the mutant
    fail('BOOL_NEGATE_4216_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4219_2 (MEDIUM) line 4219 in _parse_rfc2822_date() ---
# Source:  if ($str =~ /(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4219_2 line 4219 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4219 in _parse_rfc2822_date() to detect the mutant
    fail('COND_INV_4219_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4222_3 (MEDIUM) line 4222 in _parse_rfc2822_date() ---
# Source:  return undef unless $m;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4222_3 line 4222 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4222 in _parse_rfc2822_date() to detect the mutant
    fail('BOOL_NEGATE_4222_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4223_3 (MEDIUM) line 4223 in _parse_rfc2822_date() ---
# Source:  if (eval { require Time::Local; 1 }) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4223_3 line 4223 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4223 in _parse_rfc2822_date() to detect the mutant
    fail('COND_INV_4223_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4227_2 (MEDIUM) line 4227 in _parse_rfc2822_date() ---
# Source:  return undef;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4227_2 line 4227 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4227 in _parse_rfc2822_date() to detect the mutant
    fail('BOOL_NEGATE_4227_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4267_2 (MEDIUM) line 4267 in _debug() ---
# Source:  if($self->{verbose}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4267_2 line 4267 in _debug()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4267 in _debug() to detect the mutant
    fail('COND_INV_4267_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4268_3 (MEDIUM) line 4268 in _debug() ---
# Source:  if(my $logger = $self->{logger}) {	# May have been set in Object::Configure
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4268_3 line 4268 in _debug()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4268 in _debug() to detect the mutant
    fail('COND_INV_4268_3: replace with real assertion');
}

# --- LOW DIFFICULTY HINTS (comment stubs) ---

# --- LOW HINT: RETURN_UNDEF_775_2 line 775 in parse_email() ---
# Source:  return $self;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_775_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_860_2 line 860 in originating_ip() ---
# Source:  return $self->{_origin};
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_860_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1103_2 line 1103 in all_domains() ---
# Source:  return @out;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1103_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1219_2 line 1219 in unresolved_contacts() ---
# Source:  return @out;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1219_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1451_2 line 1451 in risk_assessment() ---
# Source:  return $self->{_risk} if $self->{_risk};
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1451_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1691_2 line 1691 in risk_assessment() ---
# Source:  return $self->{_risk};
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1691_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2140_2 line 2140 in abuse_contacts() ---
# Source:  return @contacts;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2140_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2357_2 line 2357 in form_contacts() ---
# Source:  return @contacts;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2357_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2663_2 line 2663 in _sanitise_output() ---
# Source:  return '' unless defined $str;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2663_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2666_2 line 2666 in _sanitise_output() ---
# Source:  return $str;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2666_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2884_2 line 2884 in _decode_body() ---
# Source:  return $body // '';
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2884_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2931_4 line 2931 in _find_origin() ---
# Source:  return $self->_enrich_ip($xoip, 'low',
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2931_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2935_3 line 2935 in _find_origin() ---
# Source:  return undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2935_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2939_2 line 2939 in _find_origin() ---
# Source:  return $self->_enrich_ip(
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2939_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2970_4 line 2970 in _extract_ip_from_received() ---
# Source:  return $ip if $ip =~ /:/;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2970_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2975_4 line 2975 in _extract_ip_from_received() ---
# Source:  return $ip;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2975_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2978_2 line 2978 in _extract_ip_from_received() ---
# Source:  return undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2978_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3000_2 line 3000 in _is_private() ---
# Source:  return 1 unless defined $ip && $ip ne '';
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3000_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3001_33 line 3001 in _is_private() ---
# Source:  for my $re (@PRIVATE_RANGES) { return 1 if $ip =~ $re }
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3001_33: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3002_2 line 3002 in _is_private() ---
# Source:  return 0;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3002_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3021_3 line 3021 in _is_trusted() ---
# Source:  return 1 if $self->_ip_in_cidr($ip, $cidr);
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3021_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3023_2 line 3023 in _is_trusted() ---
# Source:  return 0;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3023_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3205_2 line 3205 in _extract_http_urls() ---
# Source:  return @all;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3205_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3348_2 line 3348 in _domains_from_text() ---
# Source:  return @out;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3348_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3382_2 line 3382 in _analyse_domain() ---
# Source:  return $self->{_domain_info}{$domain}
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3382_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3390_4 line 3390 in _analyse_domain() ---
# Source:  return $cached;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3390_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3532_2 line 3532 in _resolve_host() ---
# Source:  return $host if $host =~ /^\d{1,3}(?:\.\d{1,3}){3}$/;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3532_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3537_3 line 3537 in _resolve_host() ---
# Source:  return $cached_ip if defined $cached_ip;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3537_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3575_2 line 3575 in _resolve_host() ---
# Source:  return $ip;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3575_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3592_2 line 3592 in _reverse_dns() ---
# Source:  return undef unless $ip;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3592_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3599_5 line 3599 in _reverse_dns() ---
# Source:  return $rr->ptrdname if $rr->type eq 'PTR';
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3599_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3602_3 line 3602 in _reverse_dns() ---
# Source:  return undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3602_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3632_3 line 3632 in _whois_ip() ---
# Source:  return $cached if $cached;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3632_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3650_2 line 3650 in _whois_ip() ---
# Source:  return $result;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3650_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3669_2 line 3669 in _domain_whois() ---
# Source:  return undef unless $server;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3669_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3670_2 line 3670 in _domain_whois() ---
# Source:  return $self->_raw_whois($domain, $server);
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3670_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3794_2 line 3794 in _raw_whois() ---
# Source:  return undef unless $sock;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3794_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3797_53 line 3797 in _raw_whois() ---
# Source:  $sock->print("$query\r\n") or do { $sock->close(); return undef };
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3797_53: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3818_2 line 3818 in _raw_whois() ---
# Source:  return $response || undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3818_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3888_2 line 3888 in _parse_auth_results_cached() ---
# Source:  return $self->{_auth_results} if $self->{_auth_results};
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3888_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3960_2 line 3960 in _provider_abuse_for_host() ---
# Source:  return undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3960_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3978_2 line 3978 in _provider_abuse_for_ip() ---
# Source:  return $self->_provider_abuse_for_host($rdns) if $rdns;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3978_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3979_2 line 3979 in _provider_abuse_for_ip() ---
# Source:  return undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3979_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4006_2 line 4006 in _registrable() ---
# Source:  return undef unless $host && $host =~ /\./;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4006_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4012_3 line 4012 in _registrable() ---
# Source:  return $root if $root;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4012_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4017_2 line 4017 in _registrable() ---
# Source:  return $host if @labels <= 2;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4017_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4076_3 line 4076 in _header_value() ---
# Source:  return $h->{value} if $h->{name} eq lc($name);
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4076_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4078_2 line 4078 in _header_value() ---
# Source:  return undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4078_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4096_2 line 4096 in _ip_in_cidr() ---
# Source:  return $ip eq $cidr unless $cidr =~ m{/};
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4096_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4098_2 line 4098 in _ip_in_cidr() ---
# Source:  return 0 unless defined $prefix && $prefix =~ /^\d+$/ && $prefix <= 32;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4098_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4121_2 line 4121 in _decode_mime_words() ---
# Source:  return '' unless defined $str;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4121_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4124_2 line 4124 in _decode_mime_words() ---
# Source:  return $str;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4124_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4146_2 line 4146 in _decode_ew() ---
# Source:  return $raw;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4146_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4163_2 line 4163 in _parse_date_to_epoch() ---
# Source:  return undef unless $str;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4163_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4181_4 line 4181 in _parse_date_to_epoch() ---
# Source:  return $t->epoch - $t->tzoffset->seconds;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4181_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4183_3 line 4183 in _parse_date_to_epoch() ---
# Source:  return $epoch if defined $epoch;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4183_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4191_2 line 4191 in _parse_date_to_epoch() ---
# Source:  return undef unless $y && $m && $d;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4191_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4216_2 line 4216 in _parse_rfc2822_date() ---
# Source:  return undef unless $str;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4216_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4222_3 line 4222 in _parse_rfc2822_date() ---
# Source:  return undef unless $m;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4222_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4227_2 line 4227 in _parse_rfc2822_date() ---
# Source:  return undef;
# Hint:    Mutation survived but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4227_2: add assertion here');

done_testing();
