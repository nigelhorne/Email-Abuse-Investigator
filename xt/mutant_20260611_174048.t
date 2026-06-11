#!/usr/bin/env perl
# Auto-generated mutant test stubs
# Generated: 2026-06-11 17:40:48
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

# --- SURVIVOR: COND_INV_619_2 (MEDIUM) line 619 ---
# Source:  element_type  => 'string',
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_619_2 line 619';
    # NOTE:  is a class method — call directly.
    my $result = Email::Abuse::Investigator->(...);
    # ok($result, 'COND_INV_619_2: add assertion here');
    # TODO: exercise line 619 to detect the mutant
    fail('COND_INV_619_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_753_2 (MEDIUM) line 753 in new() ---
# Source:  If C<$text> is empty or contains no header/body separator, all public
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_753_2 line 753 in new()';
    # NOTE: new is a class method — call directly.
    my $result = Email::Abuse::Investigator->new(...);
    # ok($result, 'COND_INV_753_2: add assertion here');
    # TODO: exercise line 753 in new() to detect the mutant
    fail('COND_INV_753_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_754_3 (MEDIUM) line 754 in new() ---
# Source:  methods will return empty/safe values.
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_754_3 line 754 in new()';
    # NOTE: new is a class method — call directly.
    my $result = Email::Abuse::Investigator->new(...);
    # ok($result, 'COND_INV_754_3: add assertion here');
    # TODO: exercise line 754 in new() to detect the mutant
    fail('COND_INV_754_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_757_3 (MEDIUM) line 757 in new() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_757_3 line 757 in new()';
    # NOTE: new is a class method — call directly.
    my $result = Email::Abuse::Investigator->new(...);
    # ok($result, 'COND_INV_757_3: add assertion here');
    # TODO: exercise line 757 in new() to detect the mutant
    fail('COND_INV_757_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_781_2 (MEDIUM) line 781 in new() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_781_2 line 781 in new()';
    # NOTE: new is a class method — call directly.
    my $result = Email::Abuse::Investigator->new(...);
    # ok($result, 'BOOL_NEGATE_781_2: add assertion here');
    # TODO: exercise line 781 in new() to detect the mutant
    fail('BOOL_NEGATE_781_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_867_2 (MEDIUM) line 867 in parse_email() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_867_2 line 867 in parse_email()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 867 in parse_email() to detect the mutant
    fail('BOOL_NEGATE_867_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1112_2 (MEDIUM) line 1112 in all_domains() ---
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
# Source:  next if $covered{$bare};
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
# Source:  my @sw = $analyser->sending_software();
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

# --- SURVIVOR: BOOL_NEGATE_1463_2 (MEDIUM) line 1463 in _risk_check_origin() ---
# Source:  $flag->('HIGH', 'residential_sending_ip',
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1463_2 line 1463 in _risk_check_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1463 in _risk_check_origin() to detect the mutant
    fail('BOOL_NEGATE_1463_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1477_2 (MEDIUM) line 1477 in _risk_check_origin() ---
# Source:  }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1477_2 line 1477 in _risk_check_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1477 in _risk_check_origin() to detect the mutant
    fail('COND_INV_1477_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1479_3 (MEDIUM) line 1479 in _risk_check_origin() ---
# Source:  # Statistically high-volume spam countries (informational only)
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1479_3 line 1479 in _risk_check_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1479 in _risk_check_origin() to detect the mutant
    fail('COND_INV_1479_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1490_3 (MEDIUM) line 1490 in _risk_check_origin() ---
# Source:  #   Evaluate SPF, DKIM, DMARC results and DKIM signing domain alignment.
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1490_3 line 1490 in _risk_check_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1490 in _risk_check_origin() to detect the mutant
    fail('COND_INV_1490_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1496_3 (MEDIUM) line 1496 in _risk_check_origin() ---
# Source:  #   Returns nothing; side effects via $flag closure.
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1496_3 line 1496 in _risk_check_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1496 in _risk_check_origin() to detect the mutant
    fail('COND_INV_1496_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1502_3 (MEDIUM) line 1502 in _risk_check_auth() ---
# Source:  if (defined $auth->{spf}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1502_3 line 1502 in _risk_check_auth()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1502 in _risk_check_auth() to detect the mutant
    fail('COND_INV_1502_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1511_2 (MEDIUM) line 1511 in _risk_check_auth() ---
# Source:  "SPF result: $auth->{spf} -- sending IP not authorised");
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1511_2 line 1511 in _risk_check_auth()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1511 in _risk_check_auth() to detect the mutant
    fail('COND_INV_1511_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1512_3 (MEDIUM) line 1512 in _risk_check_auth() ---
# Source:  }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1512_3 line 1512 in _risk_check_auth()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1512 in _risk_check_auth() to detect the mutant
    fail('COND_INV_1512_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1523_2 (MEDIUM) line 1523 in _risk_check_auth() ---
# Source:  return unless $auth->{dkim_domain};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1523_2 line 1523 in _risk_check_auth()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1523 in _risk_check_auth() to detect the mutant
    fail('COND_INV_1523_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1527_2 (MEDIUM) line 1527 in _risk_check_auth() ---
# Source:  my $reg_from = _registrable(lc $from_domain)     // lc $from_domain;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1527_2 line 1527 in _risk_check_auth()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1527 in _risk_check_auth() to detect the mutant
    fail('COND_INV_1527_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1532_2 (MEDIUM) line 1532 in _risk_check_auth() ---
# Source:  $flag->('INFO', 'dkim_domain_mismatch',
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1532_2 line 1532 in _risk_check_auth()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1532 in _risk_check_auth() to detect the mutant
    fail('COND_INV_1532_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1534_3 (MEDIUM) line 1534 in _risk_check_auth() ---
# Source:  . ' -- message sent via third-party sender (normal for bulk/ESP mail)');
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1534_3 line 1534 in _risk_check_auth()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1534 in _risk_check_auth() to detect the mutant
    fail('COND_INV_1534_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1537_4 (MEDIUM) line 1537 in _risk_check_auth() ---
# Source:  $flag->('MEDIUM', 'dkim_domain_mismatch',
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1537_4 line 1537 in _risk_check_auth()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1537 in _risk_check_auth() to detect the mutant
    fail('COND_INV_1537_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1539_5 (MEDIUM) line 1539 in _risk_check_auth() ---
# Source:  . ' and DKIM did not pass -- possible impersonation');
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1539_5 line 1539 in _risk_check_auth()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1539 in _risk_check_auth() to detect the mutant
    fail('COND_INV_1539_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1555_2 (MEDIUM) line 1555 in _risk_check_date() ---
# Source:  sub _risk_check_date :Private {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1555_2 line 1555 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1555 in _risk_check_date() to detect the mutant
    fail('COND_INV_1555_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1560_3 (MEDIUM) line 1560 in _risk_check_date() ---
# Source:  $flag->('MEDIUM', 'missing_date',
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1560_3 line 1560 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1560 in _risk_check_date() to detect the mutant
    fail('COND_INV_1560_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1563_26_> (HIGH) line 1563 in _risk_check_date() ---
# Source:  }
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1563_26_> line 1563 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1563 in _risk_check_date() to detect the mutant
    fail('NUM_BOUNDARY_1563_26_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1564_38_< (HIGH) line 1564 in _risk_check_date() ---
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1564_38_< line 1564 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1564 in _risk_check_date() to detect the mutant
    fail('NUM_BOUNDARY_1564_38_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1565_38_< (HIGH) line 1565 in _risk_check_date() ---
# Source:  # Check for an implausible timezone offset (outside real-world bounds)
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1565_38_< line 1565 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1565 in _risk_check_date() to detect the mutant
    fail('NUM_BOUNDARY_1565_38_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1566_4 (MEDIUM) line 1566 in _risk_check_date() ---
# Source:  if ($date_raw =~ /([+-])(\d{2})(\d{2})\s*$/) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1566_4 line 1566 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1566 in _risk_check_date() to detect the mutant
    fail('COND_INV_1566_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1575_3 (MEDIUM) line 1575 in _risk_check_date() ---
# Source:  . "($sign$hh$mm) -- header is likely forged");
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1575_3 line 1575 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1575 in _risk_check_date() to detect the mutant
    fail('COND_INV_1575_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1577_15_< (HIGH) line 1577 in _risk_check_date() ---
# Source:  }
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1577_15_< line 1577 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1577 in _risk_check_date() to detect the mutant
    fail('NUM_BOUNDARY_1577_15_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1580_20_> (HIGH) line 1580 in _risk_check_date() ---
# Source:  my $date_epoch = _parse_rfc2822_date($date_raw);
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip < to >
#   Numeric boundary flip < to <=
#   Numeric boundary flip < to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1580_20_> line 1580 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1580 in _risk_check_date() to detect the mutant
    fail('NUM_BOUNDARY_1580_20_>: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1592_2 (MEDIUM) line 1592 in _risk_check_date() ---
# Source:  # _risk_check_identity( $flag )
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1592_2 line 1592 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1592 in _risk_check_date() to detect the mutant
    fail('COND_INV_1592_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1600_4 (MEDIUM) line 1600 in _risk_check_date() ---
# Source:  #
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1600_4 line 1600 in _risk_check_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1600 in _risk_check_date() to detect the mutant
    fail('COND_INV_1600_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1608_2 (MEDIUM) line 1608 in _risk_check_identity() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1608_2 line 1608 in _risk_check_identity()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1608 in _risk_check_identity() to detect the mutant
    fail('COND_INV_1608_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1616_2 (MEDIUM) line 1616 in _risk_check_identity() ---
# Source:  my $reg_disp = _registrable($disp_domain);
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

# --- SURVIVOR: COND_INV_1619_3 (MEDIUM) line 1619 in _risk_check_identity() ---
# Source:  $flag->('HIGH', 'display_name_domain_spoof',
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1619_3 line 1619 in _risk_check_identity()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1619 in _risk_check_identity() to detect the mutant
    fail('COND_INV_1619_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1627_2 (MEDIUM) line 1627 in _risk_check_identity() ---
# Source:  || $from_raw =~ /\@mail\.ru(?:[\s>]|$)/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1627_2 line 1627 in _risk_check_identity()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1627 in _risk_check_identity() to detect the mutant
    fail('COND_INV_1627_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1634_2 (MEDIUM) line 1634 in _risk_check_identity() ---
# Source:  if ($reply_to) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1634_2 line 1634 in _risk_check_identity()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1634 in _risk_check_identity() to detect the mutant
    fail('COND_INV_1634_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1650_3 (MEDIUM) line 1650 in _risk_check_identity() ---
# Source:  # MIME-encoded Subject (potential filter evasion)
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1650_3 line 1650 in _risk_check_identity()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1650 in _risk_check_identity() to detect the mutant
    fail('COND_INV_1650_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1655_3 (MEDIUM) line 1655 in _risk_check_identity() ---
# Source:  . $self->_decode_mime_words($subj_raw) . "')");
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1655_3 line 1655 in _risk_check_identity()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1655 in _risk_check_identity() to detect the mutant
    fail('COND_INV_1655_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1664_3 (MEDIUM) line 1664 in _risk_check_identity() ---
# Source:  #
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1664_3 line 1664 in _risk_check_identity()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1664 in _risk_check_identity() to detect the mutant
    fail('COND_INV_1664_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1670_3 (MEDIUM) line 1670 in _risk_check_identity() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1670_3 line 1670 in _risk_check_identity()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1670 in _risk_check_identity() to detect the mutant
    fail('COND_INV_1670_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1671_4 (MEDIUM) line 1671 in _risk_check_urls_and_domains() ---
# Source:  sub _risk_check_urls_and_domains :Private {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1671_4 line 1671 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1671 in _risk_check_urls_and_domains() to detect the mutant
    fail('COND_INV_1671_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1674_20_< (HIGH) line 1674 in _risk_check_urls_and_domains() ---
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
    local $TODO = 'Complete: NUM_BOUNDARY_1674_20_< line 1674 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1674 in _risk_check_urls_and_domains() to detect the mutant
    fail('NUM_BOUNDARY_1674_20_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1677_25_< (HIGH) line 1677 in _risk_check_urls_and_domains() ---
# Source:  my $bare = lc $u->{host};
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1677_25_< line 1677 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1677 in _risk_check_urls_and_domains() to detect the mutant
    fail('NUM_BOUNDARY_1677_25_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1688_4 (MEDIUM) line 1688 in _risk_check_urls_and_domains() ---
# Source:  if ($u->{url} =~ m{^http://}i && !$url_host_seen{ $u->{host} }++) {
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

# --- SURVIVOR: NUM_BOUNDARY_1698_21_> (HIGH) line 1698 in _risk_check_urls_and_domains() ---
# Source:  $flag->('HIGH', 'recently_registered_domain',
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1698_21_> line 1698 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1698 in _risk_check_urls_and_domains() to detect the mutant
    fail('NUM_BOUNDARY_1698_21_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1699_21_> (HIGH) line 1699 in _risk_check_urls_and_domains() ---
# Source:  "$d->{domain} was registered $d->{registered} (less than ${\$RECENT_REG_DAYS} days ago)");
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1699_21_> line 1699 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1699 in _risk_check_urls_and_domains() to detect the mutant
    fail('NUM_BOUNDARY_1699_21_>: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1700_21_> (HIGH) line 1700 in _risk_check_urls_and_domains() ---
# Source:  }
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1700_21_> line 1700 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1700 in _risk_check_urls_and_domains() to detect the mutant
    fail('NUM_BOUNDARY_1700_21_>: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_1704_2 (MEDIUM) line 1704 in _risk_check_urls_and_domains() ---
# Source:  if(my $exp = $self->_parse_date_to_epoch($d->{expires})) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_1704_2 line 1704 in _risk_check_urls_and_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1704 in _risk_check_urls_and_domains() to detect the mutant
    fail('BOOL_NEGATE_1704_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1782_2 (MEDIUM) line 1782 in abuse_report_text() ---
# Source:  sub abuse_report_text {
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
# Source:  '';
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
# Source:  push @out, '';
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
# Source:  'NETWORK OWNER:  ' . _sanitise_output($orig->{org}),
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
# Source:  #   Actual implementation of abuse_contacts(). Separated so the public
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
# Source:  # Exit status:
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

# --- SURVIVOR: NUM_BOUNDARY_1935_22_< (HIGH) line 1935 in _compute_abuse_contacts() ---
# Source:  my $addr = lc($args{address} // '');
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1935_22_< line 1935 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1935 in _compute_abuse_contacts() to detect the mutant
    fail('NUM_BOUNDARY_1935_22_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_1940_24_< (HIGH) line 1940 in _compute_abuse_contacts() ---
# Source:  my $dom = $1;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_1940_24_< line 1940 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1940 in _compute_abuse_contacts() to detect the mutant
    fail('NUM_BOUNDARY_1940_24_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1961_2 (MEDIUM) line 1961 in _compute_abuse_contacts() ---
# Source:  if (length($joined) > $ROLE_MAX_LEN) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1961_2 line 1961 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1961 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1961_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1963_3 (MEDIUM) line 1963 in _compute_abuse_contacts() ---
# Source:  for (@display) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1963_3 line 1963 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1963 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1963_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1971_3 (MEDIUM) line 1971 in _compute_abuse_contacts() ---
# Source:  return;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1971_3 line 1971 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1971 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1971_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1991_3 (MEDIUM) line 1991 in _compute_abuse_contacts() ---
# Source:  }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1991_3 line 1991 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1991 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1991_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_1999_3 (MEDIUM) line 1999 in _compute_abuse_contacts() ---
# Source:  }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_1999_3 line 1999 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 1999 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_1999_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2014_3 (MEDIUM) line 2014 in _compute_abuse_contacts() ---
# Source:  role    => "URL host: $u->{host}",
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2014_3 line 2014 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2014 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2014_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2016_4 (MEDIUM) line 2016 in _compute_abuse_contacts() ---
# Source:  note    => "$u->{host} -- $pa->{note}",
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2016_4 line 2016 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2016 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2016_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2032_3 (MEDIUM) line 2032 in _compute_abuse_contacts() ---
# Source:  my $dom = $d->{domain};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2032_3 line 2032 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2032 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2032_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2045_3 (MEDIUM) line 2045 in _compute_abuse_contacts() ---
# Source:  $dom             // '(unknown domain)',
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2045_3 line 2045 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2045 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2045_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2058_3 (MEDIUM) line 2058 in _compute_abuse_contacts() ---
# Source:  $d->{mx_host} // '(unknown host)',
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

# --- SURVIVOR: COND_INV_2065_4 (MEDIUM) line 2065 in _compute_abuse_contacts() ---
# Source:  # NS (DNS host) contact
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_2065_4 line 2065 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2065 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2065_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2089_3 (MEDIUM) line 2089 in _compute_abuse_contacts() ---
# Source:  address => $d->{registrar_abuse},
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2089_3 line 2089 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2089 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2089_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2103_2 (MEDIUM) line 2103 in _compute_abuse_contacts() ---
# Source:  my ($addr_domain) = $addr_spec =~ /\@([\w.-]+)/;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2103_2 line 2103 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2103 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2103_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2105_3 (MEDIUM) line 2105 in _compute_abuse_contacts() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2105_3 line 2105 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2105 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2105_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2117_2 (MEDIUM) line 2117 in _compute_abuse_contacts() ---
# Source:  via     => 'provider-table',
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2117_2 line 2117 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2117 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2117_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2128_4 (MEDIUM) line 2128 in _compute_abuse_contacts() ---
# Source:  role    => "DKIM signer: $auth->{dkim_domain}",
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2128_4 line 2128 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2128 in _compute_abuse_contacts() to detect the mutant
    fail('COND_INV_2128_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2156_2 (MEDIUM) line 2156 in _compute_abuse_contacts() ---
# Source:  }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2156_2 line 2156 in _compute_abuse_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2156 in _compute_abuse_contacts() to detect the mutant
    fail('BOOL_NEGATE_2156_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2247_2 (MEDIUM) line 2247 in form_contacts() ---
# Source:  # Inner closure: add one form-contact entry, deduplicating by form URL
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2247_2 line 2247 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2247 in form_contacts() to detect the mutant
    fail('COND_INV_2247_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2249_3 (MEDIUM) line 2249 in form_contacts() ---
# Source:  my (%args) = @_;
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
# Source:  form_upload => $pa->{form_upload} // '',
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

# --- SURVIVOR: COND_INV_2283_3 (MEDIUM) line 2283 in form_contacts() ---
# Source:  form_paste  => $pa->{form_paste}  // '',
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2283_3 line 2283 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2283 in form_contacts() to detect the mutant
    fail('COND_INV_2283_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2296_3 (MEDIUM) line 2296 in form_contacts() ---
# Source:  role        => "Web host of $dom",
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2296_3 line 2296 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2296 in form_contacts() to detect the mutant
    fail('COND_INV_2296_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2299_4 (MEDIUM) line 2299 in form_contacts() ---
# Source:  note        => $pa->{note} // '',
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2299_4 line 2299 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2299 in form_contacts() to detect the mutant
    fail('COND_INV_2299_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2322_3 (MEDIUM) line 2322 in form_contacts() ---
# Source:  }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2322_3 line 2322 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2322 in form_contacts() to detect the mutant
    fail('COND_INV_2322_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2338_2 (MEDIUM) line 2338 in form_contacts() ---
# Source:  form        => $pa->{form},
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2338_2 line 2338 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2338 in form_contacts() to detect the mutant
    fail('COND_INV_2338_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2340_3 (MEDIUM) line 2340 in form_contacts() ---
# Source:  form_paste  => $pa->{form_paste}  // '',
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2340_3 line 2340 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2340 in form_contacts() to detect the mutant
    fail('COND_INV_2340_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2354_2 (MEDIUM) line 2354 in form_contacts() ---
# Source:  form        => $pa->{form},
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

# --- SURVIVOR: COND_INV_2361_4 (MEDIUM) line 2361 in form_contacts() ---
# Source:  }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2361_4 line 2361 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2361 in form_contacts() to detect the mutant
    fail('COND_INV_2361_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2374_2 (MEDIUM) line 2374 in form_contacts() ---
# Source:  role        => "ESP / bulk sender (List-Unsubscribe: $dom)",
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2374_2 line 2374 in form_contacts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2374 in form_contacts() to detect the mutant
    fail('BOOL_NEGATE_2374_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2464_2 (MEDIUM) line 2464 in report() ---
# Source:  my $risk = $self->risk_assessment();
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2464_2 line 2464 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2464 in report() to detect the mutant
    fail('COND_INV_2464_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2476_2 (MEDIUM) line 2476 in report() ---
# Source:  push @out, '[ ORIGINATING HOST ]';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2476_2 line 2476 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2476 in report() to detect the mutant
    fail('COND_INV_2476_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2491_2 (MEDIUM) line 2491 in report() ---
# Source:  # Sending software section (omitted if none found)
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2491_2 line 2491 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2491 in report() to detect the mutant
    fail('COND_INV_2491_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2503_2 (MEDIUM) line 2503 in report() ---
# Source:  my @trail = grep { defined $_->{id} || defined $_->{for} }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2503_2 line 2503 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2503 in report() to detect the mutant
    fail('COND_INV_2503_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2518_2 (MEDIUM) line 2518 in report() ---
# Source:  push @out, '[ EMBEDDED HTTP/HTTPS URLs ]';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2518_2 line 2518 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2518 in report() to detect the mutant
    fail('COND_INV_2518_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2523_4 (MEDIUM) line 2523 in report() ---
# Source:  for my $u (@urls) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_2523_4 line 2523 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2523 in report() to detect the mutant
    fail('COND_INV_2523_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2547_15_!= (HIGH) line 2547 in report() ---
# Source:  push @out, '  Abuse addr   : ' . _sanitise_output($m->{abuse})   if $m->{abuse};
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (2 variants — one test should kill all):
#   Numeric boundary flip == to !=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2547_15_!= line 2547 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2547 in report() to detect the mutant
    fail('NUM_BOUNDARY_2547_15_!=: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2563_2 (MEDIUM) line 2563 in report() ---
# Source:  push @out, '[ CONTACT / REPLY-TO DOMAINS ]';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2563_2 line 2563 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2563 in report() to detect the mutant
    fail('COND_INV_2563_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2567_4 (MEDIUM) line 2567 in report() ---
# Source:  push @out, '  Domain       : ' . _sanitise_output($d->{domain});
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2567_4 line 2567 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2567 in report() to detect the mutant
    fail('COND_INV_2567_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2574_4 (MEDIUM) line 2574 in report() ---
# Source:  push @out, '  Registrar    : ' . _sanitise_output($d->{registrar})       if $d->{registrar};
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
# Source:  push @out, '  Web host     : (no A record / unreachable)';
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

# --- SURVIVOR: COND_INV_2589_4 (MEDIUM) line 2589 in report() ---
# Source:  push @out, '  MX host      : (none found)';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2589_4 line 2589 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2589 in report() to detect the mutant
    fail('COND_INV_2589_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2605_2 (MEDIUM) line 2605 in report() ---
# Source:  push @out, '[ WHERE TO SEND ABUSE REPORTS ]';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2605_2 line 2605 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2605 in report() to detect the mutant
    fail('COND_INV_2605_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2620_2 (MEDIUM) line 2620 in report() ---
# Source:  # Web-form contacts (providers that require manual form submission)
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2620_2 line 2620 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2620 in report() to detect the mutant
    fail('COND_INV_2620_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2630_4 (MEDIUM) line 2630 in report() ---
# Source:  push @out, '  Domain/URL   : ' . _sanitise_output($c->{form_domain}) if $c->{form_domain};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2630_4 line 2630 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2630 in report() to detect the mutant
    fail('COND_INV_2630_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2636_46_< (HIGH) line 2636 in report() ---
# Source:  my (@lines, $line);
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2636_46_< line 2636 in report()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2636 in report() to detect the mutant
    fail('NUM_BOUNDARY_2636_46_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2681_2 (MEDIUM) line 2681 in _sanitise_output() ---
# Source:  sub _sanitise_output :Private {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2681_2 line 2681 in _sanitise_output()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2681 in _sanitise_output() to detect the mutant
    fail('BOOL_NEGATE_2681_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2684_2 (MEDIUM) line 2684 in _sanitise_output() ---
# Source:  # Remove C0 controls (except tab) and DEL
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2684_2 line 2684 in _sanitise_output()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2684 in _sanitise_output() to detect the mutant
    fail('BOOL_NEGATE_2684_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2731_3 (MEDIUM) line 2731 in _split_message() ---
# Source:  my @headers;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2731_3 line 2731 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2731 in _split_message() to detect the mutant
    fail('COND_INV_2731_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2750_2 (MEDIUM) line 2750 in _split_message() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2750_2 line 2750 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2750 in _split_message() to detect the mutant
    fail('COND_INV_2750_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2756_3 (MEDIUM) line 2756 in _split_message() ---
# Source:  } else {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2756_3 line 2756 in _split_message()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2756 in _split_message() to detect the mutant
    fail('COND_INV_2756_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2830_13_> (HIGH) line 2830 in _decode_multipart() ---
# Source:  # Enforce the recursion depth limit to prevent stack exhaustion on
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip >= to >
#   Numeric boundary flip >= to <
#   Numeric boundary flip >= to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2830_13_> line 2830 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2830 in _decode_multipart() to detect the mutant
    fail('NUM_BOUNDARY_2830_13_>: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2863_3 (MEDIUM) line 2863 in _decode_multipart() ---
# Source:  # Nested multipart/* must be recursed into; without this URLs in
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2863_3 line 2863 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2863 in _decode_multipart() to detect the mutant
    fail('COND_INV_2863_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2865_4 (MEDIUM) line 2865 in _decode_multipart() ---
# Source:  if ($pct =~ /multipart/i) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2865_4 line 2865 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2865 in _decode_multipart() to detect the mutant
    fail('COND_INV_2865_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2875_3 (MEDIUM) line 2875 in _decode_multipart() ---
# Source:  # Decode transfer encoding and accumulate by content type
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2875_3 line 2875 in _decode_multipart()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2875 in _decode_multipart() to detect the mutant
    fail('COND_INV_2875_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2902_2 (MEDIUM) line 2902 in _decode_body() ---
# Source:  return decode_qp($body)     if $cte =~ /quoted-printable/i;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2902_2 line 2902 in _decode_body()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2902 in _decode_body() to detect the mutant
    fail('BOOL_NEGATE_2902_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2946_2 (MEDIUM) line 2946 in _find_origin() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_2946_2 line 2946 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2946 in _find_origin() to detect the mutant
    fail('COND_INV_2946_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2948_3 (MEDIUM) line 2948 in _find_origin() ---
# Source:  unless (@candidates) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2948_3 line 2948 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2948 in _find_origin() to detect the mutant
    fail('COND_INV_2948_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2950_4 (MEDIUM) line 2950 in _find_origin() ---
# Source:  if ($xoip) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2950_4 line 2950 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2950 in _find_origin() to detect the mutant
    fail('BOOL_NEGATE_2950_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2958_2 (MEDIUM) line 2958 in _find_origin() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2958_2 line 2958 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2958 in _find_origin() to detect the mutant
    fail('BOOL_NEGATE_2958_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2960_15_< (HIGH) line 2960 in _find_origin() ---
# Source:  return $self->_enrich_ip(
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2960_15_< line 2960 in _find_origin()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2960 in _find_origin() to detect the mutant
    fail('NUM_BOUNDARY_2960_15_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_2985_3 (MEDIUM) line 2985 in _extract_ip_from_received() ---
# Source:  my ($self, $hdr) = @_;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_2985_3 line 2985 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2985 in _extract_ip_from_received() to detect the mutant
    fail('COND_INV_2985_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2989_4 (MEDIUM) line 2989 in _extract_ip_from_received() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2989_4 line 2989 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2989 in _extract_ip_from_received() to detect the mutant
    fail('BOOL_NEGATE_2989_4: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_2993_22_< (HIGH) line 2993 in _extract_ip_from_received() ---
# Source:  # Validate IPv4 format and octet range
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_2993_22_< line 2993 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2993 in _extract_ip_from_received() to detect the mutant
    fail('NUM_BOUNDARY_2993_22_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_2994_4 (MEDIUM) line 2994 in _extract_ip_from_received() ---
# Source:  next unless $ip =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_2994_4 line 2994 in _extract_ip_from_received()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 2994 in _extract_ip_from_received() to detect the mutant
    fail('BOOL_NEGATE_2994_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3019_2 (MEDIUM) line 3019 in _is_private() ---
# Source:  sub _is_private :Private {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3019_2 line 3019 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3019 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_3019_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3020_33 (MEDIUM) line 3020 in _is_private() ---
# Source:  my ($self, $ip) = @_;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3020_33 line 3020 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3020 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_3020_33: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3021_2 (MEDIUM) line 3021 in _is_private() ---
# Source:  return 1 if !defined($ip) || $ip eq '';
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3021_2 line 3021 in _is_private()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3021 in _is_private() to detect the mutant
    fail('BOOL_NEGATE_3021_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3040_3 (MEDIUM) line 3040 in _is_trusted() ---
# Source:  my ($self, $ip) = @_;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3040_3 line 3040 in _is_trusted()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3040 in _is_trusted() to detect the mutant
    fail('BOOL_NEGATE_3040_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3042_2 (MEDIUM) line 3042 in _is_trusted() ---
# Source:  return 1 if $self->_ip_in_cidr($ip, $cidr);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3042_2 line 3042 in _is_trusted()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3042 in _is_trusted() to detect the mutant
    fail('BOOL_NEGATE_3042_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3083_57_< (HIGH) line 3083 in _extract_and_resolve_urls() ---
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3083_57_< line 3083 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3083 in _extract_and_resolve_urls() to detect the mutant
    fail('NUM_BOUNDARY_3083_57_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3093_3 (MEDIUM) line 3093 in _extract_and_resolve_urls() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_3093_3 line 3093 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3093 in _extract_and_resolve_urls() to detect the mutant
    fail('COND_INV_3093_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3096_4 (MEDIUM) line 3096 in _extract_and_resolve_urls() ---
# Source:  # Check the cross-message CHI cache first
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3096_4 line 3096 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3096 in _extract_and_resolve_urls() to detect the mutant
    fail('COND_INV_3096_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3105_5 (MEDIUM) line 3105 in _extract_and_resolve_urls() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3105_5 line 3105 in _extract_and_resolve_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3105 in _extract_and_resolve_urls() to detect the mutant
    fail('COND_INV_3105_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3162_5 (MEDIUM) line 3162 in _parallel_resolve_hosts() ---
# Source:  sub {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3162_5 line 3162 in _parallel_resolve_hosts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3162 in _parallel_resolve_hosts() to detect the mutant
    fail('COND_INV_3162_5: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3167_29_< (HIGH) line 3167 in _parallel_resolve_hosts() ---
# Source:  }
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3167_29_< line 3167 in _parallel_resolve_hosts()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3167 in _parallel_resolve_hosts() to detect the mutant
    fail('NUM_BOUNDARY_3167_29_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3194_2 (MEDIUM) line 3194 in _extract_http_urls() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3194_2 line 3194 in _extract_http_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3194 in _extract_http_urls() to detect the mutant
    fail('COND_INV_3194_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3199_5 (MEDIUM) line 3199 in _extract_http_urls() ---
# Source:  for my $attr (qw(href src action)) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3199_5 line 3199 in _extract_http_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3199 in _extract_http_urls() to detect the mutant
    fail('COND_INV_3199_5: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3224_2 (MEDIUM) line 3224 in _extract_http_urls() ---
# Source:  my @all = grep { !$seen{$_}++ } @urls;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3224_2 line 3224 in _extract_http_urls()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3224 in _extract_http_urls() to detect the mutant
    fail('BOOL_NEGATE_3224_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3303_2 (MEDIUM) line 3303 in _extract_and_analyse_domains() ---
# Source:  # Message-ID domain often reveals the real bulk-sending platform
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3303_2 line 3303 in _extract_and_analyse_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3303 in _extract_and_analyse_domains() to detect the mutant
    fail('COND_INV_3303_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3318_2 (MEDIUM) line 3318 in _extract_and_analyse_domains() ---
# Source:  # List-Unsubscribe identifies the ESP or bulk sender
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3318_2 line 3318 in _extract_and_analyse_domains()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3318 in _extract_and_analyse_domains() to detect the mutant
    fail('COND_INV_3318_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3368_2 (MEDIUM) line 3368 in _domains_from_text() ---
# Source:  push @out, $dom unless $seen{$dom}++;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3368_2 line 3368 in _domains_from_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3368 in _domains_from_text() to detect the mutant
    fail('BOOL_NEGATE_3368_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3402_2 (MEDIUM) line 3402 in _analyse_domain() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3402_2 line 3402 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3402 in _analyse_domain() to detect the mutant
    fail('BOOL_NEGATE_3402_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3406_2 (MEDIUM) line 3406 in _analyse_domain() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3406_2 line 3406 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3406 in _analyse_domain() to detect the mutant
    fail('COND_INV_3406_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3408_3 (MEDIUM) line 3408 in _analyse_domain() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3408_3 line 3408 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3408 in _analyse_domain() to detect the mutant
    fail('COND_INV_3408_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3410_4 (MEDIUM) line 3410 in _analyse_domain() ---
# Source:  if ($cached) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3410_4 line 3410 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3410 in _analyse_domain() to detect the mutant
    fail('BOOL_NEGATE_3410_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3419_2 (MEDIUM) line 3419 in _analyse_domain() ---
# Source:  # --- A record -> web hosting IP ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3419_2 line 3419 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3419 in _analyse_domain() to detect the mutant
    fail('COND_INV_3419_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3427_2 (MEDIUM) line 3427 in _analyse_domain() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3427_2 line 3427 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3427 in _analyse_domain() to detect the mutant
    fail('COND_INV_3427_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3435_3 (MEDIUM) line 3435 in _analyse_domain() ---
# Source:  # --- MX record -> mail hosting ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3435_3 line 3435 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3435 in _analyse_domain() to detect the mutant
    fail('COND_INV_3435_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3438_4 (MEDIUM) line 3438 in _analyse_domain() ---
# Source:  my ($best) = sort { $a->preference <=> $b->preference }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3438_4 line 3438 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3438 in _analyse_domain() to detect the mutant
    fail('COND_INV_3438_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3442_5 (MEDIUM) line 3442 in _analyse_domain() ---
# Source:  $info{mx_host} = $mx_host;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3442_5 line 3442 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3442 in _analyse_domain() to detect the mutant
    fail('COND_INV_3442_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3453_3 (MEDIUM) line 3453 in _analyse_domain() ---
# Source:  # --- NS record -> DNS hosting ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3453_3 line 3453 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3453 in _analyse_domain() to detect the mutant
    fail('COND_INV_3453_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3455_4 (MEDIUM) line 3455 in _analyse_domain() ---
# Source:  if ($nsq) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3455_4 line 3455 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3455 in _analyse_domain() to detect the mutant
    fail('COND_INV_3455_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3459_5 (MEDIUM) line 3459 in _analyse_domain() ---
# Source:  $info{ns_host} = $ns_host;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3459_5 line 3459 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3459 in _analyse_domain() to detect the mutant
    fail('COND_INV_3459_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3471_2 (MEDIUM) line 3471 in _analyse_domain() ---
# Source:  # --- Domain WHOIS -> registrar + dates ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3471_2 line 3471 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3471 in _analyse_domain() to detect the mutant
    fail('COND_INV_3471_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3476_3 (MEDIUM) line 3476 in _analyse_domain() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3476_3 line 3476 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3476 in _analyse_domain() to detect the mutant
    fail('COND_INV_3476_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3486_4 (MEDIUM) line 3486 in _analyse_domain() ---
# Source:  qr/abuse-contact:\s*(\S+@\S+)/i,
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3486_4 line 3486 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3486 in _analyse_domain() to detect the mutant
    fail('COND_INV_3486_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3498_4 (MEDIUM) line 3498 in _analyse_domain() ---
# Source:  qr/^registered:\s*(\S+)/im,
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3498_4 line 3498 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3498 in _analyse_domain() to detect the mutant
    fail('COND_INV_3498_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3509_4 (MEDIUM) line 3509 in _analyse_domain() ---
# Source:  qr/paid-till:\s*(\S+)/i,
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3509_4 line 3509 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3509 in _analyse_domain() to detect the mutant
    fail('COND_INV_3509_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3515_3 (MEDIUM) line 3515 in _analyse_domain() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3515_3 line 3515 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3515 in _analyse_domain() to detect the mutant
    fail('COND_INV_3515_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3518_36_> (HIGH) line 3518 in _analyse_domain() ---
# Source:  my $epoch = $self->_parse_date_to_epoch($info{registered});
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip < to >
#   Numeric boundary flip < to <=
#   Numeric boundary flip < to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3518_36_> line 3518 in _analyse_domain()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3518 in _analyse_domain() to detect the mutant
    fail('NUM_BOUNDARY_3518_36_>: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3552_2 (MEDIUM) line 3552 in _resolve_host() ---
# Source:  sub _resolve_host :Protected {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3552_2 line 3552 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3552 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_3552_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3555_2 (MEDIUM) line 3555 in _resolve_host() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3555_2 line 3555 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3555 in _resolve_host() to detect the mutant
    fail('COND_INV_3555_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3557_3 (MEDIUM) line 3557 in _resolve_host() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3557_3 line 3557 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3557 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_3557_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3562_2 (MEDIUM) line 3562 in _resolve_host() ---
# Source:  my $ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3562_2 line 3562 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3562 in _resolve_host() to detect the mutant
    fail('COND_INV_3562_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3571_4 (MEDIUM) line 3571 in _resolve_host() ---
# Source:  for my $type (qw(A AAAA)) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3571_4 line 3571 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3571 in _resolve_host() to detect the mutant
    fail('COND_INV_3571_4: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3573_6 (MEDIUM) line 3573 in _resolve_host() ---
# Source:  if ($query) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3573_6 line 3573 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3573 in _resolve_host() to detect the mutant
    fail('COND_INV_3573_6: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3591_2 (MEDIUM) line 3591 in _resolve_host() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3591_2 line 3591 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3591 in _resolve_host() to detect the mutant
    fail('COND_INV_3591_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3595_2 (MEDIUM) line 3595 in _resolve_host() ---
# Source:  }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3595_2 line 3595 in _resolve_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3595 in _resolve_host() to detect the mutant
    fail('BOOL_NEGATE_3595_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3614_2 (MEDIUM) line 3614 in _reverse_dns() ---
# Source:  return unless $ip;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3614_2 line 3614 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3614 in _reverse_dns() to detect the mutant
    fail('COND_INV_3614_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3617_3 (MEDIUM) line 3617 in _reverse_dns() ---
# Source:  my $res   = Net::DNS::Resolver->new(tcp_timeout => $self->{timeout});
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3617_3 line 3617 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3617 in _reverse_dns() to detect the mutant
    fail('COND_INV_3617_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3619_5 (MEDIUM) line 3619 in _reverse_dns() ---
# Source:  if ($query) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3619_5 line 3619 in _reverse_dns()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3619 in _reverse_dns() to detect the mutant
    fail('BOOL_NEGATE_3619_5: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3650_2 (MEDIUM) line 3650 in _whois_ip() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3650_2 line 3650 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3650 in _whois_ip() to detect the mutant
    fail('COND_INV_3650_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3652_3 (MEDIUM) line 3652 in _whois_ip() ---
# Source:  if ($_cache) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3652_3 line 3652 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3652 in _whois_ip() to detect the mutant
    fail('BOOL_NEGATE_3652_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3658_2 (MEDIUM) line 3658 in _whois_ip() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition unless to if
TODO: {
    local $TODO = 'Complete: COND_INV_3658_2 line 3658 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3658 in _whois_ip() to detect the mutant
    fail('COND_INV_3658_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3660_3 (MEDIUM) line 3660 in _whois_ip() ---
# Source:  unless ($result->{org}) {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3660_3 line 3660 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3660 in _whois_ip() to detect the mutant
    fail('COND_INV_3660_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3670_2 (MEDIUM) line 3670 in _whois_ip() ---
# Source:  $_cache->set("whois_ip:$ip", $result) if $_cache && $result;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3670_2 line 3670 in _whois_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3670 in _whois_ip() to detect the mutant
    fail('BOOL_NEGATE_3670_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3690_2 (MEDIUM) line 3690 in _domain_whois() ---
# Source:  my ($server) = $iana =~ /whois:\s*([\w.-]+)/i;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3690_2 line 3690 in _domain_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3690 in _domain_whois() to detect the mutant
    fail('BOOL_NEGATE_3690_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3710_2 (MEDIUM) line 3710 in _parse_domain_whois_abuse() ---
# Source:  my $raw = $self->_domain_whois($domain) // return {};
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3710_2 line 3710 in _parse_domain_whois_abuse()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3710 in _parse_domain_whois_abuse() to detect the mutant
    fail('COND_INV_3710_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3719_3 (MEDIUM) line 3719 in _parse_domain_whois_abuse() ---
# Source:  qr/abuse-contact:\s*(\S+\@\S+)/i,
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3719_3 line 3719 in _parse_domain_whois_abuse()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3719 in _parse_domain_whois_abuse() to detect the mutant
    fail('COND_INV_3719_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3744_2 (MEDIUM) line 3744 in _rdap_lookup() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3744_2 line 3744 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3744 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3744_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3750_3 (MEDIUM) line 3750 in _rdap_lookup() ---
# Source:  );
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3750_3 line 3750 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3750 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3750_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3769_2 (MEDIUM) line 3769 in _rdap_lookup() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3769_2 line 3769 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3769 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3769_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3770_2 (MEDIUM) line 3770 in _rdap_lookup() ---
# Source:  # Extract organisation name from the JSON response
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3770_2 line 3770 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3770 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3770_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3773_2 (MEDIUM) line 3773 in _rdap_lookup() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3773_2 line 3773 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3773 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3773_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3780_2 (MEDIUM) line 3780 in _rdap_lookup() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3780_2 line 3780 in _rdap_lookup()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3780 in _rdap_lookup() to detect the mutant
    fail('COND_INV_3780_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3840_31_< (HIGH) line 3840 in _raw_whois() ---
# Source:  my $n = eval { sysread($sock, $buf, $WHOIS_READ_CHUNK) };
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3840_31_< line 3840 in _raw_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3840 in _raw_whois() to detect the mutant
    fail('NUM_BOUNDARY_3840_31_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_3844_30_< (HIGH) line 3844 in _raw_whois() ---
# Source:  last;
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (3 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_3844_30_< line 3844 in _raw_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3844 in _raw_whois() to detect the mutant
    fail('NUM_BOUNDARY_3844_30_<: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3849_2 (MEDIUM) line 3849 in _raw_whois() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3849_2 line 3849 in _raw_whois()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3849 in _raw_whois() to detect the mutant
    fail('BOOL_NEGATE_3849_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3874_3 (MEDIUM) line 3874 in _parse_whois_text() ---
# Source:  qr/^owner:\s*(.+)/mi,      qr/^descr:\s*(.+)/mi,
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3874_3 line 3874 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3874 in _parse_whois_text() to detect the mutant
    fail('COND_INV_3874_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3884_3 (MEDIUM) line 3884 in _parse_whois_text() ---
# Source:  qr/abuse-mailbox:\s*(\S+@\S+)/mi,
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3884_3 line 3884 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3884 in _parse_whois_text() to detect the mutant
    fail('COND_INV_3884_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3890_2 (MEDIUM) line 3890 in _parse_whois_text() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3890_2 line 3890 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3890 in _parse_whois_text() to detect the mutant
    fail('COND_INV_3890_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3893_2 (MEDIUM) line 3893 in _parse_whois_text() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3893_2 line 3893 in _parse_whois_text()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3893 in _parse_whois_text() to detect the mutant
    fail('COND_INV_3893_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3919_2 (MEDIUM) line 3919 in _parse_auth_results_cached() ---
# Source:  sub _parse_auth_results_cached :Private {
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3919_2 line 3919 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3919 in _parse_auth_results_cached() to detect the mutant
    fail('BOOL_NEGATE_3919_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3931_2 (MEDIUM) line 3931 in _parse_auth_results_cached() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3931_2 line 3931 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3931 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_3931_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3932_2 (MEDIUM) line 3932 in _parse_auth_results_cached() ---
# Source:  # Extract individual authentication mechanism results
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3932_2 line 3932 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3932 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_3932_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3933_2 (MEDIUM) line 3933 in _parse_auth_results_cached() ---
# Source:  if ($raw =~ /\bspf=(\S+)/i)   { $auth{spf}   = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3933_2 line 3933 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3933 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_3933_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3934_2 (MEDIUM) line 3934 in _parse_auth_results_cached() ---
# Source:  if ($raw =~ /\bdkim=(\S+)/i)  { $auth{dkim}  = $1 }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3934_2 line 3934 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3934 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_3934_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3945_3 (MEDIUM) line 3945 in _parse_auth_results_cached() ---
# Source:  my @dkim_domains;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3945_3 line 3945 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3945 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_3945_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3950_2 (MEDIUM) line 3950 in _parse_auth_results_cached() ---
# Source:  }
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3950_2 line 3950 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3950 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_3950_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_3954_4 (MEDIUM) line 3954 in _parse_auth_results_cached() ---
# Source:  my $preferred;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_3954_4 line 3954 in _parse_auth_results_cached()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3954 in _parse_auth_results_cached() to detect the mutant
    fail('COND_INV_3954_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_3988_3 (MEDIUM) line 3988 in _provider_abuse_for_host() ---
# Source:  # Strip successive subdomains until we find a match or exhaust labels
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_3988_3 line 3988 in _provider_abuse_for_host()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 3988 in _provider_abuse_for_host() to detect the mutant
    fail('BOOL_NEGATE_3988_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4010_2 (MEDIUM) line 4010 in _provider_abuse_for_ip() ---
# Source:  sub _provider_abuse_for_ip :Private {
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

# --- SURVIVOR: COND_INV_4041_2 (MEDIUM) line 4041 in _registrable() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4041_2 line 4041 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4041 in _registrable() to detect the mutant
    fail('COND_INV_4041_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4044_3 (MEDIUM) line 4044 in _registrable() ---
# Source:  my $psl = Domain::PublicSuffix->new();
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4044_3 line 4044 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4044 in _registrable() to detect the mutant
    fail('BOOL_NEGATE_4044_3: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4049_26_< (HIGH) line 4049 in _registrable() ---
# Source:  # Built-in heuristic fallback
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip <= to <
#   Numeric boundary flip <= to >
#   Numeric boundary flip <= to >=
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4049_26_< line 4049 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4049 in _registrable() to detect the mutant
    fail('NUM_BOUNDARY_4049_26_<: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4052_2 (MEDIUM) line 4052 in _registrable() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4052_2 line 4052 in _registrable()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4052 in _registrable() to detect the mutant
    fail('COND_INV_4052_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4108_3 (MEDIUM) line 4108 in _enrich_ip() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4108_3 line 4108 in _enrich_ip()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4108 in _enrich_ip() to detect the mutant
    fail('BOOL_NEGATE_4108_3: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4128_2 (MEDIUM) line 4128 in header_value() ---
# Source:  #   $name -- a lower-cased header name string.
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4128_2 line 4128 in header_value()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4128 in header_value() to detect the mutant
    fail('BOOL_NEGATE_4128_2: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4130_65_< (HIGH) line 4130 in header_value() ---
# Source:  #
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (4 variants — one test should kill all):
#   Numeric boundary flip > to <
#   Numeric boundary flip > to >=
#   Numeric boundary flip > to <=
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4130_65_< line 4130 in header_value()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4130 in header_value() to detect the mutant
    fail('NUM_BOUNDARY_4130_65_<: replace with real assertion');
}

# --- SURVIVOR: NUM_BOUNDARY_4136_25_!= (HIGH) line 4136 in _header_value() ---
# Source:  for my $h (@{ $self->{_headers} }) {
# Hint:    Likely missing edge-case test (boundary value)
# Mutations on this line (1 variant):
#   Numeric boundary flip == to !=
TODO: {
    local $TODO = 'Complete: NUM_BOUNDARY_4136_25_!= line 4136 in _header_value()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4136 in _header_value() to detect the mutant
    fail('NUM_BOUNDARY_4136_25_!=: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4153_2 (MEDIUM) line 4153 in _header_value() ---
# Source:  #   Returns 1 (true) if the IP is within the CIDR block, 0 otherwise.
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4153_2 line 4153 in _header_value()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4153 in _header_value() to detect the mutant
    fail('BOOL_NEGATE_4153_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4156_2 (MEDIUM) line 4156 in _ip_in_cidr() ---
# Source:  my ($self, $ip, $cidr) = @_;
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4156_2 line 4156 in _ip_in_cidr()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4156 in _ip_in_cidr() to detect the mutant
    fail('BOOL_NEGATE_4156_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4171_2 (MEDIUM) line 4171 in _ip_in_cidr() ---
# Source:  #   Decode MIME encoded-words (=?charset?B/Q?...?=) in a header value
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4171_2 line 4171 in _ip_in_cidr()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4171 in _ip_in_cidr() to detect the mutant
    fail('COND_INV_4171_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4178_2 (MEDIUM) line 4178 in _ip_in_cidr() ---
# Source:  #   Returns the decoded string, or '' if $str is undef.
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4178_2 line 4178 in _ip_in_cidr()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4178 in _ip_in_cidr() to detect the mutant
    fail('BOOL_NEGATE_4178_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4201_2 (MEDIUM) line 4201 in _decode_ew() ---
# Source:  $raw = decode_base64($text);
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4201_2 line 4201 in _decode_ew()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4201 in _decode_ew() to detect the mutant
    fail('COND_INV_4201_2: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4213_4 (MEDIUM) line 4213 in _decode_ew() ---
# Source:  #   Parse common WHOIS date strings to a Unix epoch integer.
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4213_4 line 4213 in _decode_ew()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4213 in _decode_ew() to detect the mutant
    fail('BOOL_NEGATE_4213_4: replace with real assertion');
}

# --- SURVIVOR: BOOL_NEGATE_4215_3 (MEDIUM) line 4215 in _decode_ew() ---
# Source:  #
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Negate boolean return expression
TODO: {
    local $TODO = 'Complete: BOOL_NEGATE_4215_3 line 4215 in _decode_ew()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4215 in _decode_ew() to detect the mutant
    fail('BOOL_NEGATE_4215_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4219_2 (MEDIUM) line 4219 in _decode_ew() ---
# Source:  # Exit status:
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4219_2 line 4219 in _decode_ew()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4219 in _decode_ew() to detect the mutant
    fail('COND_INV_4219_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4225_2 (MEDIUM) line 4225 in _parse_date_to_epoch() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4225_2 line 4225 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4225 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_4225_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4251_2 (MEDIUM) line 4251 in _parse_date_to_epoch() ---
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4251_2 line 4251 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4251 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_4251_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4255_3 (MEDIUM) line 4255 in _parse_date_to_epoch() ---
# Source:  return eval { Time::Local::timegm(0,0,0,$d,$m-1,$y-1900) };
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4255_3 line 4255 in _parse_date_to_epoch()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4255 in _parse_date_to_epoch() to detect the mutant
    fail('COND_INV_4255_3: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4299_2 (MEDIUM) line 4299 in _parse_rfc2822_date() ---
# Source:  #   $cc -- a two-letter uppercase country code string.
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4299_2 line 4299 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4299 in _parse_rfc2822_date() to detect the mutant
    fail('COND_INV_4299_2: replace with real assertion');
}

# --- SURVIVOR: COND_INV_4300_3 (MEDIUM) line 4300 in _parse_rfc2822_date() ---
# Source:  #
# Hint:    Add tests asserting both true and false outcomes
# Mutations on this line (1 variant):
#   Invert condition if to unless
TODO: {
    local $TODO = 'Complete: COND_INV_4300_3 line 4300 in _parse_rfc2822_date()';
    # NOTE: new() called with no arguments as a starting point.
    # If Email::Abuse::Investigator requires constructor arguments, add them here.
    my $obj = new_ok('Email::Abuse::Investigator');
    # TODO: exercise line 4300 in _parse_rfc2822_date() to detect the mutant
    fail('COND_INV_4300_3: replace with real assertion');
}

# --- LOW DIFFICULTY HINTS (comment stubs) ---

# --- LOW HINT: RETURN_UNDEF_781_2 line 781 in new() ---
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new is a class method — call directly.
# e.g. my $result = Email::Abuse::Investigator->new(...);
# ok($result, 'RETURN_UNDEF_781_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_867_2 line 867 in parse_email() ---
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_867_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1112_2 line 1112 in all_domains() ---
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1112_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1228_2 line 1228 in unresolved_contacts() ---
# Source:  my @sw = $analyser->sending_software();
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1228_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1463_2 line 1463 in _risk_check_origin() ---
# Source:  $flag->('HIGH', 'residential_sending_ip',
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1463_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_1704_2 line 1704 in _risk_check_urls_and_domains() ---
# Source:  if(my $exp = $self->_parse_date_to_epoch($d->{expires})) {
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_1704_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2156_2 line 2156 in _compute_abuse_contacts() ---
# Source:  }
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2156_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2374_2 line 2374 in form_contacts() ---
# Source:  role        => "ESP / bulk sender (List-Unsubscribe: $dom)",
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2374_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2681_2 line 2681 in _sanitise_output() ---
# Source:  sub _sanitise_output :Private {
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2681_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2684_2 line 2684 in _sanitise_output() ---
# Source:  # Remove C0 controls (except tab) and DEL
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2684_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2902_2 line 2902 in _decode_body() ---
# Source:  return decode_qp($body)     if $cte =~ /quoted-printable/i;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2902_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2950_4 line 2950 in _find_origin() ---
# Source:  if ($xoip) {
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2950_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2958_2 line 2958 in _find_origin() ---
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2958_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2989_4 line 2989 in _extract_ip_from_received() ---
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2989_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_2994_4 line 2994 in _extract_ip_from_received() ---
# Source:  next unless $ip =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_2994_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3019_2 line 3019 in _is_private() ---
# Source:  sub _is_private :Private {
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3019_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3020_33 line 3020 in _is_private() ---
# Source:  my ($self, $ip) = @_;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3020_33: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3021_2 line 3021 in _is_private() ---
# Source:  return 1 if !defined($ip) || $ip eq '';
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3021_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3040_3 line 3040 in _is_trusted() ---
# Source:  my ($self, $ip) = @_;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3040_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3042_2 line 3042 in _is_trusted() ---
# Source:  return 1 if $self->_ip_in_cidr($ip, $cidr);
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3042_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3224_2 line 3224 in _extract_http_urls() ---
# Source:  my @all = grep { !$seen{$_}++ } @urls;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3224_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3368_2 line 3368 in _domains_from_text() ---
# Source:  push @out, $dom unless $seen{$dom}++;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3368_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3402_2 line 3402 in _analyse_domain() ---
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3402_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3410_4 line 3410 in _analyse_domain() ---
# Source:  if ($cached) {
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3410_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3552_2 line 3552 in _resolve_host() ---
# Source:  sub _resolve_host :Protected {
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3552_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3557_3 line 3557 in _resolve_host() ---
# Source:  if ($_cache) {
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3557_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3595_2 line 3595 in _resolve_host() ---
# Source:  }
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3595_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3619_5 line 3619 in _reverse_dns() ---
# Source:  if ($query) {
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3619_5: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3652_3 line 3652 in _whois_ip() ---
# Source:  if ($_cache) {
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3652_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3670_2 line 3670 in _whois_ip() ---
# Source:  $_cache->set("whois_ip:$ip", $result) if $_cache && $result;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3670_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3690_2 line 3690 in _domain_whois() ---
# Source:  my ($server) = $iana =~ /whois:\s*([\w.-]+)/i;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3690_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3849_2 line 3849 in _raw_whois() ---
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3849_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3919_2 line 3919 in _parse_auth_results_cached() ---
# Source:  sub _parse_auth_results_cached :Private {
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3919_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_3988_3 line 3988 in _provider_abuse_for_host() ---
# Source:  # Strip successive subdomains until we find a match or exhaust labels
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_3988_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4010_2 line 4010 in _provider_abuse_for_ip() ---
# Source:  sub _provider_abuse_for_ip :Private {
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4010_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4044_3 line 4044 in _registrable() ---
# Source:  my $psl = Domain::PublicSuffix->new();
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4044_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4049_2 line 4049 in _registrable() ---
# Source:  # Built-in heuristic fallback
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4049_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4108_3 line 4108 in _enrich_ip() ---
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4108_3: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4128_2 line 4128 in header_value() ---
# Source:  #   $name -- a lower-cased header name string.
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4128_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4130_2 line 4130 in header_value() ---
# Source:  #
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4130_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4153_2 line 4153 in _header_value() ---
# Source:  #   Returns 1 (true) if the IP is within the CIDR block, 0 otherwise.
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4153_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4156_2 line 4156 in _ip_in_cidr() ---
# Source:  my ($self, $ip, $cidr) = @_;
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4156_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4178_2 line 4178 in _ip_in_cidr() ---
# Source:  #   Returns the decoded string, or '' if $str is undef.
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4178_2: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4213_4 line 4213 in _decode_ew() ---
# Source:  #   Parse common WHOIS date strings to a Unix epoch integer.
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4213_4: add assertion here');

# --- LOW HINT: RETURN_UNDEF_4215_3 line 4215 in _decode_ew() ---
# Source:  #
# Hint:    Mutation survived, but impact may be minor
# Mutations on this line (1 variant):
#   Replace return expression with undef
# NOTE: new() called with no arguments as a starting point.
# If Email::Abuse::Investigator requires constructor arguments, add them here.
# my $obj = new_ok('Email::Abuse::Investigator');
# ok($obj->..., 'RETURN_UNDEF_4215_3: add assertion here');

done_testing();
