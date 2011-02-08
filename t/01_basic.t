#!/usr/bin/env perl

use strict;
use warnings;
use Test::More qw/no_plan/;
use Test::Exception;
use Devel::Dwarn;
use Scalar::Util qw/refaddr/;

use_ok "Digest::PBKDF2";

my $dig = Digest::PBKDF2->new;

can_ok( $dig, qw/new clone add digest/ );

lives_ok( sub { $dig->add('cool') }, "I can add one chunk" );

lives_ok( sub { $dig->add('outl2nd') }, "I can add another chunk" );

my $clone;
lives_ok( sub { $clone = $dig->clone }, "I can clone my object" );
isnt(
    refaddr $dig,
    refaddr $clone,
    "Cloning gives me a new Digest::PBKDF2 object"
);
isnt(
    refaddr $dig->{guts},
    refaddr $clone->{guts},
    "Cloning gives new guts as well"
);
is( $clone->digest, $dig->digest,
    "Clone and orgiinal product the same string" );
is( $clone->digest,
    '$PBKDF2$HMACSHA1:1000:Y29vbA==$SM6RfIvXeiGLkrYngY1iyGy3LjY=',
    "And that string is what it should be"
);
is( $dig->digest,
    '$PBKDF2$HMACSHA1:1000:Y29vbA==$SM6RfIvXeiGLkrYngY1iyGy3LjY=',
    "Making sure it is..."
);
