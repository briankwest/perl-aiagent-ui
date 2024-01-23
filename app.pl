#!/usr/bin/env perl
# app.pl - SignalWire AI Agent
use lib '.', '/app';
use strict;
use warnings;

# Database tie hash
use MyTieConfig;

# PSGI/Plack
use Plack::Builder;
use Plack::Runner;
use Plack::Request;
use Plack::Response;
use Plack::App::Directory;
use Plack::App::WebSocket;
use Plack::Session::Store::DBI;
use Plack::Middleware::Debug;
use Twiggy::Server;

# SignalWire Perl Helper Library
use SignalWire::ML;
use SignalWire::RestAPI;
use SignalWire::CompatXML;

# Other modules
use HTTP::Request::Common;
use HTML::Template::Expr;
use Authen::TOTP;
use LWP::UserAgent;
use Crypt::Bcrypt qw( bcrypt bcrypt_check );
use LWP::UserAgent;
use JSON::PP;
use MIME::Base64;
use Crypt::URandom;
use File::Slurp;
use UUID 'uuid';
use Data::Dumper;
use DateTime;
use URL::Encode qw( url_encode );
use POSIX qw( strftime );
use Env::C;
use DBI;

# AI Params
my @ai_params  = qw( CONSCIENCE END_OF_SPEECH_TIMEOUT ATTENTION_TIMEOUT BACKGROUND_FILE BACKGROUND_FILE_LOOPS BACKGROUND_FILE_VOLUME ELEVEN_LABS_MODEL OPENAI_ASR_ENGINE LOCAL_TZ SAVE_CONVERSATION ACKNOWLEDGE_INTERRUPTIONS DEBUG_WEBHOOK_LEVEL VERBOSE_LOGS AI_MODEL HOLD_MUSIC CACHE_MODE INTERRUPT_PROMPT INTERRUPT_ON_NOISE INPUT_POLL_FREQ AI_VOLUME BARGE_MATCH_STRING BARGE_MIN_WORDS SWAIG_ALLOW_SWML SWAIG_POST_SWML_VARS SWAIG_ALLOW_SETTINGS  SWAIG_POST_CONVERSATION TRANSFER_SUMMARY DEVELOPER_PROMPT DIGIT_TIMEOUT DIGIT_TERMINATORS ENERGY_LEVEL SPEECH_TIMEOUT ATTENTION_TIMEOUT INACTIVITY_TIMEOUT OUTBOUND_ATTENTION_TIMEOUT LANGUAGES_ENABLED ELEVEN_LABS_KEY ELEVEN_LABS_STABILITY ELEVEN_LABS_SIMILARITY );

my $data_sql = {
    ai_agent => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_agent ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, name TEXT, description TEXT, user_id INTEGER, CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES ai_users (id) ) ),
	insert => 'INSERT INTO ai_agent ( name, description ) VALUES (?, ?, ?)',
	update => 'UPDATE ai_agent SET name = ?, description = ? WHERE id = ?',
	select => 'SELECT * FROM ai_agent WHERE id = ?',
	getall => 'SELECT * FROM ai_agent ORDER BY created DESC LIMIT ? OFFSET ?',
	delete => 'DELETE FROM ai_agent WHERE id = ?',
	nextid => 'SELECT id FROM ai_agent WHERE id > ? ORDER BY id ASC LIMIT 1',
	previd => 'SELECT id FROM ai_agent WHERE id < ? ORDER BY id DESC LIMIT 1',
	ikey   => 'id',
	fields => [
	    { name => 'name',
	      hdr  => 'Name',
	      type => 'text' },
	    { name => 'description',
	      hdr  => 'Description',
	      type => 'text' },
	    { name => 'hints',
	      hdr  => 'Hints',
	      type => 'text' },
	    { name => 'id',
	      hdr  => 'ID',
	      type => 'hidden' },
	    { name => 'created',
	      hdr  => 'Created',
	      type => 'hidden' },
	    { name => 'user_id',
	      hdr  => 'User ID',
	      type => 'hidde' },
	    ],
    },
    ai_config => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_config ( id SERIAL PRIMARY KEY, name VARCHAR(255) NOT NULL, value TEXT NOT NULL, agent_id INTEGER NOT NULL, CONSTRAINT fk_agent FOREIGN KEY (agent_id) REFERENCES ai_agent (id) ON DELETE CASCADE ) ),
	insert => 'INSERT INTO ai_config ( name, value, agent_id ) VALUES (?, ?, ?)',
	update => 'UPDATE ai_config SET name = ?, value = ? WHERE id = ?',
	select => 'SELECT * FROM ai_config WHERE id = ?',
	getall => 'SELECT * FROM ai_config WHERE agent_id = ? ORDER BY created DESC LIMIT ? OFFSET ?',
	delete => 'DELETE FROM ai_config WHERE id = ?',
	fields => [
	    { name => 'var',
	      hdr  => 'Variable',
	      type => 'text' },
	    { name => 'val',
	      hdr  => 'Value',
	      type => 'text' }
	    ],
	ikey   => 'agent_id'
    },
    ai_context => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_context ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, agent_id INTEGER REFERENCES ai_agent(id) ON DELETE CASCADE, name TEXT, pattern TEXT, toggle_function TEXT, consolidate BOOLEAN DEFAULT FALSE, full_reset BOOLEAN DEFAULT FALSE, user_prompt TEXT, system_prompt TEXT ) ),
	insert => 'INSERT INTO ai_context ( name, pattern, toggle_function, consolidate, full_reset, user_prompt, system_prompt, agent_id ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
	update => 'UPDATE ai_context SET name = ?, pattern = ?, toggle_function = ?, consolidate = ?, full_reset = ?, user_prompt = ?, system_prompt = ? WHERE id = ?',
	select => 'SELECT * FROM ai_context WHERE id = ?',
	getall => 'SELECT * FROM ai_context WHERE agent_id = ? ORDER BY created DESC LIMIT ? OFFSET ?',
	delete => 'DELETE FROM ai_context WHERE id = ?',
	fields => [
	    { name => 'name',
	      hdr  => 'Name',
	      type => 'text' },
	    { name => 'pattern',
	      hdr  => 'Pattern',
	      type => 'text' },
	    { name => 'toggle_function',
	      hdr  => 'Toggle Function',
	      type => 'text' },
	    { name => 'consolidate',
	      hdr  => 'Consolidate',
	      type => 'checkbox' },
	    { name => 'full_reset',
	      hdr  => 'Full Reset',
	      type => 'checkbox' },
	    { name => 'user_prompt',
	      hdr  => 'User Prompt',
	      type => 'textarea' },
	    { name => 'system_prompt',
	      hdr  => 'System Prompt',
	      type => 'textarea' }
	    ],
	ikey   => 'agent_id',
	bool => [ qw ( consolidate full_reset ) ]
    },
    ai_function => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_function ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, agent_id INTEGER REFERENCES ai_agent(id) ON DELETE CASCADE, name TEXT, purpose TEXT, argument TEXT, code TEXT, active BOOLEAN DEFAULT TRUE ) ),
	insert => 'INSERT INTO ai_function ( name, purpose, argument, code, active, agent_id ) VALUES (?, ?, ?, ?, ?, ?)',
	update => 'UPDATE ai_function SET name = ?, purpose = ?, argument = ?, code = ?, active = ? WHERE id = ?',
	select => 'SELECT * FROM ai_function WHERE id = ?',
	getall => 'SELECT * FROM ai_function WHERE agent_id = ? ORDER BY created DESC LIMIT ? OFFSET ?',
	delete => 'DELETE FROM ai_function WHERE id = ?',
	fields => [
	    { name => 'name',
	      hdr  => 'Name',
	      type => 'text' },
	    { name => 'purpose',
	      hdr  => 'Purpose',
	      type => 'text' },
	    { name => 'argument',
	      hdr  => 'Argument',
	      type => 'text' },
	    { name => 'code',
	      hdr  => 'Code',
	      type => 'textarea' },
	    { name => 'active',
	      hdr  => 'Active',
	      type => 'checkbox' }
	    ],
	ikey   => 'agent_id'
    },
    function_arguments => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_function_argument ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, function_id INTEGER REFERENCES ai_function(id) ON DELETE CASCADE, agent_id INTEGER REFERENCES ai_agent(id) ON DELETE CASCADE, name TEXT UNIQUE NOT NULL, type TEXT DEFAULT 'string', description TEXT, active BOOLEAN DEFAULT TRUE ) ),
	insert => 'INSERT INTO ai_function_argument ( function_id, name, type, description, active ) VALUES (?, ?, ?, ?, ?)',
	update => 'UPDATE ai_function_argument SET function_id = ?, name = ?, type = ?, description = ?, active = ? WHERE id = ?',
	select => 'SELECT * FROM ai_function_argument WHERE id = ?',
	getall => 'SELECT * FROM ai_function_argument WHERE function_id = ?',
	delete => 'DELETE FROM ai_function_argument WHERE id = ?',
	fields => [
	    { name => 'name',
	      hdr  => 'Name',
	      type => 'text' },
	    { name => 'type',
	      hdr  => 'Type',
	      type => 'text' },
	    { name => 'description',
	      hdr  => 'Description',
	      type => 'text' },
	    { name => 'active',
	      hdr  => 'Active',
	      type => 'checkbox' }
	    ],
	bool   => [ qw( active ) ],
    },
    ai_hints => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_hints ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, hint TEXT, agent_id INTEGER REFERENCES ai_agent(id) ON DELETE CASCADE ) ),
	insert => 'INSERT INTO ai_hints ( hint, agent_id ) VALUES (?, ?)',
	update => 'UPDATE ai_hints SET hint = ? WHERE id = ?',
	select => 'SELECT * FROM ai_hints WHERE id = ?',
	getall => 'SELECT * FROM ai_hints WHERE agent_id = ? ORDER BY created DESC LIMIT ? OFFSET ?',
	delete => 'DELETE FROM ai_hints WHERE id = ?',
	fields => [
	    { name => 'hint',
	      hdr  => 'Hint',
	      type => 'text' }
	    ],
	ikey   => 'agent_id'
    },
    ai_language => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_language ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, agent_id INTEGER REFERENCES ai_agent(id) ON DELETE CASCADE, code TEXT, name TEXT, voice TEXT, engine TEXT, fillers TEXT ) ),
	insert => 'INSERT INTO ai_language ( code, name, voice, engine, fillers, agent_id ) VALUES (?, ?, ?, ?, ?, ?)',
	update => 'UPDATE ai_language SET code = ?, name = ?, voice = ?, engine = ?, fillers = ? WHERE id = ?',
	select => 'SELECT * FROM ai_language WHERE id = ?',
	getall => 'SELECT * FROM ai_language WHERE agent_id = ? ORDER BY created DESC LIMIT ? OFFSET ?',
	delete => 'DELETE FROM ai_language WHERE id = ?',
	fields => [
	    { name => 'code',
	      hdr  => 'Code',
	      type => 'text' },
	    { name => 'name',
	      hdr  => 'Name',
	      type => 'text' },
	    { name => 'voice',
	      hdr  => 'Voice',
	      type => 'text' },
	    { name => 'engine',
	      hdr  => 'Engine',
	      type => 'text' },
	    { name => 'fillers',
	      hdr  => 'Fillers',
	      type => 'text' }
	    ],
	ikey   => 'agent_id',
    },
    ai_messages => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_messages ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, call_id TEXT, convo_id TEXT, message TEXT, replied BOOLEAN DEFAULT FALSE, agent_id INTEGER REFERENCES ai_agent(id) ON DELETE CASCADE ) ),
	insert => 'INSERT INTO ai_messages ( call_id, convo_id, message, replied, agent_id ) VALUES (?, ?, ?, ?, ?)',
	update => 'UPDATE ai_messages SET call_id = ?, convo_id = ?, message = ?, replied = ? WHERE id = ?',
	select => 'SELECT * FROM ai_messages WHERE id = ?',
	delete => 'DELETE FROM ai_messages WHERE id = ?',
	getall => 'SELECT * FROM ai_messages WHERE agent_id = ? ORDER BY created DESC LIMIT ? OFFSET ?',
	fields => [
	    { name => 'call_id',
	      hdr  => 'Call ID',
	      type => 'text' },
	    { name => 'convo_id',
	      hdr  => 'Convo ID',
	      type => 'text' },
	    { name => 'message',
	      hdr  => 'Message',
	      type => 'text' },
	    { name => 'replied',
	      hdr  => 'Replied',
	      type => 'checkbox' }
	    ],
	ikey   => 'agent_id',
	bool   => [ qw( replied ) ],
    },
    ai_post => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_post ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, data JSONB, agent_id INTEGER REFERENCES ai_agent(id) ON DELETE CASCADE ) ),
	insert => 'INSERT INTO ai_post ( data, agent_id ) VALUES (?, ?)',
	update => 'UPDATE ai_post SET data = ? WHERE id = ?',
	select => 'SELECT * FROM ai_post WHERE id = ?',
	getall => 'SELECT * FROM ai_post WHERE agent_id = ? ORDER BY created DESC LIMIT ? OFFSET ?',
	delete => 'DELETE FROM ai_post WHERE id = ?',
	fields => [
	    { name => 'data',
	      hdr  => 'Data',
	      type => 'json' }
	    ],
	ikey   => 'agent_id',
    },
    ai_prompt => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_prompt ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, prompt TEXT, post_prompt TEXT, agent_id INTEGER REFERENCES ai_agent(id) ON DELETE CASCADE ) ),
	insert => 'INSERT INTO ai_prompt ( prompt, post_prompt, agent_id ) VALUES (?, ?, ?)',
	update => 'UPDATE ai_prompt SET prompt = ?, post_prompt = ? WHERE id = ?',
	select => 'SELECT * FROM ai_prompt WHERE id = ?',
	getall => 'SELECT * FROM ai_prompt WHERE agent_id = ? ORDER BY created DESC LIMIT ? OFFSET ?',
	delete => 'DELETE FROM ai_prompt WHERE id = ?',
	fields => [
	    { name => 'prompt',
	      hdr  => 'Prompt',
	      type => 'text' },
	    { name => 'post_prompt',
	      hdr  => 'Post Prompt',
	      type => 'text' }
	    ],
	ikey   => 'agent_id',
    },
    ai_pronounce => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_pronounce ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, ignore_case BOOLEAN DEFAULT FALSE, replace_this TEXT, replace_with TEXT, agent_id INTEGER REFERENCES ai_agent(id) ON DELETE CASCADE ) ),
	insert => 'INSERT INTO ai_pronounce ( ignore_case, replace_this, replace_with, agent_id ) VALUES (?, ?, ?, ?)',
	update => 'UPDATE ai_pronounce SET ignore_case = ?, replace_this = ?, replace_with = ? WHERE id = ?',
	select => 'SELECT * FROM ai_pronounce WHERE id = ?',
	getall => 'SELECT * FROM ai_pronounce WHERE agent_id = ? ORDER BY created DESC LIMIT ? OFFSET ?',
	delete => 'DELETE FROM ai_pronounce WHERE id = ?',
	fields => [
	    { name => 'ignore_case',
	      hdr  => 'Ignore Case',
	      type => 'checkbox' },
	    { name => 'replace_this',
	      hdr  => 'Replace This',
	      type => 'text' },
	    { name => 'replace_with',
	      hdr  => 'Replace With',
	      type => 'text' }
	    ],
	ikey   => 'agent_id',
	bool   => [ qw( ignore_case ) ],
    },
    ai_summary => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_summary ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, convo_id TEXT, summary TEXT, agent_id INTEGER REFERENCES ai_agent(id) ON DELETE CASCADE ) ),
	insert => 'INSERT INTO ai_summary ( convo_id, summary, agent_id ) VALUES (?, ?, ?)',
	update => 'UPDATE ai_summary SET convo_id = ?, summary = ? WHERE id = ?',
	select => 'SELECT * FROM ai_summary WHERE id = ?',
	getall => 'SELECT * FROM ai_summary WHERE agent_id = ? ORDER BY created DESC LIMIT ? OFFSET ?',
	delete => 'DELETE FROM ai_summary WHERE id = ?',
	fields => [
	    { name => 'convo_id',
	      hdr  => 'Convo ID',
	      type => 'text' },
	    { name => 'summary',
	      hdr  => 'Summary',
	      type => 'text' }
	    ],
	ikey   => 'agent_id',
    },
    ai_users => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_users ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, username VARCHAR(255) UNIQUE NOT NULL, password VARCHAR(255) NOT NULL, first_name VARCHAR(255), last_name VARCHAR(255), email VARCHAR(255) UNIQUE, phone_number VARCHAR(20), totp_secret VARCHAR(255), totp_enabled BOOLEAN DEFAULT false, is_admin BOOLEAN DEFAULT false ) ),
	insert => 'INSERT INTO ai_users ( username, password, first_name, last_name, email, phone_number, totp_secret, totp_enabled, is_admin ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
	update => 'UPDATE ai_users SET username = ?, password = ?, first_name = ?, last_name = ?, email = ?, phone_number = ?, totp_secret = ?, totp_enabled = ?, is_admin = ? WHERE id = ?',
	select => 'SELECT * FROM ai_users WHERE id = ?',
	delete => 'DELETE FROM ai_users WHERE id = ?',
	fields => [
	    { name => 'username',
	      hdr  => 'Username',
	      type => 'text' },
	    { name => 'password',
	      hdr  => 'Password',
	      type => 'text' },
	    { name => 'first_name',
	      hdr  => 'First Name',
	      type => 'text' },
	    { name => 'last_name',
	      hdr  => 'Last Name',
	      type => 'text' },
	    { name => 'email',
	      hdr  => 'Email',
	      type => 'text' },
	    { name => 'phone_number',
	      hdr  => 'Phone Number',
	      type => 'text' },
	    { name => 'totp_secret',
	      hdr  => 'TOTP Secret',
	      type => 'text' },
	    { name => 'totp_enabled',
	      hdr  => 'TOTP Enabled',
	      type => 'checkbox' },
	    { name => 'is_admin',
	      hdr  => 'Is Admin',
	      type => 'checkbox' }
	    ],
	bool   => [ qw( totp_enabled is_admin ) ]
    },
    sessions => {
	create => qq( CREATE TABLE IF NOT EXISTS sessions ( id CHAR(72) PRIMARY KEY, session_data TEXT, expires INTEGER ) ),
	insert => 'INSERT INTO sessions ( session_data, expires ) VALUES (?, ? )',
	update => 'UPDATE sessions SET session_data = ?, expires = ? WHERE id = ?',
	select => 'SELECT * FROM sessions WHERE id = ?',
	delete => 'DELETE FROM sessions WHERE id = ?',
	fields => [
	    { name => 'session_data',
	      hdr  => 'Session Data',
	      type => 'text' },
	    { name => 'expires',
	      hdr  => 'Expires',
	      type => 'text' }
	    ]
    }
};


# Load environment variables
my $ENV = Env::C::getallenv();

my ( $protocol, $dbusername, $dbpassword, $host, $port, $database ) = $ENV{DATABASE_URL} =~ m{^(?<protocol>\w+):\/\/(?<username>[^:]+):(?<password>[^@]+)@(?<host>[^:]+):(?<port>\d+)\/(?<database>\w+)$};

# Onboard SWAIG Registry
my %function = (
    check_for_input => \&check_for_input
    );

# Dispatch table for PSGI
my %dispatch = (
    'GET' => {
	'/'          => \&agents,
#	'/ai_agent'  => \&do_page,
#	'/do_page'   => \&do_page,
	'/agent'     => \&agent,
	'/config'    => \&config,
	'/prompt'    => \&prompt,
	'/summary'   => \&summary,
	'/messages'  => \&messages,
	'/contexts'  => \&contexts,
	'/functions' => \&functions,
	'/languages' => \&languages,
	'/pronounce' => \&pronounce,
	'/users'     => \&users,
	'/debug'     => \&debug,
    },
    'POST' => {
	'/'          => \&agents,
#	'/ai_agent'  => \&do_page,
#	'/do_page'   => \&do_page,
	'/agent'     => \&agent,
	'/config'    => \&config,
	'/prompt'    => \&prompt,
	'/summary'   => \&summary,
	'/messages'  => \&messages,
	'/contexts'  => \&contexts,
	'/functions' => \&functions,
	'/languages' => \&languages,
	'/pronounce' => \&pronounce,
	'/users'     => \&users,
	'/post'      => \&post,
    }
    );

# Admin Navigation bar
my @nav = [
    { path => '/',          name => 'Home',          table => "ai_agent"        },
    { path => '/agent',     name => 'Conversations', table => "ai_conversation" },
    { path => '/config',    name => 'Configuration', table => "ai_config"       },
    { path => '/prompt',    name => 'Prompt',        table => "ai_prompt"       },
    { path => '/summary',   name => 'Summary',       table => "ai_summary"      },
    { path => '/contexts',  name => 'Contexts',      table => "ai_context"      },
    { path => '/functions', name => 'Functions',     table => "ai_function"     },
    { path => '/languages', name => 'Languages',     table => "ai_language"     },
    { path => '/pronounce', name => 'Pronounce',     table => "ai_pronounce"    },
    { path => '/messages',  name => 'Messages',      table => "ai_message"      },
    { path => '/debug',     name => 'Debug',         table => undef             },
    { path => '/logout',    name => 'Logout',        table => undef		}
    ];

# Main Navigation bar
my @user_nav = [
    { path => '/',         name => 'Agents'        },
    { path => '/logout',   name => 'Logout'        }
    ];

my @admin_nav = [
    { path => '/',         name => 'Agents'        },
    { path => '/users',    name => 'Users'         },
    { path => '/logout',   name => 'Logout'        }
    ];

my %clients;       # Store connected clients
my %subscriptions; # Store subscriptions by agent_id

# Broadcast to a specific client by uuid
sub broadcast_by_uuid {
    my ( $uuid, $message ) = @_;
    my $json = JSON::PP->new->ascii->pretty->allow_nonref;
    if ( my $conn = $clients{$uuid} ) {
	$conn->send( $json->encode( $message ) );
    }
}

# Broadcast to all clients subscribed to a specific agent_id
sub broadcast_by_agent_id {
    my ( $agent_id, $message ) = @_;
    my $json = JSON::PP->new->ascii->pretty->allow_nonref;
    print STDERR "Broadcasting to $agent_id\n" if $ENV{DEBUG};
    foreach my $uuid ( @{$subscriptions{$agent_id} // []} ) {
	print STDERR "Broadcasting to $uuid, Agent ID: $agent_id\n" if $ENV{DEBUG};

	if ( my $conn = $clients{$uuid} ) {
	    $conn->send( $json->encode( $message ) );
	}
    }
}

# Generate Nonce for CSP Header
sub generate_nonce {
    my $length       = shift // 16;
    my $random_bytes = Crypt::URandom::urandom( $length );

    return encode_base64( $random_bytes, '' );
}

sub e164_to_spoken {
    my $number = shift;

    $number =~ s/^\+1//g;

    my %digit_to_word = (
	'0' => 'zero',  '1' => 'one',  '2' => 'two', '3' => 'three',
	'4' => 'four',  '5' => 'five', '6' => 'six', '7' => 'seven',
	'8' => 'eight', '9' => 'nine', '+' => 'plus'
    );

    $number =~ s/(\d|\+)/$digit_to_word{$1}, /g;

    $number =~ s/, $//;

    return $number;
}

# Internal SWAIG function
sub check_for_input {
    my $env       = shift;
    my $req       = Plack::Request->new( $env );
    my $post_data = decode_json( $req->raw_body );
    my $data      = $post_data->{argument}->{parsed}->[0];
    my $agent     = $req->param( 'agent_id' );
    my $swml      = SignalWire::ML->new;
    my $json      = JSON::PP->new->ascii->pretty->allow_nonref;
    my $convo_id  = $post_data->{conversation_id};
    my @message;

    broadcast_by_agent_id( $agent, $post_data );

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 }) or die "Couldn't execute statement: $DBI::errstr\n";

    my $select_sql = "SELECT * FROM ai_messages WHERE convo_id = ? AND replied = false AND agent_id = ? ORDER BY id ASC";

    my $sth = $dbh->prepare( $select_sql );

    $sth->execute( $convo_id, $agent ) or die "Couldn't execute statement: $DBI::errstr\n";

    while ( my $row = $sth->fetchrow_hashref ) {
       push @message, "$row->{message}";

       my $update_sql = "UPDATE ai_messages SET replied = true WHERE id = ?";

       my $usth = $dbh->prepare( $update_sql );

       $usth->execute( $row->{id} ) or die $DBI::errstr;
    }

    my $res = Plack::Response->new( 200 );

    $res->content_type( 'application/json' );

    if ( @message == 0 ) {
       $res->body( $swml->swaig_response_json( [ { response => "ok" } ] ) );
    } else {
       $res->body( $swml->swaig_response_json( { action => [ { user_input => join(" ", @message) } ] }) );
    }

    broadcast_by_agent_id( $agent, $json->decode( $res->body ) );

    $dbh->disconnect;

    return $res->finalize;
}

# PSGI application code
# Not used yet.
sub do_page {
    my $env     = shift;
    my $req     = Plack::Request->new( $env );
    my $params  = $req->parameters;
    my $path    = $req->path_info;
    my $method  = $req->method;
    my $table   = $params->{table}    // $path =~ s{^/}{}r;
    my $agent   = $params->{agent_id} // undef;
    my $id      = $params->{id}       // undef;
    my $json    = JSON::PP->new->ascii->pretty->allow_nonref;
    my $session = $env->{'psgix.session'};
    my $i       = 1;
    my $sqldo   = $data_sql->{$table} if defined $table;
    my $ikey    = $sqldo->{ikey}      // undef;

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die "Couldn't execute statement: $DBI::errstr\n";

    if ( $method eq 'POST' ) {
	foreach my $bool ( @{ $sqldo->{bool} } ) {
	    $params->{$bool}               = 'off' unless defined $params->{$bool};

	    $params->{$bool}               = 'on' if $params->{$bool} eq 'on';

	    $params->{"${bool}_checked"}   = 1 if $params->{$bool} eq 'on';
	}

	if ( $params->{action} eq 'add' ) {
	    my $template = HTML::Template::Expr->new( filename => "/app/template/create.tmpl", die_on_bad_params => 0 );

	    print STDERR "fields: " . Dumper( $sqldo->{fields} );

	    my @row_fields;

	    foreach my $field (@{ $sqldo->{fields} }) {
		push @row_fields, {
		    name  => $field->{name},
		    value => '',
		    type  => $field->{type},
		    hdr   => $field->{hdr}
		};
	    }

	    print STDERR "row_fields: " . Dumper(\@row_fields);


	    $template->param(
		nav        => @nav,
		url        => "https://$env->{HTTP_HOST}",
		nonce      => $env->{'plack.nonce'},
		table      => $table,
		fields     => \@row_fields,
		);

	    
	    my $res = Plack::Response->new( 200 );

	    $res->content_type( 'text/html' );

	    $res->body( $template->output );

	    return $res->finalize;
	} elsif ( $params->{action} eq 'insert' ) {
	    my $sth = $dbh->prepare( $sqldo->{insert} );

	    foreach my $field ( @{ $sqldo->{fields} } ) {
		$sth->bind_param( $i++, $params->{$field} );
	    }

	    if ( $ikey ) {
		$sth->bind_param( $i++, $params->{$ikey} );
	    }

	    $sth->execute() or die "Couldn't execute statement: $DBI::errstr\n";

	    $sth->finish();
	} elsif ( $params->{action} eq 'update' ) {
	    my $sth = $dbh->prepare( $sqldo->{update} );

	    foreach my $field ( @{ $sqldo->{fields} } ) {
		$sth->bind_param( $i++, $params->{$field} );
	    }

	    $sth->bind_param( 1, $params->{$ikey} );

	    $sth->execute() or die "Couldn't execute statement: $DBI::errstr\n";

	    $sth->finish();
	} elsif ( $params->{action} eq 'delete' ) {
	    my $sth = $dbh->prepare( $sqldo->{delete} );

	    $sth->bind_param( 1, $params->{$ikey} );

	    $sth->execute() or die "Couldn't execute statement: $DBI::errstr\n";

	    $sth->finish();
	} elsif ( $params->{action} eq 'edit' ) {
	    my $sth = $dbh->prepare( $sqldo->{select} );

	    print STDERR "SELECT: $sqldo->{select}\n";
	    print STDERR "ikey: $ikey\n";
	    print STDERR "i: $i\n";
	    print STDERR "params: $params->{$ikey}\n";
	    
	    $sth->bind_param(1, $params->{$ikey} );

	    $sth->execute();

	    my $row = $sth->fetchrow_hashref;
	    print STDERR "row: " . Dumper( $row );
	    print STDERR "fields: " . Dumper( $sqldo->{fields} );

	    my @row_fields;
	    foreach my $field (@{ $sqldo->{fields} }) {
		if (exists $row->{$field->{name}}) {
		    push @row_fields, {
			name  => $field->{name},
			value => $row->{$field->{name}},
			type  => $field->{type},
			hdr   => $field->{hdr}
		    };
		}
	    }
	    print STDERR "row_fields: " . Dumper(\@row_fields);

	    $row->{fields} = \@row_fields;
	    
	    $sth->finish();

	    my $template = HTML::Template::Expr->new( filename => "/app/template/edit.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav                  => @nav,
		url                  => "https://$env->{HTTP_HOST}",
		nonce                => $env->{'plack.nonce'},
		table                => $table,
		fields               => $row->{fields}
		);

	    print STDERR "row: " . Dumper( $row );
	    
	    my $res = Plack::Response->new( 200 );

	    $res->content_type( 'text/html' );

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;

	} elsif ( $params->{action} eq 'view' ) {
	    my $sth = $dbh->prepare( $sqldo->{select} );

	    $sth->bind_param(++$i, $params->{$ikey} );

	    $sth->execute();

	    my $row = $sth->fetchall_hashref({});

	    $sth->finish();

	    my $template = HTML::Template::Expr->new( filename => "/app/template/view.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav                  => @nav,
		url                  => "https://$env->{HTTP_HOST}",
		nonce                => $env->{'plack.nonce'},
		table                => $table,
		);

	    $template->param( %{ $row->[0] } );

	    $template->param( %{ $sqldo->{fields} } );

	    my $res = Plack::Response->new( 200 );

	    $res->content_type( 'text/html' );

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} else {
	    die "Unknown action: $params->{action}\n";
	}
    }

    print STDERR "table: $table\n" if $table;
    print STDERR "agent: $agent\n" if $agent;
    print STDERR "id: $id\n" if $id;
    print STDERR "ikey: $ikey\n" if $ikey;
    print STDERR "sqldo: $sqldo->{getall}\n" if $sqldo->{getall};

    my $next_page_url = "";
    my $prev_page_url = "";
    my $next_id	   = "";
    my $prev_id	   = "";
    my @table_contents;
    my $row;

    my ($next_sql, $sth_next);
    my ($prev_sql, $sth_prev);
	
    if ( defined $sqldo->{nextid} && $sqldo->{nextid} !~ m/agent_id/ ) {
	$next_sql = $sqldo->{nextid};
	$sth_next = $dbh->prepare( $next_sql );
	$sth_next->bind_param( 1, $id );
    } else {
	$next_sql = "SELECT id FROM $table WHERE agent_id = ? AND id > ? ORDER BY id ASC LIMIT 1";
	$sth_next = $dbh->prepare( $next_sql );
	$sth_next->bind_param( 1, $agent );
	$sth_next->bind_param( 2, $id );
    }

    $sth_next->execute() or die "Couldn't execute statement: $DBI::errstr\n";
    
    $next_id = $sth_next->fetchrow_array;
    
    $sth_next->finish;
    
    if ( defined $sqldo->{previd} && $sqldo->{previd} !~ m/agent_id/ ) {
	$prev_sql = $sqldo->{previd};
	$sth_prev = $dbh->prepare( $prev_sql );
	$sth_prev->bind_param( 1, $id );
    } else {
	$prev_sql = "SELECT id FROM $table WHERE agent_id = ? AND id < ? ORDER BY id DESC LIMIT 1";
	$sth_prev = $dbh->prepare( $prev_sql );
	$sth_prev->bind_param( 1, $agent );
	$sth_prev->bind_param( 2, $id );
    }
    
    $sth_prev->execute() or die "Couldn't execute statement: $DBI::errstr\n";
    
    $prev_id = $sth_prev->fetchrow_array;
    
    $sth_prev->finish;

    if ( $sqldo->{getall} =~ m/OFFSET/) {
	my $page_size    = 25;

	my $current_page = $params->{page} || 1;

	my $offset       = ( $current_page - 1 ) * $page_size;

	my $total_rows_sql;

	if ( $sqldo->{getall} !~ m/agent_id/ ) {
	    $total_rows_sql = "SELECT COUNT(*) FROM $table WHERE id = ?";
	} else {
	    $total_rows_sql = "SELECT COUNT(*) FROM $table WHERE agent_id = ?";
	}

	my $total_rows_sth = $dbh->prepare( $total_rows_sql );

	$total_rows_sth->bind_param( 1, $agent ? $agent : $id );

	$total_rows_sth->execute() or die "Couldn't execute statement: $DBI::errstr\n";

	my $total_rows = $total_rows_sth->fetchrow_array();

	$total_rows_sth->finish();

	my $total_pages = int( ( $total_rows + $page_size - 1 ) / $page_size );

	$current_page = 1 if $current_page < 1;

	$current_page = $total_pages if ( $current_page > $total_pages );

	if ( $current_page > 1 ) {
	    my $prev_page = $current_page - 1;
	    $prev_page_url = "/agent?table=$table&agent_id=$agent&page=$prev_page";
	}

	if ( $current_page < $total_pages ) {
	    my $next_page = $current_page + 1;
	    $next_page_url = "/agent?table=$table&agent_id=$agent&page=$next_page";
	}

	my $page_sql = $sqldo->{getall};

	my $page_sth = $dbh->prepare( $page_sql );

	if ($sqldo->{getall} !~ m/agent_id/) {
	    $page_sth->bind_param(1, $page_size );
	    $page_sth->bind_param(2, $offset    );
	} else {
	    $page_sth->bind_param(1, $agent     );
	    $page_sth->bind_param(2, $page_size );
	    $page_sth->bind_param(3, $offset    );
	}

	$page_sth->execute() or die "Couldn't execute statement: $DBI::errstr\n";

	while ( my $row = $page_sth->fetchrow_hashref ) {
	    my $c = 0;
	    foreach my $field ( @{ $sqldo->{fields} } ) {
		if ( $row->{$field->{name}} eq '0' ) {
		    $row->{$field->{name}} = 'off';
		}
		if ( $row->{$field->{name}} eq '1' ) {
		    $row->{$field->{name}} = 'on';
		}

		$row->{"field_$c"} = $row->{$field->{name}};
		$c++;
	    }

	    push @table_contents, $row;
	}

	$page_sth->finish;

    } else {
	my $edit_sth = $dbh->prepare( $sqldo->{getall} );

	$edit_sth->bind_param(1, $agent );

	$edit_sth->execute() or die "Couldn't execute statement: $DBI::errstr\n";

	my $c = 0;

	while ( my $row = $edit_sth->fetchrow_hashref ) {
	    my $c = 0;

	    foreach my $field ( @{ $sqldo->{fields} } ) {
		if ( $row->{$field->{name}} eq '0' ) {
		    $row->{$field->{name}} = 'off';
		}

		if ( $row->{$field->{name}} eq '1' ) {
		    $row->{$field->{name}} = 'on';
		}

		$row->{"field_$c"} = $row->{$field->{name}};
		$c++;
	    }

	    push @table_contents, $row;
	}

	$edit_sth->finish();
    }

    my $template = HTML::Template::Expr->new( filename => "/app/template/list.tmpl", die_on_bad_params => 0 );

    (my $title = $table) =~ s/^ai_//;

    $title = uc(substr( $title, 0, 1) ) . substr( $title, 1 );

    $template->param(
	nav                  => @nav,
	_url                 => "https://$env->{HTTP_HOST}",
	_nonce               => $env->{'plack.nonce'},
	_css		     => '/assets/style.css',
	_title		     => $title,
	_description         => "List of $title(s)",
	_favicon	     => '/assets/favicon.png',
	table                => $table,
	fields		     => $sqldo->{fields},
	next_id		     => $next_id        ? $next_id         : undef,
	prev_id		     => $prev_id        ? $prev_id         : undef,
	next_page_url	     => $next_page_url  ? $next_page_url   : undef,
	prev_page_url	     => $prev_page_url  ? $prev_page_url   : undef,
	( (@table_contents) ? (table_contents => \@table_contents ) : ())
	);

    $dbh->disconnect;

    my $res = Plack::Response->new( 200 );

    $res->content_type( 'text/html' );

    $res->body( $template->output );

    return $res->finalize;
}

sub agent {
    my $env     = shift;
    my $req     = Plack::Request->new( $env );
    my $params  = $req->parameters;
    my $id      = $params->{id};
    my $agent   = $params->{agent_id};
    my $json    = JSON::PP->new->ascii->pretty->allow_nonref;
    my $session = $env->{'psgix.session'};

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 }) or die "Couldn't execute statement: $DBI::errstr\n";

    # Check if the agent exists and if the user has access to it.
    # If not, redirect to the home page.
    if ( $session->{user_id} ) {
	my ( $sql, $agents );

	if ( $session->{is_admin} && $agent ) {
	    $agents = $dbh->selectrow_array( "SELECT count(*) FROM ai_agent WHERE id = ?", undef, $agent );
	} else {
	    $agents = $dbh->selectrow_array( "SELECT count(*) FROM ai_agent WHERE user_id = ? AND id = ?", undef, $session->{user_id}, $agent );
	}

	if ( ! $agents ) {
	    $dbh->disconnect;
	    my $res = Plack::Response->new( 200 );
	    $res->redirect( "/" );
	    print STDERR "User $session->{user_id} tried to access agent $agent that doesn't exist.\n";
	    return $res->finalize;
	}
    }

    if ( $agent && $id ) {
	my $sql = "SELECT * FROM ai_post_prompt WHERE agent_id = ? AND id = ?";

	my $sth = $dbh->prepare( $sql );

	$sth->execute( $agent, $id ) or die "Couldn't execute statement: $DBI::errstr\n";

	my $row = $sth->fetchrow_hashref;

	my $sql_next = "SELECT id FROM ai_post_prompt WHERE agent_id = ? AND id > ? ORDER BY id ASC LIMIT 1";

	my $sql_prev = "SELECT id FROM ai_post_prompt WHERE agent_id = ? AND id < ? ORDER BY id DESC LIMIT 1";

	my $sth_next = $dbh->prepare( $sql_next );

	$sth_next->execute( $agent, $id );

	my ( $next_id ) = $sth_next->fetchrow_array;

	$sth_next->finish;

	my $sth_prev = $dbh->prepare( $sql_prev );

	$sth_prev->execute( $agent, $id );

	my ( $prev_id ) = $sth_prev->fetchrow_array;

	$sth_prev->finish;

	if ( $row ) {
	    my $p = $json->decode( $row->{data} );

	    $sth->finish;

	    $dbh->disconnect;

	    foreach my $log ( @{ $p->{'call_log'} } ) {
		$log->{content} =~ s/\r\n/<br>/g;
		$log->{content} =~ s/\n/<br>/g;
	    }

	    my $template = HTML::Template::Expr->new( filename => "/app/template/conversation.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav		    => @nav,
		nonce               => $env->{'plack.nonce'},
		agent_id            => $agent,
		next_id		    => $next_id ? "/agent?id=$next_id&agent_id=$agent" : "/agent?agent_id=$agent",
		prev_id		    => $prev_id ? "/agent?id=$prev_id&agent_id=$agent" : "/agent?agent_id=$agent",
		next_text	    => $next_id ? "Next >"     : "",
		prev_text	    => $prev_id ? "< Previous" : "",
		call_id             => $p->{'call_id'},
		call_start_date     => $p->{'call_start_date'},
		call_log            => $p->{'call_log'},
		swaig_log	    => $p->{'swaig_log'},
		caller_id_name      => $p->{'caller_id_name'},
		caller_id_number    => $p->{'caller_id_number'},
		total_output_tokens => $p->{'total_output_tokens'},
		total_input_tokens  => $p->{'total_input_tokens'},
		raw_json            => $json->encode( $p ),
		record_call_url     => $p->{SWMLVars}->{record_call_url} );

	    my $res = Plack::Response->new( 200 );

	    $res->content_type( 'text/html' );

	    $res->body( $template->output );

	    return $res->finalize;
	} else {
	    my $res = Plack::Response->new( 200 );

	    $res->redirect( "/agent?agent_id=$agent" );

	    print STDERR "User $session->{user_id} tried to access a post for $agent that doesn't exist.\n";

	    return $res->finalize;
	}
    } else {
	my %config;

	tie %config, 'MyTieConfig',
	    host     => $host,
	    port     => $port,
	    dbname   => $database,
	    user     => $dbusername,
	    password => $dbpassword,
	    table    => 'ai_config',
	    agent_id => $agent;

	my $page_size    = 25;
	my $current_page = $params->{page} || 1;
	my $offset       = ( $current_page - 1 ) * $page_size;

	my $sql = "SELECT * FROM ai_post_prompt WHERE agent_id = ? ORDER BY created DESC LIMIT ? OFFSET ?";

	my $sth = $dbh->prepare( $sql );

	$sth->execute( $agent, $page_size, $offset ) or die "Couldn't execute statement: $DBI::errstr\n";

	my @table_contents;

	while ( my $row = $sth->fetchrow_hashref ) {
	    my $p = $json->decode( $row->{data} );



	    $row->{caller_id_name}       = $p->{caller_id_name};
	    $row->{caller_id_number}     = $p->{caller_id_number};
	    $row->{call_id}              = $p->{call_id};
	    $row->{summary}              = $p->{post_prompt_data}->{substituted};
	    push @table_contents, $row;
	}

	$sth->finish;

	my $total_rows_sql = "SELECT COUNT(*) FROM ai_post_prompt WHERE agent_id = ?";

	$sth = $dbh->prepare( $total_rows_sql );

	$sth->execute( $agent );

	my ( $total_rows ) = $sth->fetchrow_array();

	my $total_pages = int( ( $total_rows + $page_size - 1 ) / $page_size );

	$current_page = 1 if $current_page < 1;
	$current_page = $total_pages if $current_page > $total_pages;

	my $next_url = "";
	my $prev_url = "";

	if ( $current_page > 1 ) {
	    my $prev_page = $current_page - 1;
	    $prev_url = "/agent?agent_id=$agent&page=$prev_page";
	}

	if ( $current_page < $total_pages ) {
	    my $next_page = $current_page + 1;
	    $next_url = "/agent?agent_id=$agent&page=$next_page";
	}

	$sth->finish;

	$dbh->disconnect;

	my $template = HTML::Template::Expr->new( filename => "/app/template/agent.tmpl", die_on_bad_params => 0 );

	$template->param(
	    nav                  => @nav,
	    url                  => "https://$env->{HTTP_HOST}",
	    nonce                => $env->{'plack.nonce'},
	    agent_id             => $agent,
	    table_contents       => \@table_contents,
	    next_url             => $next_url,
	    prev_url             => $prev_url
	    );

	untie %config;

	my $res = Plack::Response->new( 200 );

	$res->content_type( 'text/html' );

	$res->body( $template->output );

	return $res->finalize;
    }
}

sub summary {
    my $env    = shift;
    my $req    = Plack::Request->new( $env );
    my $agent  = $req->param( 'agent_id' );
    my $id     = $req->param( 'id' );
    my $method = $req->method;
    my $json   = JSON::PP->new->ascii->pretty->allow_nonref;

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die "Couldn't execute statement: $DBI::errstr\n";

    if ( $method eq 'POST' ) {
	my $params = $req->parameters;

	if ( $params->{action} eq 'delete' ) {
	    my $sql = "DELETE FROM ai_summary WHERE agent_id = ? AND id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent, $id ) or die "Couldn't execute statement: $DBI::errstr\n";

	    $sth->finish;

	    $dbh->disconnect;

	    my $res = Plack::Response->new( 200 );

	    $res->redirect( "/summary?agent_id=$agent" );

	    return $res->finalize;
	}
    }

    my $select_sql = "SELECT * FROM ai_summary WHERE agent_id = ? ORDER BY created DESC";

    my $sth = $dbh->prepare( $select_sql );

    $sth->execute( $agent ) or die "Couldn't execute statement: $DBI::errstr\n";

    my $table_contents = $sth->fetchall_arrayref({});

    $sth->finish;

    $dbh->disconnect;

    my $template = HTML::Template::Expr->new( filename => "/app/template/summary.tmpl", die_on_bad_params => 0 );

    $template->param(
	nav            => @nav,
	nonce          => $env->{'plack.nonce'},
	table_contents => $table_contents,
	agent_id       => $agent,
	url            => "https://$env->{HTTP_HOST}"
	);

    my $res = Plack::Response->new( 200 );

    $res->content_type( 'text/html' );

    $res->body( $template->output );

    return $res->finalize;
}

sub messages {
    my $env    = shift;
    my $req    = Plack::Request->new( $env );
    my $id     = $req->param( 'id' );
    my $agent  = $req->param( 'agent_id' );
    my $method = $req->method;
    my $json   = JSON::PP->new->ascii->pretty->allow_nonref;

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die "Couldn't execute statement: $DBI::errstr\n";

    if ( $method eq 'POST' ) {
	my $params = $req->parameters;

	if ( $params->{action} eq 'delete' ) {
	    my $sql = "DELETE FROM ai_messages WHERE agent_id = ? AND id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent, $id ) or die "Couldn't execute statement: $DBI::errstr\n";

	    $sth->finish;

	    $dbh->disconnect;

	    my $res = Plack::Response->new( 200 );

	    $res->redirect( "/messages?agent_id=$agent" );

	    return $res->finalize;
	}
    }

    my $select_sql = "SELECT * FROM ai_messages WHERE agent_id = ? ORDER BY created DESC";

    my $sth = $dbh->prepare( $select_sql );

    $sth->execute( $agent ) or die "Couldn't execute statement: $DBI::errstr\n";

    my $table_contents = $sth->fetchall_arrayref({});

    $sth->finish;

    $dbh->disconnect;

    my $template = HTML::Template::Expr->new( filename => "/app/template/messages.tmpl", die_on_bad_params => 0 );

    $template->param(
	nav            => @nav,
	nonce          => $env->{'plack.nonce'},
	table_contents => $table_contents,
	agent_id       => $agent,
	url            => "https://$env->{HTTP_HOST}"
	);

    my $res = Plack::Response->new( 200 );

    $res->content_type( 'text/html' );

    $res->body( $template->output );

    return $res->finalize;
}

my $laml_app = sub {
    my $env     = shift;
    my $req     = Plack::Request->new( $env );
    my $to      = $req->param( 'To' );
    my $from    = $req->param( 'From' );
    my $message = $req->param( 'Body' );
    my $sid     = $req->param( 'MessageSid' );
    my $agent   = $req->param( 'agent_id' );
    my $resp    = SignalWire::CompatXML->new;

    $resp->name( 'Response' );

    print STDERR "$to, $from, $message, $sid, $agent\n" if $ENV{DEBUG};

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 }) or die "Couldn't execute statement: $DBI::errstr\n";

    my $insert_sql = "INSERT INTO ai_messages (convo_id, message, call_id, agent_id) VALUES (?, ?, ?, ?)";

    my $sth = $dbh->prepare( $insert_sql );

    my $rv  = $sth->execute( $from, $message, $sid, $agent ) or die "Couldn't execute statement: $DBI::errstr\n";

    my $res = Plack::Response->new( 200 );

    $res->content_type( 'text/xml' );

    $res->body( $resp->to_string );

    return $res->finalize;
};

my $swml_app = sub {
    my $env         = shift;
    my $req         = Plack::Request->new( $env );
    my $agent       = $req->param( 'agent_id' );
    my $post_data   = decode_json( $req->raw_body );
    my $swml        = SignalWire::ML->new;
    my $from        = $post_data->{call}->{from};
    my $ai          = 1;
    my $prompt;
    my $post_prompt;
    my $assistant;
    my %config;
    my @prompt_fields = qw( FREQUENCY_PENALTY PRESENCE_PENALTY MAX_TOKENS TOP_P TEMPERATURE CONFIDENCE BARGE_CONFIDENCE );

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die "Couldn't execute statement: $DBI::errstr\n";

    tie %config, 'MyTieConfig',
	host     => $host,
	port     => $port,
	dbname   => $database,
	user     => $dbusername,
	password => $dbpassword,
	table    => 'ai_config',
	agent_id => $agent;

    $prompt      = $config{prompt};
    $post_prompt = $config{post_prompt};
    $assistant   = $config{ASSISTANT};

    if ( $config{ENABLE_ANSWER_DELAY} ) {
	my $delay = $config{ANSWER_DELAY_LENGTH} ? $config{ANSWER_DELAY_LENGTH} : 10;
	broadcast_by_agent_id( $agent, "Answering call in $delay seconds" );
	$swml->add_application( "main", "play", "silence:$delay");
    }

    $swml->add_application( "main", "answer" );

    if ( $config{ENABLE_SEND_DIGITS_ON_ANSWER} ) {
	my $digits = $config{SEND_DIGITS_ON_ANSWER} ||= 1;
	$swml->add_application( "main", "send_digits", "$digits" );
	$swml->add_application( "main", 'play', "silence:1" );
    }

    if ( $config{ENABLE_RECORD} ) {
	broadcast_by_agent_id( $agent, "Recording call" );
	$swml->add_application( "main", "record_call", { format => 'wav', stereo => 'true' } );
    }

    if ( $config{ENABLE_CNAM} ) {
	broadcast_by_agent_id( $agent, "Looking up caller name" );
	my $data;
	my $caller_name;

	my $sw = SignalWire::RestAPI->new(
	    AccountSid  => $config{ACCOUNT_SID},
	    AuthToken   => $config{AUTH_TOKEN},
	    Space       => $config{SPACE_NAME},
	    API_VERSION => $config{API_VERSION}
	    );

	if ( $from ) {
	    my $response = $sw->GET( "lookup/phone_number/$from", include => "carrier,cnam" );

	    eval {
		$data = decode_json( $response->{content} );
	    };

	    if ( ! $@ ) {
		my $caller_name  = $data->{cnam}->{caller_id};
		my $caller_city  = $data->{carrier}->{city};
		my $caller_state = $data->{location};
		my $caller_lec   = $data->{carrier}->{lec};
		my $caller_line  = $data->{carrier}->{linetype};

		if ( $caller_city && $caller_state ) {
		    $swml->add_application( "main", "set", { city => "$caller_city", state => "$caller_state", lec => "$caller_lec", line => "$caller_line" } );
		}

		if ( $caller_name ) {
		    $swml->add_application( "main", "set", { cnam => "$caller_name", from => "$from", num_spoken => e164_to_spoken( $from ) } );
		}
	    } else {
		$swml->add_application( "main", "set", { cnam => "UNKNOWN", from => "$from", num_spoken => "UNKNOWN" } );
	    }
	}
    }

    if ( $config{ENABLE_BYPASS} && $config{CUSTODIAN_CELL} ) {
	broadcast_by_agent_id( $agent, "Checking bypass list" );
	foreach my $source ( split( /\|/, $config{BYPASS_SOURCES} ) ) {
	    if ( $source ne '' && $from =~ /\Q$source\E/ ) {
		$ai = 0;
		$swml->add_application( "main", "connect" => { to => $config{CUSTODIAN_CELL} } );
		last;
	    }
	}
    }

    if ( $ai ) {
	foreach my $k (@prompt_fields) {
	    if ( $config{$k} ) {
		broadcast_by_agent_id( $agent, "Setting $k to $config{$k}" );
		$swml->set_aiprompt({ lc $k => $config{$k} });
	    }
	}

	$swml->set_aiprompt( { text => $prompt } );

	if ( $config{ENABLE_POST_PROMPT} ) {
	    foreach my $k (@prompt_fields) {
		if ( $config{$k} ) {
		    broadcast_by_agent_id( $agent, "Setting $k to $config{$k}" );
		    $swml->set_aipost_prompt( { lc $k => $config{$k} } );
		}
	    }

	    $swml->set_aipost_prompt( { text => $post_prompt } );
	}

	{
	    my $sql = "SELECT hints FROM ai_agent WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent ) or die "Couldn't execute statement: $DBI::errstr\n";

	    my $hints = $sth->fetchrow_array;

	    $sth->finish;
	    broadcast_by_agent_id( $agent, "Setting AI hints to $hints" );
	    $swml->add_aihints( split( /\|/, $hints ) );
	}

	{
	    my $sql = "SELECT * FROM ai_language WHERE agent_id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent ) or die "Couldn't execute statement: $DBI::errstr\n";

	    my $languages = $sth->fetchall_arrayref({});

	    $sth->finish;

	    foreach my $language ( @$languages ) {
		my @filler   = split( /\,/, $language->{fillers}  );
		broadcast_by_agent_id( $agent, "Adding language $language->{code}" );
		$swml->add_ailanguage({
		    code    => $language->{code},
		    name    => $language->{name},
		    voice   => $language->{voice},
		    engine  => $language->{engine},
		    ( @filler ? ( fillers => \@filler ) : ())
				      });
	    }
	}

	$swml->set_agent_meta_data( { agent_id => $agent } );

	if ( $config{ENABLE_DEBUG_WEBHOOK} && $config{AUTH_USERNAME} && $config{AUTH_PASSWORD} ) {
	    broadcast_by_agent_id( $agent, "Adding debug webhook" );
	    $swml->add_aiparams( { debug_webhook_url => "https://$config{AUTH_USERNAME}:$config{AUTH_PASSWORD}\@$env->{HTTP_HOST}/debughook?agent_id=$agent" } );
	}

	foreach my $key ( @ai_params ) {
	    if ( $config{$key} ) {
		my $param;
		if ( $key eq 'SAVE_CONVERSATION' ) {
		    $param = { save_conversation => 'true', conversation_id => "$from" };
		} else {
		    $param = { lc( $key ) => $config{$key} };
		}

		broadcast_by_agent_id( $agent, "Setting $key to $config{$key}" );

		$swml->add_aiparams( $param );
	    }
	}

	if ( $config{ENABLE_PRONOUNCE} ) {
	    my $sql = "SELECT * FROM ai_pronounce WHERE agent_id = ?";

	    my $sth = $dbh->prepare( $sql );

	    my $rv  = $sth->execute( $agent ) or die "Couldn't execute statement: $DBI::errstr\n";

	    my $pronounces = $sth->fetchall_arrayref({});

	    foreach my $pronounce ( @$pronounces ) {
		broadcast_by_agent_id( $agent, "Adding pronounce $pronounce->{replace_this} with $pronounce->{replace_with}, Ignore case: $pronounce->{ignore_case}" );
		$swml->add_aipronounce( {
		    replace     => $pronounce->{replace_this},
		    with        => $pronounce->{replace_with},
		    ignore_case => $pronounce->{ignore_case} } );
	    }
	}

	if ( $config{AUTH_USERNAME} && $config{AUTH_PASSWORD} ) {
	    if ( $config{ENABLE_POST_PROMPT} ) {
		broadcast_by_agent_id( $agent, "Adding post prompt defaults" );
		$swml->set_aipost_prompt_url( { post_prompt_url           => "https://$env->{HTTP_HOST}/post?agent_id=$agent",
						post_prompt_auth_user     => $config{AUTH_USERNAME},
						post_prompt_auth_password => $config{AUTH_PASSWORD}
					      } );
	    }

	    if ( $config{ENABLE_SWAIG} ) {
		broadcast_by_agent_id( $agent, "Adding SWAIG defaults" );
		$swml->add_aiswaigdefaults( { web_hook_url           => "https://$env->{HTTP_HOST}/swaig?agent_id=$agent",
					      web_hook_auth_user     => $config{AUTH_USERNAME},
					      web_hook_auth_password => $config{AUTH_PASSWORD}
					    } );
	    }
	} else {
	    if ( $config{ENABLE_POST_PROMPT} ) {
		broadcast_by_agent_id( $agent, "Adding post prompt defaults" );
		$swml->set_aipost_prompt_url( { post_prompt_url => "https://$env->{HTTP_HOST}/post?agent_id=$agent" } );
	    }

	    if ( $config{ENABLE_SWAIG} ) {
		broadcast_by_agent_id( $agent, "Adding SWAIG defaults" );
		$swml->add_aiswaigdefaults( { web_hook_url => "https://$env->{HTTP_HOST}/swaig?agent_id=$agent" } );
	    }
	}

	if ( $config{ENABLE_SWAIG} ) {
	    my $output;

	    my $sql = "SELECT * FROM ai_function WHERE agent_id = ? ORDER BY created DESC";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent ) or die "Couldn't execute statement: $DBI::errstr\n";

	    my @functions;

	    while ( my $row = $sth->fetchrow_hashref ) {
		my @args;

		if ( $row->{code} ) {
		    my @args = split( /\,/, $row->{argument});
		    my $arguments;

		    foreach my $i ( 0 .. $#args ) {
			my ( $name, $desc ) = split( /\|/, $args[$i], 2);

			$arguments->{type} = "object";

			$arguments->{properties}->{$name} = { type => "string", description => $desc };
		    }
		    broadcast_by_agent_id( $agent, "Adding function $row->{name}" );
		    $swml->add_aiswaigfunction({
			active   => $row->{active} ? 'true' : 'false',
			function => $row->{name},
			purpose  => $row->{purpose},
			argument => $arguments });
		}
	    }

	    if ( $config{ENABLE_CONTEXTS} ) {
		my $sql = "SELECT * FROM ai_context WHERE agent_id = ? ORDER BY id ASC";

		my $sth = $dbh->prepare( $sql );

		$sth->execute( $agent ) or die "Couldn't execute statement: $DBI::errstr\n";

		my @context_expressions;

		while ( my $row = $sth->fetchrow_hashref ) {
		    my @actions;

		    if ( $row->{toggle_function} ) {
			foreach my $function ( split( /\|/, $row->{toggle_function} ) ) {
			    my ( $function, $args ) = split( /:/, $function );
			    broadcast_by_agent_id( $agent, "Adding toggle function $function with args $args" );
			    push @actions, {
				toggle_function => {
				    function => $function,
				    active   => $args } };
			}
		    }
		    broadcast_by_agent_id( $agent, "Adding context switch with consolidate $row->{consolidate}, full reset $row->{full_reset}, user prompt $row->{user_prompt}, system prompt $row->{system_prompt}" );
		    push @actions, {
			context_switch => {
			    consolidate   => $row->{consolidate},
			    full_reset    => $row->{full_reset},
			    user_prompt   => $row->{user_prompt},
			    system_prompt => $row->{system_prompt} } };

		    my $expression = {
			string  => '${args.context}',
			pattern => $row->{pattern},
			output  => {
			    response => 'OK',
			    action   => \@actions
			}
		    };

		    push @context_expressions, $expression;
		}

		$swml->add_aiswaigfunction({
		    function => "switch_context",
		    purpose => "to change contexts ",
		    argument => {
			type => "object",
			properties => {
			    context => {
				type        => "string",
				description => "The name of the new context" }
			},
		    },
		    data_map => {
			expressions => \@context_expressions,
		    }});
	    }

	    if ( $config{ENABLE_SLACK_SWAIG} && $config{SLACK_WEBHOOK_URL} && $config{SLACK_CHANNEL} && $config{SLACK_USERNAME} && $config{SLACK_MESSAGE} ) {
		broadcast_by_agent_id( $agent, "Adding slack notification function" );
		$swml->add_aiswaigfunction({
		    function => 'send_slack_notification',
		    purpose => "send a slack notification with the conversation details",
		    argument => {
			type => "object",
			properties => {
			    name => {
				type        => "string",
				description => "Users name" },
			    company => {
				type        => "string",
				description => "Company name, optional" },
			    contactNumber => {
				type        => "string",
				description => "User phone number in e.164 format, required" },
			    description => {
				type        => "string",
				description => "the summary of the conversation, required" } } },
		    data_map => {
			webhooks => [{
			    url => $config{SLACK_WEBHOOK_URL},
			    form_param => 'payload',
			    method     => "POST",
			    params     => {
				text     => $config{SLACK_MESSAGE},
				channel  => $config{SLACK_CHANNEL},
				username => $config{SLACK_USERNAME},
			    },
			    output => {
				response => 'slack notification sent',
			    }}]}});
	    }

	    if ( $config{TRANSFER_TABLE} && $config{ENABLE_TRANSFER} ) {
		broadcast_by_agent_id( $agent, "Adding transfer function" );
		my $transfer = SignalWire::ML->new;

		$transfer->add_application( "main", "connect" => { to   => '${meta_data.table.${lc:args.target}}',
								   from => $assistant } );

		$output = $transfer->swaig_response( {
		    response => "transferred, the call has ended.",
		    action   => [ { say  => "Please stand by while I connect your call." },
				  { SWML => $transfer->render }, { stop => 'true' } ] } );

		my %hash;

		my @pairs = split( /\|/, $config{TRANSFER_TABLE} );

		foreach my $pair ( @pairs ) {
		    my ( $key, $value ) = split( /:/, $pair, 2 );
		    $hash{$key} = $value;
		}

		$swml->add_aiswaigfunction( {
		    function  => 'transfer',
		    purpose   => "use to transfer to a target",
		    meta_data => {
			table => \%hash
		    },
		    argument => {
			type => "object",
			properties => {
			    target => {
				type        => "string",
				description => "the target to transfer to"
			    }
			}
		    },
		    data_map => {
			expressions => [
			    {
				string  => '${meta_data.table.${lc:args.target}}',
				pattern => '\w+',
				output  => $output
			    },
			    {
				string  => '${args.target}',
				pattern => '.*',
				output  => { response => 'I\'m sorry, I was unable to transfer your call to ${input.args.target}.' }
			    }
			    ]}});

	    }

	    if ( $config{ENABLE_MESSAGE} && $assistant ) {
		broadcast_by_agent_id( $agent, "Adding message function" );
		my $msg = SignalWire::ML->new;

		$msg->add_application( "main", "send_sms" => { to_number   => '${args.to}',
							       from_number => "$assistant",
							       body        => '${args.message}, Reply STOP to stop.',
							       region      => "us" } );

		$output = $msg->swaig_response( {
		    response => "Message sent.",
		    action   => [ { SWML => $msg->render } ] } );

		$swml->add_aiswaigfunction( {
		    function => 'send_message',
		    purpose  => "use to send text messages to a user",
		    argument => {
			type => "object",
			properties => {
			    message => {
				type        => "string",
				description => "the message to send to the user" },
			    to => {
				type        => "string",
				description => "The users number in e.164 format" }
			},
		    },
		    data_map => {
			expressions => [{
			    string  => '${args.message}',
			    pattern => '.*',
			    output  => $output
					}]}} );
	    }

	    if ( $config{ENABLE_SEND_DIGITS} && $assistant ) {
		broadcast_by_agent_id( $agent, "Adding send digits function" );
		my $dtmf = SignalWire::ML->new;

		$dtmf->add_application( "main", "send_digits" => '${args.button}' );

		$output = $dtmf->swaig_response( {
		    response => "Button pressed. Now greet the user again as if you were just connected",
		    action   => [ { SWML => $dtmf->render } ] } );

		$swml->add_aiswaigfunction( {
		    function => 'send_digits',
		    purpose  => "use to press buttons when requested",
		    argument => {
			type => "object",
			properties => {
			    button => {
				type        => "string",
				description => "The button to press." },
			},
		    },
		    data_map => {
			expressions => [{
			    string  => '${args.digits}',
			    pattern => '.*',
			    output  => $output
					}]}} );
	    }

	    if ( $config{CALENDLY_MESSAGE} && $config{ENABLE_CALENDLY} && $assistant ) {
		broadcast_by_agent_id( $agent, "Adding calendly function" );
		my $cal = SignalWire::ML->new;

		$cal->add_application("main", "send_sms" => { to_number   => '${args.to}',
							      from_number => $assistant,
							      body        => $config{CALENDLY_MESSAGE},
							      region      => "us" } );

		$output = $cal->swaig_response( {
		    response => "Message sent.",
		    action   => [ { SWML => $cal->render } ] } );

		$swml->add_aiswaigfunction( {
		    function => 'send_meeting',
		    purpose  => "use to send meeting link to user",
		    argument => {
			type => "object",
			properties => {
			    to => {
				type        => "string",
				description => "The users number in e.164 format" }
			},
		    },
		    data_map => {
			expressions => [{
			    string  => '.*',
			    pattern => '.*',
			    output  => $output
					}]}});
	    }

	    if ( $config{SIMPLE_POST_FUNCTION} ) {
		broadcast_by_agent_id( $agent, "Adding simple post function" );
		$swml->add_aiswaigfunction( {
		    function => 'get_data',
		    purpose => "squery order data from the database",
		    argument => {
			type => "object",
			properties => {
			    name => {
				type        => "string",
				description => "Users name." },
			    surname => {
				type        => "string",
				description => "Users Surname" } } },
		    data_map => {
			webhooks => [{
			    url     => "https://$config{AUTH_USERNAME}:$config{AUTH_PASSWORD}\@$env->{HTTP_HOST}/debughook?agent_id=$agent",
			    method  => "POST",
			    params   => {
				name => '${args.name}',
				surname => '${args.surname}'
			    },
			    output => {
				response => '${array[0].name} your order status is testing.',
			    }}]}} );
	    }


	    if ( $config{API_NINJAS_KEY} ) {
		if ( $config{ENABLE_WEATHER} ) {
		    broadcast_by_agent_id( $agent, "Adding weather function" );
		    $swml->add_aiswaigfunction( {
			function => 'get_weather',
			purpose => "latest weather information for any city",
			argument => {
			    type => "object",
			    properties => {
				city => {
				    type        => "string",
				    description => "City name." },
				state => {
				    type        => "string",
				    description => "US state for United States cities only. Optional" } } },
			data_map => {
			    webhooks => [{
				url     => 'https://api.api-ninjas.com/v1/weather?city=${enc:args.city}&state=${enc:args.state}',
				method  => "GET",
				headers => {
				    "X-Api-Key" => "$config{API_NINJAS_KEY}" },
				output => {
				    response => 'The weather in ${input.args.city} is  @{expr (${temp} * 9/5 ) + 32}F, Humidity: ${humidity}%, High: @{expr (${max_temp} * 9/5 ) + 32}F, Low: @{expr (${min_temp} * 9/5 ) + 32}F Wind Direction: ${wind_degrees} (say cardinal direction), Clouds: ${cloud_pct}%, Feels Like: @{expr (${feels_like} * 9/5 ) + 32}F.',
				}}]}} );

		}

		if ( $config{ENABLE_JOKES} ) {
		    broadcast_by_agent_id( $agent, "Adding jokes function" );
		    $swml->add_aiswaigfunction( {
			function => 'get_joke',
			purpose  => "tell a joke",
			argument => {
			    type => "object",
			    properties => {
				type => {
				    type        => "string",
				    description => "must either be 'jokes' or 'dadjokes'" },
			    }
			},
			data_map => {
			    webhooks => [{
				url     => 'https://api.api-ninjas.com/v1/${args.type}',
				method  => "GET",
				headers => {
				    "X-Api-Key" => "$config{API_NINJAS_KEY}" },
				output => {
				    response => 'Tell the user: ${array[0].joke}'
				}}]}});

		    my $dj = SignalWire::ML->new;

		    $dj->add_application("main", "set" => { dad_joke => '${joke}' } );

		    my $djoke  = $dj->swaig_response({
			response => 'Tell the user: ${joke}',
			action   => [ { SWML => $dj->render } ] } );
		}

		if ( $config{ENABLE_TRIVIA} ) {
		    broadcast_by_agent_id( $agent, "Adding trivia function" );
		    $swml->add_aiswaigfunction( {
			function => 'get_trivia',
			purpose  => "get a trivia question",
			argument => {
			    type => "object",
			    properties => {
				category => {
				    type        => "string",
				    description => "Valid options are artliterature, language, sciencenature, general, fooddrink, peopleplaces, geography, historyholidays, entertainment, toysgames, music, mathematics, religionmythology, sportsleisure. Pick a category at random if not asked for a specific category." }
			    }
			},
			data_map => {
			    webhooks => [{
				url     => 'https://api.api-ninjas.com/v1/trivia?category=${args.category}',
				method  => "GET",
				headers => {
				    "X-Api-Key" => "$config{API_NINJAS_KEY}" },
				output => {
				    response => 'category ${array[0].category} questions: ${array[0].question} answer: ${array[0].answer}, be sure to give the user time to answer before saying the answer.',
				}}]}});
		}

	    }
	    if ( $config{ENABLE_CHECK_FOR_INPUT} ) {
		broadcast_by_agent_id( $agent, "Adding check for input function" );
		$swml->add_aiswaigfunction( {
		    function => 'check_for_input',
		    purpose  => "check for input",
		    argument => "none" } );
	    }
	}

	broadcast_by_agent_id( $agent, "Adding main AI application" );
	$swml->add_aiapplication( "main" );
    }

    untie %config;

    my $res = Plack::Response->new( 200 );

    $res->content_type( 'application/json' );

    broadcast_by_agent_id( $agent, $swml->render );

    $dbh->disconnect;

    $res->body( $swml->render_json );

    return $res->finalize;
};

my $swaig_app = sub {
    my $env       = shift;
    my $req       = Plack::Request->new( $env );
    my $agent     = $req->param('agent_id');
    my $swml      = SignalWire::ML->new;
    my $res       = Plack::Response->new( 200 );
    my $post_data;

    if ( $req->raw_body ne '' ) {
	$post_data = decode_json( $req->raw_body );
    }

    if ( defined $post_data->{function} && exists $function{$post_data->{function}} ) {
	$function{$post_data->{function}}->( $env );
    } else {
	my $dbh = DBI->connect(
	    "dbi:Pg:dbname=$database;host=$host;port=$port",
	    $dbusername,
	    $dbpassword,
	    { AutoCommit => 1, RaiseError => 1 } ) or die "Couldn't execute statement: $DBI::errstr\n";

	broadcast_by_agent_id( $agent, { response => "Looking for $post_data->{function} for agent $agent" } );

	my $sth = $dbh->prepare( "SELECT * FROM ai_function WHERE name = ? AND agent_id = ?" );

	$sth->execute( $post_data->{function}, $agent ) or die "Couldn't execute statement: $DBI::errstr\n";

	my $row = $sth->fetchrow_hashref;

	$sth->finish;

	$dbh->disconnect;

	if ($row) {
	    broadcast_by_agent_id( $agent, { response => "Found function $row->{name} for agent $agent" } );
	} else {
	    broadcast_by_agent_id( $agent, { response => "Did not find function $post_data->{function} for agent $agent" } );
	}
	
	if ( defined $row->{name} && $row->{active} ) {
	    my $code     = $row->{code};
	    my $code_ref = eval "sub { $code }";

	    if ( $@ ) {
		# Handle the error, for example by setting the response body
		$res->content_type('application/json');
		$res->body( $swml->swaig_response_json( { response => "An error occurred executing function $row->{name}: $@" } ) );
		broadcast_by_agent_id( $agent, $@ );
		return $res->finalize;
	    }

	    return &$code_ref( $env );
	}

	$res->content_type( 'application/json' );

	broadcast_by_agent_id( $agent, { response => "Unknown function: $post_data->{function} for agent $agent" } );

	$res->body( $swml->swaig_response_json( { response => "Unknown function: $post_data->{function} for agent $agent" } ) );

	return $res->finalize;
    }
};

sub config {
    my $env     = shift;
    my $req     = Plack::Request->new( $env );
    my $method  = $req->method;
    my $agent   = $req->param( 'agent_id' );
    my $res     = Plack::Response->new( 200 );
    my @toggles = qw( ENABLE_SEND_DIGITS_ON_ANSWER ENABLE_ANSWER_DELAY ENABLE_SEND_DIGITS ENABLE_BYPASS ENABLE_ZENDESK_TICKET ENABLE_CONTEXTS ENABLE_SLACK_NOTIFICATION ENABLE_CALENDLY ENABLE_SLACK_SWAIG ENABLE_PRONOUNCE ENABLE_TRANSFER ENABLE_DEBUG_WEBHOOK ENABLE_POST_PROMPT ENABLE_CNAM ENABLE_SWAIG ENABLE_RECORD ENABLE_MESSAGE ENABLE_WEATHER ENABLE_TRIVIA ENABLE_JOKES ENABLE_CHECK_FOR_INPUT SAVE_BLANK_CONVERSATIONS SEND_SUMMARY_MESSAGE SIMPLE_POST_FUNCTION);
    my @fields  = qw(AUTH_USERNAME AUTH_PASSWORD SPACE_NAME ACCOUNT_SID AUTH_TOKEN API_VERSION TEMPERATURE TOP_P BARGE_CONFIDENCE CONFIDENCE PRESENCE_PENALTY FREQUENCY_PENALTY CUSTODIAN_SMS CUSTODIAN_CELL ASSISTANT TRANSFER_TABLE CALENDLY_MESSAGE API_NINJAS_KEY MAX_TOKENS SLACK_WEBHOOK_URL SLACK_CHANNEL SLACK_USERNAME SLACK_MESSAGE ZENDESK_API_KEY ZENDESK_SUBDOMAIN BYPASS_SOURCES ANSWER_DELAY_LENGTH SEND_DIGITS_ON_ANSWER );
    my ( @controls, @settings );

    my $session = $env->{'psgix.session'};

    my %seen;

    foreach my $item (@fields, @ai_params) {
	$seen{$item} = 1;
    }

    my @merged_fields = sort keys %seen;

    @toggles = sort @toggles;

    my %config;

    tie %config, 'MyTieConfig',
	host     => $host,
	port     => $port,
	dbname   => $database,
	user     => $dbusername,
	password => $dbpassword,
	table    => 'ai_config',
	agent_id => $agent;

    $res->content_type( 'text/html' );

    if ( $method eq 'POST' ) {
	my $params = $req->parameters;

	foreach my $toggle ( @toggles ) {
	    if ( ! exists $params->{$toggle} ) {
		$config{$toggle} =  0;
	    } else {
		$config{$toggle} =  1;
	    }
	}

	foreach my $field ( @merged_fields ) {
	    if ( exists $params->{$field} ) {
		$config{$field} = $params->{$field};
	    }
	}
	my $res = Plack::Response->new( 200 );

	$res->redirect( "/config?agent_id=$agent" );

	untie %config;

	return $res->finalize;
    }

    foreach my $toggle ( @toggles ) {
	my $control = { var => $toggle, val => $config{$toggle}, checked => $config{$toggle} ? "checked" : "" };

	push @controls, $control;
    }

    foreach my $field ( @merged_fields ) {
	my $control = { var => $field, val => $config{$field} };

	push @settings, $control;
    }

    my $template = HTML::Template::Expr->new( filename => "/app/template/config.tmpl", die_on_bad_params => 0 );

    $template->param(
	nav	 => @nav,
	nonce    => $env->{'plack.nonce'},
	agent_id => $agent,
	controls => \@controls,
	fields   => \@settings,
	url      => "https://$env->{HTTP_HOST}/config",
	swml_url	   => ( $config{AUTH_USERNAME} && $config{AUTH_PASSWORD} ) ? "https://$config{AUTH_USERNAME}:$config{AUTH_PASSWORD}\@$env->{HTTP_HOST}/swml?agent_id=$agent" : "https://$env->{HTTP_HOST}/swml?agent_id=$agent",
	laml_url	   => ( $config{AUTH_USERNAME} && $config{AUTH_PASSWORD} ) ? "https://$config{AUTH_USERNAME}:$config{AUTH_PASSWORD}\@$env->{HTTP_HOST}/laml?agent_id=$agent" : "https://$env->{HTTP_HOST}/laml?agent_id=$agent"
	);

    untie %config;

    $res->body( $template->output );

    return $res->finalize;
}

sub prompt {
    my $env    = shift;
    my $req    = Plack::Request->new( $env );
    my $agent  = $req->param( 'agent_id' );
    my $method = $req->method;
    my $res    = Plack::Response->new( 200 );

    my %config;

    tie %config, 'MyTieConfig',
	host     => $host,
	port     => $port,
	dbname   => $database,
	user     => $dbusername,
	password => $dbpassword,
	table    => 'ai_config',
	agent_id => $agent;

    $res->content_type( 'text/html' );

    if ( $method eq 'POST' ) {
	my $params = $req->parameters;

	$config{prompt}          = $params->{prompt};
	$config{post_prompt}     = $params->{post_prompt};

	my $res = Plack::Response->new( 200 );

	$res->redirect( "/prompt?agent_id=$agent" );

	untie %config;

	return $res->finalize;
    }

    my $template = HTML::Template::Expr->new( filename => "/app/template/prompt.tmpl", die_on_bad_params => 0 );

    $template->param(
	nav		=> @nav,
	url             => "https://$env->{HTTP_HOST}/prompt",
	nonce           => $env->{'plack.nonce'},
	agent_id        => $agent,
	prompt          => $config{prompt},
	post_prompt     => $config{post_prompt}
	);

    $res->body( $template->output );

    untie %config;

    return $res->finalize;
}

sub agents {
    my $env    = shift;
    my $req    = Plack::Request->new( $env );
    my $method = $req->method;
    my $res    = Plack::Response->new( 200 );

    my $session = $env->{'psgix.session'};

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die "Couldn't connect to database: $DBI::errstr";

    $res->content_type( 'text/html' );

    if ( $method eq 'POST' ) {
	my $params = $req->parameters;

	if ( $params->{action} eq 'create' ) {
	    my $sql = "INSERT INTO ai_agent (name, description, hints, user_id) VALUES (?, ?, ?, ?)";
	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{name}, $params->{description}, $params->{hints}, $session->{user_id} ) or die "Couldn't execute statement: $DBI::errstr";

	    my $last_insert_id = $dbh->last_insert_id( undef, undef, 'ai_agent', 'id' );

	    $sth->finish;

	    my %config;

	    tie %config, 'MyTieConfig',
		host     => $host,
		port     => $port,
		dbname   => $database,
		user     => $dbusername,
		password => $dbpassword,
		table    => 'ai_config',
		agent_id => $last_insert_id;

	    my $username = substr(generate_nonce(), 0, 16);
	    my $password = substr(generate_nonce(), 0, 16);

	    $username =~ s/[^a-zA-Z0-9]//g;
	    $password =~ s/[^a-zA-Z0-9]//g;

	    $config{AUTH_USERNAME} = $username;
	    $config{AUTH_PASSWORD} = $password;

	    untie %config;
	} elsif ( $params->{action} eq 'add' ) {
	    my $template = HTML::Template::Expr->new( filename => "/app/template/create_agent.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav		=> $session->{is_admin} ? @admin_nav : @user_nav,
		url             => "https://$env->{HTTP_HOST}",
		nonce           => $env->{'plack.nonce'},
		);

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'edit' ) {
	    my $template = HTML::Template::Expr->new( filename => "/app/template/edit_agent.tmpl", die_on_bad_params => 0 );

	    my $sql = "SELECT * FROM ai_agent WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die "Couldn't execute statement: $DBI::errstr";

	    my $agent = $sth->fetchrow_hashref;

	    $sth->finish;

	    $template->param(
		nav		=> $session->{is_admin} ? @admin_nav : @user_nav,
		url             => "https://$env->{HTTP_HOST}",
		nonce           => $env->{'plack.nonce'},
		agent_id        => $params->{id},
		);

	    $template->param( %$agent );

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'update' ) {
	    my $sql = "UPDATE ai_agent SET name = ?, description = ?, hints = ? WHERE id = ?";
	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{name}, $params->{description}, $params->{hints}, $params->{id} ) or die "Couldn't execute statement: $DBI::errstr";

	    $sth->finish;
	} elsif ( $params->{action} eq 'delete' ) {
	    my $session = $env->{'psgix.session'};

	    if ( $session->{is_admin} ) {
		my $sql = "DELETE FROM ai_agent WHERE id = ?";
		my $sth = $dbh->prepare( $sql );

		$sth->execute( $params->{id} ) or die "Couldn't execute statement: $DBI::errstr";

		$sth->finish;
	    } else {
		$res->status( 403 );

		$res->body( "You are not authorized to delete agents." );

		return $res->finalize;
	    }
	}

	$dbh->disconnect;

	my $res = Plack::Response->new( 200 );

	$res->redirect( "/" );

	return $res->finalize;
    }

    my $sql;

    if ( $session->{is_admin} ) {
	$sql = "SELECT * FROM ai_agent ORDER BY created DESC";
    } else {
	$sql = "SELECT * FROM ai_agent where user_id = ? ORDER BY created DESC";
    }

    my $sth = $dbh->prepare( $sql );

    if (! $session->{is_admin} ) {
	$sth->bind_param( 1, $session->{user_id} );
    }

    $sth->execute or die "Couldn't execute statement: $DBI::errstr";

    my $agents = $sth->fetchall_arrayref({});

    my $template = HTML::Template::Expr->new( filename => "/app/template/agents.tmpl", die_on_bad_params => 0 );

    $template->param(
	nav             => $session->{is_admin} ? @admin_nav : @user_nav,
	nonce		=> $env->{'plack.nonce'},
	url             => "https://$env->{HTTP_HOST}",
	agents          => $agents
	);

    $res->body( $template->output );

    $dbh->disconnect;

    return $res->finalize;
}

sub languages {
    my $env    = shift;
    my $req    = Plack::Request->new( $env );
    my $agent  = $req->param( 'agent_id' );
    my $method = $req->method;
    my $res    = Plack::Response->new( 200 );

    my $session = $env->{'psgix.session'};

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die "Couldn't connect to database: $DBI::errstr";

    $res->content_type( 'text/html' );

    if ( $method eq 'POST' ) {
	my $params = $req->parameters;

	if ( $params->{action} eq 'create' ) {
	    my $sql = "INSERT INTO ai_language (agent_id, code, name, voice, engine, fillers) VALUES (?, ?, ?, ?, ?, ?)";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent, $params->{code}, $params->{name}, $params->{voice}, $params->{engine}, $params->{fillers} ) or die "Couldn't execute statement: $DBI::errstr";

	    $sth->finish;
	} elsif ( $params->{action} eq 'add' ) {
	    my $template = HTML::Template::Expr->new( filename => "/app/template/create_language.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav             => $session->{is_admin} ? @nav : @user_nav,
		nonce		=> $env->{'plack.nonce'},
		agent_id        => $agent
		);

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'edit' ) {
	    my $sql = "SELECT * FROM ai_language WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die "Couldn't execute statement: $DBI::errstr";

	    my $language = $sth->fetchrow_hashref;

	    $sth->finish;

	    my $template = HTML::Template::Expr->new( filename => "/app/template/edit_language.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav             => $session->{is_admin} ? @nav : @user_nav,
		nonce		=> $env->{'plack.nonce'},
		url             => "https://$env->{HTTP_HOST}",
		agent_id        => $agent,
		);

	    $template->param( %$language );

	    $res->body( $template->output );

	    return $res->finalize;
	} elsif ( $params->{action} eq 'update' ) {
	    my $sql = "UPDATE ai_language SET code = ?, name = ?, voice = ?, engine = ?, fillers = ? WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{code}, $params->{name}, $params->{voice}, $params->{engine}, $params->{fillers}, $params->{id} ) or die "Couldn't execute statement: $DBI::errstr";

	    $sth->finish;
	} elsif ( $params->{action} eq 'delete' ) {
	    my $session = $env->{'psgix.session'};

	    if ( $session->{is_admin} ) {
		my $sql = "DELETE FROM ai_language WHERE id = ?";
		my $sth = $dbh->prepare( $sql );

		$sth->execute( $params->{id} ) or die "Couldn't execute statement: $DBI::errstr";
		$sth->finish;
	    } else {
		$res->status( 403 );

		$res->body( "You are not authorized to delete languages." );

		return $res->finalize;
	    }
	}

	$dbh->disconnect;

	$res->redirect( "/languages?agent_id=$agent" );

	return $res->finalize;
    }

    my $sql = "SELECT * FROM ai_language WHERE agent_id = ? ORDER BY created DESC";

    my $sth = $dbh->prepare( $sql );

    $sth->execute( $agent ) or die "Couldn't execute statement: $DBI::errstr";

    my $languages = $sth->fetchall_arrayref({});

    my $template = HTML::Template::Expr->new( filename => "/app/template/languages.tmpl", die_on_bad_params => 0 );

    $template->param(
	nav             => $session->{is_admin} ? @nav : @user_nav,
	nonce		=> $env->{'plack.nonce'},
	url             => "https://$env->{HTTP_HOST}",
	agent_id        => $agent,
	languages       => $languages
	);

    $res->body( $template->output );

    $dbh->disconnect;

    return $res->finalize;
}

sub pronounce {
    my $env    = shift;
    my $req    = Plack::Request->new( $env );
    my $agent  = $req->param( 'agent_id' );
    my $method = $req->method;
    my $res    = Plack::Response->new( 200 );

    my $session = $env->{'psgix.session'};

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die "Couldn't connect to database: $DBI::errstr";

    $res->content_type( 'text/html' );

    if ( $method eq 'POST' ) {
	my $params = $req->parameters;

	$params->{ignore_case} = $params->{ignore_case} ? 1 : 0;

	if ( $params->{action} eq 'create' ) {
	    my $sql = "INSERT INTO ai_pronounce (agent_id, ignore_case, replace_this, replace_with) VALUES (?, ?, ?, ?)";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent, $params->{ignore_case}, $params->{replace_this}, $params->{replace_with} ) or die "Couldn't execute statement: $DBI::errstr";

	    $sth->finish;
	} elsif ( $params->{action} eq 'add' ) {
	    my $template = HTML::Template::Expr->new( filename => "/app/template/create_pronounce.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav             => $session->{is_admin} ? @nav : @user_nav,
		nonce		=> $env->{'plack.nonce'},
		agent_id        => $agent
		);

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'edit' ) {
	    my $sql = "SELECT * FROM ai_pronounce WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die "Couldn't execute statement: $DBI::errstr";

	    my $pronounce = $sth->fetchrow_hashref;

	    $sth->finish;

	    $pronounce->{ignore_case_checked} = $pronounce->{ignore_case} ? 'checked' : '';

	    my $template = HTML::Template::Expr->new( filename => "/app/template/edit_pronounce.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav             => $session->{is_admin} ? @nav : @user_nav,
		nonce		=> $env->{'plack.nonce'},
		url             => "https://$env->{HTTP_HOST}",
		agent_id        => $agent,
		);

	    $template->param( %$pronounce );

	    $res->body( $template->output );

	    return $res->finalize;
	} elsif ( $params->{action} eq 'update' ) {
	    my $sql = "UPDATE ai_pronounce SET ignore_case = ?, replace_this = ?, replace_with = ? WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{ignore_case}, $params->{replace_this}, $params->{replace_with}, $params->{id} ) or die "Couldn't execute statement: $DBI::errstr";

	    $sth->finish;
	} elsif ( $params->{action} eq 'delete' ) {
	    my $session = $env->{'psgix.session'};

	    if ( $session->{is_admin} ) {
		my $sql = "DELETE FROM ai_pronounce WHERE id = ?";
		my $sth = $dbh->prepare( $sql );

		$sth->execute( $params->{id} ) or die "Couldn't execute statement: $DBI::errstr";
		$sth->finish;
	    } else {
		$res->status( 403 );

		$res->body( "You are not authorized to delete pronounce." );

		return $res->finalize;
	    }
	}

	$dbh->disconnect;

	$res->redirect( "/pronounce?agent_id=$agent" );

	return $res->finalize;
    }

    my $sql = "SELECT * FROM ai_pronounce WHERE agent_id = ? ORDER BY created DESC";

    my $sth = $dbh->prepare( $sql );

    $sth->execute( $agent ) or die "Couldn't execute statement: $DBI::errstr";

    my $pronounce = $sth->fetchall_arrayref({});

    $sth->finish;

    $dbh->disconnect;

    my $template = HTML::Template::Expr->new( filename => "/app/template/pronounce.tmpl", die_on_bad_params => 0 );

    $template->param(
	nav             => @nav,
	nonce		=> $env->{'plack.nonce'},
	url             => "https://$env->{HTTP_HOST}",
	agent_id        => $agent,
	pronounce       => $pronounce
	);

    $res->body( $template->output );

    $dbh->disconnect;

    return $res->finalize;
}

sub functions {
    my $env    = shift;
    my $req    = Plack::Request->new( $env );
    my $agent  = $req->param( 'agent_id' );
    my $method = $req->method;
    my $res    = Plack::Response->new( 200 );

    my $session = $env->{'psgix.session'};

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die "Couldn't connect to database: $DBI::errstr";

    if ( $method eq 'POST' ) {

	my $params = $req->parameters;

	$params->{active_checked} = $params->{active} ? 'checked' : '';

	if ( $params->{action} eq 'create' ) {
	    my $sql = "INSERT INTO ai_function (agent_id, name, active, argument, purpose, code) VALUES (?, ?, ?, ?, ?, ?)";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent, $params->{name}, $params->{active}, $params->{argument}, $params->{purpose}, $params->{code} ) or die "Couldn't execute statement: $DBI::errstr";

	    $sth->finish;
	} elsif ( $params->{action} eq 'add' ) {
	    my $template = HTML::Template::Expr->new( filename => "/app/template/create_function.tmpl", die_on_bad_params => 0 );
	    my $code     = read_file( '/app/template/function.default' );

	    $template->param(
		nav             => @nav,
		nonce		=> $env->{'plack.nonce'},
		agent_id        => $agent,
		code            => $code
		);

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'edit' ) {
	    my $sql = "SELECT * FROM ai_function WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die "Couldn't execute statement: $DBI::errstr";

	    my $function = $sth->fetchrow_hashref;

	    $sth->finish;

	    my $template = HTML::Template::Expr->new( filename => "/app/template/edit_function.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav             => @nav,
		nonce		=> $env->{'plack.nonce'},
		url             => "https://$env->{HTTP_HOST}/functions?agent_id=$agent",
		agent_id        => $agent,
		);

	    $function->{active_checked} = $function->{active} ? 'checked' : '';

	    $template->param( %$function );

	    $res->body( $template->output );

	    return $res->finalize;
	} elsif ( $params->{action} eq 'update' ) {
	    my $sql = "UPDATE ai_function SET name = ?, active = ?, argument = ?, purpose = ?, code = ? WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{name}, $params->{active}, $params->{argument}, $params->{purpose} , $params->{code}, $params->{id} ) or die "Couldn't execute statement: $DBI::errstr";

	    $sth->finish;

	    $dbh->disconnect;

	    my $res = Plack::Response->new( 302 );

	    $res->redirect( "/functions?agent_id=$agent" );

	    return $res->finalize;
	} elsif ( $params->{action} eq 'delete' ) {
	    my $sql = "DELETE FROM ai_function WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die "Couldn't execute statement: $DBI::errstr";

	    $sth->finish;

	    $dbh->disconnect;

	    my $res = Plack::Response->new( 302 );

	    $res->redirect( "/functions?agent_id=$agent" );

	    return $res->finalize;
	}
    }
    $res->content_type( 'text/html' );

    my $sql = "SELECT * FROM ai_function WHERE agent_id = ? ORDER BY created DESC";

    my $sth = $dbh->prepare( $sql );

    $sth->execute( $agent ) or die "Couldn't execute statement: $DBI::errstr";

    my $functions = $sth->fetchall_arrayref({});

    $sth->finish;

    $dbh->disconnect;

    my $template = HTML::Template::Expr->new( filename => "/app/template/functions.tmpl", die_on_bad_params => 0 );

    $template->param(
	nav             => @nav,
	nonce		=> $env->{'plack.nonce'},
	url             => "https://$env->{HTTP_HOST}",
	agent_id        => $agent,
	functions       => $functions
	);

    $res->body( $template->output );

    return $res->finalize;
}

sub contexts {
    my $env    = shift;
    my $req    = Plack::Request->new( $env );
    my $agent  = $req->param( 'agent_id' );
    my $method = $req->method;

    my $session = $env->{'psgix.session'};

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die "Couldn't connect to database: $DBI::errstr";

    if ( $method eq 'POST' ) {
	my $params = $req->parameters;

	$params->{consolidate} = $params->{consolidate} ? 1 : 0;

	$params->{full_reset}  = $params->{full_reset}  ? 1 : 0;

	if ( $params->{action} eq 'create' ) {
	    my $sql = "INSERT INTO ai_context (agent_id, name, pattern, toggle_function, consolidate, full_reset, user_prompt, system_prompt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent, $params->{name}, $params->{pattern}, $params->{toggle_function}, $params->{consolidate}, $params->{full_reset}, $params->{user_prompt}, $params->{system_prompt} ) or die "Couldn't execute statement: $DBI::errstr\n";

	    $sth->finish;

	    $dbh->disconnect;
	} elsif ( $params->{action} eq 'add' ) {
	    my $res = Plack::Response->new( 200 );

	    $res->content_type( 'text/html' );

	    my $template = HTML::Template::Expr->new( filename => "/app/template/create_context.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav      => @nav,
		url      => "https://$env->{HTTP_HOST}",
		nonce    => $env->{'plack.nonce'},
		agent_id => $agent,
		);

	    $res->body( $template->output );

	    return $res->finalize;
	} elsif ( $params->{action} eq 'edit' ) {
	    my $res = Plack::Response->new( 200 );

	    $res->content_type( 'text/html' );

	    my $sql = "SELECT * FROM ai_context WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die "Couldn't execute statement: $DBI::errstr";

	    my $context = $sth->fetchrow_hashref;

	    $sth->finish;

	    $context->{consolidate_checked} = $context->{consolidate} ? 'checked' : '';
	    $context->{full_reset_checked}  = $context->{full_reset}  ? 'checked' : '';

	    my $template = HTML::Template::Expr->new( filename => "/app/template/edit_context.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav      => @nav,
		url      => "https://$env->{HTTP_HOST}",
		nonce    => $env->{'plack.nonce'},
		agent_id => $agent,
		);

	    $template->param( %$context );

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'update' ) {
	    my $sql = "UPDATE ai_context SET name = ?, pattern = ?, toggle_function = ?, consolidate = ?, full_reset = ? , user_prompt = ?, system_prompt = ? WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{name}, $params->{pattern}, $params->{toggle_function}, $params->{consolidate}, $params->{full_reset}, $params->{user_prompt}, $params->{system_prompt}, $params->{id} ) or die "Couldn't execute statement: $DBI::errstr\n";

	    $sth->finish;

	    $dbh->disconnect;

	    my $res = Plack::Response->new( 302 );

	    $res->redirect( "/contexts?agent_id=$agent" );

	    return $res->finalize;
	} elsif ( $params->{action} eq 'delete' ) {
	    my $sql = "DELETE FROM ai_context WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die "Couldn't execute statement: $DBI::errstr\n";

	    $sth->finish;

	    $dbh->disconnect;
	    my $res = Plack::Response->new( 302 );

	    $res->redirect( "/contexts?agent_id=$agent" );

	    return $res->finalize;
	}

    } else {
	my $res = Plack::Response->new( 200 );

	$res->content_type( 'text/html' );

	my $sql = "SELECT * FROM ai_context WHERE agent_id = ? ORDER BY created DESC";

	my $sth = $dbh->prepare( $sql );

	$sth->execute( $agent ) or die "Couldn't execute statement: $DBI::errstr\n";

	my $contexts = $sth->fetchall_arrayref({});

	$sth->finish;

	$dbh->disconnect;

	my $template = HTML::Template::Expr->new( filename => "/app/template/contexts.tmpl", die_on_bad_params => 0 );

	$template->param(
	    nav      => @nav,
	    url      => "https://$env->{HTTP_HOST}",
	    nonce    => $env->{'plack.nonce'},
	    agent_id => $agent,
	    contexts => $contexts
	    );

	$res->body( $template->output );

	return $res->finalize;
    }
}

sub users {
    my $env    = shift;
    my $req    = Plack::Request->new( $env );
    my $method = $req->method;
    my $res    = Plack::Response->new( 200 );

    $res->content_type( 'text/html' );

    my $session = $env->{'psgix.session'};

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die "Couldn't connect to database: $DBI::errstr";

    if ( $method eq 'POST' ) {
	my $params = $req->parameters;

	$params->{totp_enabled} = $params->{totp_enabled} ? 1 : 0;
	$params->{is_admin}     = $params->{is_admin}     ? 1 : 0;

	if ( $params->{action} eq 'create' ) {
	    my $sql = "INSERT INTO ai_users (username, password, first_name, last_name, email, phone_number, totp_secret, totp_enabled, is_admin) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

	    my $gen = new Authen::TOTP( secret => $ENV{TOTP_SECRET} );

	    my $salt = substr(generate_nonce(), 0, 16);

	    my $bcrypt_hash = bcrypt( $params->{password}, '2b', 12, $salt );

	    my $secret = $gen->secret();

	    my $uri = $gen->generate_otp(user => $params->{email} , issuer => "signalwire.me");

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{username}, $bcrypt_hash, $params->{first_name}, $params->{last_name}, $params->{email}, $params->{phone_number}, $secret, $params->{totp_enabled}, $params->{is_admin} )
		or die "Couldn't execute statement: $DBI::errstr\n";

	    $sth->finish;
	} elsif ( $params->{action} eq 'add' ) {
	    my $template = HTML::Template::Expr->new( filename => "/app/template/create_user.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav      => $session->{is_admin} ? @nav : @user_nav,
		url      => "https://$env->{HTTP_HOST}",
		nonce    => $env->{'plack.nonce'}
		);

	    $res->body( $template->output );

	    return $res->finalize;
	} elsif ( $params->{action} eq 'update' ) {
	    my $sql;

	    if ( $params->{password} ) {
		$sql = "UPDATE ai_users SET username = ?, password = ?, first_name = ?, last_name = ?, email = ?, phone_number = ?, totp_enabled = ?, is_admin = ? WHERE id = ?";
	    } else {
		$sql = "UPDATE ai_users SET username = ?, first_name = ?, last_name = ?, email = ?, phone_number = ?, totp_enabled = ?, is_admin = ? WHERE id = ?";
	    }

	    my $sth = $dbh->prepare( $sql );

	    if ( $params->{password} ) {
		my $salt = substr(generate_nonce(), 0, 16);

		my $bcrypt_hash = bcrypt( $params->{password}, '2b', 12, $salt );

		$sth->execute( $params->{username}, $bcrypt_hash, $params->{first_name}, $params->{last_name}, $params->{email}, $params->{phone_number}, $params->{totp_enabled}, $params->{is_admin}, $params->{id} )
		    or die "Couldn't execute statement: $DBI::errstr\n";
	    } else {
		$sth->execute( $params->{username}, $params->{first_name}, $params->{last_name}, $params->{email}, $params->{phone_number}, $params->{totp_enabled}, $params->{is_admin}, $params->{id} )
		    or die "Couldn't execute statement: $DBI::errstr\n";
	    }

	    $sth->finish;
	} elsif ( $params->{action} eq 'delete' ) {
	    my $sql = "DELETE FROM ai_users WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die "Couldn't execute statement: $DBI::errstr\n";

	    $sth->finish;
	} elsif ( $params->{action} eq 'edit' ) {
	    my $sql = "SELECT * FROM ai_users WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die "Couldn't execute statement: $DBI::errstr\n";

	    my $user = $sth->fetchrow_hashref;

	    $user->{is_admin_checked}     = $user->{is_admin} ? 'checked' : '';
	    $user->{totp_enabled_checked} = $user->{totp_enabled} ? 'checked' : '';

	    my $template = HTML::Template::Expr->new( filename => "/app/template/edit_user.tmpl", die_on_bad_params => 0 );

	    delete $user->{password};

	    $template->param(
		nav      => $session->{is_admin} ? @nav : @user_nav,
		url      => "https://$env->{HTTP_HOST}",
		nonce    => $env->{'plack.nonce'},
		);

	    $template->param( %$user );

	    $res->body( $template->output );

	    return $res->finalize;
	} elsif ( $params->{action} eq 'update' ) {
	    my $sql = "UPDATE ai_users SET username = ?, password = ?, first_name = ?, last_name = ?, email = ?, phone_number = ?, totp_enabled = ?, is_admin = ? WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{username}, $params->{password}, $params->{first_name}, $params->{last_name}, $params->{email}, $params->{phone_number}, $params->{totp_enabled}, $params->{is_admin}, $params->{id} )
		or die "Couldn't execute statement: $DBI::errstr\n";

	    $sth->finish;
	} elsif ( $params->{action} eq 'delete' ) {
	    my $sql = "DELETE FROM ai_users WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die "Couldn't execute statement: $DBI::errstr\n";

	    $sth->finish;
	}

	my $res = Plack::Response->new( 302 );

	$res->redirect( "/users" );
    }

    my $sql = "SELECT * FROM ai_users ORDER BY created DESC";

    my $sth = $dbh->prepare( $sql );

    $sth->execute() or die "Couldn't execute statement: $DBI::errstr\n";

    my $users = $sth->fetchall_arrayref({});

    my $template = HTML::Template::Expr->new( filename => "/app/template/users.tmpl", die_on_bad_params => 0 );

    $template->param(
	nav      => $session->{is_admin} ? @nav : @user_nav,
	url      => "https://$env->{HTTP_HOST}",
	nonce    => $env->{'plack.nonce'},
	users    => $users
	);

    $res->body( $template->output );

     return $res->finalize;
}

sub debug {
    my $env   = shift;
    my $req   = Plack::Request->new( $env );
    my $agent = $req->param( 'agent_id' );
    my $res   = Plack::Response->new( 200 );

    $res->content_type( 'text/html' );

    my $template = HTML::Template::Expr->new( filename => "/app/template/debug.tmpl", die_on_bad_params => 0 );

    $template->param(
	nav      => @nav,
	nonce    => $env->{'plack.nonce'},
	wss      => "wss://$env->{HTTP_HOST}/websocket",
	url      => "https://$env->{HTTP_HOST}",
	agent_id => $agent
	);

    $res->body( $template->output );

    return $res->finalize;
}

my $debug_app = sub {
    my $env       = shift;
    my $req       = Plack::Request->new( $env );
    my $swml      = SignalWire::ML->new;
    my $post_data = decode_json( $req->raw_body );
    my $agent     = $req->param( 'agent_id' );
    my $res       = Plack::Response->new( 200 );

    $res->content_type( 'application/json' );

    $res->body( $swml->swaig_response_json( { response => "data received" } ) );

    broadcast_by_agent_id( $agent, $post_data );

    return $res->finalize;
};

my $post_app = sub {
    my $env       = shift;
    my $req       = Plack::Request->new( $env );
    my $agent     = $req->param( 'agent_id' );
    my $post_data = decode_json( $req->raw_body );
    my $swml      = SignalWire::ML->new;
    my $raw       = $post_data->{post_prompt_data}->{raw};
    my $data      = $post_data->{post_prompt_data}->{parsed}->[0];
    my $recording = $post_data->{SWMLVars}->{record_call_url};
    my $from      = $post_data->{SWMLVars}->{from};
    my $json      = JSON::PP->new->ascii->allow_nonref;
    my $action    = $post_data->{action};
    my $convo_id  = $post_data->{conversation_id};
    my $convo_sum = $post_data->{conversation_summary};

    broadcast_by_agent_id( $agent, $post_data );

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die "Couldn't connect to database: $DBI::errstr";

    if ( $action eq "fetch_conversation" && defined $convo_id ) {
	my @summary;

	my $fetch_sql = "SELECT created,summary FROM ai_summary WHERE convo_id = ? AND agent_id = ? AND created >= CURRENT_TIMESTAMP - INTERVAL '4 hours'";

	my $fsth = $dbh->prepare( $fetch_sql );

	$fsth->execute( $convo_id, $agent ) or die "Couldn't execute statement: $DBI::errstr";

	while ( my $row = $fsth->fetchrow_hashref ) {
	    push @summary, "$row->{created} - $row->{summary}";
	}

	my $res = Plack::Response->new( 200 );

	$res->content_type( 'application/json' );

	if ( @summary == 0 ) {
	    $res->body( $swml->swaig_response_json( { response => "co conversation found" } ) );
	} else {
	    $res->body( $swml->swaig_response_json( { response => "conversation found" , conversation_summary => join("\n", @summary) } ) );
	}

	foreach my $summary ( @summary ) {
	    broadcast_by_agent_id( $agent, { conversation_summary => $summary } );
	}

	$dbh->disconnect;

	return $res->finalize;
    } else {
	my %config;

	tie %config, 'MyTieConfig',
	    host     => $host,
	    port     => $port,
	    dbname   => $database,
	    user     => $dbusername,
	    password => $dbpassword,
	    table    => 'ai_config',
	    agent_id => $agent;

	if ( !$config{SAVE_BLANK_CONVERSATIONS} && $post_data->{post_prompt_data}->{raw} =~ m/no\sconversation\stook\splace/g ) {
	    my $res = Plack::Response->new( 200 );

	    $res->content_type( 'application/json' );

	    $res->body( $swml->swaig_response_json( { response => "data ignored" } ) );

	    $dbh->disconnect;

	    untie %config;

	    broadcast_by_agent_id( $agent, 'Blank conversation ignored' );

	    return $res->finalize;
	}

	if ( defined $convo_id && defined $convo_sum ) {
	    my $convo_sql = "INSERT INTO ai_summary (created, convo_id, summary, agent_id) VALUES (CURRENT_TIMESTAMP, ?, ?, ?)";

	    my $csth = $dbh->prepare( $convo_sql );

	    $csth->execute( $convo_id, $convo_sum, $agent ) or die "Couldn't execute statement: $DBI::errstr";

	    broadcast_by_agent_id( $agent, { conversation_summary => $convo_sum } );
	}

	my $insert_sql = "INSERT INTO ai_post_prompt (created, data, agent_id) VALUES (CURRENT_TIMESTAMP, ?, ?)";

	my $json_data = $req->raw_body;

	my $sth = $dbh->prepare( $insert_sql );

	$sth->execute( $json_data, $agent ) or die "Couldn't execute statement: $DBI::errstr";

	my $last_insert_id = $dbh->last_insert_id( undef, undef, 'ai_post_prompt', 'id' );

	broadcast_by_agent_id( $agent, { post_prompt_data => $post_data } );

	$dbh->disconnect;

	if ( $config{ENABLE_SLACK_NOTIFICATION} && $config{SLACK_WEBHOOK_URL} && $config{SLACK_CHANNEL} && $config{SLACK_USERNAME} ) {
	    my $ua = LWP::UserAgent->new;

	    $ua->timeout( 5 );
	    $ua->agent('SignalWire-AI-Agent/1.0');

	    my $slack = POST("$config{SLACK_WEBHOOK_URL}",
			     'Content-Type' => 'application/json',
			     'Content' =>
			     $json->encode({
				 text => ":signalwire: :new: New Conversation https://$env->{HTTP_HOST}/agent?id=$last_insert_id&agent_id=$agent -> $raw",
				 channel => "$config{SLACK_CHANNEL}",
				 username => "$config{SLACK_USERNAME}",
				 icon_emoji => ":robot_face:"
					   })
		);

	    $ua->request( $slack );
	    broadcast_by_agent_id( $agent, 'Slack notification sent' );
	}

	if ( $config{ENABLE_ZENDESK_TICKET} && $config{ZENDESK_API_KEY} && $config{ZENDESK_SUBDOMAIN} ) {
	    my $ua = LWP::UserAgent->new;

	    $ua->timeout( 5 );
	    $ua->agent('SignalWire-AI-Agent/1.0');

	    my $ticket = POST("https://$config{ZENDESK_SUBDOMAIN}.zendesk.com/api/v2/tickets.json",
			      'Content-Type' => 'application/json',
			      'Authorization' => "$config{ZENDESK_API_KEY}",
			      'Content' =>
			      $json->encode({
				  ticket => {
				      comment => {
					  body => "https://$env->{HTTP_HOST}/agent?id=$last_insert_id&agent_id=$agent\n\n$raw"
				      },
				      priority => "normal",
				      subject => "Call Disposition - $from",
				  }})
		);

	    $ua->request( $ticket );
	    broadcast_by_agent_id( $agent, 'Zendesk ticket created' );
	}

	if ( $config{SEND_SUMMARY_MESSAGE} && $config{CUSTODIAN_SMS} ) {
	    my $response;

	    my $sw = SignalWire::RestAPI->new(
		AccountSid  => $config{ACCOUNT_SID},
		AuthToken   => $config{AUTH_TOKEN},
		Space       => $config{SPACE_NAME},
		);

	    my @assistants = split( /\|/, $config{CUSTODIAN_SMS} );

	    foreach my $number ( @assistants ) {
		$response = $sw->POST( 'Messages',
				       From     => $config{ASSISTANT},
				       To       => $number,
				       Body     => $raw,
				       ( $recording ? ( MediaUrl => $recording ) : ())
		    );
		print STDERR "Response: " . Dumper( $response ) . "\n" if $ENV{DEBUG};
	    }
	}

	my $res = Plack::Response->new( 200 );

	$res->content_type( 'application/json' );

	$res->body( $swml->swaig_response_json( { response => 'data received' } ) );

	untie %config;

	broadcast_by_agent_id( $agent, 'Message Summary Sent' );

	return $res->finalize;
    }
};

# This is the WebSocket entry point
my $websocket_app = sub {
    my $env = shift;

    my $websocket = Plack::App::WebSocket->new(
	on_establish => sub {
	    my $conn = shift;

	    # Assign UUID to each connection
	    my $uuid = uuid();
	    $clients{$uuid} = $conn;

	    $conn->on(
		message => sub {
		    my ( $conn, $msg ) = @_;

		    print STDERR "Subscriptions: " . Dumper( \%subscriptions ) . "\n" if $ENV{DEBUG};
		    print STDERR "Number of Clients: " . scalar( keys %clients ) . "\n" if $ENV{DEBUG};

		    print STDERR "Received message: $msg\n" if $ENV{DEBUG};

		    if ( $msg eq 'ping' ) {
			print STDERR "Received ping\n" if $ENV{DEBUG};
		    }

		    my $data = eval { decode_json( $msg ) };

		    return if $@; # Handle invalid JSON

		    if ( $data->{type} && $data->{type} eq 'subscribe' && $data->{agent_id} ) {
			$subscriptions{$data->{agent_id}} //= [];

			push @{$subscriptions{$data->{agent_id}}}, $uuid;
		    }

		    if ( $data->{message} && $data->{agent_id} ) {
			my $agent_id = $data->{agent_id};
			my $message  = $data->{message};

			if ( $message =~ m/^env$/i ) {
			    $data->{env} = \%ENV;
			}
		    }

		    $clients{$uuid}->send( encode_json( { uuid => $uuid, message => $data } ) );
		});

	    my $ping_timer;

	    $ping_timer = AnyEvent->timer(
		after    => 0,
		interval => 30,
		cb       => sub {
		    return unless $clients{$uuid};

		    eval { $conn->send( 'ping' ) };

		    if ( $@ ) {
			undef $ping_timer;
		    }
		});

	    $conn->on(
		finish => sub {
		    print STDERR "Connection closed $uuid\n" if $ENV{DEBUG};
		    foreach my $agent_id ( keys %subscriptions ) {
			@{$subscriptions{$agent_id}} = grep { $_ ne $uuid } @{$subscriptions{$agent_id}};

			delete $subscriptions{$agent_id} if scalar @{$subscriptions{$agent_id}} == 0;

			print STDERR "Deleted subscrption $uuid from Agent: $agent_id\n" if $ENV{DEBUG};
		    }

		    delete $clients{$uuid};

		    print STDERR "Deleted client $uuid\n" if $ENV{DEBUG};

		    undef $ping_timer;
		});
	});

    return $websocket->call( $env );
};

# This is the Asset entry point for the application
my $assets_app = Plack::App::Directory->new( root => "/app/assets" )->to_app;

# This is the HTTP entry point for the application
my $web_app = sub {
    my $env     = shift;
    my $req     = Plack::Request->new( $env );
    my $swml    = SignalWire::ML->new;
    my $agent   = $req->param( 'agent_id' );
    my $path    = $req->path_info;
    my $method  = $req->method;

    my $session = $env->{'psgix.session'};

    print STDERR "Path: $path\n" if $ENV{DEBUG};
    print STDERR "Method: $method\n" if $ENV{DEBUG};
    print STDERR "Agent: $agent\n" if $agent && $ENV{DEBUG};

    if ( $path eq '/login' ) {
	my $res = Plack::Response->new( 200 );

	$res->content_type( 'text/html' );

	if ( $method eq 'POST' ) {
	    my $username = $req->param( 'username' );
	    my $password = $req->param( 'password' );

	    my $dbh = DBI->connect(
		"dbi:Pg:dbname=$database;host=$host;port=$port",
		$dbusername,
		$dbpassword,
		{ AutoCommit => 1, RaiseError => 1 } ) or die "Couldn't connect to database: $DBI::errstr";

	    my $stored_bcrypt_hash = $dbh->selectrow_array( "SELECT password FROM ai_users WHERE username = ?", undef, $username );

	    if ( $stored_bcrypt_hash && bcrypt_check( $password, $stored_bcrypt_hash ) ) {
		$session->{logged_in} = 1;

		my $admin   = $dbh->selectrow_array( "SELECT is_admin FROM ai_users WHERE username = ?", undef, $username );

		my $totp    = $dbh->selectrow_array( "SELECT totp_enabled FROM ai_users WHERE username = ?", undef, $username );

		my $user_id = $dbh->selectrow_array( "SELECT id FROM ai_users WHERE username = ?", undef, $username );

		$dbh->disconnect;

		$session->{is_admin}     = $admin;
		$session->{totp_enabled} = $totp;
		$session->{username}     = $username;
		$session->{user_id}      = $user_id;

		$res->redirect( "/" );

	    } else {
		$res->redirect( "/login?error=1" );
	    }
	} else {
	    if ( $session->{logged_in} ) {
		$res->redirect( "/" );
	    } else {
		my $error = $req->param( 'error' ) || 0;

		my $template = HTML::Template::Expr->new( filename => '/app/template/login.tmpl', die_on_bad_params => 0 );

		$template->param(
		    error    => $error,
		    nonce    => $env->{'plack.nonce'},
		    );

		$res->body( $template->output );
	    }
	}

	return $res->finalize;
    } elsif ( $session->{logged_in} ) {
	if ( exists $dispatch{$method} && exists $dispatch{$method}{$path} ) {
	    return $dispatch{$method}{$path}->( $env );
	} else {
	    my $res = Plack::Response->new( 200 );

	    $res->content_type( 'text/html' );

	    $res->redirect( "/logout" );

	    return $res->finalize;
	}
    } else {
	my $res = Plack::Response->new( 200 );

	$res->content_type( 'text/html' );

	$res->redirect( '/login' );

	return $res->finalize;
    }
};

my $logout_app = sub {
	my $env     = shift;
	my $session = $env->{'psgix.session'};

	$session->{logged_in} = 0;

	$session->{is_admin}  = 0;

	$session->{totp_enabled} = 0;

	$session->{redirected} = 0;

	delete $session->{username};

	my $res = Plack::Response->new( 200 );

	$res->content_type( 'text/html' );

	$res->redirect( '/login' );

	return $res->finalize;
};

sub authenticator {
    my ( $ausername, $apassword, $env ) = @_;
    my $req    = Plack::Request->new( $env );
    my $method = $req->method;
    my $agent  = $req->param( 'agent_id' );

    my %config;

    tie %config, 'MyTieConfig',
	host     => $host,
	port     => $port,
	dbname   => $database,
	user     => $dbusername,
	password => $dbpassword,
	table    => 'ai_config',
	agent_id => $agent;

    my $susername = $config{AUTH_USERNAME};
    my $spassword = $config{AUTH_PASSWORD};

    untie %config;

    return $ausername eq $susername && $apassword eq $spassword
}

my $server = builder {
#    enable "Debug";
    enable "Session", store => Plack::Session::Store::DBI->new(
	get_dbh => sub {
	    my $dbh = DBI->connect(
		"dbi:Pg:dbname=$database;host=$host;port=$port",
		$dbusername,
		$dbpassword,
		{ AutoCommit => 1, RaiseError => 1 } ) or die "Couldn't connect to database: $DBI::errstr";
	}
	);

    mount "/swml" => builder {
	enable "Auth::Basic", authenticator => \&authenticator;
	$swml_app;
    };

    mount "/swaig" => builder {
	enable "Auth::Basic", authenticator => \&authenticator;
	$swaig_app;
    };

    mount "/laml" => builder {
	enable "Auth::Basic", authenticator => \&authenticator;
	$laml_app;
    };

    mount "/post" => builder {
	enable "Auth::Basic", authenticator => \&authenticator;
	$post_app;
    };

    mount "/debughook" => builder {
	enable "Auth::Basic", authenticator => \&authenticator;
	$debug_app;
    };

    mount "/websocket" => $websocket_app;

    enable sub {
	my $app = shift;

	return sub {
	    my $env     = shift;
	    my $nonce   = generate_nonce();
	    my $wss     = "wss://$env->{HTTP_HOST}";
	    my $session = $env->{'psgix.session'};

	    $env->{'plack.nonce'} = $nonce;

	    my $res     = $app->( $env );

	    if ( $env->{PATH_INFO} ) {
		Plack::Util::header_set( $res->[1], 'Expires', 0 );
		Plack::Util::header_set(
		    $res->[1],
		    'Content-Security-Policy',
		    "default-src 'none'; script-src 'nonce-$nonce' 'strict-dynamic' 'unsafe-inline' https: cdn.jsdelivr.net; connect-src 'self' $wss https:; img-src 'self' data:; style-src 'self' 'unsafe-inline'; base-uri 'self'; media-src 'self' files.swire.io files.signalwire.com;"
		    );
	    }

	    return $res;
	};
    };

    mount "/assets"    => $assets_app;
    mount "/logout"    => $logout_app;

    mount '/' => $web_app;
};

my $dbh = DBI->connect(
    "dbi:Pg:dbname=$database;host=$host;port=$port",
    $dbusername,
    $dbpassword,
    { AutoCommit => 1, RaiseError => 1 } ) or die "Couldn't execute statement: $DBI::errstr\n";

foreach my $table ( keys %{$data_sql} ) {
    print STDERR "Checking for table $table\n" if $ENV{DEBUG};
    my $sql = $data_sql->{$table}->{create};
    print STDERR "Creating table $sql\n" if $ENV{DEBUG};
    $dbh->do( $sql ) or die "Couldn't execute statement: $DBI::errstr\n";
}

$dbh->disconnect;

# Running the PSGI application
my $runner = Plack::Runner->new;

if ( $ENV{PLACK_DEV} ) {
    $runner->parse_options( '-s', 'Twiggy', '-p', 9080 );
} else {
    $runner->parse_options( '-s', 'Twiggy' );
}

$runner->run( $server );

1;
