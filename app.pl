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
use URI::Escape qw(uri_escape);
use List::Util qw(any);
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
	create => qq( CREATE TABLE IF NOT EXISTS ai_agent ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, name TEXT, description TEXT, phone_number VARCHAR(20), user_id INTEGER, CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES ai_users (id) ) )
    },
    ai_config => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_config ( id SERIAL PRIMARY KEY, name VARCHAR(255) NOT NULL, value TEXT NOT NULL, agent_id INTEGER NOT NULL, CONSTRAINT fk_agent FOREIGN KEY (agent_id) REFERENCES ai_agent (id) ON DELETE CASCADE ) )
    },
    ai_context => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_context ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, agent_id INTEGER REFERENCES ai_agent(id) ON DELETE CASCADE, name TEXT, pattern TEXT, toggle_function TEXT, consolidate BOOLEAN DEFAULT FALSE, full_reset BOOLEAN DEFAULT FALSE, user_prompt TEXT, system_prompt TEXT ) )
    },
    ai_function => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_function ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, agent_id INTEGER REFERENCES ai_agent(id) ON DELETE CASCADE, name TEXT, purpose TEXT, code TEXT, active BOOLEAN DEFAULT TRUE ) )
    },
    ai_function_argument => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_function_argument ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, function_id INTEGER REFERENCES ai_function(id) ON DELETE CASCADE, agent_id INTEGER REFERENCES ai_agent(id) ON DELETE CASCADE, name TEXT NOT NULL, type TEXT DEFAULT 'string',  description TEXT, active BOOLEAN DEFAULT TRUE, required BOOLEAN DEFAULT FALSE, UNIQUE (agent_id, function_id, name) ) )
    },
    ai_hints => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_hints ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, hint TEXT, agent_id INTEGER REFERENCES ai_agent(id) ON DELETE CASCADE ) )
    },
    ai_language => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_language ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, agent_id INTEGER REFERENCES ai_agent(id) ON DELETE CASCADE, code TEXT, name TEXT, voice TEXT, engine TEXT, fillers TEXT, language_order INTEGER NOT NULL DEFAULT 0 ) )
    },
    ai_messages => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_messages ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, call_id TEXT, convo_id TEXT, message TEXT, replied BOOLEAN DEFAULT FALSE, agent_id INTEGER REFERENCES ai_agent(id) ON DELETE CASCADE ) )
    },
    ai_post_prompt => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_post_prompt ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, data JSONB, agent_id INTEGER REFERENCES ai_agent(id) ON DELETE CASCADE ) )
    },
    ai_prompt => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_prompt ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, prompt TEXT, post_prompt TEXT, agent_id INTEGER REFERENCES ai_agent(id) ON DELETE CASCADE, UNIQUE(agent_id) ) )
    },
    ai_pronounce => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_pronounce ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, ignore_case BOOLEAN DEFAULT FALSE, replace_this TEXT, replace_with TEXT, agent_id INTEGER REFERENCES ai_agent(id) ON DELETE CASCADE ) )
    },
    ai_summary => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_summary ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, convo_id TEXT, summary TEXT, agent_id INTEGER REFERENCES ai_agent(id) ON DELETE CASCADE ) )
    },
    ai_features => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_features ( id SERIAL PRIMARY KEY, created TIMESTAMP NOT NULL, description TEXT, code TEXT ) )
    },
    ai_feature_toggles => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_feature_toggles ( id SERIAL PRIMARY KEY, toggle TEXT NOT NULL UNIQUE, description TEXT, toggle_order INT NOT NULL DEFAULT 0, feature_id INTEGER REFERENCES ai_features(id) ON DELETE CASCADE ) ) 
    },	
    ai_feature_strings => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_feature_strings ( id SERIAL PRIMARY KEY, string TEXT NOT NULL UNIQUE, description TEXT, string_order INT NOT NULL DEFAULT 0, required BOOLEAN NOT NULL, feature_id INTEGER REFERENCES ai_features(id) ON DELETE CASCADE ) ) 
    },
    ai_users => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_users ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, username VARCHAR(255) UNIQUE NOT NULL, password VARCHAR(255) NOT NULL, first_name VARCHAR(255), last_name VARCHAR(255), email VARCHAR(255) UNIQUE, phone_number VARCHAR(20), totp_secret VARCHAR(255), totp_enabled BOOLEAN DEFAULT false, is_admin BOOLEAN DEFAULT false, is_viewer BOOLEAN DEFAULT false ) )
    },
    ai_user_roles => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_user_roles ( id SERIAL PRIMARY KEY, user_id INT NOT NULL, name VARCHAR(255) NOT NULL, description VARCHAR(255) NOT NULL, FOREIGN KEY (user_id) REFERENCES ai_users(id) ON DELETE CASCADE, CONSTRAINT unique_user_role_name UNIQUE (user_id, name) ) )
    },
    ai_password_reset => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_password_reset ( id SERIAL PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, user_id INTEGER REFERENCES ai_users(id) ON DELETE CASCADE, token VARCHAR(255) NOT NULL ) )
    },
    ai_steps => {
	create => qq( CREATE TABLE IF NOT EXISTS ai_steps ( id SERIAL PRIMARY KEY, ai_step_pattern TEXT NOT NULL, toggle_function TEXT, custom_action TEXT, ai_step_response TEXT NOT NULL, ai_step_b2b_functions BOOLEAN NOT NULL, agent_id INTEGER REFERENCES ai_agent(id) ON DELETE CASCADE ) )
    },
    default_admin_user => {
	create => qq( INSERT INTO ai_users (username, password, first_name, last_name, email, phone_number, totp_enabled, is_admin, is_viewer) VALUES ('admin', '\$2b\$12\$bCbkTUnxSiHDPCfDWUWzP.1qPZKVPWI59Tnzry0AcuKX7e5tmF6pu', 'Admin', 'User', 'admin\@example.com', '+10000000000', false, true, false) ON CONFLICT (username) DO NOTHING )
    }
};

my %role_names = (
    admin_view          => "Admin View",
    admin_delete        => "Admin Delete",
    admin_create        => "Admin Create",
    admin_update        => "Admin Update",
    user_view           => "User View",
    user_delete         => "User Delete",
    user_create         => "User Create",
    user_update         => "User Update",
    view_agent          => "View Agent",
    view_config         => "View Config",
    update_config       => "Update Config",
    view_prompt         => "View Prompt",
    update_prompt       => "Update Prompt",
    view_agents         => "View Agents",
    delete_agents       => "Delete Agents",
    create_agents       => "Create Agents",
    update_agents       => "Update Agents",
    view_hints          => "View Hints",
    delete_hints        => "Delete Hints",
    create_hints        => "Create Hints",
    update_hints        => "Update Hints",
    view_languages      => "View Languages",
    delete_languages    => "Delete Languages",
    create_languages    => "Create Languages",
    update_languages    => "Update Languages",
    view_step           => "View Step",
    delete_step         => "Delete Step",
    create_step         => "Create Step",
    update_step         => "Update Step",
    view_pronounce      => "View Pronounce",
    delete_pronounce    => "Delete Pronounce",
    create_pronounce    => "Create Pronounce",
    update_pronounce    => "Update Pronounce",
    view_functions      => "View Functions",
    delete_functions    => "Delete Functions",
    create_functions    => "Create Functions",
    update_functions    => "Update Functions",
    view_functionargs   => "View FunctionArgs",
    delete_functionargs => "Delete FunctionArgs",
    create_functionargs => "Create FunctionArgs",
    update_functionargs => "Update FunctionArgs",
    view_contexts       => "View Contexts",
    delete_contexts     => "Delete Contexts",
    create_contexts     => "Create Contexts",
    update_contexts     => "Update Contexts",
    view_features       => "View Features",
    delete_features     => "Delete Features",
    create_features     => "Create Features",
    update_features     => "Update Features",
    view_feature_toggles   => "View Feature Toggles",
    delete_feature_toggles => "Delete Feature Toggles",
    create_feature_toggles => "Create Feature Toggles",
    update_feature_toggles => "Update Feature Toggles",
    view_feature_strings   => "View Feature Strings",
    delete_feature_strings => "Delete Feature Strings",
    create_feature_strings => "Create Feature Strings",
    update_feature_strings => "Update Feature Strings",
    view_users          => "View Users",
    delete_users        => "Delete Users",
    create_users        => "Create Users",
    update_users        => "Update Users",
    view_summary        => "View Summary",
    delete_summary      => "Delete Summary",
    view_messages       => "View Messages",
    delete_messages     => "Delete Messages",
    view_debug          => "View Debug"
    );

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
	'/'             => \&agents,
	'/agent'        => \&agent,
	'/config'       => \&config,
	'/prompt'       => \&prompt,
	'/summary'      => \&summary,
	'/messages'     => \&messages,
	'/context'      => \&context,
	'/step'         => \&step,
	'/feature'      => \&feature,
	'/featuretoggles' => \&featuretoggles,,
	'/featurestrings' => \&featurestrings,
	'/function'     => \&function,
	'/functionargs' => \&functionargs,
	'/language'     => \&language,
	'/pronounce'    => \&pronounce,
	'/hints'        => \&hints,
	'/users'        => \&users,
	'/debug'        => \&debug,
	'/totp'         => \&totp,
	'/roles'        => \&roles,
    },
    'POST' => {
	'/'             => \&agents,
	'/agent'        => \&agent,
	'/config'       => \&config,
	'/prompt'       => \&prompt,
	'/summary'      => \&summary,
	'/messages'     => \&messages,
	'/context'      => \&context,
	'/step'         => \&step,
	'/featuretoggles' => \&featuretoggles,,
	'/featurestrings' => \&featurestrings,
	'/feature'      => \&feature,
	'/function'     => \&function,
	'/functionargs' => \&functionargs,
	'/language'     => \&language,
	'/pronounce'    => \&pronounce,
	'/hints'        => \&hints,
	'/users'        => \&users,
	'/post'         => \&post,
	'/totp'         => \&totp,
	'/roles'        => \&roles,
    }
    );

# Admin Navigation bar
my @nav = [
    { path => '/',          name => 'Home',          table => "ai_agent"        },
    { path => '/agent',     name => 'Conversations', table => "ai_conversation" },
    { path => '/config',    name => 'Configuration', table => "ai_config"       },
    { path => '/prompt',    name => 'Prompt',        table => "ai_prompt"       },
    { path => '/summary',   name => 'Summary',       table => "ai_summary"      },
    { path => '/context',   name => 'Contexts',      table => "ai_context"      },
    { path => '/step',      name => 'Steps',         table => "ai_step"         },
    { path => '/function',  name => 'Functions',     table => "ai_function"     },
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
    { path => '/feature',  name => 'Features'      },
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
	{ AutoCommit => 1, RaiseError => 1 }) or die $DBI::errstr;

    my $select_sql = "SELECT * FROM ai_messages WHERE convo_id = ? AND replied = false AND agent_id = ? ORDER BY id ASC";

    my $sth = $dbh->prepare( $select_sql );

    $sth->execute( $convo_id, $agent ) or die $DBI::errstr;

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

sub generate_random_string {
    my $length = shift // 16;
    my @chars = ('0'..'9', 'A'..'Z', 'a'..'z');
    my $random_string;
    foreach (1..$length) {
	$random_string .= $chars[rand @chars];
    }
    return $random_string;
}


# PSGI application code
my $reset_app = sub {
    my $env     = shift;
    my $error   = shift;
    my $req     = Plack::Request->new( $env );
    my $params  = $req->parameters;

    my $res = Plack::Response->new( 200 );

    $res->content_type( 'text/html' );

    my $template = HTML::Template::Expr->new( filename => "/app/template/reset.tmpl", die_on_bad_params => 0 );

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 }) or die $DBI::errstr;

    if ( $req->method eq 'POST' ) {
	if ($params->{action} eq 'doreset' && $params->{token} && ( $params->{password} eq $params->{password2} ) ) {
	    my $sql = "SELECT au.*, pr.token AS password_reset_token, pr.created AS password_reset_created FROM ai_users au LEFT JOIN ai_password_reset pr ON au.id = pr.user_id WHERE au.username = ? AND pr.token = ?  AND pr.created > NOW() - INTERVAL '15 minutes'";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{username}, $params->{token} );

	    my $row = $sth->fetchrow_hashref;

	    $sth->finish;

	    if ( $row ) {
		my $salt = substr(generate_nonce(), 0, 16);

		my $bcrypt_hash = bcrypt( $params->{password}, '2b', 12, $salt );

		my $update_sql = "UPDATE ai_users SET password = ?, totp_secret = null, totp_enabled = false WHERE id = ?";

		my $usth = $dbh->prepare( $update_sql );

		$usth->execute( $bcrypt_hash, $row->{id} ) or die $DBI::errstr;

		$usth->finish;

		my $delete_sql = "DELETE FROM ai_password_reset WHERE user_id = ?";

		my $dth = $dbh->prepare( $delete_sql );

		$dth->execute( $row->{id} ) or die $DBI::errstr;

		$dth->finish;

		my $sw = SignalWire::RestAPI->new(
		    AccountSid  => $ENV{ACCOUNT_SID},
		    AuthToken   => $ENV{AUTH_TOKEN},
		    Space       => $ENV{SPACE_NAME},
		    );

		my $response = $sw->POST( 'Messages',
					  From     => $ENV{FROM_NUMBER},
					  To       => $row->{phone_number},
					  Body     => "Your password was reset and TOTP disabled.  If you did not request this, please contact support immediately."
		    );

		print STDERR Dumper( $response ) if ! $response->{is_success};

		$template->param( message => "Password reset", success => 1 );
	    } else {
		$template->param( message => "Password failed" );
	    }

	} else {
	    my $sql = "SELECT * FROM ai_users WHERE username = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{username} ) or die $DBI::errstr;

	    my $row = $sth->fetchrow_hashref;

	    $sth->finish;

	    if ( $row ) {
		my $token = generate_random_string( 32 );

		my $sw = SignalWire::RestAPI->new(
		    AccountSid  => $ENV{ACCOUNT_SID},
		    AuthToken   => $ENV{AUTH_TOKEN},
		    Space       => $ENV{SPACE_NAME},
		    );

		my $response = $sw->POST( 'Messages',
					  From     => $ENV{FROM_NUMBER},
					  To       => $row->{phone_number},
					  Body     => "Your password reset link is https://$env->{HTTP_HOST}/reset?token=$token"
		    );
		print STDERR Dumper( $response ) if ! $response->{is_success};


		my $token_sql = "INSERT INTO ai_password_reset (user_id, token) VALUES (?, ?)";

		my $token_sth = $dbh->prepare( $token_sql );

		$token_sth->execute( $row->{id}, $token ) or die $DBI::errstr;

		$token_sth->finish;

		$template->param( message => "A reset link was sent to the phone number on file" );
	    } else {
		$template->param( message => "A reset link was sent to the phone number on file" );
	    }
	}
    } else {
	if ( $params->{token} ) {
	    my $sql = "SELECT au.*, pr.token AS password_reset_token, pr.created AS password_reset_created FROM ai_users au LEFT JOIN ai_password_reset pr ON au.id = pr.user_id WHERE pr.token = ?  AND pr.created > NOW() - INTERVAL '15 minutes'";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{token} ) or die $DBI::errstr;

	    my $row = $sth->fetchrow_hashref;

	    $sth->finish;

	    if ( $row ) {
		$template->param( reset => 1, token => $params->{token}, username => $row->{username} );
	    } else {
		$template->param( message => "The token has expired or is invalid" );
	    }
	} else {
	    $template->param( gettoken => 1, message => "Enter your username to reset your password" );
	}
    }
    $dbh->disconnect;

    $res->body( $template->output );

    return $res->finalize;
};

sub check_role {
    my $session = shift;
    my $role    = shift;
    my $roles   = $session->{roles};

    my @roles_to_check = split /,/, $role;

    if (any { my $y = $_; any { $y->{name} eq $_ } @roles_to_check } @$roles) {
	return 1;
    }
    return 0;
}

sub roles {
    my $env      = shift;
    my $req      = Plack::Request->new( $env );
    my $params   = $req->parameters;
    my $user_id  = $params->{user_id};
    my $username = $params->{username};
    my $json     = JSON::PP->new->ascii->pretty->allow_nonref;
    my $session  = $env->{'psgix.session'};

    my $res = Plack::Response->new( 200 );

    $res->content_type( 'text/html' );

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die $DBI::errstr;

    if ( $req->method eq 'POST' && check_role( $session ,'admin_update' ) ) {
	if ( $params->{action} eq 'add' ) {
	    my $sql = "INSERT INTO ai_user_roles (name, description, user_id) VALUES (?, ?, ?)";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{name}, $role_names{$params->{name}}, $params->{user_id} ) or die $DBI::errstr;

	    $sth->finish;
	} elsif ( $params->{action} eq 'delete' && check_role( $session ,'admin_delete' ) ) {
	    my $sql = "DELETE FROM ai_user_roles WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;

	    $sth->finish;
	}

	$dbh->disconnect;

	$res->redirect( "/roles?user_id=$user_id&username=$username" );

	return $res->finalize;
    }

    my %my_roles = %{ \%role_names };

    my $sql = "SELECT * FROM ai_user_roles WHERE user_id = ?";

    my $sth = $dbh->prepare( $sql );

    $sth->execute( $user_id ) or die $DBI::errstr;

    my $roles = $sth->fetchall_arrayref({});

    $sth->finish;

    map { delete $my_roles{$_->{name}} } @$roles;

    my @role_array = map { { name => $_, description => $role_names{$_} } } sort keys %my_roles;

    my $template = HTML::Template::Expr->new( filename => "/app/template/roles.tmpl", die_on_bad_params => 0 );

    $template->param(
	nonce     => $env->{'plack.nonce'},
	roles     => $roles,
	username  => $params->{username},
	user_id   => $user_id,
	my_roles  => \@role_array
	);
    $res->body( $template->output );

    $dbh->disconnect;

    return $res->finalize;
}

sub totp {
    my $env     = shift;
    my $error   = shift;
    my $req     = Plack::Request->new( $env );
    my $params  = $req->parameters;
    my $session = $env->{'psgix.session'};

    $params->{code} =~ s/[^0-9]//g;

    my $res = Plack::Response->new( 200 );

    $res->content_type( 'text/html' );

    my $template = HTML::Template::Expr->new( filename => "/app/template/totp.tmpl", die_on_bad_params => 0 );

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 }) or die $DBI::errstr;

    my $sql = "SELECT * FROM ai_users WHERE id = ?";

    my $sth = $dbh->prepare( $sql );

    $sth->execute( $session->{user_id} ) or die $DBI::errstr;

    my $row = $sth->fetchrow_hashref;

    $sth->finish;

    if ( $req->method eq 'POST' ) {
	if ( $row->{totp_enabled} ) {
	    if ( $params->{disable} ) {
		my $sql = "UPDATE ai_users SET totp_secret = null, totp_enabled = false WHERE id = ?";

		my $sth = $dbh->prepare( $sql );

		$sth->execute( $session->{user_id} ) or die $DBI::errstr;

		$sth->finish;

		$template->param( disabled => 1 );
	    } elsif ( $params->{code} ) {

		my $gen = new Authen::TOTP( secret => $ENV{TOTP_SECRET} );

		if ( $params->{code} && $gen->validate_otp(otp => $params->{code}, base32secret => $row->{totp_secret}, tolerance => 2) ) {
		    $template->param( check => 1 );
		} else {
		    $template->param( invalid => 1 );
		}
	    } else {
		$template->param( enabled => 1 );
	    }
	}  else {

	    my $gen = new Authen::TOTP( secret => $ENV{TOTP_SECRET} );

	    if ( $params->{code} && $gen->validate_otp(otp => $params->{code}, base32secret => $params->{base32secret}, tolerance => 2) ) {
		$template->param( valid   => 1 );

		my $sql = "UPDATE ai_users SET totp_secret = ?, totp_enabled = true WHERE id = ?";

		my $sth = $dbh->prepare( $sql );

		$sth->execute( $params->{base32secret}, $session->{user_id} ) or die $DBI::errstr;

		$sth->finish;
	    } else {
		$template->param( invalid => 1 );
	    }

	}

	$dbh->disconnect;

	$res->body( $template->output );

	return $res->finalize;
    }

    if ( $row->{totp_enabled} ) {
	$template->param( enabled => 1 );
    } else {
	my $gen = new Authen::TOTP( secret => $ENV{TOTP_SECRET} );

	my $base32secret = $gen->base32secret();

	my $uri = $gen->generate_otp(user => $row->{email}, issuer =>$ENV{TOTP_ISSUER} );

	my $url = "https://chart.googleapis.com/chart?chs=150x150&chld=M|0&cht=qr&chl=$uri";

	$template->param(
	    enable       => 1,
	    base32secret => $base32secret,
	    qrcode       => $url
	    );
    }

    $res->body( $template->output );

    return $res->finalize;
}

sub error {
    my $env   = shift;
    my $error = shift;
    my $req   = Plack::Request->new( $env );

    my $template = HTML::Template::Expr->new( filename => "/app/template/error.tmpl", die_on_bad_params => 0 );

    $template->param( error => $error );

    my $res = Plack::Response->new( 200 );

    $res->content_type( 'text/html' );

    $res->body( $template->output );

    return $res->finalize;
}

my $register_app = sub {
    my $env   = shift;
    my $error = "Not Implemented";
    my $req   = Plack::Request->new( $env );

    my $template = HTML::Template::Expr->new( filename => "/app/template/register.tmpl", die_on_bad_params => 0 );

    $template->param( error => $error );

    my $res = Plack::Response->new( 200 );

    $res->content_type( 'text/html' );

    $res->body( $template->output );

    return $res->finalize;
};

sub check_agent_id {
    my $env      = shift;
    my $error    = shift;
    my $req      = Plack::Request->new( $env );
    my $agent_id = $req->param( 'agent_id' );

    if ( $agent_id eq '' ) {
	my $res = Plack::Response->new( 200 );

	$res->redirect( "/" );

	print STDERR "No agent_id when one is required" if $ENV{DEBUG};

	return $res->finalize;
    }
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
	{ AutoCommit => 1, RaiseError => 1 }) or die $DBI::errstr;

    if ( $session->{user_id} ) {
	my ( $sql, $agents );

	if ( ( $session->{is_admin} or $session->{is_viewer} ) && $agent) {
	    $agents = $dbh->selectrow_array( "SELECT count(*) FROM ai_agent WHERE id = ?", undef, $agent );
	} else {
	    $agents = $dbh->selectrow_array( "SELECT count(*) FROM ai_agent WHERE user_id = ? AND id = ?", undef, $session->{user_id}, $agent );
	}

	if ( ! $agents ) {
	    $dbh->disconnect;
	    my $res = Plack::Response->new( 200 );
	    $res->redirect( "/" );
	    print STDERR "User $session->{user_id} tried to access agent $agent that doesn't exist, or they down't own.\n";
	    return $res->finalize;
	}
    }

    if ( $agent && $id ) {
	my $sql = "SELECT * FROM ai_post_prompt WHERE agent_id = ? AND id = ?";

	my $sth = $dbh->prepare( $sql );

	$sth->execute( $agent, $id ) or die $DBI::errstr;

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
	    my $start =  ($p->{'ai_end_date'}   / 1000) - 5000;
	    my $end   =  ($p->{'ai_start_date'} / 1000) + 5000;
	    
	    my $grafana_url = "https://grafana.proxy.signalwire.cloud/grafana/d/18d8e226-2f9e-4485-a1cf-31bd98ff6ff1/support-logs?orgId=1&from=$start&to=$end&var-tenant=us-west&var-search_string=$p->{'call_id'}";
	    
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
		grafana_url         => $grafana_url,
		is_admin	    => $session->{is_admin},
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
	my $page_size    = 20;
	my $current_page = $params->{page} || 1;
	my $offset       = ( $current_page - 1 ) * $page_size;

	my $sql = "SELECT * FROM ai_post_prompt WHERE agent_id = ? ORDER BY created DESC LIMIT ? OFFSET ?";

	my $sth = $dbh->prepare( $sql );

	$sth->execute( $agent, $page_size, $offset ) or die $DBI::errstr;

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
	    nonce                => $env->{'plack.nonce'},
	    agent_id             => $agent,
	    table_contents       => \@table_contents,
	    next_url             => $next_url,
	    prev_url             => $prev_url
	    );

	my $res = Plack::Response->new( 200 );

	$res->content_type( 'text/html' );

	$res->body( $template->output );

	return $res->finalize;
    }
}

sub summary {
    my $env     = shift;
    my $req     = Plack::Request->new( $env );
    my $agent   = $req->param( 'agent_id' );
    my $id      = $req->param( 'id' );
    my $method  = $req->method;
    my $json    = JSON::PP->new->ascii->pretty->allow_nonref;
    my $params  = $req->parameters;
    my $session = $env->{'psgix.session'};
    my $res     = Plack::Response->new( 200 );


    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die $DBI::errstr;

    if ( $method eq 'POST' ) {
	if ( $params->{action} eq 'delete' && check_role( $session ,'admin_delete,delete_summary' ) ) {
	    my $sql = "DELETE FROM ai_summary WHERE agent_id = ? AND id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent, $id ) or die $DBI::errstr;

	    $sth->finish;

	    $dbh->disconnect;

	    $res->redirect( "/summary?agent_id=$agent" );

	    return $res->finalize;
	}
    } else {
	if ( check_role( $session ,'admin_view,view_summary') ) {
	    my $select_sql = "SELECT * FROM ai_summary WHERE agent_id = ? ORDER BY created DESC";

	    my $sth = $dbh->prepare( $select_sql );

	    $sth->execute( $agent ) or die $DBI::errstr;

	    my $table_contents = $sth->fetchall_arrayref({});

	    $sth->finish;

	    $dbh->disconnect;

	    my $template = HTML::Template::Expr->new( filename => "/app/template/summary.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav            => @nav,
		nonce          => $env->{'plack.nonce'},
		table_contents => $table_contents,
		agent_id       => $agent,
		);

	    my $res = Plack::Response->new( 200 );

	    $res->content_type( 'text/html' );

	    $res->body( $template->output );

	    return $res->finalize;
	} else {
	    my $template = HTML::Template->new(filename => '/app/template/403.tmpl');

	    $template->param(message => "You do not have permission to access this resource");

	    $res->status( 403 );

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	}
    }
}

sub messages {
    my $env     = shift;
    my $req     = Plack::Request->new( $env );
    my $id      = $req->param( 'id' );
    my $agent   = $req->param( 'agent_id' );
    my $method  = $req->method;
    my $json    = JSON::PP->new->ascii->pretty->allow_nonref;
    my $params  = $req->parameters;
    my $session = $env->{'psgix.session'};
    my $res     = Plack::Response->new( 200 );

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die $DBI::errstr;

    if ( $method eq 'POST' ) {
	if ( $params->{action} eq 'delete' && check_role( $session ,'admin_delete,delete_messages' ) ) {
	    my $sql = "DELETE FROM ai_messages WHERE agent_id = ? AND id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent, $id ) or die $DBI::errstr;

	    $sth->finish;

	    $dbh->disconnect;

	    $res->redirect( "/messages?agent_id=$agent" );

	    return $res->finalize;
	}
    } else {
	if ( check_role( $session ,'admin_view,view_messages') ) {
	    my $select_sql = "SELECT * FROM ai_messages WHERE agent_id = ? ORDER BY created DESC";

	    my $sth = $dbh->prepare( $select_sql );

	    $sth->execute( $agent ) or die $DBI::errstr;

	    my $table_contents = $sth->fetchall_arrayref({});

	    $sth->finish;

	    $dbh->disconnect;

	    my $template = HTML::Template::Expr->new( filename => "/app/template/messages.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav            => @nav,
		nonce          => $env->{'plack.nonce'},
		table_contents => $table_contents,
		agent_id       => $agent,
		);

	    $res->content_type( 'text/html' );

	    $res->body( $template->output );

	    return $res->finalize;
	} else {
	    my $template = HTML::Template->new(filename => '/app/template/403.tmpl');

	    $template->param(message => "You do not have permission to access this resource");

	    $res->status( 403 );

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	}
    }
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
	{ AutoCommit => 1, RaiseError => 1 }) or die $DBI::errstr;

    my $insert_sql = "INSERT INTO ai_messages (convo_id, message, call_id, agent_id) VALUES (?, ?, ?, ?)";

    my $sth = $dbh->prepare( $insert_sql );

    my $rv  = $sth->execute( $from, $message, $sid, $agent ) or die $DBI::errstr;

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

    if ($from =~ /sip:(.*?)@/) {
	$from = $1;
    }

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die $DBI::errstr;

    tie %config, 'MyTieConfig',
	host     => $host,
	port     => $port,
	dbname   => $database,
	user     => $dbusername,
	password => $dbpassword,
	table    => 'ai_config',
	agent_id => $agent;

    {
	my $sql = 'SELECT prompt,post_prompt FROM ai_prompt WHERE agent_id = ?';

	my $sth = $dbh->prepare($sql);

	$sth->execute($agent) or die $DBI::errstr;

	my $row = $sth->fetchrow_hashref();


	$prompt      = $row->{prompt};
	$post_prompt = $row->{post_prompt};
	$assistant   = $config{ASSISTANT};

	$sth->finish;
    }

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

    if ( $config{ENABLE_DENOISE} ) {
	broadcast_by_agent_id( $agent, "Denoise Avtivated" );
	$swml->add_application( "main", "denoise" );
    }

    if ( $config{ENABLE_RECORD} ) {
	broadcast_by_agent_id( $agent, "Recording call" );
	$swml->add_application( "main", "record_call", { format => 'wav', stereo => 'true' } );
    }

    if ( $config{ENABLE_CNAM} &&  $config{ACCOUNT_SID} && $config{AUTH_TOKEN} && $config{SPACE_NAME} && $config{API_VERSION} ) {

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
	    my $sql = "SELECT hint FROM ai_hints WHERE agent_id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent ) or die $DBI::errstr;

	    while ( my $row = $sth->fetchrow_hashref ) {
		broadcast_by_agent_id( $agent, "Setting AI hints to $row->{hint}" );
		$swml->add_aihints( $row->{hint} );
	    }

	    $sth->finish;
	}

	{
	    my $sql = "SELECT * FROM ai_language WHERE agent_id = ? ORDER BY language_order ASC";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent ) or die $DBI::errstr;

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

	if ( $config{SET_CONVERSATION_ID} ) {
	    broadcast_by_agent_id( $agent, "Setting conversation_id to $from" );
	    $swml->add_aiparams( { conversation_id => "$from" } );
	}

	if ( $config{ENABLE_PRONOUNCE} ) {
	    my $sql = "SELECT * FROM ai_pronounce WHERE agent_id = ?";

	    my $sth = $dbh->prepare( $sql );

	    my $rv  = $sth->execute( $agent ) or die $DBI::errstr;

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

	    $sth->execute( $agent ) or die $DBI::errstr;

	    my @functions;

	    while ( my $row = $sth->fetchrow_hashref ) {
		my @args;
		my $argcount = 0;
		my @required;
		
		if ( $row->{code} ) {
		    my $arguments;

		    $arguments->{type} = "object";

		    my $argsql = "SELECT * FROM ai_function_argument WHERE function_id = ? AND agent_id = ? ORDER BY created DESC";

		    my $argsth = $dbh->prepare( $argsql );

		    $argsth->execute( $row->{id}, $agent ) or die $DBI::errstr;

		    while ( my $arg = $argsth->fetchrow_hashref ) {
			next if $arg->{active} == 0;
			$argcount++;
			$arguments->{properties}->{$arg->{name}} = { type => $arg->{type}, description => $arg->{description} };
			push @required, $arg->{name} if $arg->{required};
		    }

		    $arguments->{required} = \@required if scalar @required > 0;
		    
		    $argsth->finish;

		    if  ( $argcount > 0 ) {
			broadcast_by_agent_id( $agent, "Adding function $row->{name}" );
		    
			$swml->add_aiswaigfunction({
			    active   => $row->{active} ? 'true' : 'false',
			    function => $row->{name},
			    purpose  => $row->{purpose},
			    argument => $arguments });
		    } else {
			broadcast_by_agent_id( $agent, "Skipping function $row->{name}, no arguments defined." );
		    }
	    }

	    if ( $config{ENABLE_CONTEXTS} ) {
		my $sql = "SELECT * FROM ai_context WHERE agent_id = ? ORDER BY id ASC";
		my $contextcount = 0;
		my $sth = $dbh->prepare( $sql );

		$sth->execute( $agent ) or die $DBI::errstr;

		my @context_expressions;

		while ( my $row = $sth->fetchrow_hashref ) {
		    my @actions;

		    if ( $row->{toggle_function} ) {
			foreach my $function ( split( /\|/, $row->{toggle_function} ) ) {
			    my ( $function, $args ) = split( /:/, $function );
			    broadcast_by_agent_id( $agent, "Adding toggle function $function with args $args" );
			    push @actions, {
				toggle_functions => [{
				    function => $function,
				    active   => $args }] };
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
		    $contextcount++;
		    push @context_expressions, $expression;
		}

		if ( $contextcount > 0 ) {
		    broadcast_by_agent_id( $agent, "Adding context switch function" );
		    $swml->add_aiswaigfunction({
			function => "switch_context",
			purpose  => "to switch contexts ",
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
		}
	    }
	    
	    if ( $config{ENABLE_STEPS} ) {
		my $steps = 0;
		my $sql = "SELECT * FROM ai_steps WHERE agent_id = ? ORDER BY id ASC";
		
		my $sth = $dbh->prepare( $sql );

		$sth->execute( $agent ) or die $DBI::errstr;

		my @step_expressions;

		while ( my $row = $sth->fetchrow_hashref ) {
		    my @actions;

		    if ( $row->{custom_action} ) {
			my ($do, $arg, $say) = split( /\|/, $row->{custom_action}, 3 );
			
			if ( $do eq "send_message" ) {
			    my $msg = SignalWire::ML->new;
			    
			    $msg->add_application( "main", "send_sms" => { to_number   => "$from",
									   from_number => "$assistant",
									   body        => "$arg, Reply STOP to stop." } );
			    if ( $say ) {
				push @actions, { say => "$say" };
			    }
			    push @actions, { SWML => $msg->render };
			} elsif ( $do eq "transfer" ) {
			    my $transfer = SignalWire::ML->new;
			
			    $transfer->add_application( "main", "connect" => { to   => $arg } );
			
			    if ( $say ) {
				push @actions, { say => "$say" };
			    }
			    
			    push @actions, { SWML => $transfer->render };
			    
			}
		    }

		    
		    if ( $row->{toggle_function} ) {
			foreach my $function ( split( /\|/, $row->{toggle_function} ) ) {
			    my ( $function, $args ) = split( /:/, $function );
			    broadcast_by_agent_id( $agent, "Adding toggle function $function with args $args" );
			    push @actions, {
				toggle_functions => [{
				    function =>  $function ,
				    active   => $args }] };
			}
		    }
		    
		    if ( $row->{ai_step_b2b_functions} ) {
			push @actions, { back_to_back_functions => 'true' };
		    }

		    my $expression = {
			string  => '${args.step}',
			pattern => $row->{ai_step_pattern},
			output  => {
			    response => $row->{ai_step_response},
			    ( scalar @actions > 0 ? ( action   => \@actions) : () )
			}
		    };

		    push @step_expressions, $expression;
		    $steps++;
		}
		
		if ( $steps ) {
		    $swml->add_aiswaigfunction({
			function => "advance_step",
			purpose  => "to advance to a particular step",
			argument => {
			    type => "object",
			    properties => {
				step => {
				    type        => "string",
				    description => "The step number as a string" }
			    },
			},
			data_map => {
			    expressions => \@step_expressions,
			}});
		}
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
		    post_process => 'true',
		    response => "Tell the user you are going to transfer the call. Do not change languages from the one you are currently using. Do not hangup.",       
		    action => [ { SWML => $transfer->render, transfer => 'true' } ] } );   


		my %hash;

		my @pairs = split( /\|/, $config{TRANSFER_TABLE} );

		foreach my $pair ( @pairs ) {
		    my ( $key, $value ) = split( /:/, $pair, 2 );
		    $hash{$key} = $value;
		}

		$swml->add_aiswaigfunction( {
		    function  => 'transfer',
		    ( $config{ENABLE_TRANSFER_INACTIVE} ? ( active => 'false' ) : ()),
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
							       body        => '${args.message}, Reply STOP to stop.' } );

		$output = $msg->swaig_response( {
		    response => "Message sent.",
		    action   => [ { SWML => $msg->render } ] } );

		$swml->add_aiswaigfunction( {
		    function => 'send_message',
		    ( $config{ENABLE_MESSAGE_INACTIVE} ? ( acive => 'false' ) : ()),
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
			required => [ "message", "to" ]
		    },
		    data_map => {
			expressions => [{
			    string  => '${args.message}',
			    pattern => '.*',
			    output  => $output
					}]}} );
	    }

	    if ( $config{ENABLE_MMS_MESSAGE} && $assistant ) {
		broadcast_by_agent_id( $agent, "Adding mms  message function" );
		my $msg = SignalWire::ML->new;

		$msg->add_application( "main", "send_sms" => { to_number   => '${args.to}',
							       from_number => "$assistant",
							       body        => '${args.message}, Reply STOP to stop.',
							       media       => [ '${args.media}' ] } );

		$output = $msg->swaig_response( {
		    response => "Message sent.",
		    action   => [ { SWML => $msg->render } ] } );

		$swml->add_aiswaigfunction( {
		    function => 'send_mms',
		    purpose  => "use to send text messages to a user",
		    argument => {
			type => "object",
			properties => {
			    media   => {
				type        => "string",
				description => "the media URL to send to the user" },
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

	    if ( $config{AI_ROOMIESERVE_URL} ) {
		broadcast_by_agent_id( $agent, "Adding AI Roomieserve includes" );
		if ( $config{AI_ROOMIESERVE_URL} =~ m|https:\/\/([^:]+):([^@]+)@([^/]+)(/[^?#]*)?|) {
		    $swml->add_aiinclude( { url  => $config{AI_ROOMIESERVE_URL} } );
		} else {
		    broadcast_by_agent_id( $agent, "AI Roomieserve URL is not valid" );
		}
	    }

	    if ( $config{AI_SHEETS_URL} ) {
		broadcast_by_agent_id( $agent, "Adding AI Sheets includes" );
		if ( $config{AI_SHEETS_URL} =~ m|https:\/\/([^:]+):([^@]+)@([^/]+)(/[^?#]*)?|) {
		    my $username = $1;
		    my $password = $2;
		    my $host = $3;
		    my $path = $4 // "/";

		    $swml->add_aiinclude( {
			functions => [ 'append' ],
			url  => $config{AI_SHEETS_URL},
			user => $username,
			pass => $password } );
		} else {
		    broadcast_by_agent_id( $agent, "AI Sheets URL is not valid" );
		}
	    }

	    if ( $config{AI_CALENDAR_URL} ) {
		broadcast_by_agent_id( $agent, "Adding AI Calendar includes" );
		if ( $config{AI_CALENDAR_URL} =~ m|https:\/\/([^:]+):([^@]+)@([^/]+)(/[^?#]*)?|) {
		    my $username = $1;
		    my $password = $2;
		    my $host = $3;
		    my $path = $4 // "/";

		    $swml->add_aiinclude( {
			functions => [ 'freebusy', 'events' ],
			url  => $config{AI_CALENDAR_URL},
#			user => $username,
#			pass => $password
					  } );
		} else {
		    broadcast_by_agent_id( $agent, "AI Calendar URL is not valid" );
		}
	    }

	    if ( $config{AI_EMAIL_URL} ) {
		broadcast_by_agent_id( $agent, "Adding AI Email includes" );
		if ( $config{AI_EMAIL_URL} =~ m|https:\/\/([^:]+):([^@]+)@([^/]+)(/[^?#]*)?|) {
		    my $username = $1;
		    my $password = $2;
		    my $host = $3;
		    my $path = $4 // "/";

		    $swml->add_aiinclude( {
			functions => [ 'sendmail' ],
			url  => $config{AI_EMAIL_URL},
			user => $username,
			pass => $password } );
		} else {
		    broadcast_by_agent_id( $agent, "AI Email URL is not valid" );
		}
	    }

	    if ( $config{AI_CONTACTS_URL} ) {
		broadcast_by_agent_id( $agent, "Adding AI Contacts includes" );
		if ( $config{AI_CONTACTS_URL} =~ m|https:\/\/([^:]+):([^@]+)@([^/]+)(/[^?#]*)?|) {
		    my $username = $1;
		    my $password = $2;
		    my $host = $3;
		    my $path = $4 // "/";

		    $swml->add_aiinclude( {
			functions => [ 'searchdirectory', 'searchcontacts', 'contacttransfer' ],
			url  => $config{AI_CONTACTS_URL},
			user => $username,
			pass => $password } );
		} else {
		    broadcast_by_agent_id( $agent, "AI Contacts URL is not valid" );
		}
	    }

	    if ( $config{ENABLE_OPENSTREET_MAP} ) {
		$swml->add_aiswaigfunction( {
		    function => 'get_lat_lon',
		    purpose => "lattitude and logitude for any city or state",
		    argument => {
			type => "object",
			properties => {
			    city => {
				type        => "string",
				description => "City name" },
			    state => {
				type        => "string",
				description => "Two letter US state code" } } },
		    data_map => {
			webhooks => [{
			    url     => 'https://nominatim.openstreetmap.org/search?format=json&q=${enc:args.city}%2C${enc:args.state}',
			    method  => "GET",
			    output => {
				response => 'The lattitude is ${array[0].lat}, longitude is ${array[0].lon} for ${input.args.city}, ${input.args.state}',
				action  => [ { back_to_back_functions => 'true' } ],
			    }}]}} );
	    }
	    if ( $config{ENABLE_WEATHER_GOV} ) {
		$swml->add_aiswaigfunction( {
		    function => 'get_weather_point',
			purpose => "lattitude and logitude for any city",
			argument => {
			    type => "object",
			    properties => {
				lat => {
				    type        => "string",
				    description => "Lattitude to four decimal places." },
				lon => {
				    type        => "string",
				    description => "Longitude to four decimal places." } } },
			data_map => {
			    webhooks => [{
				url     => 'https://api.weather.gov/points/${enc:args.lat},${enc:args.lon}',
				method  => "GET",
				output  => {
				    response => 'Now use get_weather_detailed_forecast function to get the forecast using this URL ${properties.forecast} as the argument.',
				    action  => [ { back_to_back_functions => 'true' } ],
				}}]}} );

		$swml->add_aiswaigfunction( {
		    function => 'get_weather_detailed_forecast',
		    purpose => "get detailed forecast for a location using forecast URL",
		    argument => {
			type => "object",
			properties => {
			    url => {
				type        => "string",
				description => "complete forcast URL" } } },
		    data_map => {
			webhooks => [{
			    url     => '${args.url}',
			    method  => "GET",
			    output  => {
				response => '${properties.periods[0].detailedForecast}'
			    } } ]}} );
	    }

	    if ( $config{ENABLE_GOOGLE_ADDRESS_VALIDATION} ) {
			$swml->add_aiswaigfunction({
			    function => 'verify_address',
			    purpose  => "verify an address",
			    argument => {
				type => "object",
				properties => {
				    address => {
					type => "string",
					description => "street address" },
				    city => {
					type => "string",
					description => "city" },
				    state => {
					type => "string",
					description => "state" }
				}
			    },
			    data_map => {
				webhooks => [{
				    url        => "https://addressvalidation.googleapis.com/v1:validateAddress?key=$config{GOOGLE_API_KEY}",
				    method     => "POST",
				    error_keys => 'error',
				    params     => {
					address => {
					    regionCode   => 'US',
					    addressLines => ['${args.address}', '${args.city}, ${args.state}']
					},
					enableUspsCass => 'true',
				    },
				    output => {
					response => 'Verified Address: ${result.address.formattedAddress}'
				    }}]}});

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
	    { AutoCommit => 1, RaiseError => 1 } ) or die $DBI::errstr;

	broadcast_by_agent_id( $agent, { response => "Looking for $post_data->{function} for agent $agent" } );

	my $sth = $dbh->prepare( "SELECT * FROM ai_function WHERE name = ? AND agent_id = ?" );

	$sth->execute( $post_data->{function}, $agent ) or die $DBI::errstr;

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
    my $env    = shift;
    my $req    = Plack::Request->new( $env );
    my $method = $req->method;
    my $agent  = $req->param( 'agent_id' );
    my $res    = Plack::Response->new( 200 );
    my $params = $req->parameters;

    my @toggles = qw( ENABLE_DENOISE ENABLE_GOOGLE_ADDRESS_VALIDATION ENABLE_WEATHER_GOV ENABLE_OPENSTREET_MAP ENABLE_SEND_DIGITS_ON_ANSWER ENABLE_ANSWER_DELAY ENABLE_SEND_DIGITS ENABLE_BYPASS ENABLE_ZENDESK_TICKET ENABLE_CONTEXTS ENABLE_STEPS ENABLE_SLACK_NOTIFICATION ENABLE_CALENDLY ENABLE_SLACK_SWAIG ENABLE_PRONOUNCE ENABLE_TRANSFER ENABLE_TRANSFER_INACTIVE ENABLE_DEBUG_WEBHOOK ENABLE_POST_PROMPT ENABLE_CNAM ENABLE_SWAIG ENABLE_RECORD ENABLE_MESSAGE ENABLE_MESSAGE_INACTIVE ENABLE_MMS_MESSAGE ENABLE_WEATHER ENABLE_TRIVIA ENABLE_JOKES ENABLE_CHECK_FOR_INPUT SAVE_BLANK_CONVERSATIONS SEND_SUMMARY_MESSAGE SIMPLE_POST_FUNCTION SET_CONVERSATION_ID);

    my @fields  = qw(GOOGLE_API_KEY AUTH_USERNAME AUTH_PASSWORD SPACE_NAME ACCOUNT_SID AUTH_TOKEN API_VERSION TEMPERATURE TOP_P BARGE_CONFIDENCE CONFIDENCE PRESENCE_PENALTY FREQUENCY_PENALTY CUSTODIAN_SMS CUSTODIAN_CELL ASSISTANT TRANSFER_TABLE CALENDLY_MESSAGE API_NINJAS_KEY AI_CONTACTS_URL AI_EMAIL_URL AI_CALENDAR_URL AI_SHEETS_URL AI_ROOMIESERVE_URL MAX_TOKENS SLACK_WEBHOOK_URL SLACK_CHANNEL SLACK_USERNAME SLACK_MESSAGE ZENDESK_API_KEY ZENDESK_SUBDOMAIN BYPASS_SOURCES ANSWER_DELAY_LENGTH SEND_DIGITS_ON_ANSWER );

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

    if ( $method eq 'POST' && check_role( $session ,'admin_update,update_config' ) ) {

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
    } else {
	if ( check_role( $session ,'admin_view,view_config' ) ) {
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
		is_admin => $session->{is_admin},
		url      => "https://$env->{HTTP_HOST}/config",
		swml_url => ( $config{AUTH_USERNAME} && $config{AUTH_PASSWORD} ) ? "https://$config{AUTH_USERNAME}:$config{AUTH_PASSWORD}\@$env->{HTTP_HOST}/swml?agent_id=$agent" : "https://$env->{HTTP_HOST}/swml?agent_id=$agent",
		laml_url => ( $config{AUTH_USERNAME} && $config{AUTH_PASSWORD} ) ? "https://$config{AUTH_USERNAME}:$config{AUTH_PASSWORD}\@$env->{HTTP_HOST}/laml?agent_id=$agent" : "https://$env->{HTTP_HOST}/laml?agent_id=$agent"
		);

	    untie %config;

	    $res->body( $template->output );

	    return $res->finalize;
	} else {
	    my $template = HTML::Template->new(filename => '/app/template/403.tmpl');

	    $template->param(message => "You do not have permission to access this resource");

	    $res->status(403);

	    $res->body($template->output);

	    return $res->finalize;
	}
    }
}

sub prompt {
    my $env    = shift;
    my $req    = Plack::Request->new( $env );
    my $agent  = $req->param( 'agent_id' );
    my $method = $req->method;
    my $res    = Plack::Response->new( 200 );
    my $params = $req->parameters;

    my $session = $env->{'psgix.session'};

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die $DBI::errstr;

    $res->content_type( 'text/html' );

    if ( $method eq 'POST' ) {
	if ( check_role( $session ,'admin_update,update_prompt' ) ) {
	    my $sql = "INSERT INTO ai_prompt (agent_id, prompt, post_prompt) VALUES (?, ?, ?) ON CONFLICT (agent_id) DO UPDATE SET prompt = EXCLUDED.prompt, post_prompt = EXCLUDED.post_prompt";
	    
	    my $sth = $dbh->prepare( $sql );
	    
	    $sth->execute( $agent, $params->{prompt}, $params->{post_prompt} ) or die $DBI::errstr;
	    
	    $sth->finish;
	    
	    $dbh->disconnect;
	    
	    my $res = Plack::Response->new( 200 );
	    
	    $res->redirect( "/prompt?agent_id=$agent" );
	    
	    return $res->finalize;
	} else {
	    my $template = HTML::Template->new(filename => '/app/template/403.tmpl');
	    
	    $template->param(message => "You do not have permission to access this resource");
	    
	    $res->status(403);
	    
	    $res->body($template->output);
	    
	    return $res->finalize;
	}
    } else {
	if ( check_role( $session ,'admin_view,view_prompt' ) ) {
	    my $sql = 'SELECT prompt,post_prompt FROM ai_prompt WHERE agent_id = ?';
	    
	    my $sth = $dbh->prepare($sql);
	    
	    $sth->execute($agent) or die $DBI::errstr;
	    
	    my $row = $sth->fetchrow_hashref();
	    print STDERR Dumper($row);
	    my $template = HTML::Template::Expr->new( filename => "/app/template/prompt.tmpl", die_on_bad_params => 0 );
	    
	    $template->param(
		nav		=> @nav,
		nonce           => $env->{'plack.nonce'},
		agent_id        => $agent,
		prompt          => $row->{prompt},
		post_prompt     => $row->{post_prompt}
		);
	    
	    $res->body( $template->output );
	    
	    $sth->finish;
	    
	    $dbh->disconnect;

	    return $res->finalize;
	} else {
	    my $template = HTML::Template->new(filename => '/app/template/403.tmpl');

	    $template->param(message => "You do not have permission to access this resource");

	    $res->status(403);

	    $res->body($template->output);

	    return $res->finalize;
	}
    }
}

sub agents {
    my $env    = shift;
    my $req    = Plack::Request->new( $env );
    my $method = $req->method;
    my $res    = Plack::Response->new( 200 );
    my $params = $req->parameters;

    my $session = $env->{'psgix.session'};

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die $DBI::errstr;

    $res->content_type( 'text/html' );

    if ( $method eq 'POST' ) {
	if ( $params->{action} eq 'create' && check_role( $session ,'admin_create,create_agents' ) ) {
	    my $sql = "INSERT INTO ai_agent (name, description, phone_number, user_id) VALUES (?, ?, ?, ?)";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{name}, $params->{description}, $params->{phone_number}, $session->{user_id} ) or die $DBI::errstr;

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
	} elsif ( $params->{action} eq 'add' && check_role( $session ,'admin_create,create_agents' ) ) {
	    my $template = HTML::Template::Expr->new( filename => "/app/template/create_agent.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav		=> $session->{is_admin} ? @admin_nav : @user_nav,
		url             => "https://$env->{HTTP_HOST}",
		nonce           => $env->{'plack.nonce'},
		);

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'edit' && check_role( $session ,'admin_update,update_agents' ) ) {
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
	} elsif ( $params->{action} eq 'update' && check_role( $session ,'admin_update,update_agents' ) ) {
	    my $sql = "UPDATE ai_agent SET name = ?, description = ?, phone_number = ?  WHERE id = ?";
	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{name}, $params->{description}, $params->{phone_number}, $params->{id} ) or die $DBI::errstr;

	    $sth->finish;
	} elsif ( $params->{action} eq 'delete' && check_role( $session ,'admin_delete,delete_agents' ) ) {
	    my $session = $env->{'psgix.session'};

	    if ( $session->{is_admin} ) {
		my $sql = "DELETE FROM ai_agent WHERE id = ?";
		my $sth = $dbh->prepare( $sql );

		$sth->execute( $params->{id} ) or die $DBI::errstr;

		$sth->finish;
	    } else {
		$res->status( 403 );

		$res->body( "You are not authorized to delete agents." );

		return $res->finalize;
	    }
	}

	$dbh->disconnect;

	$res->status( 302 );

	$res->redirect( "/" );

	return $res->finalize;
    } else {

	if ( check_role( $session, 'admin_view,view_agents') ) {
	    my $sql;
	    my $sth;

	    if ( check_role( $session, 'admin_view') ) {
		$sql = "SELECT * FROM ai_agent ORDER BY created DESC";
		$sth = $dbh->prepare( $sql );
	    } else {
		$sql = "SELECT * FROM ai_agent WHERE user_id = ? ORDER BY created DESC";
		$sth = $dbh->prepare( $sql );
		$sth->bind_param(1, $session->{user_id});
	    }

	    $sth->execute or die "Couldn't execute statement: $DBI::errstr";

	    my $agents = $sth->fetchall_arrayref({});

	    my $template = HTML::Template::Expr->new( filename => "/app/template/agents.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav             => $session->{is_admin} ? @admin_nav : @user_nav,
		nonce		=> $env->{'plack.nonce'},
		url             => "https://$env->{HTTP_HOST}",
		agents          => $agents,
		is_admin	=> $session->{is_admin},
		);

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} else {
	    my $template = HTML::Template->new(filename => '/app/template/403.tmpl');

	    $template->param(message => "You do not have permission to access this resource");

	    $res->status(403);

	    $res->body($template->output);

	    $dbh->disconnect;

	    return $res->finalize;
	}
    }
}

sub hints {
    my $env        = shift;
    my $req        = Plack::Request->new( $env );
    my $agent      = $req->param( 'agent_id' );
    my $agent_name = $req->param( 'agent_name' );
    my $method     = $req->method;
    my $res        = Plack::Response->new( 200 );
    my $params     = $req->parameters;
    my $session    = $env->{'psgix.session'};

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die $DBI::errstr;

    $res->content_type( 'text/html' );

    if ( $method eq 'POST' ) {
	if ( $params->{action} eq 'create' && check_role( $session, 'admin_create,create_hints' ) ) {
	    my $sql = "INSERT INTO ai_hints (hint, agent_id) VALUES (?, ?)";
	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{hint}, $agent ) or die $DBI::errstr;

	    $sth->finish;
	} elsif ( $params->{action} eq 'add' && check_role( $session, 'admin_create,create_hints' ) ) {
	    my $template = HTML::Template::Expr->new( filename => "/app/template/create_hint.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nonce           => $env->{'plack.nonce'},
		agent_id        => $agent,
		agent_name      => $agent_name
		);

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'edit' && check_role( $session, 'admin_update,update_hints' ) ) {
	    my $template = HTML::Template::Expr->new( filename => "/app/template/edit_hint.tmpl", die_on_bad_params => 0 );

	    my $sql = "SELECT * FROM ai_hints WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;

	    my $hint = $sth->fetchrow_hashref;

	    $sth->finish;

	    $template->param(
		nonce           => $env->{'plack.nonce'},
		agent_id        => $agent,
		agent_name      => $agent_name
		);

	    $template->param( %$hint );

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'update' && check_role( $session, 'admin_update,update_hints' ) ) {
	    my $sql = "UPDATE ai_hints SET hint = ? WHERE id = ?";
	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{hint}, $params->{id} ) or die $DBI::errstr;

	    $sth->finish;
	} elsif ( $params->{action} eq 'delete'  && check_role( $session, 'admin_delete,delete_hints' ) ) {
	    my $sql = "DELETE FROM ai_hints WHERE id = ?";
	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;
	    $sth->finish;
	}

	$dbh->disconnect;

	$res->status( 302 );

	$res->redirect( "/hints?agent_id=$agent&agent_name=$agent_name" );

	return $res->finalize;
    } else {
	if ( check_role($session, 'admin_view,view_hints') ) {
	    my $sql = "SELECT * FROM ai_hints WHERE agent_id = ? ORDER BY created DESC";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent ) or die $DBI::errstr;

	    my $hints = $sth->fetchall_arrayref({});

	    my $template = HTML::Template::Expr->new( filename => "/app/template/hints.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nonce           => $env->{'plack.nonce'},
		agent_id        => $agent,
		agent_name      => $agent_name,
		hints           => $hints
		);

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} else {
	    my $template = HTML::Template->new(filename => '/app/template/403.tmpl');

	    $template->param(message => "You do not have permission to access this resource");

	    $res->status(403);

	    $res->body($template->output);

	    $dbh->disconnect;

	    return $res->finalize;
	}
    }
}

sub language {
    my $env        = shift;
    my $req        = Plack::Request->new( $env );
    my $agent      = $req->param( 'agent_id' );
    my $agent_name = $req->param( 'agent_name' );
    my $method     = $req->method;
    my $res        = Plack::Response->new( 200 );
    my $params     = $req->parameters;
    my $session    = $env->{'psgix.session'};

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die $DBI::errstr;

    $res->content_type( 'text/html' );

    if ( $method eq 'POST' ) {
	if ( $params->{action} eq 'create' && check_role( $session, 'admin_create,create_languages' ) ) {
	    my $sql = "INSERT INTO ai_language (agent_id, code, name, voice, engine, fillers, language_order) VALUES (?, ?, ?, ?, ?, ?, ?)";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent, $params->{code}, $params->{name}, $params->{voice}, $params->{engine}, $params->{fillers}, $params->{language_order} ) or die $DBI::errstr;

	    $sth->finish;
	} elsif ( $params->{action} eq 'add'  && check_role( $session, 'admin_create,create_languages' ) ) {
	    my $template = HTML::Template::Expr->new( filename => "/app/template/create_language.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav             => $session->{is_admin} ? @nav : @user_nav,
		nonce		=> $env->{'plack.nonce'},
		agent_id        => $agent,
		agent_name      => $agent_name
		);

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'edit' && check_role( $session, 'admin_update,update_languages' ) ) {
	    my $sql = "SELECT * FROM ai_language WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;

	    my $language = $sth->fetchrow_hashref;

	    $sth->finish;
	    my $template = HTML::Template::Expr->new( filename => "/app/template/edit_language.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav             => $session->{is_admin} ? @nav : @user_nav,
		nonce		=> $env->{'plack.nonce'},
		url             => "https://$env->{HTTP_HOST}",
		agent_id        => $agent,
		agent_name      => $agent_name,
		);

	    $template->param( %$language );

	    $res->body( $template->output );

	    return $res->finalize;
	} elsif ( $params->{action} eq 'update' && check_role( $session, 'admin_update,update_languages' ) ) {
	    my $sql = "UPDATE ai_language SET code = ?, name = ?, voice = ?, engine = ?, fillers = ?, language_order = ? WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{code}, $params->{name}, $params->{voice}, $params->{engine}, $params->{fillers}, $params->{language_order}, $params->{id} ) or die $DBI::errstr;

	    $sth->finish;
	} elsif ( $params->{action} eq 'delete' && check_role( $session, 'admin_delete,delete_languages' ) ) {
	    my $session = $env->{'psgix.session'};
	    my $sql = "DELETE FROM ai_language WHERE id = ?";
	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;
	    $sth->finish;
	}

	$dbh->disconnect;

	$res->redirect( "/language?agent_id=$agent&agent_name=$agent_name" );

	return $res->finalize;
    } else {
	if ( check_role( $session, 'admin_view,view_languages' ) ) {
	    my $sql = "SELECT * FROM ai_language WHERE agent_id = ? ORDER BY language_order ASC";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent ) or die "Couldn't execute statement: $DBI::errstr";

	    my $languages = $sth->fetchall_arrayref({});

	    my $template = HTML::Template::Expr->new( filename => "/app/template/language.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav             => $session->{is_admin} ? @nav : @user_nav,
		nonce		=> $env->{'plack.nonce'},
		url             => "https://$env->{HTTP_HOST}",
		agent_id        => $agent,
		agent_name      => $agent_name,
		languages       => $languages
		);

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} else {
	    my $template = HTML::Template->new(filename => '/app/template/403.tmpl');

	    $template->param(message => "You do not have permission to access this resource");

	    $res->status(403);

	    $res->body($template->output);

	    $dbh->disconnect;

	    return $res->finalize;
	}
    }
}

sub pronounce {
    my $env        = shift;
    my $req        = Plack::Request->new( $env );
    my $agent      = $req->param( 'agent_id' );
    my $agent_name = $req->param( 'agent_name' );
    my $method     = $req->method;
    my $res        = Plack::Response->new( 200 );
    my $params     = $req->parameters;
    my $session    = $env->{'psgix.session'};

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die $DBI::errstr;

    $res->content_type( 'text/html' );

    if ( $method eq 'POST' ) {
	$params->{ignore_case} = $params->{ignore_case} ? 1 : 0;

	if ( $params->{action} eq 'create' && check_role( $session, 'admin_create,create_pronounce' ) ) {
	    my $sql = "INSERT INTO ai_pronounce (agent_id, ignore_case, replace_this, replace_with) VALUES (?, ?, ?, ?)";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent, $params->{ignore_case}, $params->{replace_this}, $params->{replace_with} ) or die $DBI::errstr;

	    $sth->finish;
	} elsif ( $params->{action} eq 'add' && check_role( $session, 'admin_create,create_pronounce' ) ) {
	    my $template = HTML::Template::Expr->new( filename => "/app/template/create_pronounce.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav             => $session->{is_admin} ? @nav : @user_nav,
		nonce		=> $env->{'plack.nonce'},
		agent_id        => $agent,
		agent_name      => $agent_name
		);

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'edit' && check_role( $session, 'admin_update,update_pronounce' ) ) {
	    my $sql = "SELECT * FROM ai_pronounce WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;

	    my $pronounce = $sth->fetchrow_hashref;

	    $sth->finish;

	    $pronounce->{ignore_case_checked} = $pronounce->{ignore_case} ? 'checked' : '';

	    my $template = HTML::Template::Expr->new( filename => "/app/template/edit_pronounce.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav             => $session->{is_admin} ? @nav : @user_nav,
		nonce		=> $env->{'plack.nonce'},
		agent_id        => $agent,
		agent_name      => $agent_name
		);

	    $template->param( %$pronounce );

	    $res->body( $template->output );

	    return $res->finalize;
	} elsif ( $params->{action} eq 'update' && check_role( $session, 'admin_update,update_pronounce' ) ) {
	    my $sql = "UPDATE ai_pronounce SET ignore_case = ?, replace_this = ?, replace_with = ? WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{ignore_case}, $params->{replace_this}, $params->{replace_with}, $params->{id} ) or die $DBI::errstr;

	    $sth->finish;
	} elsif ( $params->{action} eq 'delete' && check_role( $session, 'admin_delete,delete_pronounce' ) ) {
	    my $session = $env->{'psgix.session'};

	    my $sql = "DELETE FROM ai_pronounce WHERE id = ?";
	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;
	    $sth->finish;
	}

	$dbh->disconnect;

	$res->redirect( "/pronounce?agent_id=$agent&agent_name=$agent_name" );

	return $res->finalize;
    } else {

	if ( check_role ($session, 'admin_view,view_pronounce' ) ) {
	    my $sql = "SELECT * FROM ai_pronounce WHERE agent_id = ? ORDER BY created DESC";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent ) or die $DBI::errstr;

	    my $pronounce = $sth->fetchall_arrayref({});

	    $sth->finish;

	    $dbh->disconnect;

	    my $template = HTML::Template::Expr->new( filename => "/app/template/pronounce.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav             => @nav,
		nonce		=> $env->{'plack.nonce'},
		agent_id        => $agent,
		agent_name      => $agent_name,
		pronounce       => $pronounce
		);

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} else {
	    my $template = HTML::Template->new(filename => '/app/template/403.tmpl');

	    $template->param(message => "You do not have permission to access this resource");

	    $res->status(403);

	    $res->body($template->output);

	    $dbh->disconnect;

	    return $res->finalize;
	}
    }
}

sub function {
    my $env    = shift;
    my $req    = Plack::Request->new( $env );
    my $agent  = $req->param( 'agent_id' );
    my $method = $req->method;
    my $res    = Plack::Response->new( 200 );
    my $params = $req->parameters;

    my $session = $env->{'psgix.session'};

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die $DBI::errstr;


    $res->content_type( 'text/html' );

    $params->{active_checked} = $params->{active} ? 'checked' : '';

    if ( $method eq 'POST' ) {

	if ( $params->{action} eq 'create' && check_role( $session, 'admin_create,create_functions' ) ) {
	    my $sql = "INSERT INTO ai_function (agent_id, name, active, purpose, code) VALUES (?, ?, ?, ?, ?)";

	    my $sth = $dbh->prepare( $sql );

	    $params->{code} = read_file( '/app/template/function.default' );

	    $sth->execute( $agent, $params->{name}, $params->{active}, $params->{purpose}, $params->{code} ) or die $DBI::errstr;

	    $sth->finish;

	    $dbh->disconnect;

	    $res->redirect( "/function?agent_id=$agent" );

	    return $res->finalize;
	} elsif ( $params->{action} eq 'add' && check_role( $session, 'admin_create,create_functions' ) ) {
	    my $template = HTML::Template::Expr->new( filename => "/app/template/create_function.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav             => @nav,
		nonce		=> $env->{'plack.nonce'},
		agent_id        => $agent,
		);

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'edit' && check_role( $session, 'admin_update,update_functions' ) ) {
	    my $sql = "SELECT * FROM ai_function WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;

	    my $function = $sth->fetchrow_hashref;

	    $sth->finish;

	    my $template = HTML::Template::Expr->new( filename => "/app/template/edit_function.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav             => @nav,
		nonce		=> $env->{'plack.nonce'},
		agent_id        => $agent,
		);

	    $function->{active_checked} = $function->{active} ? 'checked' : '';

	    $template->param( %$function );

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'update'  && check_role( $session, 'admin_update,update_functions' ) ) {
	    my $sql = "UPDATE ai_function SET name = ?, active = ?, purpose = ?, code = ? WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{name}, $params->{active}, $params->{purpose} , $params->{code}, $params->{id} ) or die $DBI::errstr;

	    $sth->finish;

	    my $res = Plack::Response->new( 302 );

	    $res->redirect( "/function?agent_id=$agent" );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'delete'  && check_role( $session, 'admin_delete,delete_function' )) {
	    my $sql = "DELETE FROM ai_function WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;

	    $sth->finish;

	    my $res = Plack::Response->new( 302 );

	    $res->redirect( "/function?agent_id=$agent" );

	    $dbh->disconnect;

	    return $res->finalize;
	}
    } else {
	if ( check_role( $session, 'admin_view,view_functions' ) ) {
	    my $sql = "SELECT * FROM ai_function WHERE agent_id = ? ORDER BY created DESC";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent ) or die $DBI::errstr;

	    my $functions = $sth->fetchall_arrayref({});

	    $sth->finish;

	    my $template = HTML::Template::Expr->new( filename => "/app/template/function.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav       => @nav,
		nonce	  => $env->{'plack.nonce'},
		agent_id  => $agent,
		functions => $functions
		);

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} else {
	    my $template = HTML::Template->new(filename => '/app/template/403.tmpl');

	    $template->param(message => "You do not have permission to access this resource");

	    $res->status( 403 );

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	}
    }
}

sub feature {
    my $env    = shift;
    my $req    = Plack::Request->new( $env );
    my $agent  = $req->param( 'agent_id' );
    my $method = $req->method;
    my $res    = Plack::Response->new( 200 );
    my $params = $req->parameters;

    my $session = $env->{'psgix.session'};

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die $DBI::errstr;

    $res->content_type( 'text/html' );

    if ( $method eq 'POST' ) {
	if ( $params->{action} eq 'create' && check_role( $session, 'admin_create,create_features' ) ) {
	    my $sql = "INSERT INTO ai_features ( created, description ) VALUES ( now(), ?)";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{description} ) or die $DBI::errstr;

	    $sth->finish;

	    $dbh->disconnect;

	    $res->redirect( "/feature" );

	    return $res->finalize;
	} elsif ( $params->{action} eq 'add' && check_role( $session, 'admin_create,create_features' ) ) {
	    my $template = HTML::Template::Expr->new( filename => "/app/template/create_feature.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav             => @admin_nav,
		nonce		=> $env->{'plack.nonce'},
		agent_id        => $agent,
		);
	    
	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'edit' && check_role( $session, 'admin_update,update_features' ) ) {
	    my $sql = "SELECT * FROM ai_features WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;

	    my $feature = $sth->fetchrow_hashref;

	    $sth->finish;

	    my $template = HTML::Template::Expr->new( filename => "/app/template/edit_feature.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav             => $session->{is_admin} ? @admin_nav : @nav,
		nonce		=> $env->{'plack.nonce'},
		);
	    
	    $template->param( %$feature );

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'update'  && check_role( $session, 'admin_update,update_features' ) ) {
	    my $sql = "UPDATE ai_features SET description = ?, code = ? WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{description}, $params->{code}, $params->{id} ) or die $DBI::errstr;

	    $sth->finish;

	    my $res = Plack::Response->new( 302 );

	    $res->redirect( "/feature" );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'delete'  && check_role( $session, 'admin_delete,delete_feature' )) {
	    my $sql = "DELETE FROM ai_features WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;

	    $sth->finish;

	    my $res = Plack::Response->new( 302 );

	    $res->redirect( "/feature" );

	    $dbh->disconnect;

	    return $res->finalize;
	}
    } else {
	if ( check_role( $session, 'admin_view,view_features' ) ) {
	    my $sql = "SELECT * FROM ai_features";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute() or die $DBI::errstr;

	    my $features = $sth->fetchall_arrayref({});

	    $sth->finish;

	    my $template = HTML::Template::Expr->new( filename => "/app/template/features.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav       => $session->{is_admin} ? @admin_nav : @nav,
		nonce	  => $env->{'plack.nonce'},
		agent_id  => $agent,
		features  => $features
		);

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} else {
	    my $template = HTML::Template->new(filename => '/app/template/403.tmpl');

	    $template->param(message => "You do not have permission to access this resource");

	    $res->status( 403 );

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	}
    }
}

sub functionargs {
    my $env          = shift;
    my $req          = Plack::Request->new( $env );
    my $agent        = $req->param( 'agent_id' );
    my $function_id  = $req->param( 'function_id' );
    my $functionnam  = $req->param( 'function_name' );
    my $method       = $req->method;
    my $res          = Plack::Response->new( 200 );
    my $params       = $req->parameters;

    my $session = $env->{'psgix.session'};

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die $DBI::errstr;


    $res->content_type( 'text/html' );

    $params->{active_checked} = $params->{active} ? 'checked' : '';
    $params->{required_checked} = $params->{required} ? 'checked' : '';
    
    if ( $method eq 'POST' ) {
	if ( $params->{action} eq 'create' && check_role( $session ,'admin_create,create_functionargs' ) ) {
	    my $sql = "INSERT INTO ai_function_argument (function_id, agent_id, name, type, description, active, required) VALUES (?, ?, ?, ?, ?, ?, ?)";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{function_id}, $params->{agent_id}, $params->{name}, $params->{type}, $params->{description}, $params->{active}, $params->{required} ) or die $DBI::errstr;

	    $sth->finish;

	    $res->redirect( "/functionargs?agent_id=$agent&function_id=$function_id&function_name=$functionnam" );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'add' && check_role( $session ,'admin_create,create_functionargs' ) ) {
	    my $template = HTML::Template::Expr->new( filename => "/app/template/create_function_argument.tmpl", die_on_bad_params => 0 );
	    print STDERR Dumper($params);
	    $template->param(
		nav             => @nav,
		nonce		=> $env->{'plack.nonce'},
		agent_id        => $agent,
		function_id     => $function_id,
		function_name   => $functionnam
		);

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'edit' && check_role( $session ,'admin_create,update_functionargs' ) ) {
	    my $sql = "SELECT * FROM ai_function_argument WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;

	    my $function_args = $sth->fetchrow_hashref;

	    $sth->finish;

	    my $template = HTML::Template::Expr->new( filename => "/app/template/edit_function_argument.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav             => @nav,
		nonce		=> $env->{'plack.nonce'},
		agent_id        => $agent,
		function_id     => $function_id,
		function_name   => $functionnam
		);

	    $function_args->{active_checked}   = $function_args->{active}   ? 'checked' : '';
	    $function_args->{required_checked} = $function_args->{required} ? 'checked' : '';
	    
	    $template->param( %$function_args );

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'update' && check_role( $session ,'admin_create,update_functionargs' ) ) {
	    my $sql = "UPDATE ai_function_argument SET name = ?, type = ?, description = ?, active = ?, required = ? WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{name}, $params->{type}, $params->{description}, $params->{active}, $params->{required}, $params->{id} ) or die $DBI::errstr;

	    $sth->finish;

	    my $res = Plack::Response->new( 302 );

	    $res->redirect( "/functionargs?agent_id=$agent&function_id=$function_id&function_name=$functionnam" );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'delete'  && check_role( $session ,'admin_delete,delete_functionargs' )) {
	    my $sql = "DELETE FROM ai_function_argument WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;

	    $sth->finish;

	    my $res = Plack::Response->new( 302 );

	    $res->redirect( "/functionargs?agent_id=$agent&function_id=$function_id&function_name=$functionnam" );

	    $dbh->disconnect;

	    return $res->finalize;
	}
    } else {
	if ( check_role( $session ,'admin_view,view_functionargs' ) ) {
	    my $sql = "SELECT * FROM ai_function_argument WHERE function_id = ? AND agent_id = ? ORDER BY created DESC";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $function_id, $agent ) or die $DBI::errstr;

	    my $functionargs = $sth->fetchall_arrayref({});

	    $sth->finish;

	    my $template = HTML::Template::Expr->new( filename => "/app/template/function_arguments.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav            => @nav,
		nonce	   => $env->{'plack.nonce'},
		agent_id       => $agent,
		function_id    => $function_id,
		functionargs   => $functionargs,
		function_name  => $functionnam
		);

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} else {
	    my $template = HTML::Template->new(filename => '/app/template/403.tmpl');

	    $template->param(message => "You do not have permission to access this resource");

	    $res->status( 403 );

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	}
    }
}

sub featuretoggles {
    my $env          = shift;
    my $req          = Plack::Request->new( $env );
    my $feature_id   = $req->param( 'feature_id' );
    my $featurenam   = $req->param( 'feature_name' );
    my $method       = $req->method;
    my $res          = Plack::Response->new( 200 );
    my $params       = $req->parameters;

    my $session = $env->{'psgix.session'};

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die $DBI::errstr;


    $res->content_type( 'text/html' );

    if ( $method eq 'POST' ) {
	if ( $params->{action} eq 'create' && check_role( $session ,'admin_create,create_featuretoggles' ) ) {
	    my $sql = "INSERT INTO ai_feature_toggles ( feature_id, toggle, description, toggle_order ) VALUES ( ?, ?, ?, ? )";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $feature_id, $params->{toggle}, $params->{description}, $params->{toggle_order} ) or die $DBI::errstr;

	    $sth->finish;

	    $res->redirect( "/featuretoggles?feature_id=$feature_id&feature_name=$featurenam" );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'add' && check_role( $session ,'admin_create,create_featuretoggles' ) ) {
	    my $template = HTML::Template::Expr->new( filename => "/app/template/create_feature_toggle.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav             => @nav,
		nonce		=> $env->{'plack.nonce'},
		feature_id      => $feature_id,
		feature_name    => $featurenam
		);

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'edit' && check_role( $session ,'admin_create,update_featuretoggles' ) ) {
	    my $sql = "SELECT * FROM ai_feature_toggles WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;

	    my $feature_toggles = $sth->fetchrow_hashref;

	    $sth->finish;

	    my $template = HTML::Template::Expr->new( filename => "/app/template/edit_feature_toggle.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav             => @nav,
		nonce		=> $env->{'plack.nonce'},
		feature_id      => $feature_id,
		feature_name    => $featurenam
		);

	    $template->param( %$feature_toggles );

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'update' && check_role( $session ,'admin_create,update_featuretoggles' ) ) {
	    my $sql = "UPDATE ai_feature_toggles SET toggle = ?, description = ?, toggle_order = ? WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{toggle}, $params->{description}, $params->{toggle_order}, $params->{id} ) or die $DBI::errstr;

	    $sth->finish;

	    my $res = Plack::Response->new( 302 );

	    $res->redirect( "/featuretoggles?feature_id=$feature_id&feature_name=$featurenam" );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'delete'  && check_role( $session ,'admin_delete,delete_featuretoggles' )) {
	    my $sql = "DELETE FROM ai_feature_toggles WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;

	    $sth->finish;

	    my $res = Plack::Response->new( 302 );

	    $res->redirect( "/featuretoggles?feature_id=$feature_id&feature_name=$featurenam" );

	    $dbh->disconnect;

	    return $res->finalize;
	}
    } else {
	if ( check_role( $session ,'admin_view,view_featuretoggles' ) ) {
	    my $sql = "SELECT * FROM ai_feature_toggles WHERE feature_id = ? ORDER BY toggle_order ASC";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $feature_id ) or die $DBI::errstr;

	    my $featuretoggles = $sth->fetchall_arrayref({});

	    $sth->finish;

	    my $template = HTML::Template::Expr->new( filename => "/app/template/feature_toggle.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav             => @nav,
		nonce	        => $env->{'plack.nonce'},
		feature_id      => $feature_id,
		feature_name    => $featurenam,
		featuretoggles  => $featuretoggles
		);

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} else {
	    my $template = HTML::Template->new(filename => '/app/template/403.tmpl');

	    $template->param(message => "You do not have permission to access this resource");

	    $res->status( 403 );

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	}
    }
}

sub featurestrings {
    my $env          = shift;
    my $req          = Plack::Request->new( $env );
    my $feature_id   = $req->param( 'feature_id' );
    my $featurenam   = $req->param( 'feature_name' );
    my $method       = $req->method;
    my $res          = Plack::Response->new( 200 );
    my $params       = $req->parameters;

    my $session = $env->{'psgix.session'};

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die $DBI::errstr;


    $res->content_type( 'text/html' );

    $params->{required_checked} = $params->{required} ? 'checked' : '';
    
    if ( $method eq 'POST' ) {
	if ( $params->{action} eq 'create' && check_role( $session ,'admin_create,create_featurestrings' ) ) {
	    my $sql = "INSERT INTO ai_feature_strings ( string, description, string_order, required, feature_id ) VALUES ( ?, ?, ?, ?, ? )";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{string}, $params->{description}, $params->{string_order}, $params->{required}, $feature_id ) or die $DBI::errstr;

	    $sth->finish;

	    $res->redirect( "/featurestrings?feature_id=$feature_id&feature_name=$featurenam" );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'add' && check_role( $session ,'admin_create,create_featurestrings' ) ) {
	    my $template = HTML::Template::Expr->new( filename => "/app/template/create_feature_string.tmpl", die_on_bad_params => 0 );
	    print STDERR Dumper($params);
	    $template->param(
		nav             => @nav,
		nonce		=> $env->{'plack.nonce'},
		feature_id      => $feature_id,
		feature_name    => $featurenam,
		);

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'edit' && check_role( $session ,'admin_create,update_featurestrings' ) ) {
	    my $sql = "SELECT * FROM ai_feature_strings WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;

	    my $feature_strings = $sth->fetchrow_hashref;

	    $sth->finish;

	    my $template = HTML::Template::Expr->new( filename => "/app/template/edit_feature_string.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav             => @nav,
		nonce		=> $env->{'plack.nonce'},
		feature_id      => $feature_id,
		feature_name    => $featurenam,
		);

	    $feature_strings->{required_checked} = $feature_strings->{required} ? 'checked' : '';
	    
	    $template->param( %$feature_strings );

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'update' && check_role( $session ,'admin_create,update_featurestrings' ) ) {
	    my $sql = "UPDATE ai_feature_strings SET string = ?, description = ?, string_order = ?, required = ? WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{string}, $params->{description}, $params->{string_order}, $params->{required}, $params->{id} ) or die $DBI::errstr;

	    $sth->finish;

	    my $res = Plack::Response->new( 302 );

	    $res->redirect( "/featurestrings?feature_id=$feature_id&feature_name=$featurenam" );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'delete'  && check_role( $session ,'admin_delete,delete_featurestrings' )) {
	    my $sql = "DELETE FROM ai_feature_strings WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;

	    $sth->finish;

	    my $res = Plack::Response->new( 302 );

	    $res->redirect( "/featurestrings?feature_id=$feature_id&feature_name=$featurenam" );

	    $dbh->disconnect;

	    return $res->finalize;
	}
    } else {
	if ( check_role( $session ,'admin_view,view_featurestrings' ) ) {
	    my $sql = "SELECT * FROM ai_feature_strings WHERE feature_id = ? ORDER BY string_order";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $feature_id ) or die $DBI::errstr;

	    my $featurestrings = $sth->fetchall_arrayref({});

	    $sth->finish;

	    my $template = HTML::Template::Expr->new( filename => "/app/template/feature_strings.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav            => @nav,
		nonce	   => $env->{'plack.nonce'},
		feature_id     => $feature_id,
		feature_name   => $featurenam,
		featurestrings => $featurestrings
		);

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} else {
	    my $template = HTML::Template->new(filename => '/app/template/403.tmpl');

	    $template->param(message => "You do not have permission to access this resource");

	    $res->status( 403 );

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	}
    }
}

sub context {
    my $env    = shift;
    my $req    = Plack::Request->new( $env );
    my $agent  = $req->param( 'agent_id' );
    my $method = $req->method;
    my $params = $req->parameters;
    my $res    = Plack::Response->new( 200 );

    my $session = $env->{'psgix.session'};

    $res->content_type( 'text/html' );

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die $DBI::errstr;

    if ( $method eq 'POST' ) {

	$params->{consolidate} = $params->{consolidate} ? 1 : 0;

	$params->{full_reset}  = $params->{full_reset}  ? 1 : 0;

	if ( $params->{action} eq 'create' && check_role( $session ,'admin_create,create_contexts' ) ) {
	    my $sql = "INSERT INTO ai_context (agent_id, name, pattern, toggle_function, consolidate, full_reset, user_prompt, system_prompt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent, $params->{name}, $params->{pattern}, $params->{toggle_function}, $params->{consolidate}, $params->{full_reset}, $params->{user_prompt}, $params->{system_prompt} ) or die $DBI::errstr;

	    $sth->finish;

	    $dbh->disconnect;

	    $res->redirect( "/context?agent_id=$agent" );

	    return $res->finalize;
	} elsif ( $params->{action} eq 'add' && check_role( $session ,'admin_create,create_contexts' ) ) {

	    my $template = HTML::Template::Expr->new( filename => "/app/template/create_context.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav      => @nav,
		nonce    => $env->{'plack.nonce'},
		agent_id => $agent,
		);

	    $res->body( $template->output );

	    return $res->finalize;
	} elsif ( $params->{action} eq 'edit' && check_role( $session ,'admin_update,update_contexts' ) ) {
	    my $sql = "SELECT * FROM ai_context WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;

	    my $context = $sth->fetchrow_hashref;

	    $sth->finish;

	    $context->{consolidate_checked} = $context->{consolidate} ? 'checked' : '';
	    $context->{full_reset_checked}  = $context->{full_reset}  ? 'checked' : '';

	    my $template = HTML::Template::Expr->new( filename => "/app/template/edit_context.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav      => @nav,
		nonce    => $env->{'plack.nonce'},
		agent_id => $agent,
		);

	    $template->param( %$context );

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'update' && check_role( $session ,'admin_update,update_contexts' ) ) {
	    my $sql = "UPDATE ai_context SET name = ?, pattern = ?, toggle_function = ?, consolidate = ?, full_reset = ? , user_prompt = ?, system_prompt = ? WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{name}, $params->{pattern}, $params->{toggle_function}, $params->{consolidate}, $params->{full_reset}, $params->{user_prompt}, $params->{system_prompt}, $params->{id} ) or die $DBI::errstr;

	    $sth->finish;

	    $dbh->disconnect;

	    $res->redirect( "/context?agent_id=$agent" );

	    return $res->finalize;
	} elsif ( $params->{action} eq 'delete' && check_role( $session ,'admin_delete,delete_contexts' ) ) {
	    my $sql = "DELETE FROM ai_context WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;

	    $sth->finish;

	    $dbh->disconnect;

	    $res->redirect( "/context?agent_id=$agent" );

	    return $res->finalize;
	}
    } else {
	if ( check_role( $session ,'admin_view,view_contexts' ) ) {
	    my $sql = "SELECT * FROM ai_context WHERE agent_id = ? ORDER BY created DESC";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent ) or die $DBI::errstr;

	    my $contexts = $sth->fetchall_arrayref({});

	    $sth->finish;

	    $dbh->disconnect;

	    my $template = HTML::Template::Expr->new( filename => "/app/template/context.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav      => @nav,
		nonce    => $env->{'plack.nonce'},
		agent_id => $agent,
		contexts => $contexts
		);

	    $res->body( $template->output );

	    return $res->finalize;
	} else {
	    my $template = HTML::Template->new(filename => '/app/template/403.tmpl');

	    $template->param(message => "You do not have permission to access this resource");

	    $res->status(403);

	    $res->body($template->output);

	    $dbh->disconnect;

	    return $res->finalize;
	}
    }
}

sub step {
    my $env    = shift;
    my $req    = Plack::Request->new( $env );
    my $agent  = $req->param( 'agent_id' );
    my $method = $req->method;
    my $params = $req->parameters;
    my $res    = Plack::Response->new( 200 );

    my $session = $env->{'psgix.session'};

    $res->content_type( 'text/html' );

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die $DBI::errstr;

    if ( $method eq 'POST' ) {

	$params->{ai_step_b2b_functions} = $params->{ai_step_b2b_functions} ? 1 : 0;

	if ( $params->{action} eq 'create' && check_role( $session ,'admin_create,create_step' ) ) {
	    my $sql = "INSERT INTO ai_steps (agent_id, ai_step_pattern, ai_step_response, ai_step_b2b_functions, toggle_function, custom_action) VALUES ( ?, ?, ?, ?, ?, ? )";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent, $params->{ai_step_pattern}, $params->{ai_step_response}, $params->{ai_step_b2b_functions}, $params->{toggle_function}, $params->{custom_action} ) or die $DBI::errstr;

	    $sth->finish;

	    $dbh->disconnect;

	    $res->redirect( "/step?agent_id=$agent" );

	    return $res->finalize;
	} elsif ( $params->{action} eq 'add' && check_role( $session ,'admin_create,create_step' ) ) {

	    my $template = HTML::Template::Expr->new( filename => "/app/template/create_step.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav      => @nav,
		nonce    => $env->{'plack.nonce'},
		agent_id => $agent,
		);

	    $res->body( $template->output );

	    return $res->finalize;
	} elsif ( $params->{action} eq 'edit' && check_role( $session ,'admin_update,update_step' ) ) {
	    my $sql = "SELECT * FROM ai_steps WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;

	    my $step = $sth->fetchrow_hashref;

	    $sth->finish;

	    $step->{ai_step_b2b_functions_checked} = $step->{ai_step_b2b_functions} ? 'checked' : '';

	    my $template = HTML::Template::Expr->new( filename => "/app/template/edit_step.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav      => @nav,
		nonce    => $env->{'plack.nonce'},
		agent_id => $agent,
		);

	    $template->param( %$step );

	    $res->body( $template->output );

	    $dbh->disconnect;

	    return $res->finalize;
	} elsif ( $params->{action} eq 'update' && check_role( $session ,'admin_update,update_step' ) ) {
	    my $sql = "UPDATE ai_steps SET ai_step_pattern = ?, ai_step_response = ?, ai_step_b2b_functions = ?, toggle_function = ?, custom_action = ? WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{ai_step_pattern}, $params->{ai_step_response}, $params->{ai_step_b2b_functions}, $params->{toggle_function}, $params->{custom_action}, $params->{id} ) or die $DBI::errstr;
	    $sth->finish;

	    $dbh->disconnect;

	    $res->redirect( "/step?agent_id=$agent" );

	    return $res->finalize;
	} elsif ( $params->{action} eq 'delete' && check_role( $session ,'admin_delete,delete_step' ) ) {
	    my $sql = "DELETE FROM ai_steps WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;

	    $sth->finish;

	    $dbh->disconnect;

	    $res->redirect( "/step?agent_id=$agent" );

	    return $res->finalize;
	}
    } else {
	if ( check_role( $session ,'admin_view,view_step' ) ) {
	    my $sql = "SELECT * FROM ai_steps WHERE agent_id = ? ORDER BY ai_step_pattern ASC";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $agent ) or die $DBI::errstr;

	    my $steps = $sth->fetchall_arrayref({});

	    $sth->finish;

	    $dbh->disconnect;

	    my $template = HTML::Template::Expr->new( filename => "/app/template/step.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav      => @nav,
		nonce    => $env->{'plack.nonce'},
		agent_id => $agent,
		steps => $steps
		);

	    $res->body( $template->output );

	    return $res->finalize;
	} else {
	    my $template = HTML::Template->new(filename => '/app/template/403.tmpl');

	    $template->param(message => "You do not have permission to access this resource");

	    $res->status(403);

	    $res->body($template->output);

	    $dbh->disconnect;

	    return $res->finalize;
	}
    }
}

sub users {
    my $env    = shift;
    my $req    = Plack::Request->new( $env );
    my $method = $req->method;
    my $res    = Plack::Response->new( 200 );
    my $params = $req->parameters;

    $res->content_type( 'text/html' );

    my $session = $env->{'psgix.session'};

    my $dbh = DBI->connect(
	"dbi:Pg:dbname=$database;host=$host;port=$port",
	$dbusername,
	$dbpassword,
	{ AutoCommit => 1, RaiseError => 1 } ) or die $DBI::errstr;

    if ( $method eq 'POST' ) {
	$params->{is_admin}     = $params->{is_admin}     ? 1 : 0;
	$params->{is_viewer}    = $params->{is_viewer}    ? 1 : 0;

	if ( $params->{action} eq 'create' && check_role( $session ,'admin_create,create_users' ) ) {
	    my $sql = "INSERT INTO ai_users (username, password, first_name, last_name, email, phone_number, is_admin, is_viewer) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

	    my $salt = substr(generate_nonce(), 0, 16);

	    my $bcrypt_hash = bcrypt( $params->{password}, '2b', 12, $salt );

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( lc($params->{username}), $bcrypt_hash, $params->{first_name}, $params->{last_name}, $params->{email}, $params->{phone_number}, $params->{is_admin}, $params->{is_viewer} )
		or die $DBI::errstr;

	    $sth->finish;

	    $res->status( 302 );
	    
	    $res->redirect( "/users" );

	    return $res->finalize;
	} elsif ( $params->{action} eq 'add' && check_role( $session ,'admin_create,create_users' ) ) {
	    my $template = HTML::Template::Expr->new( filename => "/app/template/create_user.tmpl", die_on_bad_params => 0 );

	    $template->param(
		nav      => $session->{is_admin} ? @admin_nav : @user_nav,
		nonce    => $env->{'plack.nonce'}
		);

	    $res->body( $template->output );

	    return $res->finalize;
	} elsif ( $params->{action} eq 'update' && check_role( $session ,'admin_update,update_users' ) ) {
	    my $sql;

	    if ( $params->{password} ) {
		$sql = "UPDATE ai_users SET password = ?, first_name = ?, last_name = ?, email = ?, phone_number = ?, is_admin = ?, is_viewer = ? WHERE id = ?";
	    } else {
		$sql = "UPDATE ai_users SET first_name = ?, last_name = ?, email = ?, phone_number = ?, is_admin = ?, is_viewer = ? WHERE id = ?";
	    }

	    my $sth = $dbh->prepare( $sql );

	    if ( $params->{password} ) {
		my $salt = substr(generate_nonce(), 0, 16);

		my $bcrypt_hash = bcrypt( $params->{password}, '2b', 12, $salt );

		$sth->execute( $bcrypt_hash, $params->{first_name}, $params->{last_name}, $params->{email}, $params->{phone_number}, $params->{is_admin}, $params->{is_viewer}, $params->{id} )
		    or die $DBI::errstr;
	    } else {
		$sth->execute( $params->{first_name}, $params->{last_name}, $params->{email}, $params->{phone_number}, $params->{is_admin}, $params->{is_viewer}, $params->{id} )
		    or die $DBI::errstr;
	    }

	    $sth->finish;

	    $res->status( 302 );

	    $res->redirect( "/users" );

	    return $res->finalize;
	} elsif ( $params->{action} eq 'delete' && check_role( $session ,'admin_delete,delete_users' ) ) {
	    my $sql = "DELETE FROM ai_users WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;

	    $sth->finish;
	} elsif ( $params->{action} eq 'edit' && check_role( $session ,'admin_update,update_users' ) ) {
	    my $totp_qrcode;
	    my $sql = "SELECT * FROM ai_users WHERE id = ?";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute( $params->{id} ) or die $DBI::errstr;

	    my $user = $sth->fetchrow_hashref;

	    $user->{is_admin_checked}     = $user->{is_admin}     ? 'checked' : '';
	    $user->{is_viewer_checked}    = $user->{is_viewer}    ? 'checked' : '';

	    my $template = HTML::Template::Expr->new( filename => "/app/template/edit_user.tmpl", die_on_bad_params => 0 );

	    delete $user->{password};

	    $template->param(
		nav         => $session->{is_admin} ? @admin_nav : @user_nav,
		nonce       => $env->{'plack.nonce'},
		);

	    $template->param( %$user );

	    $res->body( $template->output );

	    return $res->finalize;
	}
    } else {
	if ( check_role( $session ,'admin_view,view_users' ) ) {
	    my $sql = "SELECT * FROM ai_users ORDER BY created DESC";

	    my $sth = $dbh->prepare( $sql );

	    $sth->execute() or die $DBI::errstr;

	    my $users = $sth->fetchall_arrayref({});

	    my $template = HTML::Template::Expr->new( filename => "/app/template/users.tmpl", die_on_bad_params => 0 );

	    $dbh->disconnect;

	    $template->param(
		nav      => $session->{is_admin} ? @admin_nav : @user_nav,
		nonce    => $env->{'plack.nonce'},
		users    => $users
		);

	    $res->body( $template->output );

	    return $res->finalize;
	} else {
	    my $template = HTML::Template->new(filename => '/app/template/403.tmpl');

	    $template->param(message => "You do not have permission to access this resource");

	    $res->status(403);

	    $res->body($template->output);

	    $dbh->disconnect;

	    return $res->finalize;
	}
    }
}

sub debug {
    my $env   = shift;
    my $req   = Plack::Request->new( $env );
    my $agent = $req->param( 'agent_id' );
    my $res   = Plack::Response->new( 200 );

    my $session = $env->{'psgix.session'};

    $res->content_type( 'text/html' );

    if ( check_role( $session ,'admin_view,view_debug' ) ) {

	my $template = HTML::Template::Expr->new( filename => "/app/template/debug.tmpl", die_on_bad_params => 0 );

	$template->param(
	    nav      => @nav,
	    nonce    => $env->{'plack.nonce'},
	    wss      => "wss://$env->{HTTP_HOST}/websocket",
	    agent_id => $agent
	    );

	$res->body( $template->output );

	return $res->finalize;
    } else {
	my $template = HTML::Template->new(filename => '/app/template/403.tmpl');

	$template->param(message => "You do not have permission to access this resource");

	$res->status(403);

	$res->body($template->output);

	return $res->finalize;
    }
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
	{ AutoCommit => 1, RaiseError => 1 } ) or die $DBI::errstr;

    if ( $action eq "fetch_conversation" && defined $convo_id ) {
	my @summary;

	my $fetch_sql = "SELECT created,summary FROM ai_summary WHERE convo_id = ? AND agent_id = ? AND created >= CURRENT_TIMESTAMP - INTERVAL '4 hours'";

	my $fsth = $dbh->prepare( $fetch_sql );

	$fsth->execute( $convo_id, $agent ) or die $DBI::errstr;

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

	    $csth->execute( $convo_id, $convo_sum, $agent ) or die $DBI::errstr;

	    broadcast_by_agent_id( $agent, { conversation_summary => $convo_sum } );
	}

	my $insert_sql = "INSERT INTO ai_post_prompt (created, data, agent_id) VALUES (CURRENT_TIMESTAMP, ?, ?)";

	my $json_data = $req->raw_body;

	my $sth = $dbh->prepare( $insert_sql );

	$sth->execute( $json_data, $agent ) or die $DBI::errstr;

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
				 text       => ":signalwire: :new: New Conversation https://$env->{HTTP_HOST}/agent?id=$last_insert_id&agent_id=$agent -> $raw",
				 channel    => "$config{SLACK_CHANNEL}",
				 username   => "$config{SLACK_USERNAME}",
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
			      'Content-Type'  => 'application/json',
			      'Authorization' => "$config{ZENDESK_API_KEY}",
			      'Content' =>
			      $json->encode({
				  ticket => {
				      comment  => {
					  body => "https://$env->{HTTP_HOST}/agent?id=$last_insert_id&agent_id=$agent\n\n$raw"
				      },
				      priority => "normal",
				      subject  => "Call Disposition - $from",
				  }})
		);

	    $ua->request( $ticket );
	    broadcast_by_agent_id( $agent, 'Zendesk ticket created' );
	}

	if ( $config{SEND_SUMMARY_MESSAGE} && $config{CUSTODIAN_SMS} && $config{ACCOUNT_SID} && $config{AUTH_TOKEN} && $config{SPACE_NAME} && $config{API_VERSION} ) {
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

my $assets_app = Plack::App::Directory->new( root => "/app/assets" )->to_app;

my $web_app = sub {
    my $env      = shift;
    my $req      = Plack::Request->new( $env );
    my $swml     = SignalWire::ML->new;
    my $agent    = $req->param( 'agent_id' );
    my $path     = $req->path_info;
    my $method   = $req->method;
    my $redirect = $req->param( 'redirect' );
    my $request  =  uri_escape( $env->{'REQUEST_URI'} );

    my $session = $env->{'psgix.session'};

    print STDERR "Path: $path\n"                       if $ENV{DEBUG};
    print STDERR "Method: $method\n"                   if $ENV{DEBUG};
    print STDERR "Agent: $agent\n"                     if $agent && $ENV{DEBUG};

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
		{ AutoCommit => 1, RaiseError => 1 } ) or die $DBI::errstr;

	    my $stored_bcrypt_hash = $dbh->selectrow_array( "SELECT password FROM ai_users WHERE username = ?", undef, $username );

	    if ( $stored_bcrypt_hash && bcrypt_check( $password, $stored_bcrypt_hash ) ) {
		$session->{logged_in} = 1;

		my $admin   = $dbh->selectrow_array( "SELECT is_admin FROM ai_users WHERE username = ?", undef, $username );

		my $viewer  = $dbh->selectrow_array( "SELECT is_viewer FROM ai_users WHERE username = ?", undef, $username );

		my $totp    = $dbh->selectrow_array( "SELECT totp_enabled FROM ai_users WHERE username = ?", undef, $username );

		my $user_id = $dbh->selectrow_array( "SELECT id FROM ai_users WHERE username = ?", undef, $username );

		$session->{is_admin}     = $admin;
		$session->{is_viewer}    = $viewer;
		$session->{totp_enabled} = $totp;
		$session->{username}     = $username;
		$session->{user_id}      = $user_id;

		my $sth = $dbh->prepare("SELECT * FROM ai_user_roles WHERE user_id = ?");

		$sth->execute( $user_id );

		$session->{roles}  = $sth->fetchall_arrayref({});

		$sth->finish;

		print STDERR Dumper $session if $ENV{DEBUG};

		$dbh->disconnect;


		$res->redirect( $redirect ? $redirect : "/" );

	    } else {
		$res->redirect( "/login?error=1" );
	    }
	} else {
	    if ( $session->{logged_in} ) {
		$res->redirect( $redirect ne '' ? $redirect : "/" );
	    } else {
		my $error = $req->param( 'error' ) || 0;

		my $template = HTML::Template::Expr->new( filename => '/app/template/login.tmpl', die_on_bad_params => 0 );

		$template->param(
		    error    => $error,
		    nonce    => $env->{'plack.nonce'},
		     ( $redirect ? ( redirect => $redirect ) : ())
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
	    $res->redirect( "/" );

	    return $res->finalize;
	}
    } else {
	my $res = Plack::Response->new( 200 );

	$res->content_type( 'text/html' );

	$res->redirect( $request ne '' ? "/login?redirect=$request" : "/login" );

	return $res->finalize;
    }
};

my $logout_app = sub {
	my $env      = shift;
	my $session  = $env->{'psgix.session'};
	my $req      = Plack::Request->new( $env );
	my $redirect = $req->param( 'redirect' );

	$session->{logged_in} = 0;

	$session->{is_admin}  = 0;

	$session->{totp_enabled} = 0;

	$session->{redirected} = 0;

	delete $session->{username};

	my $res = Plack::Response->new( 200 );

	$res->content_type( 'text/html' );

	$res->redirect( $redirect ne '' ? "/login?redirect=$redirect" : "/login" );

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
	    }

	    return $res;
	};
    };

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
    mount "/register"  => $register_app;
    mount "/reset"     => $reset_app;
    mount "/assets"    => $assets_app;
    mount "/logout"    => $logout_app;

    mount '/' => $web_app;
};

my $dbh = DBI->connect(
    "dbi:Pg:dbname=$database;host=$host;port=$port",
    $dbusername,
    $dbpassword,
    { AutoCommit => 1, RaiseError => 1 } ) or die "Couldn't connect to database: $DBI::errstr";

foreach my $table ( keys %{$data_sql} ) {
    print STDERR "Checking for table $table\n" if $ENV{DEBUG};
    my $sql = $data_sql->{$table}->{create};
    print STDERR "Creating table $sql\n" if $ENV{DEBUG};
    $dbh->do( $sql ) or die "Couldn't execute statement: $DBI::errstr";
}

$dbh->disconnect;

# Running the PSGI application
my $runner = Plack::Runner->new;

$runner->run( $server );

1;
